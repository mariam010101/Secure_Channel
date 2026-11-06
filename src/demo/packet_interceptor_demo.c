#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include <unistd.h>
#include <errno.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#include <linux/netfilter.h>
#include <libnetfilter_queue/libnetfilter_queue.h>

#include "../common/secure_packet.h"
#include "../common/packet_parser.h"

#define PC1_IP "10.10.1.2"
#define PC2_IP "10.10.3.2"

#define QUEUE_NUMBER 0
#define BUFFER_SIZE 65536

typedef enum {
    MODE_ENCRYPT,
    MODE_DECRYPT
} InterceptionMode;

typedef struct {
    struct nfq_q_handle *queue;
    InterceptionMode mode;
    unsigned char key[AES_KEY_SIZE];
} InterceptorContext;


/*
 * Load the 32-byte session key.
 */
static int load_session_key(
    const char *filename,
    unsigned char key[AES_KEY_SIZE]
) {
    FILE *file = fopen(filename, "rb");

    if (!file) {
        perror("Cannot open session key");
        return 0;
    }

    size_t bytes = fread(key, 1, AES_KEY_SIZE, file);

    fclose(file);

    if (bytes != AES_KEY_SIZE) {
        fprintf(stderr, "Invalid session key size.\n");
        return 0;
    }

    return 1;
}


/*
 * Process intercepted packets.
 */
static int packet_callback(
    struct nfq_q_handle *queue,
    struct nfgenmsg *message,
    struct nfq_data *packet_data,
    void *user_data
) {
    (void)message;

    InterceptorContext *context =
        (InterceptorContext *)user_data;

    struct nfqnl_msg_packet_hdr *header =
        nfq_get_msg_packet_hdr(packet_data);

    if (!header) {
        return 0;
    }

    uint32_t packet_id = ntohl(header->packet_id);

    unsigned char *packet = NULL;

    int packet_length =
        nfq_get_payload(packet_data, &packet);

    if (packet_length <= 0) {
        return nfq_set_verdict(
            queue,
            packet_id,
            NF_ACCEPT,
            0,
            NULL
        );
    }

    ParsedPacket parsed;

    if (parse_tcp_packet(
        packet,
        (size_t)packet_length,
        &parsed
    ) != PARSE_SUCCESS) {

        return nfq_set_verdict(
            queue,
            packet_id,
            NF_ACCEPT,
            0,
            NULL
        );
    }

    /*
     * Process only PC1 -> PC2 TCP traffic.
     */

    if (parsed.source_ip.s_addr != inet_addr(PC1_IP) ||
        parsed.destination_ip.s_addr != inet_addr(PC2_IP)) {

        return nfq_set_verdict(
            queue,
            packet_id,
            NF_ACCEPT,
            0,
            NULL
        );
    }

    unsigned char *processed_packet = NULL;
    size_t processed_length = 0;

    int success;

    if (context->mode == MODE_ENCRYPT) {

        printf("[DEVICE 1] Encrypting packet...\n");

        success = secure_packet_encrypt(
            packet,
            (size_t)packet_length,
            context->key,
            &processed_packet,
            &processed_length
        );

    } else {

        printf("[DEVICE 2] Decrypting packet...\n");

        success = secure_packet_decrypt(
            packet,
            (size_t)packet_length,
            context->key,
            &processed_packet,
            &processed_length
        );
    }

    /*
     * Reject packets if encryption or authentication fails.
     */

    if (!success) {

        printf("[ERROR] Packet processing failed. Dropping packet.\n");

        return nfq_set_verdict(
            queue,
            packet_id,
            NF_DROP,
            0,
            NULL
        );
    }

    printf(
        "[SUCCESS] Packet processed. Original size: %d, New size: %zu\n",
        packet_length,
        processed_length
    );

    /*
     * Forward the modified packet.
     */

    int result = nfq_set_verdict(
        queue,
        packet_id,
        NF_ACCEPT,
        (uint32_t)processed_length,
        processed_packet
    );

    free(processed_packet);

    return result;
}


/*
 * Main interceptor.
 */
int main(int argc, char *argv[])
{
    if (argc != 3) {

        printf(
            "Usage: sudo %s <encrypt|decrypt> <session_key_file>\n",
            argv[0]
        );

        return EXIT_FAILURE;
    }

    InterceptorContext context;

    memset(&context, 0, sizeof(context));

    if (strcmp(argv[1], "encrypt") == 0) {

        context.mode = MODE_ENCRYPT;

    } else if (strcmp(argv[1], "decrypt") == 0) {

        context.mode = MODE_DECRYPT;

    } else {

        fprintf(stderr, "Invalid interception mode.\n");

        return EXIT_FAILURE;
    }

    /*
     * Load the shared session key.
     */

    if (!load_session_key(argv[2], context.key)) {
        return EXIT_FAILURE;
    }

    printf("\n====================================\n");
    printf("       SECURE PACKET INTERCEPTOR\n");
    printf("====================================\n");

    printf(
        "Mode: %s\n",
        context.mode == MODE_ENCRYPT ? "ENCRYPTION" : "DECRYPTION"
    );

    /*
     * Initialize NFQUEUE.
     */

    struct nfq_handle *handle = nfq_open();

    if (!handle) {

        fprintf(stderr, "Cannot open NFQUEUE.\n");

        return EXIT_FAILURE;
    }

    nfq_unbind_pf(handle, AF_INET);

    if (nfq_bind_pf(handle, AF_INET) < 0) {

        fprintf(stderr, "Cannot bind IPv4.\n");

        nfq_close(handle);

        return EXIT_FAILURE;
    }

    context.queue = nfq_create_queue(
        handle,
        QUEUE_NUMBER,
        &packet_callback,
        &context
    );

    if (!context.queue) {

        fprintf(stderr, "Cannot create NFQUEUE.\n");

        nfq_close(handle);

        return EXIT_FAILURE;
    }

    /*
     * Request complete packet copies.
     */

    if (nfq_set_mode(
        context.queue,
        NFQNL_COPY_PACKET,
        0xffff
    ) < 0) {

        fprintf(stderr, "Cannot configure NFQUEUE packet mode.\n");

        nfq_destroy_queue(context.queue);
        nfq_close(handle);

        return EXIT_FAILURE;
    }

    int socket_fd = nfq_fd(handle);

    unsigned char buffer[BUFFER_SIZE];

    printf("[READY] Waiting for intercepted packets...\n\n");

    /*
     * Receive and process packets continuously.
     */

    while (1) {

        int received = recv(
            socket_fd,
            buffer,
            sizeof(buffer),
            0
        );

        if (received < 0) {

            if (errno == EINTR) {
                continue;
            }

            perror("NFQUEUE receive error");

            break;
        }

        nfq_handle_packet(
            handle,
            (char *)buffer,
            received
        );
    }

    /*
     * Cleanup.
     */

    nfq_destroy_queue(context.queue);

    nfq_close(handle);

    memset(context.key, 0, sizeof(context.key));

    return EXIT_SUCCESS;
}