#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

#include <linux/netfilter.h>
#include <libnetfilter_queue/libnetfilter_queue.h>

static int packet_callback(
    struct nfq_q_handle *qh,
    struct nfgenmsg *nfmsg,
    struct nfq_data *nfa,
    void *data
) {
    struct nfqnl_msg_packet_hdr *header;
    unsigned char *packet;

    header = nfq_get_msg_packet_hdr(nfa);

    if (header == NULL) {
        return 0;
    }

    uint32_t id = ntohl(header->packet_id);

    int length = nfq_get_payload(nfa, &packet);

    printf("\n--- Packet intercepted ---\n");

    if (length >= (int)sizeof(struct iphdr)) {

        struct iphdr *ip = (struct iphdr *)packet;

        if (ip->version == 4 &&
            ip->ihl >= 5 &&
            length >= (int)(ip->ihl * 4)) {

            char source[INET_ADDRSTRLEN];
            char destination[INET_ADDRSTRLEN];

            inet_ntop(AF_INET, &ip->saddr,
                      source, sizeof(source));

            inet_ntop(AF_INET, &ip->daddr,
                      destination, sizeof(destination));

            printf("Source IP: %s\n", source);
            printf("Destination IP: %s\n", destination);
            printf("Protocol: %d\n", ip->protocol);

            if (ip->protocol == IPPROTO_TCP) {

                unsigned int ip_header_length = ip->ihl * 4;

                if (length >= (int)(ip_header_length + sizeof(struct tcphdr))) {

                    struct tcphdr *tcp =
                        (struct tcphdr *)(packet + ip_header_length);

                    printf("Source port: %u\n",
                           ntohs(tcp->source));

                    printf("Destination port: %u\n",
                           ntohs(tcp->dest));
                }
            }
        }
    }

    printf("Packet ID: %u\n", id);

    fflush(stdout);

    return nfq_set_verdict(
        qh,
        id,
        NF_ACCEPT,
        0,
        NULL
    );
}

int main(void) {

    struct nfq_handle *handle;
    struct nfq_q_handle *queue;

    char buffer[65536];

    handle = nfq_open();

    if (handle == NULL) {
        fprintf(stderr, "Error opening NFQUEUE\n");
        return EXIT_FAILURE;
    }

    if (nfq_bind_pf(handle, AF_INET) < 0) {
        fprintf(stderr, "Error binding IPv4\n");
        nfq_close(handle);
        return EXIT_FAILURE;
    }

    queue = nfq_create_queue(
        handle,
        0,
        &packet_callback,
        NULL
    );

    if (queue == NULL) {
        fprintf(stderr, "Error creating queue\n");
        nfq_close(handle);
        return EXIT_FAILURE;
    }

    if (nfq_set_mode(
        queue,
        NFQNL_COPY_PACKET,
        0xffff
    ) < 0) {

        fprintf(stderr, "Error setting packet mode\n");

        nfq_destroy_queue(queue);
        nfq_close(handle);

        return EXIT_FAILURE;
    }

    printf("NFQUEUE packet interceptor started...\n");
    fflush(stdout);

    int fd = nfq_fd(handle);

    while (1) {

        int received = recv(
            fd,
            buffer,
            sizeof(buffer),
            0
        );

        if (received < 0) {
            perror("recv");
            continue;
        }

        nfq_handle_packet(
            handle,
            buffer,
            received
        );
    }

    nfq_destroy_queue(queue);
    nfq_close(handle);

    return EXIT_SUCCESS;
}