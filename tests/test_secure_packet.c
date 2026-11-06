#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

#include "../src/common/secure_packet.h"
#include "../src/common/packet_parser.h"

#define TEST_PAYLOAD "Hello Secure Channel!"
#define TEST_PAYLOAD_SIZE (sizeof(TEST_PAYLOAD) - 1)

static int tests_passed = 0;
static int tests_failed = 0;

static void check_result(const char *name, int result)
{
    if (result) {
        printf("[PASS] %s\n", name);
        tests_passed++;
    } else {
        printf("[FAIL] %s\n", name);
        tests_failed++;
    }
}

/*
 * Construct a sample IPv4/TCP packet.
 */
static unsigned char *create_test_packet(size_t *packet_length)
{
    size_t header_length =
        sizeof(struct iphdr) + sizeof(struct tcphdr);

    *packet_length = header_length + TEST_PAYLOAD_SIZE;

    unsigned char *packet = calloc(1, *packet_length);

    if (!packet) {
        return NULL;
    }

    struct iphdr *ip = (struct iphdr *)packet;

    ip->version = 4;
    ip->ihl = 5;
    ip->ttl = 64;
    ip->protocol = IPPROTO_TCP;

    ip->saddr = inet_addr("10.10.1.2");
    ip->daddr = inet_addr("10.10.2.2");

    ip->tot_len = htons((uint16_t)*packet_length);

    struct tcphdr *tcp =
        (struct tcphdr *)(packet + sizeof(struct iphdr));

    tcp->source = htons(12345);
    tcp->dest = htons(80);
    tcp->seq = htonl(1000);
    tcp->ack_seq = htonl(2000);
    tcp->doff = 5;
    tcp->ack = 1;

    memcpy(
        packet + header_length,
        TEST_PAYLOAD,
        TEST_PAYLOAD_SIZE
    );

    return packet;
}

int main(void)
{
    printf("\n");
    printf("====================================\n");
    printf("     SECURE PACKET TEST SUITE\n");
    printf("====================================\n\n");

    unsigned char key[AES_KEY_SIZE];

    memset(key, 0x42, sizeof(key));

    size_t original_length;

    unsigned char *original =
        create_test_packet(&original_length);

    if (!original) {
        printf("ERROR: Cannot create test packet.\n");
        return EXIT_FAILURE;
    }

    unsigned char *encrypted = NULL;
    size_t encrypted_length = 0;

    unsigned char *decrypted = NULL;
    size_t decrypted_length = 0;

    /* TEST 1: Encryption */

    int encryption_result = secure_packet_encrypt(
        original,
        original_length,
        key,
        &encrypted,
        &encrypted_length
    );

    check_result(
        "TCP packet encryption",
        encryption_result == 1
    );

    if (!encryption_result) {
        free(original);
        return EXIT_FAILURE;
    }

    /* TEST 2: Encrypted packet size */

    check_result(
        "Encrypted packet contains nonce and tag",
        encrypted_length ==
            original_length + SECURE_PACKET_OVERHEAD
    );

    /* TEST 3: Original IP and TCP headers preserved */

    ParsedPacket original_parsed;
    ParsedPacket encrypted_parsed;

    int parsed_original = parse_tcp_packet(
        original,
        original_length,
        &original_parsed
    );

    int parsed_encrypted = parse_tcp_packet(
        encrypted,
        encrypted_length,
        &encrypted_parsed
    );

    int headers_preserved =
        parsed_original == PARSE_SUCCESS &&
        parsed_encrypted == PARSE_SUCCESS &&
        original_parsed.source_port ==
            encrypted_parsed.source_port &&
        original_parsed.destination_port ==
            encrypted_parsed.destination_port &&
        original_parsed.source_ip.s_addr ==
            encrypted_parsed.source_ip.s_addr &&
        original_parsed.destination_ip.s_addr ==
            encrypted_parsed.destination_ip.s_addr;

    check_result(
        "Original IP addresses and TCP ports preserved",
        headers_preserved
    );

    /* TEST 4: Decryption */

    int decryption_result = secure_packet_decrypt(
        encrypted,
        encrypted_length,
        key,
        &decrypted,
        &decrypted_length
    );

    check_result(
        "TCP packet decryption",
        decryption_result == 1
    );

    if (decryption_result) {

        check_result(
            "Original packet length restored",
            decrypted_length == original_length
        );

        check_result(
            "Original TCP payload restored",
            memcmp(
                decrypted + original_parsed.payload_offset,
                TEST_PAYLOAD,
                TEST_PAYLOAD_SIZE
            ) == 0
        );

    } else {
        check_result("Original packet length restored", 0);
        check_result("Original TCP payload restored", 0);
    }

    free(decrypted);
    decrypted = NULL;

    /* TEST 5: Incorrect encryption key */

    unsigned char wrong_key[AES_KEY_SIZE];

    memset(wrong_key, 0x99, sizeof(wrong_key));

    int wrong_key_result = secure_packet_decrypt(
        encrypted,
        encrypted_length,
        wrong_key,
        &decrypted,
        &decrypted_length
    );

    check_result(
        "Incorrect key rejected",
        wrong_key_result == 0
    );

    free(decrypted);
    decrypted = NULL;

    /* TEST 6: Modified authentication tag */

    unsigned char *tampered = malloc(encrypted_length);

    if (!tampered) {
        free(original);
        free(encrypted);
        return EXIT_FAILURE;
    }

    memcpy(tampered, encrypted, encrypted_length);

    tampered[encrypted_parsed.payload_offset + AES_NONCE_SIZE]
        ^= 0x01;

    int tampered_result = secure_packet_decrypt(
        tampered,
        encrypted_length,
        key,
        &decrypted,
        &decrypted_length
    );

    check_result(
        "Modified authentication tag rejected",
        tampered_result == 0
    );

    free(decrypted);
    free(tampered);
    free(encrypted);
    free(original);

    /* FINAL RESULTS */

    printf("\n====================================\n");
    printf("           TEST RESULTS\n");
    printf("====================================\n");

    printf("Passed: %d\n", tests_passed);
    printf("Failed: %d\n", tests_failed);

    if (tests_failed == 0) {
        printf("\nALL SECURE PACKET TESTS PASSED!\n");
        return EXIT_SUCCESS;
    }

    printf("\nSOME TESTS FAILED!\n");

    return EXIT_FAILURE;
}