#include "secure_packet.h"
#include "packet_parser.h"

#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

#define AAD_SIZE 23

/*
 * Build Additional Authenticated Data.
 *
 * We authenticate stable packet fields:
 * - Source IP
 * - Destination IP
 * - Protocol
 * - TCP ports
 * - TCP sequence number
 * - TCP acknowledgment number
 * - TCP header length and flags
 *
 * Mutable fields such as TTL, checksums and packet lengths
 * are excluded.
 */
static void build_aad(
    const unsigned char *packet,
    const ParsedPacket *parsed,
    unsigned char aad[AAD_SIZE]
) {
    size_t offset = 0;

    /* Source and destination IPv4 addresses. */

    memcpy(aad + offset, packet + 12, 8);
    offset += 8;

    /* IP protocol. */

    aad[offset++] = packet[9];

    /* TCP source port, destination port, sequence number,
       acknowledgment number, data offset and flags. */

    size_t tcp_offset = parsed->ip_header_length;

    memcpy(
        aad + offset,
        packet + tcp_offset,
        14
    );
}

/*
 * Calculate Internet checksum.
 */
static uint16_t calculate_checksum(
    const unsigned char *data,
    size_t length
) {
    uint32_t sum = 0;

    while (length > 1) {

        sum += ((uint16_t)data[0] << 8) | data[1];

        data += 2;
        length -= 2;
    }

    if (length == 1) {
        sum += (uint16_t)data[0] << 8;
    }

    while (sum >> 16) {
        sum = (sum & 0xffff) + (sum >> 16);
    }

    return (uint16_t)(~sum);
}

/*
 * Recalculate IPv4 and TCP checksums.
 */
static int update_checksums(
    unsigned char *packet,
    size_t packet_length
) {
    ParsedPacket parsed;

    if (parse_tcp_packet(
        packet,
        packet_length,
        &parsed
    ) != PARSE_SUCCESS) {
        return 0;
    }

    struct iphdr *ip = (struct iphdr *)packet;

    unsigned char *tcp_data =
        packet + parsed.ip_header_length;

    size_t tcp_length =
        parsed.total_length - parsed.ip_header_length;

    struct tcphdr *tcp =
        (struct tcphdr *)tcp_data;

    /* IPv4 checksum. */

    ip->check = 0;

    ip->check = htons(
        calculate_checksum(
            packet,
            parsed.ip_header_length
        )
    );

    /* TCP checksum. */

    tcp->check = 0;

    uint32_t sum = 0;

    /* IPv4 source and destination addresses. */

    for (int i = 12; i < 20; i += 2) {
        sum += ((uint16_t)packet[i] << 8)
             | packet[i + 1];
    }

    /* Protocol and TCP length. */

    sum += IPPROTO_TCP;
    sum += (uint16_t)tcp_length;

    /* TCP header and payload. */

    const unsigned char *ptr = tcp_data;

    size_t remaining = tcp_length;

    while (remaining > 1) {

        sum += ((uint16_t)ptr[0] << 8) | ptr[1];

        ptr += 2;
        remaining -= 2;
    }

    if (remaining == 1) {
        sum += (uint16_t)ptr[0] << 8;
    }

    while (sum >> 16) {
        sum = (sum & 0xffff) + (sum >> 16);
    }

    tcp->check = htons((uint16_t)(~sum));

    return 1;
}

/*
 * Encrypt TCP payload using AES-256-GCM.
 */
int secure_packet_encrypt(
    const unsigned char *packet,
    size_t packet_length,
    const unsigned char key[AES_KEY_SIZE],
    unsigned char **encrypted_packet,
    size_t *encrypted_packet_length
) {
    if (!packet || !key ||
        !encrypted_packet ||
        !encrypted_packet_length) {
        return 0;
    }

    *encrypted_packet = NULL;
    *encrypted_packet_length = 0;

    ParsedPacket parsed;

    if (parse_tcp_packet(
        (unsigned char *)packet,
        packet_length,
        &parsed
    ) != PARSE_SUCCESS) {
        return 0;
    }

    /* Prevent IPv4 packet length overflow. */

    if (parsed.total_length >
        UINT16_MAX - SECURE_PACKET_OVERHEAD) {
        return 0;
    }

    size_t new_length =
        parsed.total_length + SECURE_PACKET_OVERHEAD;

    unsigned char *output = malloc(new_length);

    if (!output) {
        return 0;
    }

    /* Copy original IP and TCP headers. */

    memcpy(
        output,
        packet,
        parsed.payload_offset
    );

    size_t payload_length = parsed.payload_length;

    unsigned char *nonce =
        output + parsed.payload_offset;

    unsigned char *tag =
        nonce + AES_NONCE_SIZE;

    unsigned char *ciphertext =
        tag + AES_TAG_SIZE;

    unsigned char *temporary_ciphertext =
        malloc(payload_length ? payload_length : 1);

    if (!temporary_ciphertext) {
        free(output);
        return 0;
    }

    unsigned char aad[AAD_SIZE];

    build_aad(packet, &parsed, aad);

    int success = aes_gcm_encrypt(
        key,
        parsed.payload,
        payload_length,
        aad,
        sizeof(aad),
        nonce,
        temporary_ciphertext,
        tag
    );

    if (!success) {
        free(temporary_ciphertext);
        free(output);
        return 0;
    }

    if (payload_length > 0) {
        memcpy(
            ciphertext,
            temporary_ciphertext,
            payload_length
        );
    }

    free(temporary_ciphertext);

    /* Update IPv4 total length. */

    struct iphdr *ip = (struct iphdr *)output;

    ip->tot_len = htons((uint16_t)new_length);

    if (!update_checksums(output, new_length)) {
        free(output);
        return 0;
    }

    *encrypted_packet = output;
    *encrypted_packet_length = new_length;

    return 1;
}

/*
 * Decrypt TCP payload using AES-256-GCM.
 */
int secure_packet_decrypt(
    const unsigned char *packet,
    size_t packet_length,
    const unsigned char key[AES_KEY_SIZE],
    unsigned char **decrypted_packet,
    size_t *decrypted_packet_length
) {
    if (!packet || !key ||
        !decrypted_packet ||
        !decrypted_packet_length) {
        return 0;
    }

    *decrypted_packet = NULL;
    *decrypted_packet_length = 0;

    ParsedPacket parsed;

    if (parse_tcp_packet(
        (unsigned char *)packet,
        packet_length,
        &parsed
    ) != PARSE_SUCCESS) {
        return 0;
    }

    if (parsed.payload_length < SECURE_PACKET_OVERHEAD) {
        return 0;
    }

    size_t original_payload_length =
        parsed.payload_length - SECURE_PACKET_OVERHEAD;

    size_t new_length =
        parsed.total_length - SECURE_PACKET_OVERHEAD;

    unsigned char *output = malloc(new_length);

    if (!output) {
        return 0;
    }

    /* Copy original IP and TCP headers. */

    memcpy(
        output,
        packet,
        parsed.payload_offset
    );

    const unsigned char *nonce =
        parsed.payload;

    const unsigned char *tag =
        nonce + AES_NONCE_SIZE;

    const unsigned char *ciphertext =
        tag + AES_TAG_SIZE;

    unsigned char *plaintext =
        output + parsed.payload_offset;

    unsigned char aad[AAD_SIZE];

    build_aad(packet, &parsed, aad);

    int success = aes_gcm_decrypt(
        key,
        ciphertext,
        original_payload_length,
        aad,
        sizeof(aad),
        nonce,
        tag,
        plaintext
    );

    if (!success) {
        free(output);
        return 0;
    }

    /* Restore original IPv4 total length. */

    struct iphdr *ip = (struct iphdr *)output;

    ip->tot_len = htons((uint16_t)new_length);

    if (!update_checksums(output, new_length)) {
        free(output);
        return 0;
    }

    *decrypted_packet = output;
    *decrypted_packet_length = new_length;

    return 1;
}