#ifndef SECURE_PACKET_H
#define SECURE_PACKET_H

#include <stddef.h>
#include <stdint.h>

#include "../crypto/aes_gcm.h"

#define SECURE_PACKET_OVERHEAD (AES_NONCE_SIZE + AES_TAG_SIZE)

/*
 * Encrypt the TCP payload of an IPv4 packet.
 *
 * Original IP and TCP headers are preserved.
 *
 * Encrypted payload format:
 *
 * [NONCE: 12 bytes]
 * [AUTHENTICATION TAG: 16 bytes]
 * [CIPHERTEXT: variable]
 *
 * Returns:
 * 1 on success
 * 0 on failure
 */
int secure_packet_encrypt(
    const unsigned char *packet,
    size_t packet_length,
    const unsigned char key[AES_KEY_SIZE],
    unsigned char **encrypted_packet,
    size_t *encrypted_packet_length
);

/*
 * Decrypt an encrypted TCP packet.
 *
 * Restores the original TCP payload.
 *
 * Returns:
 * 1 on success
 * 0 on failure
 */
int secure_packet_decrypt(
    const unsigned char *packet,
    size_t packet_length,
    const unsigned char key[AES_KEY_SIZE],
    unsigned char **decrypted_packet,
    size_t *decrypted_packet_length
);

#endif