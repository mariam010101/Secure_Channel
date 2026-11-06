
#ifndef AES_GCM_H
#define AES_GCM_H

#include <stddef.h>

#define AES_KEY_SIZE 32
#define AES_NONCE_SIZE 12
#define AES_TAG_SIZE 16

/*
 * Encrypt data using AES-256-GCM.
 *
 * key:          256-bit encryption key
 * plaintext:    Original data
 * plaintext_len: Length of original data
 * aad:          Additional authenticated data
 * aad_len:      Length of AAD
 * nonce:        Generated 96-bit nonce
 * ciphertext:   Encrypted data
 * tag:          Generated authentication tag
 *
 * Returns 1 on success, 0 on failure.
 */
int aes_gcm_encrypt(
    const unsigned char key[AES_KEY_SIZE],
    const unsigned char *plaintext,
    size_t plaintext_len,
    const unsigned char *aad,
    size_t aad_len,
    unsigned char nonce[AES_NONCE_SIZE],
    unsigned char *ciphertext,
    unsigned char tag[AES_TAG_SIZE]
);

/*
 * Decrypt data using AES-256-GCM.
 *
 * Returns 1 on successful authentication and decryption,
 * 0 on failure.
 */
int aes_gcm_decrypt(
    const unsigned char key[AES_KEY_SIZE],
    const unsigned char *ciphertext,
    size_t ciphertext_len,
    const unsigned char *aad,
    size_t aad_len,
    const unsigned char nonce[AES_NONCE_SIZE],
    const unsigned char tag[AES_TAG_SIZE],
    unsigned char *plaintext
);

#endif
