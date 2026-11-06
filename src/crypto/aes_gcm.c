#include "aes_gcm.h"

#include <limits.h>

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/crypto.h>

/*
 * Encrypt plaintext using AES-256-GCM.
 */
int aes_gcm_encrypt(
    const unsigned char key[AES_KEY_SIZE],
    const unsigned char *plaintext,
    size_t plaintext_len,
    const unsigned char *aad,
    size_t aad_len,
    unsigned char nonce[AES_NONCE_SIZE],
    unsigned char *ciphertext,
    unsigned char tag[AES_TAG_SIZE])
{
    if (key == NULL ||
        nonce == NULL ||
        ciphertext == NULL ||
        tag == NULL ||
        (plaintext == NULL && plaintext_len != 0) ||
        (aad == NULL && aad_len != 0) ||
        plaintext_len > INT_MAX ||
        aad_len > INT_MAX) {
        return 0;
    }

    EVP_CIPHER_CTX *ctx = NULL;

    int success = 0;
    int len = 0;
    int ciphertext_len = 0;

    ctx = EVP_CIPHER_CTX_new();

    if (ctx == NULL) {
        goto cleanup;
    }

    /* Generate a random 96-bit nonce. */
    if (RAND_bytes(nonce, AES_NONCE_SIZE) != 1) {
        goto cleanup;
    }

    /* Initialize AES-256-GCM. */
    if (EVP_EncryptInit_ex(
            ctx,
            EVP_aes_256_gcm(),
            NULL,
            NULL,
            NULL) != 1) {
        goto cleanup;
    }

    /* Configure nonce length. */
    if (EVP_CIPHER_CTX_ctrl(
            ctx,
            EVP_CTRL_GCM_SET_IVLEN,
            AES_NONCE_SIZE,
            NULL) != 1) {
        goto cleanup;
    }

    /* Set encryption key and nonce. */
    if (EVP_EncryptInit_ex(
            ctx,
            NULL,
            NULL,
            key,
            nonce) != 1) {
        goto cleanup;
    }

    /* Process Additional Authenticated Data. */
    if (aad_len > 0) {
        if (EVP_EncryptUpdate(
                ctx,
                NULL,
                &len,
                aad,
                (int)aad_len) != 1) {
            goto cleanup;
        }
    }

    /* Encrypt plaintext. */
    if (plaintext_len > 0) {
        if (EVP_EncryptUpdate(
                ctx,
                ciphertext,
                &len,
                plaintext,
                (int)plaintext_len) != 1) {
            goto cleanup;
        }

        ciphertext_len = len;
    }

    /* Finalize encryption. */
    if (EVP_EncryptFinal_ex(
            ctx,
            ciphertext + ciphertext_len,
            &len) != 1) {
        goto cleanup;
    }

    ciphertext_len += len;

    /* GCM ciphertext must have the same length as plaintext. */
    if ((size_t)ciphertext_len != plaintext_len) {
        goto cleanup;
    }

    /* Retrieve authentication tag. */
    if (EVP_CIPHER_CTX_ctrl(
            ctx,
            EVP_CTRL_GCM_GET_TAG,
            AES_TAG_SIZE,
            tag) != 1) {
        goto cleanup;
    }

    success = 1;

cleanup:

    EVP_CIPHER_CTX_free(ctx);

    if (!success) {
        OPENSSL_cleanse(nonce, AES_NONCE_SIZE);
        OPENSSL_cleanse(tag, AES_TAG_SIZE);

        if (plaintext_len > 0) {
            OPENSSL_cleanse(ciphertext, plaintext_len);
        }
    }

    return success;
}


/*
 * Decrypt ciphertext using AES-256-GCM.
 *
 * Authentication must succeed before plaintext is trusted.
 */
int aes_gcm_decrypt(
    const unsigned char key[AES_KEY_SIZE],
    const unsigned char *ciphertext,
    size_t ciphertext_len,
    const unsigned char *aad,
    size_t aad_len,
    const unsigned char nonce[AES_NONCE_SIZE],
    const unsigned char tag[AES_TAG_SIZE],
    unsigned char *plaintext)
{
    if (key == NULL ||
        nonce == NULL ||
        tag == NULL ||
        plaintext == NULL ||
        (ciphertext == NULL && ciphertext_len != 0) ||
        (aad == NULL && aad_len != 0) ||
        ciphertext_len > INT_MAX ||
        aad_len > INT_MAX) {
        return 0;
    }

    EVP_CIPHER_CTX *ctx = NULL;

    int success = 0;
    int len = 0;
    int plaintext_len = 0;

    ctx = EVP_CIPHER_CTX_new();

    if (ctx == NULL) {
        goto cleanup;
    }

    /* Initialize AES-256-GCM. */
    if (EVP_DecryptInit_ex(
            ctx,
            EVP_aes_256_gcm(),
            NULL,
            NULL,
            NULL) != 1) {
        goto cleanup;
    }

    /* Configure nonce length. */
    if (EVP_CIPHER_CTX_ctrl(
            ctx,
            EVP_CTRL_GCM_SET_IVLEN,
            AES_NONCE_SIZE,
            NULL) != 1) {
        goto cleanup;
    }

    /* Set encryption key and nonce. */
    if (EVP_DecryptInit_ex(
            ctx,
            NULL,
            NULL,
            key,
            nonce) != 1) {
        goto cleanup;
    }

    /* Process Additional Authenticated Data. */
    if (aad_len > 0) {
        if (EVP_DecryptUpdate(
                ctx,
                NULL,
                &len,
                aad,
                (int)aad_len) != 1) {
            goto cleanup;
        }
    }

    /* Decrypt ciphertext. */
    if (ciphertext_len > 0) {
        if (EVP_DecryptUpdate(
                ctx,
                plaintext,
                &len,
                ciphertext,
                (int)ciphertext_len) != 1) {
            goto cleanup;
        }

        plaintext_len = len;
    }

    /* Set the expected authentication tag. */
    if (EVP_CIPHER_CTX_ctrl(
            ctx,
            EVP_CTRL_GCM_SET_TAG,
            AES_TAG_SIZE,
            (void *)tag) != 1) {
        goto cleanup;
    }

    /*
     * Finalization verifies the authentication tag.
     * If verification fails, plaintext must not be used.
     */
    if (EVP_DecryptFinal_ex(
            ctx,
            plaintext + plaintext_len,
            &len) != 1) {
        goto cleanup;
    }

    plaintext_len += len;

    if ((size_t)plaintext_len != ciphertext_len) {
        goto cleanup;
    }

    success = 1;

cleanup:

    EVP_CIPHER_CTX_free(ctx);

    if (!success && ciphertext_len > 0) {
        OPENSSL_cleanse(plaintext, ciphertext_len);
    }

    return success;
}