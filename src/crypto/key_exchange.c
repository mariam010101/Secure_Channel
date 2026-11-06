#include "key_exchange.h"

#include <string.h>

#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/crypto.h>

/*
 * Generate an X25519 key pair.
 */
int generate_keypair(x25519_keypair_t *keypair)
{
    if (keypair == NULL) {
        return 0;
    }

    EVP_PKEY_CTX *ctx = NULL;
    EVP_PKEY *pkey = NULL;

    int success = 0;

    ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, NULL);

    if (ctx == NULL) {
        goto cleanup;
    }

    if (EVP_PKEY_keygen_init(ctx) <= 0) {
        goto cleanup;
    }

    if (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
        goto cleanup;
    }

    size_t private_len = X25519_KEY_SIZE;
    size_t public_len = X25519_KEY_SIZE;

    if (EVP_PKEY_get_raw_private_key(
            pkey,
            keypair->private_key,
            &private_len) <= 0) {
        goto cleanup;
    }

    if (EVP_PKEY_get_raw_public_key(
            pkey,
            keypair->public_key,
            &public_len) <= 0) {
        goto cleanup;
    }

    if (private_len != X25519_KEY_SIZE ||
        public_len != X25519_KEY_SIZE) {
        goto cleanup;
    }

    success = 1;

cleanup:

    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(ctx);

    if (!success) {
        clear_keypair(keypair);
    }

    return success;
}


/*
 * Calculate the X25519 shared secret.
 */
int derive_shared_secret(
    const x25519_keypair_t *keypair,
    const unsigned char peer_public_key[X25519_KEY_SIZE],
    unsigned char shared_secret[SHARED_SECRET_SIZE])
{
    if (keypair == NULL ||
        peer_public_key == NULL ||
        shared_secret == NULL) {
        return 0;
    }

    EVP_PKEY *private_key = NULL;
    EVP_PKEY *public_key = NULL;
    EVP_PKEY_CTX *ctx = NULL;

    int success = 0;

    private_key = EVP_PKEY_new_raw_private_key(
        EVP_PKEY_X25519,
        NULL,
        keypair->private_key,
        X25519_KEY_SIZE
    );

    if (private_key == NULL) {
        goto cleanup;
    }

    public_key = EVP_PKEY_new_raw_public_key(
        EVP_PKEY_X25519,
        NULL,
        peer_public_key,
        X25519_KEY_SIZE
    );

    if (public_key == NULL) {
        goto cleanup;
    }

    ctx = EVP_PKEY_CTX_new(private_key, NULL);

    if (ctx == NULL) {
        goto cleanup;
    }

    if (EVP_PKEY_derive_init(ctx) <= 0) {
        goto cleanup;
    }

    if (EVP_PKEY_derive_set_peer(ctx, public_key) <= 0) {
        goto cleanup;
    }

    size_t secret_len = SHARED_SECRET_SIZE;

    if (EVP_PKEY_derive(
            ctx,
            shared_secret,
            &secret_len) <= 0) {
        goto cleanup;
    }

    if (secret_len != SHARED_SECRET_SIZE) {
        goto cleanup;
    }

    success = 1;

cleanup:

    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(private_key);
    EVP_PKEY_free(public_key);

    if (!success) {
        OPENSSL_cleanse(shared_secret, SHARED_SECRET_SIZE);
    }

    return success;
}


/*
 * Derive a 256-bit session key using HKDF-SHA256.
 */
int derive_session_key(
    const unsigned char shared_secret[SHARED_SECRET_SIZE],
    const unsigned char *salt,
    size_t salt_len,
    unsigned char session_key[SESSION_KEY_SIZE])
{
    if (shared_secret == NULL ||
        session_key == NULL ||
        (salt == NULL && salt_len != 0)) {
        return 0;
    }

    EVP_PKEY_CTX *ctx = NULL;

    int success = 0;

    ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);

    if (ctx == NULL) {
        goto cleanup;
    }

    if (EVP_PKEY_derive_init(ctx) <= 0) {
        goto cleanup;
    }

    if (EVP_PKEY_CTX_set_hkdf_md(ctx, EVP_sha256()) <= 0) {
        goto cleanup;
    }

    if (salt_len > 0) {
        if (EVP_PKEY_CTX_set1_hkdf_salt(
                ctx, salt, salt_len) <= 0) {
            goto cleanup;
        }
    }

    if (EVP_PKEY_CTX_set1_hkdf_key(
            ctx,
            shared_secret,
            SHARED_SECRET_SIZE) <= 0) {
        goto cleanup;
    }

    static const unsigned char info[] =
        "Secure Inline Communication Channel";

    if (EVP_PKEY_CTX_add1_hkdf_info(
            ctx,
            info,
            sizeof(info) - 1) <= 0) {
        goto cleanup;
    }

    size_t key_len = SESSION_KEY_SIZE;

    if (EVP_PKEY_derive(
            ctx,
            session_key,
            &key_len) <= 0) {
        goto cleanup;
    }

    if (key_len != SESSION_KEY_SIZE) {
        goto cleanup;
    }

    success = 1;

cleanup:

    EVP_PKEY_CTX_free(ctx);

    if (!success) {
        OPENSSL_cleanse(session_key, SESSION_KEY_SIZE);
    }

    return success;
}


/*
 * Securely erase the key pair.
 */
void clear_keypair(x25519_keypair_t *keypair)
{
    if (keypair != NULL) {
        OPENSSL_cleanse(keypair, sizeof(*keypair));
    }
}