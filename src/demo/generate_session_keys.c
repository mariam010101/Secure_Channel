#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include <openssl/rand.h>
#include <openssl/crypto.h>

#include "../crypto/key_exchange.h"

static int save_key(const char *filename,
                    const unsigned char *key)
{
    FILE *file = fopen(filename, "wb");

    if (!file) {
        perror("Cannot create key file");
        return 0;
    }

    int success =
        fwrite(key, 1, SESSION_KEY_SIZE, file) == SESSION_KEY_SIZE;

    if (fclose(file) != 0) {
        success = 0;
    }

    return success;
}

int main(void)
{
    x25519_keypair_t device1;
    x25519_keypair_t device2;

    unsigned char secret1[SHARED_SECRET_SIZE];
    unsigned char secret2[SHARED_SECRET_SIZE];

    unsigned char session1[SESSION_KEY_SIZE];
    unsigned char session2[SESSION_KEY_SIZE];

    unsigned char salt[32];

    memset(&device1, 0, sizeof(device1));
    memset(&device2, 0, sizeof(device2));

    memset(secret1, 0, sizeof(secret1));
    memset(secret2, 0, sizeof(secret2));

    memset(session1, 0, sizeof(session1));
    memset(session2, 0, sizeof(session2));

    memset(salt, 0, sizeof(salt));

    printf("[1] Generating X25519 key pairs...\n");

    if (!generate_keypair(&device1) ||
        !generate_keypair(&device2)) {
        fprintf(stderr, "Key generation failed.\n");
        goto cleanup;
    }

    printf("[2] Generating random HKDF salt...\n");

    if (RAND_bytes(salt, sizeof(salt)) != 1) {
        fprintf(stderr, "Salt generation failed.\n");
        goto cleanup;
    }

    printf("[3] Deriving shared secrets...\n");

    if (!derive_shared_secret(
            &device1,
            device2.public_key,
            secret1) ||
        !derive_shared_secret(
            &device2,
            device1.public_key,
            secret2)) {

        fprintf(stderr, "Shared secret derivation failed.\n");
        goto cleanup;
    }

    if (CRYPTO_memcmp(secret1, secret2,
                      SHARED_SECRET_SIZE) != 0) {
        fprintf(stderr, "Shared secrets do not match!\n");
        goto cleanup;
    }

    printf("[4] Deriving AES-256 session keys...\n");

    if (!derive_session_key(
            secret1, salt, sizeof(salt), session1) ||
        !derive_session_key(
            secret2, salt, sizeof(salt), session2)) {

        fprintf(stderr, "Session key derivation failed.\n");
        goto cleanup;
    }

    if (CRYPTO_memcmp(session1, session2,
                      SESSION_KEY_SIZE) != 0) {
        fprintf(stderr, "Session keys do not match!\n");
        goto cleanup;
    }

    printf("[5] Saving session keys...\n");

    umask(077);

    if (!save_key("build/device1_session.key", session1) ||
        !save_key("build/device2_session.key", session2)) {

        fprintf(stderr, "Could not save session keys.\n");
        goto cleanup;
    }

    printf("\n====================================\n");
    printf("SESSION KEY GENERATION SUCCESSFUL\n");
    printf("====================================\n");

    printf("Shared secrets match: YES\n");
    printf("Session keys match: YES\n");
    printf("Key size: %d bytes\n", SESSION_KEY_SIZE);

    printf("Device1: build/device1_session.key\n");
    printf("Device2: build/device2_session.key\n");

    clear_keypair(&device1);
    clear_keypair(&device2);

    OPENSSL_cleanse(secret1, sizeof(secret1));
    OPENSSL_cleanse(secret2, sizeof(secret2));
    OPENSSL_cleanse(session1, sizeof(session1));
    OPENSSL_cleanse(session2, sizeof(session2));
    OPENSSL_cleanse(salt, sizeof(salt));

    return EXIT_SUCCESS;

cleanup:
    clear_keypair(&device1);
    clear_keypair(&device2);

    OPENSSL_cleanse(secret1, sizeof(secret1));
    OPENSSL_cleanse(secret2, sizeof(secret2));
    OPENSSL_cleanse(session1, sizeof(session1));
    OPENSSL_cleanse(session2, sizeof(session2));
    OPENSSL_cleanse(salt, sizeof(salt));

    return EXIT_FAILURE;
}