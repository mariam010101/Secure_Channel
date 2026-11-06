#include <stdio.h>
#include <string.h>

#include <openssl/crypto.h>

#include "../src/crypto/key_exchange.h"
#include "../src/crypto/aes_gcm.h"

int main(void)
{
    x25519_keypair_t device1;
    x25519_keypair_t device2;

    unsigned char secret1[SHARED_SECRET_SIZE] = {0};
    unsigned char secret2[SHARED_SECRET_SIZE] = {0};

    unsigned char key1[SESSION_KEY_SIZE] = {0};
    unsigned char key2[SESSION_KEY_SIZE] = {0};

    unsigned char nonce[AES_NONCE_SIZE] = {0};
    unsigned char tag[AES_TAG_SIZE] = {0};

    unsigned char salt[] = "secure-channel-handshake";

    unsigned char plaintext[] =
        "Hello from PC1 to PC2 through the secure channel!";

    unsigned char aad[] = "TCP packet metadata";

    unsigned char ciphertext[sizeof(plaintext)] = {0};
    unsigned char decrypted[sizeof(plaintext)] = {0};

    printf("========================================\n");
    printf("   SECURE CHANNEL INTEGRATION TEST\n");
    printf("========================================\n");

    /* TEST 1: Generate Device1 key pair */

    printf("\nTEST 1: Device1 key generation\n");

    if (!generate_keypair(&device1)) {
        goto failure;
    }

    printf("PASS\n");


    /* TEST 2: Generate Device2 key pair */

    printf("\nTEST 2: Device2 key generation\n");

    if (!generate_keypair(&device2)) {
        goto failure;
    }

    printf("PASS\n");


    /* TEST 3: Calculate shared secrets */

    printf("\nTEST 3: Shared secret establishment\n");

    if (!derive_shared_secret(
            &device1, device2.public_key, secret1)) {
        goto failure;
    }

    if (!derive_shared_secret(
            &device2, device1.public_key, secret2)) {
        goto failure;
    }

    if (CRYPTO_memcmp(
            secret1, secret2, SHARED_SECRET_SIZE) != 0) {
        goto failure;
    }

    printf("PASS\n");


    /* TEST 4: Derive session keys */

    printf("\nTEST 4: Session key derivation\n");

    if (!derive_session_key(
            secret1, salt, sizeof(salt) - 1, key1)) {
        goto failure;
    }

    if (!derive_session_key(
            secret2, salt, sizeof(salt) - 1, key2)) {
        goto failure;
    }

    if (CRYPTO_memcmp(
            key1, key2, SESSION_KEY_SIZE) != 0) {
        goto failure;
    }

    printf("PASS\n");


    /* TEST 5: Device1 encrypts TCP payload */

    printf("\nTEST 5: Device1 encrypts TCP payload\n");

    if (!aes_gcm_encrypt(
            key1,
            plaintext,
            sizeof(plaintext),
            aad,
            sizeof(aad) - 1,
            nonce,
            ciphertext,
            tag)) {
        goto failure;
    }

    printf("PASS\n");


    /* TEST 6: Device2 decrypts TCP payload */

    printf("\nTEST 6: Device2 decrypts TCP payload\n");

    if (!aes_gcm_decrypt(
            key2,
            ciphertext,
            sizeof(plaintext),
            aad,
            sizeof(aad) - 1,
            nonce,
            tag,
            decrypted)) {
        goto failure;
    }

    printf("PASS\n");


    /* TEST 7: Verify original payload */

    printf("\nTEST 7: Verify original TCP payload\n");

    if (CRYPTO_memcmp(
            plaintext,
            decrypted,
            sizeof(plaintext)) != 0) {
        goto failure;
    }

    printf("PASS\n");


    /* Cleanup */

    clear_keypair(&device1);
    clear_keypair(&device2);

    OPENSSL_cleanse(secret1, sizeof(secret1));
    OPENSSL_cleanse(secret2, sizeof(secret2));

    OPENSSL_cleanse(key1, sizeof(key1));
    OPENSSL_cleanse(key2, sizeof(key2));

    printf("\n========================================\n");
    printf("ALL INTEGRATION TESTS PASSED\n");
    printf("========================================\n");

    return 0;

failure:

    printf("FAIL\n");

    clear_keypair(&device1);
    clear_keypair(&device2);

    OPENSSL_cleanse(secret1, sizeof(secret1));
    OPENSSL_cleanse(secret2, sizeof(secret2));

    OPENSSL_cleanse(key1, sizeof(key1));
    OPENSSL_cleanse(key2, sizeof(key2));

    return 1;
}