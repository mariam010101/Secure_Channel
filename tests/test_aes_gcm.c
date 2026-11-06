
#include <stdio.h>
#include <string.h>

#include <openssl/crypto.h>

#include "../src/crypto/aes_gcm.h"

#define TEST(name) \
    printf("\nTEST: %s\n", name)

#define PASS() \
    printf("PASS\n")

#define FAIL() \
    do { \
        printf("FAIL\n"); \
        return 1; \
    } while (0)


int main(void)
{
    unsigned char key[AES_KEY_SIZE] = {0};

    unsigned char nonce[AES_NONCE_SIZE] = {0};
    unsigned char tag[AES_TAG_SIZE] = {0};

    unsigned char plaintext[] =
        "Secure communication between Device1 and Device2";

    unsigned char aad[] = "TCP packet metadata";

    unsigned char ciphertext[sizeof(plaintext)] = {0};
    unsigned char decrypted[sizeof(plaintext)] = {0};

    printf("================================\n");
    printf("       AES-256-GCM TESTS\n");
    printf("================================\n");


    /* TEST 1: Encryption */

    TEST("AES-256-GCM encryption");

    if (!aes_gcm_encrypt(
            key,
            plaintext,
            sizeof(plaintext),
            aad,
            sizeof(aad) - 1,
            nonce,
            ciphertext,
            tag)) {
        FAIL();
    }

    PASS();


    /* TEST 2: Decryption */

    TEST("AES-256-GCM decryption");

    if (!aes_gcm_decrypt(
            key,
            ciphertext,
            sizeof(plaintext),
            aad,
            sizeof(aad) - 1,
            nonce,
            tag,
            decrypted)) {
        FAIL();
    }

    PASS();


    /* TEST 3: Original data verification */

    TEST("Original plaintext matches decrypted plaintext");

    if (memcmp(
            plaintext,
            decrypted,
            sizeof(plaintext)) != 0) {
        FAIL();
    }

    PASS();


    /* TEST 4: Authentication tag verification */

    TEST("Tampered authentication tag is rejected");

    unsigned char modified_tag[AES_TAG_SIZE];

    memcpy(modified_tag, tag, AES_TAG_SIZE);
    modified_tag[0] ^= 0x01;

    memset(decrypted, 0, sizeof(decrypted));

    if (aes_gcm_decrypt(
            key,
            ciphertext,
            sizeof(plaintext),
            aad,
            sizeof(aad) - 1,
            nonce,
            modified_tag,
            decrypted)) {
        FAIL();
    }

    PASS();


    /* TEST 5: Modified ciphertext */

    TEST("Modified ciphertext is rejected");

    unsigned char modified_ciphertext[sizeof(ciphertext)];

    memcpy(modified_ciphertext, ciphertext, sizeof(ciphertext));

    modified_ciphertext[0] ^= 0x01;

    memset(decrypted, 0, sizeof(decrypted));

    if (aes_gcm_decrypt(
            key,
            modified_ciphertext,
            sizeof(plaintext),
            aad,
            sizeof(aad) - 1,
            nonce,
            tag,
            decrypted)) {
        FAIL();
    }

    PASS();


    /* TEST 6: Modified AAD */

    TEST("Modified AAD is rejected");

    unsigned char modified_aad[sizeof(aad)];

    memcpy(modified_aad, aad, sizeof(aad));
    modified_aad[0] ^= 0x01;

    memset(decrypted, 0, sizeof(decrypted));

    if (aes_gcm_decrypt(
            key,
            ciphertext,
            sizeof(plaintext),
            modified_aad,
            sizeof(aad) - 1,
            nonce,
            tag,
            decrypted)) {
        FAIL();
    }

    PASS();


    /* TEST 7: Empty plaintext */

    TEST("Empty plaintext encryption and decryption");

    unsigned char empty_ciphertext[1] = {0};
    unsigned char empty_decrypted[1] = {0};

    unsigned char empty_nonce[AES_NONCE_SIZE] = {0};
    unsigned char empty_tag[AES_TAG_SIZE] = {0};

    if (!aes_gcm_encrypt(
            key,
            NULL,
            0,
            NULL,
            0,
            empty_nonce,
            empty_ciphertext,
            empty_tag)) {
        FAIL();
    }

    if (!aes_gcm_decrypt(
            key,
            NULL,
            0,
            NULL,
            0,
            empty_nonce,
            empty_tag,
            empty_decrypted)) {
        FAIL();
    }

    PASS();


    /* TEST 8: Invalid NULL input */

    TEST("Invalid NULL key is rejected");

    if (aes_gcm_encrypt(
            NULL,
            plaintext,
            sizeof(plaintext),
            NULL,
            0,
            nonce,
            ciphertext,
            tag)) {
        FAIL();
    }

    PASS();


    printf("\n================================\n");
    printf("ALL TESTS PASSED\n");
    printf("================================\n");

    return 0;
}
