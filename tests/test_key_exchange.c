#include <stdio.h>
#include <string.h>

#include <openssl/crypto.h>

#include "../src/crypto/key_exchange.h"

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
    x25519_keypair_t device1;
    x25519_keypair_t device2;

    unsigned char secret1[SHARED_SECRET_SIZE] = {0};
    unsigned char secret2[SHARED_SECRET_SIZE] = {0};

    unsigned char session_key1[SESSION_KEY_SIZE] = {0};
    unsigned char session_key2[SESSION_KEY_SIZE] = {0};

    unsigned char salt[] = "secure-channel-session";

    printf("================================\n");
    printf("  DIFFIE-HELLMAN KEY EXCHANGE\n");
    printf("================================\n");

    /* TEST 1: Device1 key generation */

    TEST("Device1 key generation");

    if (!generate_keypair(&device1)) {
        FAIL();
    }

    PASS();


    /* TEST 2: Device2 key generation */

    TEST("Device2 key generation");

    if (!generate_keypair(&device2)) {
        clear_keypair(&device1);
        FAIL();
    }

    PASS();


    /* TEST 3: Shared secret calculation */

    TEST("Device1 shared secret calculation");

    if (!derive_shared_secret(
            &device1,
            device2.public_key,
            secret1)) {
        clear_keypair(&device1);
        clear_keypair(&device2);
        FAIL();
    }

    PASS();


    /* TEST 4: Shared secret calculation on Device2 */

    TEST("Device2 shared secret calculation");

    if (!derive_shared_secret(
            &device2,
            device1.public_key,
            secret2)) {
        clear_keypair(&device1);
        clear_keypair(&device2);
        FAIL();
    }

    PASS();


    /* TEST 5: Verify identical shared secrets */

    TEST("Both devices have identical shared secrets");

    if (CRYPTO_memcmp(
            secret1,
            secret2,
            SHARED_SECRET_SIZE) != 0) {
        FAIL();
    }

    PASS();


    /* TEST 6: Derive session key on Device1 */

    TEST("Device1 HKDF session key derivation");

    if (!derive_session_key(
            secret1,
            salt,
            sizeof(salt) - 1,
            session_key1)) {
        FAIL();
    }

    PASS();


    /* TEST 7: Derive session key on Device2 */

    TEST("Device2 HKDF session key derivation");

    if (!derive_session_key(
            secret2,
            salt,
            sizeof(salt) - 1,
            session_key2)) {
        FAIL();
    }

    PASS();


    /* TEST 8: Verify identical session keys */

    TEST("Both devices have identical session keys");

    if (CRYPTO_memcmp(
            session_key1,
            session_key2,
            SESSION_KEY_SIZE) != 0) {
        FAIL();
    }

    PASS();


    /* Cleanup sensitive material */

    clear_keypair(&device1);
    clear_keypair(&device2);

    OPENSSL_cleanse(secret1, sizeof(secret1));
    OPENSSL_cleanse(secret2, sizeof(secret2));

    OPENSSL_cleanse(session_key1, sizeof(session_key1));
    OPENSSL_cleanse(session_key2, sizeof(session_key2));

    printf("\n================================\n");
    printf("ALL TESTS PASSED\n");
    printf("================================\n");

    return 0;
}