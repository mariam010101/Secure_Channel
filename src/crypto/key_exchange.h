#ifndef KEY_EXCHANGE_H
#define KEY_EXCHANGE_H

#include <stddef.h>
#include <stdint.h>

#define X25519_KEY_SIZE 32
#define SHARED_SECRET_SIZE 32
#define SESSION_KEY_SIZE 32

typedef struct {
    unsigned char private_key[X25519_KEY_SIZE];
    unsigned char public_key[X25519_KEY_SIZE];
} x25519_keypair_t;

/* Generate an X25519 public/private key pair. */
int generate_keypair(x25519_keypair_t *keypair);

/* Derive a shared secret using the peer's public key. */
int derive_shared_secret(
    const x25519_keypair_t *keypair,
    const unsigned char peer_public_key[X25519_KEY_SIZE],
    unsigned char shared_secret[SHARED_SECRET_SIZE]
);

/* Derive an AES-256 session key using HKDF-SHA256. */
int derive_session_key(
    const unsigned char shared_secret[SHARED_SECRET_SIZE],
    const unsigned char *salt,
    size_t salt_len,
    unsigned char session_key[SESSION_KEY_SIZE]
);

/* Securely erase sensitive key material. */
void clear_keypair(x25519_keypair_t *keypair);

#endif