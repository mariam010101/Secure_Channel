#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/stat.h>

#include <openssl/rand.h>
#include <openssl/crypto.h>

#include "../crypto/key_exchange.h"

#define HANDSHAKE_PORT 4444
#define SALT_SIZE 32

/* Send all bytes, handling partial writes. */
static int send_all(int fd, const void *data, size_t length)
{
    const unsigned char *ptr = data;

    while (length > 0) {
        ssize_t sent = send(fd, ptr, length, MSG_NOSIGNAL);

        if (sent < 0) {
            if (errno == EINTR)
                continue;
            return 0;
        }

        if (sent == 0)
            return 0;

        ptr += sent;
        length -= (size_t)sent;
    }

    return 1;
}

/* Receive all expected bytes. */
static int receive_all(int fd, void *data, size_t length)
{
    unsigned char *ptr = data;

    while (length > 0) {
        ssize_t received = recv(fd, ptr, length, 0);

        if (received < 0) {
            if (errno == EINTR)
                continue;
            return 0;
        }

        if (received == 0)
            return 0;

        ptr += received;
        length -= (size_t)received;
    }

    return 1;
}

/* Save the derived session key with restricted permissions. */
static int save_session_key(
    const char *filename,
    const unsigned char key[SESSION_KEY_SIZE])
{
    umask(077);

    int fd = open(
        filename,
        O_WRONLY | O_CREAT | O_TRUNC,
        0600
    );

    if (fd < 0) {
        perror("Cannot create session key");
        return 0;
    }

    size_t offset = 0;

    while (offset < SESSION_KEY_SIZE) {
        ssize_t written = write(
            fd,
            key + offset,
            SESSION_KEY_SIZE - offset
        );

        if (written < 0) {
            if (errno == EINTR)
                continue;

            close(fd);
            return 0;
        }

        if (written == 0) {
            close(fd);
            return 0;
        }

        offset += (size_t)written;
    }

    if (close(fd) != 0)
        return 0;

    return 1;
}

/* Perform the X25519 + HKDF handshake. */
static int run_handshake(
    int fd,
    int is_server,
    const char *key_file)
{
    x25519_keypair_t local;

    unsigned char peer_public[X25519_KEY_SIZE];
    unsigned char salt[SALT_SIZE];
    unsigned char shared[SHARED_SECRET_SIZE];
    unsigned char session[SESSION_KEY_SIZE];

    memset(&local, 0, sizeof(local));
    memset(peer_public, 0, sizeof(peer_public));
    memset(salt, 0, sizeof(salt));
    memset(shared, 0, sizeof(shared));
    memset(session, 0, sizeof(session));

    int success = 0;

    printf("[HANDSHAKE] Generating X25519 key pair...\n");

    if (!generate_keypair(&local))
        goto cleanup;

    if (is_server) {

        printf("[DEVICE 2] Generating HKDF salt...\n");

        if (RAND_bytes(salt, sizeof(salt)) != 1)
            goto cleanup;

        if (!receive_all(fd, peer_public, sizeof(peer_public))) {
            fprintf(stderr, "Failed to receive Device1 public key.\n");
            goto cleanup;
        }

        unsigned char response[
            X25519_KEY_SIZE + SALT_SIZE
        ];

        memcpy(response, local.public_key, X25519_KEY_SIZE);
        memcpy(response + X25519_KEY_SIZE, salt, SALT_SIZE);

        if (!send_all(fd, response, sizeof(response))) {
            fprintf(stderr, "Failed to send handshake response.\n");
            goto cleanup;
        }

        OPENSSL_cleanse(response, sizeof(response));

    } else {

        if (!send_all(fd, local.public_key, X25519_KEY_SIZE)) {
            fprintf(stderr, "Failed to send Device1 public key.\n");
            goto cleanup;
        }

        unsigned char response[
            X25519_KEY_SIZE + SALT_SIZE
        ];

        if (!receive_all(fd, response, sizeof(response))) {
            fprintf(stderr, "Failed to receive handshake response.\n");
            goto cleanup;
        }

        memcpy(peer_public, response, X25519_KEY_SIZE);
        memcpy(salt, response + X25519_KEY_SIZE, SALT_SIZE);

        OPENSSL_cleanse(response, sizeof(response));
    }

    printf("[HANDSHAKE] Deriving shared secret...\n");

    if (!derive_shared_secret(
            &local,
            peer_public,
            shared)) {
        fprintf(stderr, "X25519 key agreement failed.\n");
        goto cleanup;
    }

    printf("[HANDSHAKE] Deriving AES-256 session key...\n");

    if (!derive_session_key(
            shared,
            salt,
            sizeof(salt),
            session)) {
        fprintf(stderr, "HKDF key derivation failed.\n");
        goto cleanup;
    }

    if (!save_session_key(key_file, session)) {
        fprintf(stderr, "Failed to save session key.\n");
        goto cleanup;
    }

    printf("\n====================================\n");
    printf("       HANDSHAKE SUCCESSFUL\n");
    printf("====================================\n");
    printf("X25519: SUCCESS\n");
    printf("HKDF-SHA256: SUCCESS\n");
    printf("Session key: 32 bytes\n");
    printf("Saved to: %s\n", key_file);
    printf("====================================\n");

    success = 1;

cleanup:

    clear_keypair(&local);

    OPENSSL_cleanse(peer_public, sizeof(peer_public));
    OPENSSL_cleanse(salt, sizeof(salt));
    OPENSSL_cleanse(shared, sizeof(shared));
    OPENSSL_cleanse(session, sizeof(session));

    return success;
}

int main(int argc, char **argv)
{
    if (argc < 3) {
        fprintf(stderr,
            "Usage:\n"
            "  %s server <key_file>\n"
            "  %s client <server_ip> <key_file>\n",
            argv[0], argv[0]);

        return EXIT_FAILURE;
    }

    int is_server = strcmp(argv[1], "server") == 0;
    int is_client = strcmp(argv[1], "client") == 0;

    if (!is_server && !is_client) {
        fprintf(stderr, "Invalid mode.\n");
        return EXIT_FAILURE;
    }

    if ((is_server && argc != 3) ||
        (is_client && argc != 4)) {
        fprintf(stderr, "Invalid arguments.\n");
        return EXIT_FAILURE;
    }

    int server_fd = -1;
    int connection_fd = -1;

    struct sockaddr_in address;
    memset(&address, 0, sizeof(address));

    if (is_server) {

        server_fd = socket(AF_INET, SOCK_STREAM, 0);

        if (server_fd < 0) {
            perror("socket");
            return EXIT_FAILURE;
        }

        int reuse = 1;

        setsockopt(
            server_fd,
            SOL_SOCKET,
            SO_REUSEADDR,
            &reuse,
            sizeof(reuse)
        );

        address.sin_family = AF_INET;
        address.sin_port = htons(HANDSHAKE_PORT);
        address.sin_addr.s_addr = INADDR_ANY;

        if (bind(
                server_fd,
                (struct sockaddr *)&address,
                sizeof(address)) < 0) {
            perror("bind");
            close(server_fd);
            return EXIT_FAILURE;
        }

        if (listen(server_fd, 1) < 0) {
            perror("listen");
            close(server_fd);
            return EXIT_FAILURE;
        }

        printf("[DEVICE 2] Waiting for Device1 on port %d...\n",
               HANDSHAKE_PORT);

        connection_fd = accept(server_fd, NULL, NULL);

    } else {

        connection_fd = socket(AF_INET, SOCK_STREAM, 0);

        if (connection_fd < 0) {
            perror("socket");
            return EXIT_FAILURE;
        }

        address.sin_family = AF_INET;
        address.sin_port = htons(HANDSHAKE_PORT);

        if (inet_pton(
                AF_INET,
                argv[2],
                &address.sin_addr) != 1) {
            fprintf(stderr, "Invalid server IP.\n");
            close(connection_fd);
            return EXIT_FAILURE;
        }

        printf("[DEVICE 1] Connecting to Device2...\n");

        if (connect(
                connection_fd,
                (struct sockaddr *)&address,
                sizeof(address)) < 0) {
            perror("connect");
            close(connection_fd);
            return EXIT_FAILURE;
        }
    }

    if (connection_fd < 0) {
        perror("accept");

        if (server_fd >= 0)
            close(server_fd);

        return EXIT_FAILURE;
    }

    const char *key_file = is_server ? argv[2] : argv[3];

    int result = run_handshake(
        connection_fd,
        is_server,
        key_file
    );

    close(connection_fd);

    if (server_fd >= 0)
        close(server_fd);

    return result ? EXIT_SUCCESS : EXIT_FAILURE;
}