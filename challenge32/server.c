/*
 * Break HMAC-SHA1 with a slightly less artificial timing leak
 */

#define _GNU_SOURCE

#include <assert.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <sys/un.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include "hash.h"
#include "utils.h"

uint8_t *secret_key;
size_t secret_key_size;

#define SHA1_BLOCK_SIZE 64
uint8_t *sha1_hmac(const uint8_t *message, size_t size,
        const uint8_t *secret_key, size_t secret_key_size) {
    uint8_t *block_key = calloc(1, SHA1_BLOCK_SIZE); // initialize with zeros for padding
    if (secret_key_size > SHA1_BLOCK_SIZE) { // key too big, hash the key
        sha1_hash(secret_key, secret_key_size, block_key);
    } else {
        memcpy(block_key, secret_key, secret_key_size);
    }

    uint8_t *buf = malloc(2 * SHA1_BLOCK_SIZE + size);

    // outer block-sized key
    memcpy(buf, block_key, SHA1_BLOCK_SIZE);
    for (size_t i = 0; i < SHA1_BLOCK_SIZE; ++i)
        buf[i] ^= 0x5c;

    // inner block-sized key
    memcpy(buf + SHA1_BLOCK_SIZE, block_key, SHA1_BLOCK_SIZE);
    for (size_t i = 0; i < SHA1_BLOCK_SIZE; ++i)
        buf[SHA1_BLOCK_SIZE + i] ^= 0x36;

    // concatenate message
    memcpy(buf + 2 * SHA1_BLOCK_SIZE, message, size);

    // H((K' ^ ipad) || m)
    sha1_hash(buf + SHA1_BLOCK_SIZE, SHA1_BLOCK_SIZE + size, buf + SHA1_BLOCK_SIZE);

    uint8_t *hmac = malloc(SHA1_HASH_SIZE);
    // H(outer block-sized key || inner-hash)
    sha1_hash(buf, SHA1_BLOCK_SIZE + SHA1_HASH_SIZE, hmac);

    free(buf);
    return hmac;
}

bool signature_valid(const uint8_t *buf, size_t buf_size, const uint8_t *hmac) {
    uint8_t *test_hmac = sha1_hmac(buf, buf_size, secret_key, secret_key_size);

    for (size_t i = 0; i < SHA1_HASH_SIZE; ++i) {
        /* Artificial 3 ms delay */
        struct timespec t = {
            .tv_sec = 0,
            .tv_nsec = 3000000,
        };
        nanosleep(&t, NULL);

        if (hmac[i] != test_hmac[i]) {
            free(test_hmac);
            return false;
        }
    }
    free(test_hmac);
    return true;
}

void setup_secret_key(void) {
    /*
     * Set up secret key
     */
    FILE *f = fopen("/dev/urandom", "r");
    fread(&secret_key_size, 1, sizeof (size_t), f);
    fclose(f);
    secret_key_size %= 100;
    secret_key_size += 10;

    secret_key = malloc(secret_key_size);
    fill_rand(secret_key, secret_key_size);
    printf("Key size: %ld\n", secret_key_size);
    puts("Key for debug purposes:");
    print_bin(secret_key, secret_key_size);
}

int create_socket(const char *path) {
    struct sockaddr_un addr;
    addr.sun_family = AF_UNIX;
    strcpy(addr.sun_path, path);
    unlink(addr.sun_path);

    int socket_fd = socket(PF_UNIX, SOCK_STREAM, 0);
    if (socket_fd < 0) {
        perror("socket");
        exit(-1);
    }
    if (bind(socket_fd, (struct sockaddr *)&addr, sizeof addr) < 0) {
        perror("bind");
        exit(-1);
    }
    return socket_fd;
}

void handle_client(int s) {
    for (;;) {
        uint32_t size;
        if (recv(s, &size, sizeof (uint32_t), 0) <= 0)
            break;
        uint8_t *filename = malloc(size);
        if (recv(s, filename, size, 0) <= 0)
            break;
        uint8_t hmac[SHA1_HASH_SIZE];
        if (recv(s, hmac, SHA1_HASH_SIZE, 0) <= 0)
            break;

        int res = signature_valid(filename, size, hmac);
        send(s, &res, sizeof (int), 0);
    }
    close(s);
    exit(0);
}

int main(void) {
    signal(SIGCHLD, SIG_IGN);

    setup_secret_key();

    int sock = create_socket("hmac_socket");
    if (listen(sock, 32) < 0) {
        perror("listen");
        exit(-1);
    }

    struct sockaddr_un remote;
    socklen_t len = sizeof(struct sockaddr_un);

    for (;;) {
        int connection = accept(sock, &remote, &len);
        if (connection < 0) {
            perror("accept");
            exit(1);
        }

        pid_t pid = fork();
        if (pid < 0) {
            perror("fork");
            exit(1);
        }
        if (pid == 0)
            handle_client(connection);
        close(connection);
    }
}
