/*
 * Implement a SHA-1 keyed MAC
 */

#include <assert.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "hash.h"

uint8_t key[] = "password123";
size_t keysize = 11;

uint8_t *sha1_mac(const uint8_t *message, size_t size, 
                  const uint8_t *secretkey, size_t keysize) {
    uint8_t *buf = malloc(size + keysize);
    memcpy(buf, secretkey, keysize);
    memcpy(buf + keysize, message, size);

    struct sha1_ctx ctx;
    sha1_init(&ctx);

    uint8_t *mac = malloc(SHA1_HASH_SIZE);
    sha1_hash(&ctx, buf, size + keysize, mac);
    return mac;
}

bool is_authentic(const uint8_t *message, size_t size, const uint8_t *mac) {
    uint8_t *test_mac = sha1_mac(message, size, key, keysize);

    for (size_t i = 0; i < SHA1_HASH_SIZE; ++i) {
        if (mac[i] != test_mac[i])
            return false;
    }
    return true;
}

int main() {
    uint8_t message[] = "Lorem ipsum dolor sit amet, consectetur adipiscing elit, "
                        "sed do eiusmod tempor incididunt ut labore et dolore magna aliqua.";
    size_t size = strlen((char *)message);

    size_t mac_size;
    uint8_t *mac = sha1_mac(message, size, key, keysize);

    assert(is_authentic(message, size, mac) == true);

    // Verify that we cannot modify the message
    message[0] = 'A';
    assert(is_authentic(message, size, mac) == false);
}
