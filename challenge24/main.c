/*
 * Create the MT19937 stream cipher and break it
 */

#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>

#include "mt.h"
#include "utils.h"

void mt_cipher(uint16_t key, uint8_t *buf, size_t size) {
    struct mt_ctx src;
    mt_seed(&src, key);

    for (size_t offset = 0; offset < size; offset += 4) {
        uint32_t n = mt_rand(&src);
        for (size_t i = offset; i < offset + 4 && i < size; ++i)
            buf[i] ^= (n >> ((3 - i) * 8)) & 0xFF; 
    }
}

uint8_t *random_prefix(const uint8_t *plaintext, size_t size, size_t *out_size) {
    size_t prefix_size = 5 + rand() % 10;
    uint8_t *buf = malloc(size + prefix_size);
    fill_rand(buf, prefix_size);
    memcpy(buf + prefix_size, plaintext, size);
    *out_size = size + prefix_size;
    return buf;
}

uint32_t password_reset_token() {
    struct mt_ctx src;
    uint32_t seed = time(NULL);
    seed -= rand() % 4000; // simulate time passing
    printf("Seeding password reset token with %u\n", seed);
    mt_seed(&src, seed);
    return mt_rand(&src);
}


bool test_block(uint8_t *p, uint32_t n) {
    size_t i = 0;
    while (++i) {
        if (i == 4)
            return true;
        if (p[i] != ((n >> ((3 - i) * 8)) & 0xFF))
            break;
    }
    return false;
}

int main() {
    srand(time(NULL));

    uint8_t p[32] = {0};

    size_t size;
    uint8_t *buf = random_prefix(p, 32, &size);
    size_t prefix_size = size - 32;
    int skip = (prefix_size / 4) + (prefix_size % 4? 1: 0);

    uint16_t key;
    fill_rand((uint8_t *)&key, 2);
    mt_cipher(key, buf, size);

    /*
     * Brute force cipher
     */
    {
        struct mt_ctx test;
        uint16_t test_key;
        for (test_key = 0;; ++test_key) {
            mt_seed(&test, test_key);
            for (int i = 0; i < skip; ++i)
                mt_rand(&test);

            bool ok = true;
            for (size_t offset = skip * 4; offset < size - 4; offset += 4) {
                uint32_t n = mt_rand(&test);
                if (!test_block(buf + offset, n)) {
                    ok = false;
                    break;
                }
            }
            
            if (ok)
                break;
        }
        printf("Expected key %u, found %u\n", key, test_key);
    }

    /*
     * Seeded with timestamp?
     */
    {
        uint32_t token = password_reset_token();
        uint32_t timestamp = time(NULL);
        struct mt_ctx test;
        do {
            mt_seed(&test, timestamp);
            if (mt_rand(&test) == token) {
                printf("Password was seeded with timestamp: %u\n", timestamp);
                return 0;
            }
        } while (timestamp--);
        printf("Could not recover seed\n");
    }
}
