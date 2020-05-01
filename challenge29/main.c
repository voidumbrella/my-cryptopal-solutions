/*
 * Break a SHA-1 keyed MAC using length extension
 */

#include <assert.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "hash.h"
#include "utils.h"

uint8_t *secret_key;
size_t secret_key_size;

uint8_t *sha1_mac(const uint8_t *message, size_t size, 
                  const uint8_t *secretkey, size_t keysize) {
    uint8_t *buf = malloc(size + keysize);
    memcpy(buf, secretkey, keysize);
    memcpy(buf + keysize, message, size);

    uint8_t *mac = malloc(SHA1_HASH_SIZE);
    sha1_hash(buf, size + keysize, mac);
    free(buf);
    return mac;
}

bool is_authentic(const uint8_t *message, size_t size, const uint8_t *mac) {
    uint8_t *test_mac = sha1_mac(message, size, secret_key, secret_key_size);

    bool ret = true;
    for (size_t i = 0; i < SHA1_HASH_SIZE; ++i) {
        ret &= mac[i] == test_mac[i];
    }
    free(test_mac);
    return ret;
}

void setup_secret_key(void) {
    /*
     * Set up secret key
     */
    FILE *f = fopen("/dev/urandom", "r");
    fread(&secret_key_size, 1, sizeof (size_t), f);
    fclose(f);
    secret_key_size %= 990;
    secret_key_size += 10;

    secret_key = malloc(secret_key_size);
    fill_rand(secret_key, secret_key_size);
    printf("Key size: %ld\n", secret_key_size);

}

/*
 * Modified version of SHA-1
 *
 * The initial state can be set with the given input
 * Uses `fake_size` while padding, so the hashing of the full text can be emulated
 */
#define SHA1_BLOCK_SIZE 64

static void sha1_process_block(const uint8_t *block, uint32_t *state) {
    uint32_t K[4] = { 0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xCA62C1D6 };
    uint32_t W[80] = {0};
    for (size_t t = 0; t < 16; ++t) {
        W[t]  = block[t * 4]     << 24;
        W[t] |= block[t * 4 + 1] << 16;
        W[t] |= block[t * 4 + 2] << 8;
        W[t] |= block[t * 4 + 3];
    }
    for (size_t t = 16; t < 80; ++t) {
        uint32_t temp = W[t-3] ^ W[t-8] ^ W[t-14] ^ W[t-16];
        W[t] = (temp << 1) | (temp >> 31);
    }

    uint32_t A, B, C, D, E;
    A = state[0];
    B = state[1];
    C = state[2];
    D = state[3];
    E = state[4];
    for (size_t t = 0; t < 80; ++t) {
        uint32_t temp = ((A << 5) | (A >> 27)) + E + W[t] + K[t / 20];
        if      (t < 20) temp += (B & C) | ((~B) & D);
        else if (t < 40) temp += B ^ C ^ D;
        else if (t < 60) temp += (B & C) | (B & D) | (C & D);
        else             temp += B ^ C ^ D;

        E = D;
        D = C;
        C = (B << 30) | (B >> 2);
        B = A;
        A = temp;
    }

    state[0] += A;
    state[1] += B;
    state[2] += C;
    state[3] += D;
    state[4] += E;
}

void sha1_hash_from_state(const uint32_t *initial_state, const uint8_t *buf, size_t size, size_t fake_size, uint8_t *out_buf) {
    uint8_t block[SHA1_BLOCK_SIZE];
    uint32_t state[5];
    memcpy(state, initial_state, 5 * sizeof(uint32_t));

    /*
     * If size is not a multiple of the block size,
     * the loop stops right before the last block (since it must be padded).
     *
     * If not, last_block_pos = size and every block is processed.
     */
    size_t last_block_pos = size / SHA1_BLOCK_SIZE * SHA1_BLOCK_SIZE;
    for (size_t i = 0; i < last_block_pos; i += 64) {
        memcpy(block, buf + i, SHA1_BLOCK_SIZE);
        sha1_process_block(block, state);
    }

    if (size % SHA1_BLOCK_SIZE != 0)
        memcpy(block, buf + last_block_pos, size - last_block_pos);

    // Pad the final block
    {
        size_t i = size - last_block_pos;
        block[i++] = 0x80;
        if (i > 56) { // message length is written to 56-64th bytes
            // not enough space, leak padding into next block and process current block
            while (i < 64) block[i++] = 0x00;
            sha1_process_block(block, state);
            i = 0;
        }
        while (i < 56) block[i++] = 0x00;

        /*
         * size is currently the number of bytes, but SHA expects the number of bits.
         * (Also, use fake_size instead to simulate the previous padding)
         */
        fake_size *= 8;
        int shift = 56;
        for (size_t i = 56; i < 64; ++i) {
            block[i] = fake_size >> shift;
            shift -= 8;
        }
        sha1_process_block(block, state);
    }

    for (size_t i = 0; i < 5; ++i) {
        out_buf[i * 4    ] = state[i] >> 24;
        out_buf[i * 4 + 1] = state[i] >> 16;
        out_buf[i * 4 + 2] = state[i] >>  8;
        out_buf[i * 4 + 3] = state[i]      ;
    }
}

int main(void) {
    setup_secret_key();

    uint8_t message[] = "comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon";
    size_t size = sizeof message - 1;

    uint8_t *mac = sha1_mac(message, size, secret_key, secret_key_size);

    uint32_t state[5];
    for (size_t i = 0; i < 5; ++i) {
        state[i] = mac[i * 4]     << 24 |
                   mac[i * 4 + 1] << 16 |
                   mac[i * 4 + 2] <<  8 |
                   mac[i * 4 + 3];
    }

    uint8_t suffix[]= ";admin=true;";
    size_t suffix_size = sizeof suffix - 1;

    size_t key_size = 0;
    do {
        // size of "key || original-message || glue-padding"
        size_t padded_size = 64 * ((size + key_size) / 64 + ((size + key_size) % 64? 1: 0));

        uint8_t *modified = malloc(padded_size + suffix_size - key_size);
        memcpy(modified, message, size);

        // Generate padding
        {
            size_t i = size;
            modified[i++] = 0x80;
            if (i >= padded_size - key_size - 8) { // ensure enough space for reserved bytes
                padded_size += 64;
                modified = realloc(modified, padded_size + suffix_size - key_size);
            }
            while (i < padded_size - key_size - 8)
                modified[i++] = 0;

            size_t num_bits = (size + key_size) * 8;
            int shift = 56;
            while (i < padded_size - key_size) {
                modified[i++] = num_bits >> shift;
                shift -= 8;
            }
        }
        memcpy(modified + padded_size - key_size, suffix, suffix_size);

        uint8_t new_mac[SHA1_HASH_SIZE];
        sha1_hash_from_state(state,
                modified + padded_size - key_size,
                suffix_size,
                padded_size + suffix_size,
                new_mac);

        if (is_authentic(modified, padded_size + suffix_size - key_size, new_mac)) {
            puts("Successfully forged message!");
            exit(0);
            break;
        }

        free(modified);
    } while (key_size++ < secret_key_size);
    puts("Failed to forge message");
}
