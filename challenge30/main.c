/*
 * Break a MD4 keyed MAC using length extension
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

uint8_t *md4_mac(const uint8_t *message, size_t size, 
                  const uint8_t *secretkey, size_t keysize) {
    uint8_t *buf = malloc(size + keysize);
    memcpy(buf, secretkey, keysize);
    memcpy(buf + keysize, message, size);

    uint8_t *mac = malloc(MD4_HASH_SIZE);
    md4_hash(buf, size + keysize, mac);
    free(buf);
    return mac;
}

bool is_authentic(const uint8_t *message, size_t size, const uint8_t *mac) {
    uint8_t *test_mac = md4_mac(message, size, secret_key, secret_key_size);

    bool ret = true;
    // I forgot to replace this from SHA1_HASH_SIZE,
    // which took embarassingly long to debug
    for (size_t i = 0; i < MD4_HASH_SIZE; ++i) {
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
 * Modified MD4 hash
 */
#define MD4_BLOCK_SIZE 64

static uint32_t circ_shift_left_32(uint32_t n, int shift) {
    return (n << shift) | (n >> (32 - shift));
}

static void md4_process_block(const uint8_t *block, uint32_t *state) {
    uint32_t X[16] = {0};
    for (size_t t = 0; t < 16; ++t) { // little endian!!
        X[t]  = block[t * 4];
        X[t] |= block[t * 4 + 1] << 8;
        X[t] |= block[t * 4 + 2] << 16;
        X[t] |= block[t * 4 + 3] << 24;
    }
    uint32_t A, B, C, D;
    A = state[0];
    B = state[1];
    C = state[2];
    D = state[3];

#define F(x, y, z) ((x&y) | ((~x)&z))
#define G(x, y, z) ((x&y) | (x&z) | (y&z))
#define H(x, y, z) (x^y^z)
#define ROUND1(a,b,c,d,i,s) a += F(b, c, d) + X[i]             ; a = circ_shift_left_32(a, s);
#define ROUND2(a,b,c,d,i,s) a += G(b, c, d) + X[i] + 0x5A827999; a = circ_shift_left_32(a, s);
#define ROUND3(a,b,c,d,i,s) a += H(b, c, d) + X[i] + 0x6ED9EBA1; a = circ_shift_left_32(a, s);
    for (int i = 0; i < 4; ++i) {
        ROUND1(A, B, C, D, i*4,    3);
        ROUND1(D, A, B, C, i*4+1,  7);
        ROUND1(C, D, A, B, i*4+2,  11);
        ROUND1(B, C, D, A, i*4+3,  19);
    }

    for (int i = 0; i < 4; ++i) {
        ROUND2(A, B, C, D, i,    3);
        ROUND2(D, A, B, C, 4+i,  5);
        ROUND2(C, D, A, B, 8+i,  9);
        ROUND2(B, C, D, A, 12+i, 13);
    }

    int off[4] = {0, 2, 1, 3};
    for (int i = 0; i < 4; ++i) {
        ROUND3(A, B, C, D, off[i],    3);
        ROUND3(D, A, B, C, 8+off[i],  9);
        ROUND3(C, D, A, B, 4+off[i],  11);
        ROUND3(B, C, D, A, 12+off[i], 15);
    }
#undef ROUND1
#undef ROUND2
#undef ROUND3
#undef f
#undef g
#undef h

    state[0] += A;
    state[1] += B;
    state[2] += C;
    state[3] += D;
}

void md4_hash_from_state(const uint32_t *initial_state, const uint8_t *buf, size_t size, size_t fake_size, uint8_t *out_buf) {
    uint8_t block[MD4_BLOCK_SIZE];
    uint32_t state[4];
    memcpy(state, initial_state, 4 * sizeof(uint32_t));

    size_t last_block_pos = size / MD4_BLOCK_SIZE * MD4_BLOCK_SIZE;
    for (size_t i = 0; i < last_block_pos; i += 64) {
        memcpy(block, buf + i, MD4_BLOCK_SIZE);
        md4_process_block(block, state);
    }

    if (size % MD4_BLOCK_SIZE != 0)
        memcpy(block, buf + last_block_pos, size - last_block_pos);

    {
        size_t i = size - last_block_pos;
        block[i++] = 0x80;
        if (i > 56) {
            while (i < 64) block[i++] = 0x00;
            md4_process_block(block, state);
            i = 0;
        }
        while (i < 56) block[i++] = 0x00;
        fake_size *= 8;
        int shift = 0;
        for (size_t i = 56; i < 64; ++i) {
            block[i] = fake_size >> shift;
            shift += 8;
        }
        md4_process_block(block, state);
    }

    for (size_t i = 0; i < 4; ++i) {
        out_buf[i * 4    ] = state[i];
        out_buf[i * 4 + 1] = state[i] >>  8;
        out_buf[i * 4 + 2] = state[i] >> 16;
        out_buf[i * 4 + 3] = state[i] >> 24;
    }
}

int main(void) {
    setup_secret_key();

    uint8_t message[] = "comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon";
    size_t size = sizeof message - 1;

    uint8_t *mac = md4_mac(message, size, secret_key, secret_key_size);

    uint32_t state[4];
    for (size_t i = 0; i < 4; ++i) {
        state[i] = mac[i * 4]           |
                   mac[i * 4 + 1] <<  8 |
                   mac[i * 4 + 2] << 16 |
                   mac[i * 4 + 3] << 24;
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
            int shift = 0;
            while (i < padded_size - key_size) {
                modified[i++] = num_bits >> shift;
                shift += 8;
            }
        }
        memcpy(modified + padded_size - key_size, suffix, suffix_size);

        uint8_t new_mac[MD4_HASH_SIZE];
        md4_hash_from_state(state,
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
