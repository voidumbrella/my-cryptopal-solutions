#include <string.h>

#include "hash.h"

static uint32_t circ_shift_left_32(uint32_t n, int shift) {
    return (n << shift) | (n >> (32 - shift));
}

/*
 * SHA-1 implementation
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
        W[t] = circ_shift_left_32(W[t-3] ^ W[t-8] ^ W[t-14] ^ W[t-16], 1);
    }

    uint32_t A, B, C, D, E;
    A = state[0];
    B = state[1];
    C = state[2];
    D = state[3];
    E = state[4];
    for (size_t t = 0; t < 80; ++t) {
        uint32_t temp = circ_shift_left_32(A, 5) + E + W[t] + K[t / 20];
        if      (t < 20) temp += (B & C) | ((~B) & D);
        else if (t < 40) temp += B ^ C ^ D;
        else if (t < 60) temp += (B & C) | (B & D) | (C & D);
        else             temp += B ^ C ^ D;

        E = D;
        D = C;
        C = circ_shift_left_32(B, 30);
        B = A;
        A = temp;
    }

    state[0] += A;
    state[1] += B;
    state[2] += C;
    state[3] += D;
    state[4] += E;
}

void sha1_hash(const uint8_t *buf, size_t size, uint8_t *out_buf) {
    uint8_t block[SHA1_BLOCK_SIZE];
    uint32_t state[5];
    state[0] = 0x67452301;
    state[1] = 0xEFCDAB89;
    state[2] = 0x98BADCFE;
    state[3] = 0x10325476;
    state[4] = 0xC3D2E1F0;

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
         */
        size *= 8;
        int shift = 56;
        for (size_t i = 56; i < 64; ++i) {
            block[i] = size >> shift;
            shift -= 8;
        }
        sha1_process_block(block, state);
    }

    for (size_t i = 0; i < 5; ++i) {
        out_buf[i * 4    ] = state[i] >> 24;
        out_buf[i * 4 + 1] = state[i] >> 16;
        out_buf[i * 4 + 2] = state[i] >>  8;
        out_buf[i * 4 + 3] = state[i];
    }
}




/*
 * MD4 implementation
 */

#define MD4_BLOCK_SIZE 64

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

void md4_hash(const uint8_t *buf, size_t size, uint8_t *out_buf) {
    uint8_t block[MD4_BLOCK_SIZE];
    uint32_t state[4];
    state[0] = 0x67452301;
    state[1] = 0xEFCDAB89;
    state[2] = 0x98BADCFE;
    state[3] = 0x10325476;

    /*
     * If size is not a multiple of the block size,
     * the loop stops right before the last block (since it must be padded).
     *
     * If not, last_block_pos = size and every block is processed.
     */
    size_t last_block_pos = size / MD4_BLOCK_SIZE * MD4_BLOCK_SIZE;
    for (size_t i = 0; i < last_block_pos; i += 64) {
        memcpy(block, buf + i, MD4_BLOCK_SIZE);
        md4_process_block(block, state);
    }

    if (size % MD4_BLOCK_SIZE != 0)
        memcpy(block, buf + last_block_pos, size - last_block_pos);

    // Padding scheme is identical to SHA-1 (besides the little-endian order)
    {
        size_t i = size - last_block_pos;
        block[i++] = 0x80;
        if (i > 56) {
            while (i < 64) block[i++] = 0x00;
            md4_process_block(block, state);
            i = 0;
        }
        while (i < 56) block[i++] = 0x00;
        size *= 8;
        int shift = 0;
        for (size_t i = 56; i < 64; ++i) {
            block[i] = size >> shift;
            shift += 8;
        }
        md4_process_block(block, state);
    }

    for (size_t i = 0; i < 4; ++i) { // little-endian!!
        out_buf[i * 4    ] = state[i];
        out_buf[i * 4 + 1] = state[i] >>  8;
        out_buf[i * 4 + 2] = state[i] >> 16;
        out_buf[i * 4 + 3] = state[i] >> 24;
    }
}
