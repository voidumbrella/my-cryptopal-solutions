#include <string.h>

#include "hash.h"

/*
 * SHA-1 implementation
 *
 * Does not implement streaming because I didn't feel like it
 */

static void sha1_process_block(struct sha1_ctx *ctx) {
    uint32_t K[4] = { 0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xCA62C1D6 };
    uint32_t W[80] = {0};
    for (size_t t = 0; t < 16; ++t) {
        W[t]  = ctx->block[t * 4]     << 24;
        W[t] |= ctx->block[t * 4 + 1] << 16;
        W[t] |= ctx->block[t * 4 + 2] << 8;
        W[t] |= ctx->block[t * 4 + 3];
    }
    for (size_t t = 16; t < 80; ++t) {
        uint32_t temp = W[t-3] ^ W[t-8] ^ W[t-14] ^ W[t-16];
        W[t] = (temp << 1) | (temp >> 31);
    }

    uint32_t A, B, C, D, E;
    A = ctx->H[0];
    B = ctx->H[1];
    C = ctx->H[2];
    D = ctx->H[3];
    E = ctx->H[4];
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

    ctx->H[0] += A;
    ctx->H[1] += B;
    ctx->H[2] += C;
    ctx->H[3] += D;
    ctx->H[4] += E;
}

void sha1_init(struct sha1_ctx *ctx) {
    ctx->H[0] = 0x67452301;
    ctx->H[1] = 0xEFCDAB89;
    ctx->H[2] = 0x98BADCFE;
    ctx->H[3] = 0x10325476;
    ctx->H[4] = 0xC3D2E1F0;
}

void sha1_hash(struct sha1_ctx *ctx, const uint8_t *buf, size_t size, uint8_t *out_buf) {
    ctx->H[0] = 0x67452301;
    ctx->H[1] = 0xEFCDAB89;
    ctx->H[2] = 0x98BADCFE;
    ctx->H[3] = 0x10325476;
    ctx->H[4] = 0xC3D2E1F0;

    /*
     * If size is not a multiple of the block size,
     * the loop stops right before the last block (since it must be padded).
     *
     * If not, last_block_pos = size and every block is processed.
     */
    size_t last_block_pos = size / SHA1_BLOCK_SIZE * SHA1_BLOCK_SIZE;
    for (size_t i = 0; i < last_block_pos; i += 64) {
        memcpy(ctx->block, buf + i, SHA1_BLOCK_SIZE);
        sha1_process_block(ctx);
    }

    if (size % SHA1_BLOCK_SIZE != 0)
        memcpy(ctx->block, buf + last_block_pos, size - last_block_pos);

    // Pad the final block
    {
        size_t i = size - last_block_pos;
        ctx->block[i++] = 0x80;
        if (i >= 56) {
            // not enough space, leak padding into next block and process current block
            while (i < 64) ctx->block[i++] = 0x00;
            sha1_process_block(ctx);
            i = 0;
        }
        while (i < 56) ctx->block[i++] = 0x00;

        /*
         * size is currently the number of bytes, but SHA expects the number of bits.
         */
        size *= 8;
        int shift = 56;
        for (size_t i = 56; i < 64; ++i) {
            ctx->block[i] = size >> shift;
            shift -= 8;
        }
        sha1_process_block(ctx);
    }

    for (size_t i = 0; i < 5; ++i) {
        out_buf[i * 4    ] = ctx->H[i] >> 24;
        out_buf[i * 4 + 1] = ctx->H[i] >> 16;
        out_buf[i * 4 + 2] = ctx->H[i] >>  8;
        out_buf[i * 4 + 3] = ctx->H[i]      ;
    }
}
