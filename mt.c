#include <stddef.h>

#include "mt.h"

#define N 624

void mt_seed(struct mt_ctx *ctx, uint32_t seed) {
    ctx->index = N;
    ctx->state[0] = seed;
    for (size_t i = 1; i < N; ++i) {
        ctx->state[i] = 1812433253 * (ctx->state[i-1] ^ (ctx->state[i-1] >> 30)) + i;
    }
}

static void twist(struct mt_ctx *ctx) {
    for (size_t i = 0; i < N; ++i) {
        uint32_t x = (ctx->state[i] & 0x80000000) |
                     (ctx->state[(i + 1) % N] & 0x7fffffff);
        uint32_t y = (x >> 1) ^ ((x & 1) * 0x9908b0df);
        ctx->state[i] = ctx->state[(i + 397) % N] ^ y;
    }
    ctx->index = 0;
}

uint32_t mt_rand(struct mt_ctx *ctx) {
    if (ctx->index >= N)
        twist(ctx);
    uint32_t x = ctx->state[ctx->index++];
    x ^= x >> 11;
    x ^= (x << 7) & 0x9d2c5680;
    x ^= (x << 15) & 0xefc60000;
    x ^= x >> 18;
    return x;
}
