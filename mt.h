#include <stdint.h>

#define N 624

struct mt_ctx {
    uint32_t state[N];
    size_t index;
};

void mt_seed(struct mt_ctx *ctx, uint32_t seed);
uint32_t mt_rand(struct mt_ctx *ctx);

#undef N
