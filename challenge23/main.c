/*
 * Clone an MT19937 RNG from its output
 */

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>

#include "mt.h"

uint32_t untemper(uint32_t x) {
    x ^= x >> 18;
    x ^= (x << 15) & 0xefc60000;
    uint32_t mask = (1 << 7) - 1;
    for (int i = 0; i < 4; ++i) {
        x ^= ((x & mask) << 7) & 0x9d2c5680;
        mask <<= 7;
    }
    for (int i = 0; i < 3; ++i)
        x ^= (x >> 11);

    return x;
}

int main() {
    struct mt_ctx ctx, cloned;
    mt_seed(&ctx, 0xDEADCAFE);

    for (int i = 0; i < 624; ++i)
        cloned.state[i] = untemper(mt_rand(&ctx));
    cloned.index = 624;

    for (int i = 0; i < 1000; ++i)
        assert(mt_rand(&ctx) == mt_rand(&cloned));
}
