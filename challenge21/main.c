/*
 * Implement the MT19937 Mersenne Twister RNG
 */

#include <stdio.h>

#include "mt.h"

int main() {
    struct mt_ctx ctx;
    mt_seed(&ctx, 12345);
    for (int _ = 0; _ < 20; ++_) {
        printf("%08X\n", mt_rand(&ctx));
    }
}
