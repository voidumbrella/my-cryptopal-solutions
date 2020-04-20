/*
 * Crack an MT19937 seed
 */

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

#include "mt.h"

uint32_t box() {
    struct mt_ctx ctx;
    sleep(40 + rand() % 1000);
    mt_seed(&ctx, time(NULL));
    sleep(40 + rand() % 1000);
    return mt_rand(&ctx);
}

int main() {
    uint32_t result = box();
    printf("Received : %08X | %u\n", result, result);
    uint32_t trial, timestamp = time(NULL);
    struct mt_ctx ctx;
    do {
        mt_seed(&ctx, timestamp--);
        trial = mt_rand(&ctx);
    } while (trial != result);
    ++timestamp;
    printf("Seed     : %08X | %u\n", timestamp, timestamp);

    mt_seed(&ctx, timestamp);
    result = mt_rand(&ctx);
    printf("From seed: %08X | %u\n", result, result);
}
