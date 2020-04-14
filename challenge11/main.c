/*
 * An ECB/CBC detection oracle
 */

#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "aes.h"
#include "utils.h"

#define ECB 0
#define CBC 1

uint8_t *blackbox(const uint8_t *plaintext, const size_t len, size_t *out_len, int *out_mode) {
    uint8_t key[16], iv[16];
    fill_rand(key, 16);
    fill_rand(iv, 16);

    int mode = rand() % 2;
    *out_mode = mode;

    size_t prefix_len = 5 + rand() % 5;
    size_t suffix_len = 5 + rand() % 5;
    size_t total_len = prefix_len + len + suffix_len;
    size_t padded_len = pkcs7_pad_length(total_len, 16);
    *out_len = padded_len;

    uint8_t *buf = malloc(padded_len);
    fill_rand(buf, prefix_len);
    memcpy(buf + prefix_len, plaintext, len);
    fill_rand(buf + prefix_len + len, suffix_len);
    pkcs7_pad(buf, total_len, 16);

    struct aes_ctx ctx;
    aes_ctx_init(&ctx, key);
    if (mode == ECB) {
        aes_128_ecb_encrypt(&ctx, buf, padded_len);
    } else {
        aes_ctx_set_iv(&ctx, iv);
        aes_128_cbc_encrypt(&ctx, buf, padded_len);
    }
    return buf;
}

int block_compare(const void *a, const void *b) {
    return memcmp((const char *)a, (const char *)b, 16);
}

int detect_mode(const uint8_t *ciphertext, const size_t len) {
    size_t nblocks = len / 16;

    qsort((void *)ciphertext, nblocks, 16, &block_compare);
    for (size_t i = 0; i < len - 16; i += 16) {
        if (memcmp(ciphertext + i, ciphertext + i + 16, 16) == 0) {
            return ECB;
        }
    }
    return CBC;
}

int main() {
    srand(1);
    uint8_t *plaintext = (uint8_t *)
        "$$$$$$$$$$$$$$$$"
        "$$$$$$$$$$$$$$$$"
        "$$$$$$$$$$$$$$$$"
        "$$$$$$$$$$$$$$$$"
        "$$$$$$$$$$$$$$$$"
        "$$$$$$$$$$$$$$$$"
        "$$$$$$$$$$$$$$$$"
        "$$$$$$$$$$$$$$$$";
    size_t len = strlen((char *)plaintext);

    int failure = 0, N = 10000;
    for (int i = 0; i < N; ++i) {
        int mode, detected;
        size_t cipher_len;
        uint8_t *ciphertext = blackbox(plaintext, len, &cipher_len, &mode);
        detected = detect_mode(ciphertext, cipher_len);
        if (detected != mode) {
            printf("detected %s, is actually %s\n",
                    detected == ECB? "ECB": "CBC",
                    mode == ECB? "ECB": "CBC");
            ++failure;
        }
        free(ciphertext);
    }
    printf("%.2f%% success rate\n", 100 - failure * 1. / N * 100);
}
