/*
 * Break "random access read/write" AES CTR
 */

#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include "aes.h"
#include "utils.h"

struct aes_ctx ctx;
uint8_t key[16];
uint8_t nonce[8];

uint8_t *get_ciphertext(size_t *out_size) {
    FILE *f = fopen("input.txt", "r");
    assert(f);
    char *encoded = read_ignoring_newlines(f);

    size_t size;
    uint8_t *buf = b64decode(encoded, &size);
    free(encoded);

    uint8_t ecb_key[16] = "YELLOW SUBMARINE";
    aes_ctx_init(&ctx, ecb_key);
    aes_128_ecb_decrypt(&ctx, buf, size);

    fill_rand(key, 16);
    fill_rand(nonce, 8);
    aes_ctx_init(&ctx, key);
    aes_ctx_set_nonce(&ctx, nonce);
    aes_128_ctr(&ctx, buf, size);

    *out_size = size;
    return buf;
}

void edit(uint8_t *ciphertext, const size_t ciphertext_size, size_t offset,
          const uint8_t *newtext, const size_t newtext_size) {
    // Lazy to modify the CTR mode API so we do it the inefficient way
    assert(offset + newtext_size <= ciphertext_size);

    uint8_t *temp = calloc(1, ciphertext_size);
    memcpy(temp + offset, newtext, newtext_size);

    aes_ctx_init(&ctx, key);
    aes_ctx_set_nonce(&ctx, nonce);
    aes_128_ctr(&ctx, temp, ciphertext_size);

    memcpy(ciphertext + offset, temp + offset, newtext_size);
}

int main() {
    size_t size;
    uint8_t *ciphertext = get_ciphertext(&size);

    // Reencrypt a copy of the ciphertext copy with zeros, which just tells us what the keystream was
    uint8_t *copy = malloc(size);
    memcpy(copy, ciphertext, size);
    uint8_t *newtext = calloc(1, size);
    edit(copy, size, 0, newtext, size);

    // Then XOR it with the recovered keystream
    for (size_t i = 0; i < size; ++i) {
        ciphertext[i] ^= copy[i];
    }
    printf("%.*s", (int)size, ciphertext);
}
