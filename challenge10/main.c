/*
 * Implement CBC mode
 */

#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "aes.h"
#include "utils.h"

int main() {
    FILE *f = fopen("input.txt", "r");
    assert(f);
    char *encoded = read_ignoring_newlines(f);

    size_t text_len;
    uint8_t *buffer = b64decode(encoded, &text_len);
    free(encoded);

    uint8_t *key = (uint8_t *)"YELLOW SUBMARINE";
    uint8_t *iv  = (uint8_t *)"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";

    struct aes_ctx ctx;
    aes_ctx_init(&ctx, key);
    aes_ctx_set_iv(&ctx, iv);
    aes_128_cbc_decrypt(&ctx, buffer, text_len);
    printf("%.*s", (int)text_len, buffer);
}
