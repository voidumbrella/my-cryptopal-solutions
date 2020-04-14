/*
 * AES in ECB mode
 */

#include <assert.h>
#include <ctype.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>

#include "aes.h"

uint8_t b64index(const char c) {
    if ('A' <= c && c <= 'Z') { return c - 'A'; }
    else if ('a' <= c && c <= 'z') { return c - 'a' + 26; }
    else if ('0' <= c && c <= '9') { return c - '0' + 52; }
    else if (c == '+') { return 62; }
    else if (c == '/') { return 63; }
    else { fprintf(stderr, "Base64 string contains invalid character '0x%02X'\n", c); abort(); }
}

uint8_t *b64decode(const char *b64_string, size_t *out_length) {
    size_t b64_len = strlen(b64_string);
    assert(b64_len % 4 == 0);
    size_t num_blocks = b64_len / 4, length = num_blocks * 3;

    uint8_t *ret = malloc(length);
    for (size_t i = 0; i < num_blocks; ++i) {
        const char *p = &b64_string[i*4];
        uint8_t *r = &ret[i*3];

        assert(p[0] != '=' && p[1] != '=');
        r[0] = b64index(p[0]) << 2 | b64index(p[1]) >> 4;
        if (p[2] == '=') {
            assert(p[3] == '=' && p[4] == '\0');
            r[1] = '\0';
            length -= 2;
            break;
        }
        r[1] = (b64index(p[1]) & 0x0F) << 4 | (b64index(p[2]) >> 2);
        if (p[3] == '=') {
            assert(p[4] == '\0');
            r[2] = '\0';
            length -= 1;
            break;
        }
        r[2] = (b64index(p[2]) & 0x03) << 6 | (b64index(p[3]) & 0x3F);
    }
    *out_length = length;
    return ret;
}

char *read_ignoring_newlines(FILE *f) {
    char *s;
    // Read from file while ignoring newlines
    size_t length, block_size = 1024, capacity = BUFSIZ;
    s = malloc(capacity);
    char *nl, *p = s;
    while (fgets(p, block_size, f)) {
        p += strcspn(p, "\n");
        *p = '\0';

        length = p - s;
        if (length + block_size >= capacity) {
            capacity *= 2;
            s = realloc(s, capacity);
            p = s + length;
        }
    }
    return s;
}

int main(int argc, char *argv[]) {
    FILE *f = fopen("input.txt", "r");
    assert(f);
    char *encoded = read_ignoring_newlines(f);

    size_t len;
    uint8_t *buf = b64decode(encoded, &len);
    free(encoded);

    struct aes_ctx ctx;
    aes_ctx_init(&ctx, (uint8_t *)"YELLOW SUBMARINE");
    aes_128_ecb_encrypt(&ctx, buf, len);
    aes_128_ecb_decrypt(&ctx, buf, len);
    aes_128_ecb_decrypt(&ctx, buf, len);
    printf("%.*s", (int)len, buf);

    free(buf);
}
