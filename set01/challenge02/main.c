/*
 * Fixed XOR
 */

#include <assert.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>

uint8_t *hex2bin(const char *hex_string, size_t *out_length) {
    size_t hex_len = strlen(hex_string);
    assert(hex_len % 2 == 0);

    size_t bin_len = hex_len / 2;
    uint8_t *ret = calloc(1, bin_len);

    for (size_t i = 0; i < hex_len; ++i) {
        char c = hex_string[i];
        if ('0' <= c && c <= '9')
            ret[i/2] += (c - '0') * (i % 2? 1: 16);
        else if ('A' <= c && c <= 'F')
            ret[i/2] += (c - 'A' + 10) * (i % 2? 1: 16);
        else if ('a' <= c && c <= 'f')
            ret[i/2] += (c - 'a' + 10) * (i % 2? 1: 16);
        else {
            fprintf(stderr, "invalid character in hexstring: %c", c);
            abort();
        }
    }

    *out_length = bin_len;
    return ret;
}

char *bin2hex(const uint8_t *b, const size_t bin_len) {
    char *ret = malloc(bin_len * 2 + 1);
    for (size_t i = 0; i < bin_len; ++i) {
        char hi = b[i] >> 4, lo = b[i] & 0xF;
        ret[i*2] = hi + (hi < 10? '0': 'a' - 10);
        ret[i*2+1] = lo + (lo < 10? '0': 'a' - 10);
    }
    ret[bin_len * 2] = '\0';
    return ret;
}

int main(int argc, char *argv[]) {
    static char *input1 = "1c0111001f010100061a024b53535009181c";
    static char *input2 = "686974207468652062756c6c277320657965";
    static char *expected = "746865206b696420646f6e277420706c6179";

    size_t a_len, b_len;
    uint8_t *a = hex2bin(input1, &a_len);
    uint8_t *b = hex2bin(input2, &b_len);

    assert(a_len == b_len);
    for (size_t i = 0; i < a_len; ++i) {
        a[i] ^= b[i];
    }

    char *output = bin2hex(a, a_len);
    printf("%s\n", output);
    assert(strcmp(output, expected) == 0);
}
