/*
 * Convert hex to base64
 */

#include <assert.h>
#include <ctype.h>
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

char *b64encode(const uint8_t *b, const size_t bin_len) {
    static char table[64] = {
        'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
        'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
        'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
        'w', 'x', 'y', 'z', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '+', '/',
    };
    size_t num_blocks = bin_len / 3 + (bin_len % 3? 1: 0);
    char *ret = malloc(num_blocks * 4 + 1);
    for (size_t i = 0; i < num_blocks; ++i) {
        const uint8_t *p = &b[i*3];
        char *r = &ret[i*4];

        r[0] = table[(p[0] & 0xFC) >> 2];
        if (i*3+1 >= bin_len) {
            r[1] = table[(p[0] & 0x03) << 4];
            r[2] = r[3] = '=';
        } else if (i*3+2 >= bin_len) {
            r[1] = table[(p[0] & 0x03) << 4 | p[1] >> 4];
            r[2] = table[(p[1] & 0x0F) << 2];
            r[3] = '=';
        } else {
            r[1] = table[(p[0] & 0x03) << 4 | p[1] >> 4];
            r[2] = table[(p[1] & 0x0F) << 2 | p[2] >> 6];
            r[3] = table[p[2] & 0x3F];
        }
    }
    ret[num_blocks * 4] = '\0';
    return ret;
}

int main(int argc, char *argv[]) {
    static char *input = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
    static char *expected = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t";

    size_t length;
    uint8_t *b = hex2bin(input, &length);
    char *output = b64encode(b, length);
    printf("%s\n", output);
    assert(strcmp(output, expected) == 0);
}
