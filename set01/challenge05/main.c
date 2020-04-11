/*
 * Implement repeating-key XOR
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
    static char *plaintext =
        "Burning 'em, if you ain't quick and nimble\n"
        "I go crazy when I hear a cymbal";
    static char *expected =
        "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272"
        "a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f";
    static char *key = "ICE";

    size_t text_len = strlen(plaintext);
    size_t key_len = 3;

    uint8_t *ciphertext = malloc(text_len);
    for (size_t i = 0; i < text_len; ++i) {
        ciphertext[i] = plaintext[i] ^ key[i % key_len];
    }

    char *output = bin2hex(ciphertext, text_len);
    assert(strcmp(output, expected) == 0);
}
