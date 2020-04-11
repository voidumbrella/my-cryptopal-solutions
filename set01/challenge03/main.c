/*
 * Single-byte XOR cipher
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

char *bin2hex(const uint8_t *b, const size_t len) {
    char *ret = malloc(len * 2 + 1);
    for (size_t i = 0; i < len; ++i) {
        char hi = b[i] >> 4, lo = b[i] & 0xF;
        ret[i*2] = hi + (hi < 10? '0': 'a' - 10);
        ret[i*2+1] = lo + (lo < 10? '0': 'a' - 10);
    }
    ret[len * 2] = '\0';
    return ret;
}

double score_text(const uint8_t *b, const size_t len) {
    double score = 0;
    /* Basic English frequency analysis with data from somewhere */
    for (size_t i = 0; i < len; ++i) {
        switch (tolower(b[i])) {
        case 'a': score +=  8.55; break;
        case 'b': score +=  1.60; break;
        case 'c': score +=  3.16; break;
        case 'd': score +=  3.87; break;
        case 'e': score += 12.10; break;
        case 'f': score +=  2.18; break;
        case 'g': score +=  2.09; break;
        case 'h': score +=  4.96; break;
        case 'i': score +=  7.33; break;
        case 'j': score +=  0.22; break;
        case 'k': score +=  0.81; break;
        case 'l': score +=  4.21; break;
        case 'm': score +=  2.53; break;
        case 'n': score +=  7.17; break;
        case 'o': score +=  7.47; break;
        case 'p': score +=  2.07; break;
        case 'q': score +=  0.10; break;
        case 'r': score +=  6.33; break;
        case 's': score +=  6.73; break;
        case 't': score +=  8.94; break;
        case 'u': score +=  2.68; break;
        case 'v': score +=  1.06; break;
        case 'w': score +=  1.83; break;
        case 'x': score +=  0.19; break;
        case 'y': score +=  1.72; break;
        case 'z': score +=  0.11; break;
        case ' ': score +=  0.50; break;
        case '.': score +=  6.50; break;
        case ',': score +=  6.10; break;
        case '"': score +=  2.67; break;
        case '\'': score += 2.43; break;
        case '?': score +=  0.56; break;
        case '!': score +=  0.43; break;
        case ':': score +=  0.33; break;
        case ';': score +=  0.33; break;
        default: score -= 1.5;
        }
    }
    return score;
}

uint8_t break_single_key_xor(uint8_t *ciphertext, size_t length) {
    double max_score = 0.;
    uint8_t key;
    for (int k = 0; k < 256; ++k) {
        for (size_t i = 0; i < length; ++i) { ciphertext[i] ^= k; }
        double score = score_text(ciphertext, length);
        if (score > max_score) {
            max_score = score;
            key = k;
        }
        for (size_t i = 0; i < length; ++i) { ciphertext[i] ^= k; }
    }
    return key;
}

int main(int argc, char *argv[]) {
    static char *input = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";

    size_t length;
    uint8_t *ciphertext = hex2bin(input, &length);

    uint8_t key = break_single_key_xor(ciphertext, length);
    uint8_t *plaintext = malloc(length);
    for (size_t i = 0; i < length; ++i) {
        plaintext[i] = ciphertext[i] ^ key;
    }
    printf("Decoded \"%.*s\" with \"%c\" as the key\n", (int)length, plaintext, key);
}
