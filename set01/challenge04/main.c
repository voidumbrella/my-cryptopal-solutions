/*
 * Detect single-character XOR
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

double score_bin(const uint8_t *b, const size_t len) {
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
        case ' ': score += 12.50; break;
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

int main(int argc, char *argv[]) {
    FILE *f = fopen("input.txt", "r");
    assert(f);

    char *ciphertext;
    uint8_t *plaintext;
    double max_score = 0.;

    char line[BUFSIZ];
    size_t text_len;
    while (fgets(line, BUFSIZ, f)) {
        char *p;
        if ((p = strchr(line, '\n'))) {
            *p = '\0'; // strip newline
        }

        uint8_t *candidate = hex2bin(line, &text_len);

        for (int k = 0; k < 256; ++k) {
            uint8_t *test = malloc(text_len);
            memcpy(test, candidate, text_len);
            for (size_t i = 0; i < text_len; ++i) {
                test[i] ^= k;
            }
            double score = score_bin(test, text_len);
            if (score > max_score) {
                plaintext = test;
                max_score = score;
            } else {
                free(test);
            }
        }
    }
    printf("%.*s\n", (int)text_len, plaintext);
}
