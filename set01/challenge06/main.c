/*
 * Break repeating key XOR
 */

#include <assert.h>
#include <ctype.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>

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

int hamming_distance(const uint8_t *a, const uint8_t *b, size_t length) {
    int distance = 0;
    for (size_t i = 0; i < length; ++i) {
        uint8_t n = a[i] ^ b[i];
        while (n) {
            n &= n - 1;
            ++distance;
        }
    }
    return distance;
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

char *read_ignoring_newlines(FILE *f) {
    char *s;
    // Read from file while ignoring newlines
    size_t length, block_size = 1024, capacity = BUFSIZ;
    s = malloc(capacity);
    char *nl, *p = s;
    while (fgets(p, block_size, f)) {
        // Why can't fgets return a pointer to the last character?
        // What is the point of returning back the pointer that we already have?
        if ((nl = strchr(p, '\n'))) { p = nl; *p = '\0'; }
        else { p = strchr(p, '\0'); }

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
    assert(hamming_distance((uint8_t *)"this is a test", (uint8_t *)"wokka wokka!!!", 14) == 37);

    FILE *f = fopen("input.txt", "r");
    assert(f);
    char *encoded = read_ignoring_newlines(f);

    size_t text_len;
    uint8_t *ciphertext = b64decode(encoded, &text_len);
    free(encoded);

    size_t key_size;
    double min_dist = 1.0/0.0;
    for (int trial_key = 2; trial_key < 40; ++trial_key) {
        double sum_dists = 0.;
        for (int i = 0; i < 10; ++i) {
            sum_dists += hamming_distance(ciphertext + i * trial_key,
                                          ciphertext + (i + 1) * trial_key,
                                          trial_key);
        }
        double avg_dist = sum_dists / trial_key / 10;
        if (avg_dist < min_dist) {
            min_dist = avg_dist;
            key_size = trial_key;
        }
    }

    char key[key_size];
    uint8_t *block = malloc(text_len / key_size);
    for (size_t i = 0; i < key_size; ++i) {
        for (size_t j = 0; j < text_len / key_size; ++j) {
            block[j] = ciphertext[i + j * key_size];
        }
        key[i] = break_single_key_xor(block, text_len / key_size);
    }

    printf("=============Decrypted using the key '%.*s'=============\n", (int)key_size, key);
    for (size_t i = 0; i < text_len; ++i) {
        putchar(ciphertext[i] ^ key[i % key_size]);
    }
    free(ciphertext);
}
