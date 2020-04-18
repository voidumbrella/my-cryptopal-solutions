/*
 * Break fixed-nonce CTR statistically
 */

#include <assert.h>
#include <ctype.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "aes.h"
#include "utils.h"

#define NUM_STRINGS 40
static const char *strings[NUM_STRINGS] = {
    "SSBoYXZlIG1ldCB0aGVtIGF0IGNsb3NlIG9mIGRheQ==",
    "Q29taW5nIHdpdGggdml2aWQgZmFjZXM=",
    "RnJvbSBjb3VudGVyIG9yIGRlc2sgYW1vbmcgZ3JleQ==",
    "RWlnaHRlZW50aC1jZW50dXJ5IGhvdXNlcy4=",
    "SSBoYXZlIHBhc3NlZCB3aXRoIGEgbm9kIG9mIHRoZSBoZWFk",
    "T3IgcG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==",
    "T3IgaGF2ZSBsaW5nZXJlZCBhd2hpbGUgYW5kIHNhaWQ=",
    "UG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==",
    "QW5kIHRob3VnaHQgYmVmb3JlIEkgaGFkIGRvbmU=",
    "T2YgYSBtb2NraW5nIHRhbGUgb3IgYSBnaWJl",
    "VG8gcGxlYXNlIGEgY29tcGFuaW9u",
    "QXJvdW5kIHRoZSBmaXJlIGF0IHRoZSBjbHViLA==",
    "QmVpbmcgY2VydGFpbiB0aGF0IHRoZXkgYW5kIEk=",
    "QnV0IGxpdmVkIHdoZXJlIG1vdGxleSBpcyB3b3JuOg==",
    "QWxsIGNoYW5nZWQsIGNoYW5nZWQgdXR0ZXJseTo=",
    "QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4=",
    "VGhhdCB3b21hbidzIGRheXMgd2VyZSBzcGVudA==",
    "SW4gaWdub3JhbnQgZ29vZCB3aWxsLA==",
    "SGVyIG5pZ2h0cyBpbiBhcmd1bWVudA==",
    "VW50aWwgaGVyIHZvaWNlIGdyZXcgc2hyaWxsLg==",
    "V2hhdCB2b2ljZSBtb3JlIHN3ZWV0IHRoYW4gaGVycw==",
    "V2hlbiB5b3VuZyBhbmQgYmVhdXRpZnVsLA==",
    "U2hlIHJvZGUgdG8gaGFycmllcnM/",
    "VGhpcyBtYW4gaGFkIGtlcHQgYSBzY2hvb2w=",
    "QW5kIHJvZGUgb3VyIHdpbmdlZCBob3JzZS4=",
    "VGhpcyBvdGhlciBoaXMgaGVscGVyIGFuZCBmcmllbmQ=",
    "V2FzIGNvbWluZyBpbnRvIGhpcyBmb3JjZTs=",
    "SGUgbWlnaHQgaGF2ZSB3b24gZmFtZSBpbiB0aGUgZW5kLA==",
    "U28gc2Vuc2l0aXZlIGhpcyBuYXR1cmUgc2VlbWVkLA==",
    "U28gZGFyaW5nIGFuZCBzd2VldCBoaXMgdGhvdWdodC4=",
    "VGhpcyBvdGhlciBtYW4gSSBoYWQgZHJlYW1lZA==",
    "QSBkcnVua2VuLCB2YWluLWdsb3Jpb3VzIGxvdXQu",
    "SGUgaGFkIGRvbmUgbW9zdCBiaXR0ZXIgd3Jvbmc=",
    "VG8gc29tZSB3aG8gYXJlIG5lYXIgbXkgaGVhcnQs",
    "WWV0IEkgbnVtYmVyIGhpbSBpbiB0aGUgc29uZzs=",
    "SGUsIHRvbywgaGFzIHJlc2lnbmVkIGhpcyBwYXJ0",
    "SW4gdGhlIGNhc3VhbCBjb21lZHk7",
    "SGUsIHRvbywgaGFzIGJlZW4gY2hhbmdlZCBpbiBoaXMgdHVybiw=",
    "VHJhbnNmb3JtZWQgdXR0ZXJseTo=",
    "QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4=",
};

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

int main() {
    /*
     * The decryption gets less accurate at the end of longer strings,
     * because the sample becomes too short.
     *
     * To improve this a better frequency analysis method would be needed..?
     */
    uint8_t key[16];
    uint8_t nonce[8];
    fill_rand(key, 16);
    memset(nonce, 0, 8);

    struct aes_ctx ctx;
    aes_ctx_init(&ctx, key);
    aes_ctx_set_nonce(&ctx, nonce);

    size_t keystream_size = 0;
    uint8_t *ciphertexts[NUM_STRINGS];
    size_t sizes[NUM_STRINGS];
    for (size_t i = 0; i < NUM_STRINGS; ++i) {
        ciphertexts[i] = b64decode(strings[i], &sizes[i]);
        aes_128_ctr(&ctx, ciphertexts[i], sizes[i]);
        if (sizes[i] > keystream_size)
            keystream_size = sizes[i];
    }
    
    size_t keystream[keystream_size];

    uint8_t *block = malloc(NUM_STRINGS);
    for (size_t i = 0; i < keystream_size; ++i) {
        size_t block_size = 0;
        for (size_t j = 0; j < NUM_STRINGS; ++j) {
            if (i < sizes[j]) {
                block[block_size++] = ciphertexts[j][i];
            }
        }
        keystream[i] = break_single_key_xor(block, block_size);
    }

    for (size_t i = 0; i < NUM_STRINGS; ++i) {
        for (size_t j = 0; j < sizes[i]; ++j) {
            char c = keystream[j] ^ ciphertexts[i][j];
            putchar(isprint(c)? c: '_');
        }
        putchar('\n');
    }
}
