/*
 * CBC padding oracle
 */

#include <assert.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include "aes.h"
#include "utils.h"

struct aes_ctx ctx;
uint8_t iv[16];

#define NUMTEXTS 10

int r = 0;
char *plaintexts[NUMTEXTS] = {
    "MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=",
    "MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=",
    "MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==",
    "MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==",
    "MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl",
    "MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==",
    "MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==",
    "MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=",
    "MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=",
    "MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93",
};

uint8_t *random_ciphertext(size_t *out_size, uint8_t *out_iv) {
    size_t size;
    uint8_t *plaintext = b64decode(plaintexts[r], &size);
    r = (r + 1) % NUMTEXTS; // supposed to be random but does it really matter
    size_t padded_size = pkcs7_pad_length(size, 16);
    *out_size = padded_size;

    uint8_t *buf = malloc(padded_size);
    memcpy(buf, plaintext, size);
    pkcs7_pad(buf, size, 16);

    aes_ctx_set_iv(&ctx, iv);
    aes_128_cbc_encrypt(&ctx, buf, padded_size);
    memcpy(out_iv, iv, 16);
    return buf;
}

bool validate(const uint8_t *buf, const uint8_t *iv, size_t size) {
    size_t foo;
    uint8_t *temp = malloc(size);
    memcpy(temp, buf, size);

    aes_ctx_set_iv(&ctx, iv);
    aes_128_cbc_decrypt(&ctx, temp, size);
    int res = pkcs7_unpad(temp, size, &foo) == 0? true: false;
    free(temp);
    return res;
}

void setup() {
    uint8_t key[16];
    fill_rand(key, 16);
    fill_rand(iv, 16);
    aes_ctx_init(&ctx, key);
    aes_ctx_set_iv(&ctx, iv);
}

void crack_block(const uint8_t *block, const uint8_t *iv, uint8_t *dest) {
    uint8_t guesses[16] = {0};
    uint8_t iv_copy[16];
    for (int i = 15; i >= 0;) {
        memcpy(iv_copy, iv, 16);

        uint8_t pad = 16 - i;
        for (int j = 15; j > i; --j)
            iv_copy[j] ^= guesses[j] ^ pad;

        // Start with the last guess; if everything went well this is zero
        for (uint8_t c = guesses[i];; ++c) {
            iv_copy[i] ^= c;
            bool padding_valid = validate(block, iv_copy, 16);
            iv_copy[i] ^= c;

            if (padding_valid) {
                // Guess seems to work, write down and move on
                guesses[i--] = c ^ pad;
                break;
            } else if (c == 255) {
                // Last guess was incorrect, go back to previous position and try a different byte
                ++guesses[++i];
                break;
            }
        }
    }
    memcpy(dest, guesses, 16);
}

int main() {
    setup();

    for (int i = 0; i < NUMTEXTS; ++i) {
        size_t size;
        uint8_t iv[16];
        uint8_t *ciphertext = random_ciphertext(&size, iv);

        size_t num_blocks = size / 16;
        uint8_t plaintext[size];
        for (size_t i = 0; i < num_blocks; ++i) {
            crack_block(ciphertext + i * 16,
                        i == 0? iv: ciphertext + (i - 1) * 16,
                        plaintext + i * 16);
        }
        pkcs7_unpad(plaintext, size, &size);
        printf("%.*s\n", (int)size, plaintext);
    }
}
