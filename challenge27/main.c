/*
 * Recover the key from CBC with IV=Key
 */

#define _GNU_SOURCE

#include <assert.h>
#include <ctype.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include "aes.h"
#include "utils.h"

struct aes_ctx ctx;

uint8_t *encrypt(const char *s, size_t *out_size) {
    size_t size = strlen(s);
    size_t padded_size = pkcs7_pad_length(size, 16);

    uint8_t *ret = malloc(padded_size);
    memcpy(ret, s, size);
    pkcs7_pad(ret, size, 16);

    aes_128_cbc_encrypt(&ctx, ret, padded_size);

    *out_size = padded_size;
    return ret;
}

/*
 * Supposed to return an error message containing the plaintext
 * (mimicking poorly configured systems)
 * but I just decrypt the input buffer
 */
bool validate_ascii(uint8_t *s, size_t size) {
    aes_128_cbc_decrypt(&ctx, s, size);
    for (size_t i = 0; i < size; ++i) {
        if (!isascii(s[i]))
            return false;
    }
    return true;
}

void setup() {
    uint8_t key[16];
    fill_rand(key, 16);
    puts("The secret key is:");
    print_bin(key, 16);
    aes_ctx_init(&ctx, key);
    aes_ctx_set_iv(&ctx, key);
}

int main() {
    setup();

    /*
     * Why does this work? If d is the decryption function,
     *
     * P1 = d(C1) ^ IV
     * P3 = d(C1) ^ 0 = d(C1)
     * so P1 ^ P3 = IV, but IV = key!
     *
     * In fact, we only need two blocks of ciphertext;
     * if we copy C1 into C2, then
     *
     * P1 = d(C1) ^ IV
     * P2 = d(C1) ^ C1
     * P1 ^ P2 = IV ^ C1
     *
     * and we know what C1 is, so IV (and the key) can be recovered.
     */
    size_t size;
    uint8_t *ciphertext = encrypt("@@@@@@@@@@@@@@@|AAAAAAAAAAAAAAA|BBBBBBBBBBBBBBB|", &size);
    memset(ciphertext + 16, 0, 16);
    memcpy(ciphertext + 32, ciphertext, 16);
    if (!validate_ascii(ciphertext, size)) {
        uint8_t key[16];
        for (size_t i = 0; i < 16; ++i) {
            key[i] = ciphertext[i] ^ ciphertext[32 + i];
        }
        puts("The recovered key is:");
        print_bin(key, 16);
    }
}
