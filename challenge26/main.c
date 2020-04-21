/*
 * CTR bitflipping
 */

#define _GNU_SOURCE

#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include "aes.h"
#include "utils.h"

#define PREFIX "comment1=cooking%20MCs;userdata="
#define PREFIX_SIZE (sizeof PREFIX - 1)
#define SUFFIX ";comment2=%20like%20a%20pound%20of%20bacon"
#define SUFFIX_SIZE (sizeof SUFFIX - 1)

struct aes_ctx ctx;

uint8_t *gen_comment(const char *s, size_t *out_size) {
    size_t original_size = strlen(s);
    size_t size = PREFIX_SIZE + original_size + SUFFIX_SIZE;
    *out_size = size;

    uint8_t *ret = malloc(size);
    memcpy(ret, PREFIX, PREFIX_SIZE);
    memcpy(ret + PREFIX_SIZE, s, original_size);
    memcpy(ret + PREFIX_SIZE + original_size, SUFFIX, SUFFIX_SIZE);
    for (size_t i = PREFIX_SIZE; i < PREFIX_SIZE + original_size; ++i)
        if (ret[i] == '=' || ret[i] == ';')
            ret[i] = '?';

    aes_128_ctr(&ctx, ret, size);
    return ret;
}

int authenticate(const uint8_t *s, size_t size) {
    uint8_t *buf = malloc(size);
    memcpy(buf, s, size);
    aes_128_ctr(&ctx, buf, size);

    int res = memmem(buf, size, ";admin=true;", 12)? 1: 0;
    free(buf);
    return res;
}

void setup() {
    uint8_t key[16], nonce[8];
    fill_rand(key, 16);
    fill_rand(nonce, 8);
    aes_ctx_init(&ctx, key);
    aes_ctx_set_nonce(&ctx, nonce);
}

int main() {
    setup();

    /*
     * 0               16              32    38
     * |               |               |     |
     * comment1=cooking%20MCs;userdata=AadminAtrue...
     *
     * If k is the byte from the keystream xored with 'A', then
     * ciphertext = 'A' ^ k
     * modified   = 'A' ^ k ^ 'A' ^ ';'
     *            = k ^ ';'
     * plaintext  = ';'
     *
     * Even easier than bitflipping CBC mode!
     */
    size_t size;
    uint8_t *foo = gen_comment("AadminAtrue", &size);
    foo[32] ^= 'A' ^ ';';
    foo[38] ^= 'A' ^ '=';
    assert(authenticate(foo, size) == 1);
    free(foo);
}
