/*
 * CBC bitflipping attacks
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
    size_t size = strlen(s);
    size_t total = PREFIX_SIZE + size + SUFFIX_SIZE;
    size_t padded_size = pkcs7_pad_length(total, 16);
    *out_size = padded_size;

    uint8_t *ret = malloc(padded_size);
    memcpy(ret, PREFIX, PREFIX_SIZE);
    memcpy(ret + PREFIX_SIZE, s, size);
    memcpy(ret + PREFIX_SIZE + size, SUFFIX, SUFFIX_SIZE);
    for (size_t i = PREFIX_SIZE; i < PREFIX_SIZE + size; ++i)
        if (ret[i] == '=' || ret[i] == ';')
            ret[i] = '?';
    pkcs7_pad(ret, total, 16);

    aes_128_cbc_encrypt(&ctx, ret, padded_size);
    return ret;
}

int authenticate(const uint8_t *s, size_t size) {
    uint8_t *buf = malloc(size);
    memcpy(buf, s, size);
    aes_128_cbc_decrypt(&ctx, buf, size);

    int res = memmem(buf, size, ";admin=true;", 12)? 1: 0;
    free(buf);
    return res;
}

void setup() {
    uint8_t key[16], iv[16];
    fill_rand(key, 16);
    fill_rand(iv, 16);
    aes_ctx_init(&ctx, key);
    aes_ctx_init(&ctx, iv);
}

int main() {
    setup();

    /* 
     * Block 1         Block 2         Block 3         Block 4
     *
     * 0               16              32    38   43
     * |               |               |               |
     * comment1=cooking%20MCs;userdata=@_____@____@____AadminBtrueA...
     *                                 AadminBtrueA
     *
     * xoring `block[3][0]` with `; ^ A` also xors `block[4][0]` with `; ^ A`
     * then `block[4][0] = A ^ (; ^ A) = ;`
     */
    size_t size;
    uint8_t *foo = gen_comment("@_____@____@____AadminEtrueA", &size);
    foo[32] ^= 'z';
    foo[38] ^= 'x';
    foo[43] ^= 'z';
    assert(authenticate(foo, size) == 1);
    free(foo);
}
