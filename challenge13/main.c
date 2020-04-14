/*
 * ECB cut-and-paste
 */

#define _GNU_SOURCE

#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "aes.h"
#include "utils.h"

struct aes_ctx ctx;

int is_admin(uint8_t *profile, size_t len) {
    aes_128_ecb_decrypt(&ctx, profile, len);
    assert(pkcs7_unpad(profile, len, 16, &len) == 0);
    return memmem(profile, len, (uint8_t *)"&role=admin", 10)? 1: 0;
}

char *profile_for(const char *email) {
    size_t len = strlen(email);
    char *escaped = malloc(len + 1);
    strcpy(escaped, email);
    for (size_t i = 0; i < len; ++i)
        if (escaped[i] == '=' || escaped[i] == '&')
            escaped[i] = '?';
    char *res = malloc(24 + len);;
    sprintf(res, "email=%s&uid=10&role=user", escaped);
    free(escaped);
    return res;
}

uint8_t *encrypted_profile(const char *email, size_t *out_len) {
    char *profile = profile_for(email);
    size_t profile_len = strlen(profile);
    size_t padded_len = pkcs7_pad_length(profile_len, 16);
    *out_len = padded_len;
    uint8_t *buf = malloc(padded_len);
    memcpy(buf, profile, profile_len);
    free(profile);
    pkcs7_pad(buf, profile_len, 16);
    aes_128_ecb_encrypt(&ctx, buf, padded_len);

    return buf;
}       

int main() {
    uint8_t key[16];
    fill_rand(key, 16);
    aes_ctx_init(&ctx, key);

    {
        size_t len;
        uint8_t *profile = encrypted_profile("hacker@gmail.com&role=admin", &len);
        assert(!is_admin(profile, len));
        free(profile);
    }

    size_t len;
    // 1               2               3
    // 0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF
    //       |         '               ' |
    // email=void@mail.admin  (pad)    com&uid=10&role=
    uint8_t *profile = encrypted_profile("void@mail." "admin\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b" "com", &len);
    uint8_t buf[48]; 
    memcpy(buf, profile, 16); // email=void@mail.
    memcpy(buf + 16, profile + 32, 16); // email=void@mail.com%uid=10%role=
    memcpy(buf + 32, profile + 16, 16); // email=void@mail.com%uid=10%role=admin (pad)

    assert(is_admin(buf, 48));
    puts("Success!");
}
