/*
 * Byte-at-a-time ECB decryption (Simple)
 */

#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "aes.h"
#include "utils.h"

struct aes_ctx ctx;
uint8_t *unknown_string;
size_t unknown_len;

uint8_t *blackbox(const uint8_t *plaintext, const size_t len, size_t *out_len) {
    size_t total_len = unknown_len + len;
    size_t padded_len = pkcs7_pad_length(total_len, 16);
    *out_len = padded_len;

    uint8_t *buf = malloc(padded_len);
    memcpy(buf, plaintext, len);
    memcpy(buf + len, unknown_string, unknown_len);
    pkcs7_pad(buf, total_len, 16);

    aes_128_ecb_encrypt(&ctx, buf, padded_len);
    return buf;
}

int block_compare(const void *a, const void *b) {
    return memcmp((const char *)a, (const char *)b, 16);
}

int is_ecb(const uint8_t *ciphertext, const size_t len) {
    size_t nblocks = len / 16;

    qsort((void *)ciphertext, nblocks, 16, &block_compare);
    for (size_t i = 0; i < len - 16; i += 16) {
        if (memcmp(ciphertext + i, ciphertext + i + 16, 16) == 0) {
            return 1;
        }
    }
    return 0;
}

void setup_blackbox() {
    FILE *f = fopen("input.txt", "r");
    assert(f);
    char *encoded = read_ignoring_newlines(f);
    fclose(f);

    unknown_string = b64decode(encoded, &unknown_len);
    free(encoded);
    
    uint8_t key[16];
    fill_rand(key, 16);
    aes_ctx_init(&ctx, key);
}

int main() {
    setup_blackbox();

    /* Step 1: Discover block size of cipher */
    size_t block_size, len;
    {
        uint8_t buf[BUFSIZ];
        free(blackbox(NULL, 0, &len));
        for (size_t i = 0;; ++i) {
            size_t new_len;
            buf[i] = 'A';
            free(blackbox(buf, i, &new_len));
            if (len != new_len) {
                block_size = new_len - len;
                break;
            }
        }
    }
    assert(block_size == 16);

    /* Step 2: Make sure this is ECB */
    {
        char *buf = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        size_t len = 32, new_len;
        uint8_t *ciphertext = blackbox((uint8_t *)buf, len, &new_len);
        assert(is_ecb(ciphertext, new_len));
        free(ciphertext);
    }

    uint8_t buf[len];
    memset(buf, '\xfe', len);

    size_t foo;
    uint8_t last_block[block_size];
    for (size_t i = 0; i < len; ++i) {
        memmove(buf, buf + 1, len - 1);
        uint8_t *ciphertext = blackbox(buf, len - i - 1, &foo);
        memcpy(last_block, ciphertext + len - block_size, block_size);
        free(ciphertext);

        for (uint8_t c = 0;; ++c) {
            buf[len - 1] = c;
            uint8_t *ciphertext = blackbox(buf, len, &foo);
            if (memcmp(last_block, ciphertext + len - block_size, block_size) == 0) {
                free(ciphertext);
                break;
            }
            free(ciphertext);
            
            // Could not find the next byte, we probably reached the padding
            if (c == 255)
                goto end;
        }
    }

end:
    printf("%.*s", (int)len, buf);
    free(unknown_string);
}
