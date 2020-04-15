/*
 * Byte-at-a-time ECB decryption (Harder)
 */

#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

#include "aes.h"
#include "utils.h"

struct aes_ctx ctx;
uint8_t secret_prefix[16];
size_t secret_prefix_size;
uint8_t *unknown_string;
size_t unknown_size;

uint8_t *blackbox(const uint8_t *plaintext, const size_t size, size_t *out_size) {
    size_t total_size = secret_prefix_size + unknown_size + size;
    size_t padded_size = pkcs7_pad_length(total_size, 16);
    *out_size = padded_size;

    uint8_t *buf = malloc(padded_size);
    memcpy(buf, secret_prefix, secret_prefix_size);
    memcpy(buf + secret_prefix_size, plaintext, size);
    memcpy(buf + secret_prefix_size + size, unknown_string, unknown_size);
    pkcs7_pad(buf, total_size, 16);

    aes_128_ecb_encrypt(&ctx, buf, padded_size);
    return buf;
}

int block_compare(const void *a, const void *b) {
    return memcmp((const char *)a, (const char *)b, 16);
}

int is_ecb(const uint8_t *ciphertext, const size_t size) {
    size_t nblocks = size / 16;

    qsort((void *)ciphertext, nblocks, 16, &block_compare);
    for (size_t i = 0; i < size - 16; i += 16) {
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

    secret_prefix_size = 5 + rand() % 6;
    fill_rand(secret_prefix, secret_prefix_size);

    unknown_string = b64decode(encoded, &unknown_size);
    free(encoded);

    uint8_t key[16];
    fill_rand(key, 16);
    aes_ctx_init(&ctx, key);

    fclose(f);
}

int main() {
    srand(time(NULL));
    setup_blackbox();

    /*
     * If block_size = 5,
     *
     * PPPMM MMM
     * PPPAM MMMM
     * PPPAA MMMMM   < first block is same
     * PPPAA AMMMM M <
     *
     * Then do the same thing as before:
     * PPPAA AAAAA MMMMM
     * PPPAA AAAAB MMMMM ...
     */
    size_t block_size = 16, size, alignment;
    {
        uint8_t buf[BUFSIZ];
        uint8_t first_block[block_size];
        free(blackbox(NULL, 0, &size));
        for (size_t i = 0;; ++i) {
            size_t new_size;
            buf[i] = 'A';
            uint8_t *curr = blackbox(buf, i, &new_size);
            if (memcmp(first_block, curr, 16) == 0) {
                free(curr);
                alignment = i - 1;
                break;
            }
            memcpy(first_block, curr, 16);
            free(curr);
        }
    }

    size_t buf_size = size + alignment;
    uint8_t buf[buf_size];
    memset(buf, '\xfe', buf_size);

    size_t foo;
    uint8_t last_block[block_size];
    for (size_t i = 0; i < buf_size; ++i) {
        memmove(buf, buf + 1, buf_size - 1);
        uint8_t *ciphertext = blackbox(buf, buf_size - i - 1, &foo);
        memcpy(last_block, ciphertext + buf_size - block_size, block_size);
        free(ciphertext);

        for (uint8_t c = 0;; ++c) {
            buf[buf_size - 1] = c;
            uint8_t *ciphertext = blackbox(buf, buf_size, &foo);
            if (memcmp(last_block, ciphertext + buf_size - block_size, block_size) == 0) {
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
    printf("%.*s", (int)size, buf + alignment);
    free(unknown_string);
}
