/*
 * Implement PKCS#7 padding
 */

#include <stdio.h>
#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

void pkcs7_pad(uint8_t *s, size_t len, size_t block_size) {
    uint8_t c = (len / block_size + 1) * block_size - len;
    s += len;
    for (size_t i = 0; i < c; ++i)
        *(s+i) = c;
}

int main() {
    uint8_t *buffer = malloc(20);

    memcpy(buffer, "YELLOW SUBMARINE", 16);
    pkcs7_pad(buffer, 16, 20);
    for (size_t i = 16; i < 20; ++i)
        assert(buffer[i] == '\x04');

    memcpy(buffer, "FOO", 16);
    pkcs7_pad(buffer, 3, 16);
    for (size_t i = 3; i < 16; ++i)
        assert(buffer[i] == '\x0d');

    pkcs7_pad(buffer, 3, 3);
    for (size_t i = 3; i < 6; ++i)
        assert(buffer[i] == '\x03');
}
