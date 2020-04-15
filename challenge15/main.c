/*
 * PKCS#7 padding validation
 */

#include <assert.h>
#include <string.h>

#include "utils.h"

int main() {
    uint8_t buf[32];
    size_t len;

    memcpy(buf, "ICE ICE BABY\x04\x04\x04\x04", 16);
    assert(pkcs7_unpad(buf, 16, &len) == 0);
    assert(len == 12);

    memcpy(buf, "@^@^@^@^@^@^@^@^ICE ICE BABY\x04\x04\x04\x04", 32);
    assert(pkcs7_unpad(buf, 32, &len) == 0);
    assert(len == 28);

    memset(buf, 16, 16);
    assert(pkcs7_unpad(buf, 16, &len) == 0);
    assert(len == 0);

    memcpy(buf, "ICE ICE BABY\x05\x05\x05\x05", 16);
    assert(pkcs7_unpad(buf, 16, &len) != 0);

    memcpy(buf, "ICE ICE BABY\x01\x02\x03\x04", 16);
    assert(pkcs7_unpad(buf, 16, &len) != 0);

    memset(buf, '\xff', 16);
    assert(pkcs7_unpad(buf, 16, &len) != 0);

    puts("Success!");
}
