/*
 * Implement CTR, the stream cipher mode
 */

#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include "aes.h"
#include "utils.h"

int main() {
    char *encoded = "L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==";
    size_t size;
    uint8_t *buf = b64decode(encoded, &size);

    uint8_t *key = (uint8_t *)"YELLOW SUBMARINE";
    uint8_t *nonce = (uint8_t *)"\x00\x00\x00\x00\x00\x00\x00\x00";

    struct aes_ctx ctx;
    aes_ctx_init(&ctx, key);
    aes_ctx_set_nonce(&ctx, nonce);

    aes_128_ctr(&ctx, buf, size);
    printf("%.*s\n", (int)size, buf);
}
