#include <stdint.h>
#include <stddef.h>

#define SHA1_HASH_SIZE 20
#define SHA1_BLOCK_SIZE 64

struct sha1_ctx {
    uint32_t H[5];
    uint8_t block[SHA1_BLOCK_SIZE];
};

void sha1_init(struct sha1_ctx *ctx);
void sha1_hash(struct sha1_ctx *ctx, const uint8_t *buf, size_t size, uint8_t *out_buf);
