#include <stdint.h>
#include <stddef.h>

#define SHA1_HASH_SIZE 20
void sha1_hash(const uint8_t *buf, size_t size, uint8_t *out_buf);
