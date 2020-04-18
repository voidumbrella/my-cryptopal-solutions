#include <stdint.h>
#include <stddef.h>

#define NUM_ROUNDS 10

struct aes_ctx {
    uint8_t round_keys[NUM_ROUNDS+1][16];
    uint8_t iv[16]; // used for CBC mode
    uint8_t nonce[8]; // used for CTR mode
};

void aes_ctx_init(struct aes_ctx *ctx, const uint8_t *key);
void aes_ctx_set_iv(struct aes_ctx *ctx, const uint8_t *iv);
void aes_ctx_set_nonce(struct aes_ctx *ctx, const uint8_t *nonce);

void aes_128_ecb_encrypt(struct aes_ctx *ctx, uint8_t *buf, size_t text_len);
void aes_128_ecb_decrypt(struct aes_ctx *ctx, uint8_t *buf, size_t text_len);
void aes_128_cbc_encrypt(struct aes_ctx *ctx, uint8_t *buf, size_t text_len);
void aes_128_cbc_decrypt(struct aes_ctx *ctx, uint8_t *buf, size_t text_len);
void aes_128_ctr(struct aes_ctx *ctx, uint8_t *buf, size_t text_len);
