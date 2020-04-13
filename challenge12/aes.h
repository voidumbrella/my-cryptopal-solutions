#include <stdint.h>
#include <stddef.h>

void aes_128_ecb_encrypt(uint8_t *plaintext, size_t text_len, const uint8_t *key);
void aes_128_ecb_decrypt(uint8_t *ciphertext, size_t text_len, const uint8_t *key);
void aes_128_cbc_encrypt(uint8_t *plaintext, size_t text_len, const uint8_t *key, const uint8_t *iv);
void aes_128_cbc_decrypt(uint8_t *ciphertext, size_t text_len, const uint8_t *key, const uint8_t *iv);
