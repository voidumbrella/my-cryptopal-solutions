#pragma once

#include <stddef.h>
#include <stdio.h>
#include <stdint.h>

uint8_t *hex2bin(const char *hex_string, size_t *out_length);
char *bin2hex(const uint8_t *b, const size_t bin_len);
void print_bin(const uint8_t *b, const size_t bin_len);

char *b64encode(const uint8_t *b, const size_t bin_len);
uint8_t *b64decode(const char *b64_string, size_t *out_length);

size_t pkcs7_pad_length(size_t orig_len, size_t block_size);
void pkcs7_pad(uint8_t *s, size_t len, size_t block_size);
int pkcs7_unpad(uint8_t *s, size_t len, size_t *out_size);

void fill_rand(uint8_t *dest, const size_t len);

char *read_ignoring_newlines(FILE *f);
