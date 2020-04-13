#pragma once

uint8_t *hex2bin(const char *hex_string, size_t *out_length);
char *bin2hex(const uint8_t *b, const size_t bin_len);
void print_bin(const uint8_t *b, const size_t bin_len);
char *b64encode(const uint8_t *b, const size_t bin_len);
uint8_t *b64decode(const char *b64_string, size_t *out_length);
char *read_ignoring_newlines(FILE *f);
