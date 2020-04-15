#include <assert.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>

uint8_t *hex2bin(const char *hex_string, size_t *out_length) {
    size_t hex_len = strlen(hex_string);
    assert(hex_len % 2 == 0);

    size_t bin_len = hex_len / 2;
    uint8_t *ret = calloc(1, bin_len);

    for (size_t i = 0; i < hex_len; ++i) {
        char c = hex_string[i];
        if ('0' <= c && c <= '9')
            ret[i/2] += (c - '0') * (i % 2? 1: 16);
        else if ('A' <= c && c <= 'F')
            ret[i/2] += (c - 'A' + 10) * (i % 2? 1: 16);
        else if ('a' <= c && c <= 'f')
            ret[i/2] += (c - 'a' + 10) * (i % 2? 1: 16);
        else {
            fprintf(stderr, "invalid character in hexstring: %c", c);
            abort();
        }
    }

    *out_length = bin_len;
    return ret;
}

char *bin2hex(const uint8_t *b, const size_t bin_len) {
    char *ret = malloc(bin_len * 2 + 1);
    for (size_t i = 0; i < bin_len; ++i) {
        char hi = b[i] >> 4, lo = b[i] & 0xF;
        ret[i*2] = hi + (hi < 10? '0': 'a' - 10);
        ret[i*2+1] = lo + (lo < 10? '0': 'a' - 10);
    }
    ret[bin_len * 2] = '\0';
    return ret;
}

void print_bin(const uint8_t *b, const size_t bin_len) {
    for (size_t i = 0; i < bin_len; ++i) {
        printf("%02x", b[i]);
    }
    putchar('\n');
}

char *b64encode(const uint8_t *b, const size_t bin_len) {
    static char table[64] = {
        'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
        'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
        'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
        'w', 'x', 'y', 'z', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '+', '/',
    };
    size_t num_blocks = bin_len / 3 + (bin_len % 3? 1: 0);
    char *ret = malloc(num_blocks * 4 + 1);
    for (size_t i = 0; i < num_blocks; ++i) {
        const uint8_t *p = &b[i*3];
        char *r = &ret[i*4];

        r[0] = table[(p[0] & 0xFC) >> 2];
        if (i*3+1 >= bin_len) {
            r[1] = table[(p[0] & 0x03) << 4];
            r[2] = r[3] = '=';
        } else if (i*3+2 >= bin_len) {
            r[1] = table[(p[0] & 0x03) << 4 | p[1] >> 4];
            r[2] = table[(p[1] & 0x0F) << 2];
            r[3] = '=';
        } else {
            r[1] = table[(p[0] & 0x03) << 4 | p[1] >> 4];
            r[2] = table[(p[1] & 0x0F) << 2 | p[2] >> 6];
            r[3] = table[p[2] & 0x3F];
        }
    }
    ret[num_blocks * 4] = '\0';
    return ret;
}

static uint8_t b64index(const char c) {
    if ('A' <= c && c <= 'Z') { return c - 'A'; }
    else if ('a' <= c && c <= 'z') { return c - 'a' + 26; }
    else if ('0' <= c && c <= '9') { return c - '0' + 52; }
    else if (c == '+') { return 62; }
    else if (c == '/') { return 63; }
    else { fprintf(stderr, "Base64 string contains invalid character '0x%02X'\n", c); abort(); }
}

uint8_t *b64decode(const char *b64_string, size_t *out_length) {
    size_t b64_len = strlen(b64_string);
    assert(b64_len % 4 == 0);
    size_t num_blocks = b64_len / 4, length = num_blocks * 3;

    uint8_t *ret = malloc(length);
    for (size_t i = 0; i < num_blocks; ++i) {
        const char *p = &b64_string[i*4];
        uint8_t *r = &ret[i*3];

        assert(p[0] != '=' && p[1] != '=');
        r[0] = b64index(p[0]) << 2 | b64index(p[1]) >> 4;
        if (p[2] == '=') {
            assert(p[3] == '=' && p[4] == '\0');
            r[1] = '\0';
            length -= 2;
            break;
        }
        r[1] = (b64index(p[1]) & 0x0F) << 4 | (b64index(p[2]) >> 2);
        if (p[3] == '=') {
            assert(p[4] == '\0');
            r[2] = '\0';
            length -= 1;
            break;
        }
        r[2] = (b64index(p[2]) & 0x03) << 6 | (b64index(p[3]) & 0x3F);
    }
    *out_length = length;
    return ret;
}

char *read_ignoring_newlines(FILE *f) {
    char *s;
    // Read from file while ignoring newlines
    size_t length, block_size = 1024, capacity = BUFSIZ;
    s = malloc(capacity);
    char *nl, *p = s;
    while (fgets(p, block_size, f)) {
        p += strcspn(p, "\n");
        *p = '\0';

        length = p - s;
        if (length + block_size >= capacity) {
            capacity *= 2;
            s = realloc(s, capacity);
            p = s + length;
        }
    }
    return s;
}

size_t pkcs7_pad_length(size_t orig_len, size_t block_size) {
    return block_size * (orig_len / 16 + 1);
}

void pkcs7_pad(uint8_t *s, size_t len, size_t block_size) {
    uint8_t c = (len / block_size + 1) * block_size - len;
    s += len;
    for (size_t i = 0; i < c; ++i)
        *(s+i) = c;
}

int pkcs7_unpad(uint8_t *s, size_t len, size_t *out_size) {
    uint8_t pad = s[len - 1];
    if (pad > len)
        return -1;

    for (size_t i = 0; i < pad; ++i)
        if (s[len - 1 - i] != pad)
            return -1;

    *out_size = len - pad;
    return 0;
}

void fill_rand(uint8_t *dest, const size_t len) {
    FILE *rand_source = fopen("/dev/urandom", "r");
    assert(rand_source);
    assert(fread(dest, 1, len, rand_source) == len);
    fclose(rand_source);
}
