/*
 * Detect AES in ECB mode
 */

#include <string.h>
#include <stdio.h>
#include <stdlib.h>

int block_compare(const void *a, const void *b) {
    return strncmp((const char *)a, (const char *)b, 16);
}

int main() {
    FILE *f = fopen("input.txt", "r");
    char line[BUFSIZ], temp[BUFSIZ];
    size_t nblocks = 0;
    while (fgets(line, BUFSIZ, f)) {
        line[strcspn(line, "\n")] = '\0';
        strcpy(temp, line);

        if (!nblocks) {
            nblocks = strlen(line) / 16; // assuming each line has same length
        }

        qsort((void *)temp, nblocks, 16, &block_compare);
        for (size_t i = 0; temp[i]; i += 16) {
            if (strncmp(temp + i, temp + i + 16, 16) == 0) {
                printf("Detected ECB mode:\n%s\n", line);
                break;
            }
        }
    }
}
