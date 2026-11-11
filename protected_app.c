/*
 * Q-SAFE bounded file-inspection example.
 * The original version intentionally overflowed a 64-byte stack buffer.
 * This replacement is a safe parser demonstration, not a malware detector.
 */
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv) {
    unsigned char buffer[4096];
    size_t total = 0;
    FILE *input;

    if (argc != 2) {
        fprintf(stderr, "Usage: %s FILE\n", argv[0]);
        return 2;
    }
    input = fopen(argv[1], "rb");
    if (input == NULL) {
        perror("fopen");
        return 1;
    }

    while (!feof(input) && total < sizeof(buffer)) {
        size_t count = fread(buffer + total, 1, sizeof(buffer) - total, input);
        total += count;
        if (ferror(input)) {
            perror("fread");
            fclose(input);
            return 1;
        }
        if (count == 0) break;
    }
    if (fclose(input) != 0) {
        perror("fclose");
        return 1;
    }
    printf("Read at most %zu bytes safely.\n", total);
    if (total == sizeof(buffer))
        puts("Input reached the inspection limit; remaining bytes were not read.");
    return 0;
}
