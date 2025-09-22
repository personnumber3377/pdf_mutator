

#include <stdio.h>
#include <stdlib.h>

#define CRASH_LENGTH 1337  // change this to your magic length

int main(void) {
    char buffer[65536];  // up to 64 KB input
    size_t total = 0;

    // read from stdin until EOF or buffer full
    size_t n;
    while ((n = fread(buffer + total, 1, sizeof(buffer) - total, stdin)) > 0) {
        total += n;
    }

    if (total == CRASH_LENGTH) {
        fprintf(stderr, "Crash triggered! Input length = %zu\n", total);
        // Cause a real crash for fuzzers (segfault)
        *(volatile int *)0 = 0;  // write to NULL
    }

    printf("Read %zu bytes (no crash)\n", total);
    return 0;
}

