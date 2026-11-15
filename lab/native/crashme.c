/* Deliberately vulnerable LOCAL fixture. Build with AddressSanitizer. */
#include <stdio.h>
#include <string.h>

int main(void) {
    char input[4096];
    char destination[32];
    if (!fgets(input, sizeof input, stdin)) return 0;
    /* Lab-only flaw: copies without checking destination capacity. */
    strcpy(destination, input);
    printf("accepted %zu bytes\n", strlen(destination));
    return 0;
}

