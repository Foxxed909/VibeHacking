/*
 * EXPLOITLAB: intentionally vulnerable, LOCAL-ONLY sanitizer exercise.
 * Build/run only in an isolated training environment.
 * No shellcode, persistence, networking or exploit delivery.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(__GNUC__) || defined(__clang__)
__attribute__((noinline))
#endif
static void parse_label(const char *input) {
    char label[32];
    strcpy(label, input); /* INTENTIONALLY UNSAFE: observe ASan diagnostics */
    printf("Parsed label (%zu bytes)\n", strlen(label));
}

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "Usage: crash_demo LABEL\n");
        return 64;
    }
    parse_label(argv[1]);
    return 0;
}
