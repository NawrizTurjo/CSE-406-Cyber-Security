#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

// ============================================================
// IMPORTANT: Replace <LAST_3_DIGITS_OF_YOUR_ID> below with
// the last 3 digits of your Student ID without leading zeroes.
// For example, if your ID is 2105085, use 85
// ============================================================
#define STUDENT_ID <LAST_3_DIGITS_OF_YOUR_ID>

#define BUF_SZ    (80 + STUDENT_ID)
#define READ_SZ   (BUF_SZ + 200)

unsigned int canary_seed;

void init_canary() {
    srand(STUDENT_ID);
    canary_seed = (unsigned int)rand();
    canary_seed |= 0x01010101;
}

void vuln(char *str) {
    char buffer[BUF_SZ];
    unsigned int canary;

    strcpy(buffer, str);

    if (canary != canary_seed) {
        printf("*** Canary has not been set! ***\n");
        exit(1);
    }
}

int main() {
    char str[READ_SZ];
    FILE *badfile;

    init_canary();

    badfile = fopen("badfile", "r");
    if (!badfile) {
        printf("Error: Cannot open badfile\n");
        return 1;
    }

    fread(str, sizeof(char), READ_SZ, badfile);
    fclose(badfile);
    vuln(str);

    printf("Returned Properly\n");
    return 0;
}
