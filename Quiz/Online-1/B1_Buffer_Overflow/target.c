#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

// ============================================================
// IMPORTANT: Replace <LAST_3_DIGITS_OF_YOUR_ID> below with
// the last 3 digits of your Student ID without any leading zeroes
// For example, if your ID is 2105023, use 23
// ============================================================
#define STUDENT_ID <LAST_3_DIGITS_OF_YOUR_ID>

#define BUF_SZ    (80 + STUDENT_ID)
#define READ_SZ   (BUF_SZ + 300)
#define TOKEN     (1000 + STUDENT_ID * 7)

void validate(int token) {
    printf("Validating token: %d\n", token);
    if (token == TOKEN) {
        printf("Token accepted! Identity verified.\n");
    } else {
        printf("Invalid token! Rejected.\n");
        exit(1);
    }
}

void vuln(char *str) {
    char buffer[BUF_SZ];
    strcpy(buffer, str);
}

int main() {
    char str[READ_SZ];
    FILE *badfile;

    badfile = fopen("badfile", "r");
    if (!badfile) {
        printf("Error: Cannot open badfile\n");
        return 1;
    }

    printf("Required TOKEN value: %d (0x%x)\n", TOKEN, TOKEN);
    fread(str, sizeof(char), READ_SZ, badfile);
    vuln(str);

    printf("Returned Properly\n");
    return 0;
}
