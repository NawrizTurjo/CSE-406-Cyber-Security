#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

// ============================================================
// IMPORTANT: Replace <LAST_3_DIGITS_OF_YOUR_ID> below with
// the last 3 digits of your Student ID.
// For example, if your ID is 2105185, use 185
// ============================================================
#define STUDENT_ID 032

#define BUF_SZ      (60 + STUDENT_ID)
#define READ_SZ     (BUF_SZ + 200)
#define UNLOCK_CODE (0xA5A5A000 + STUDENT_ID)

void unlock(int code) {
    printf("Checking code: 0x%x\n", code);
    if (code == UNLOCK_CODE) {
        printf("Code accepted! Vault unlocked!\n");
    } else {
        printf("Wrong code! Access denied!\n");
        exit(1);
    }
}

void get_reward() {
    printf("Treasure claimed! You win!\n");
    system("/bin/sh");
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

    fread(str, sizeof(char), READ_SZ, badfile);
    vuln(str);

    printf("Returned Properly\n");
    return 0;
}
