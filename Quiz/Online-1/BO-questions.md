A1:
```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// ============================================================
// IMPORTANT: Replace <LAST_3_DIGITS_OF_YOUR_ID> below with
// the last 3 digits of your Student ID without any leading zeroes
// For example, if your ID is 2105061, use 61
// ============================================================
#define STUDENT_ID 32

#define USERNAME_SZ  (60 + STUDENT_ID % 40)
#define PROFILE_SZ   64
#define ACCESS_SZ    32
#define READ_SZ      400
#define CANARY_VAL   (0xDEAD0000 + STUDENT_ID + 16)

char username[USERNAME_SZ];
int canary_guard;
char profile[PROFILE_SZ];
char access_code[ACCESS_SZ];

int main() {
    char str[READ_SZ];
    FILE *badfile;

    canary_guard = CANARY_VAL;

    badfile = fopen("badfile", "r");
    if (!badfile) {
        printf("Error: Cannot open badfile\n");
        return 1;
    }

    printf("Authenticating user...\n");

    if (fgets(str, READ_SZ, badfile)) {
        str[strcspn(str, "\n")] = '\0';
        strcpy(username, str);
    }

    if (fgets(str, READ_SZ, badfile)) {
        str[strcspn(str, "\n")] = '\0';
        strcpy(profile, str);
    }

    fclose(badfile);

    if (canary_guard != CANARY_VAL) {
        printf("Intrusion detected! Memory corruption guard triggered!\n");
        exit(1);
    }

    if (strncmp(username, "admin", 5) == 0 &&
        strncmp(access_code, "UNLOCK", 6) == 0) {
        printf("Access Granted - Welcome, Administrator!\n");
        system("/bin/sh");
    } else {
        printf("Authentication Failed!\n");
        if (strncmp(username, "admin", 5) != 0) {
            printf("  Reason: Invalid username\n");
        }
        if (strncmp(access_code, "UNLOCK", 6) != 0) {
            printf("  Reason: Invalid access code\n");
        }
    }

    return 0;
}

```
A2:
```c
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

```
B1:
```c
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

```
B2:
```c
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

```
C1:
```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// ============================================================
// IMPORTANT: Replace <LAST_3_DIGITS_OF_YOUR_ID> below with
// the last 3 digits of your Student ID without leading zeroes.
// For example, if your ID is 2105067, use 67
// ============================================================
#define STUDENT_ID 32

#define BUF_SZ    (100 + STUDENT_ID)
#define READ_SZ   (BUF_SZ + 300)

int process(char *str) {
    char buffer[BUF_SZ];

    strcpy(buffer, str);

    return 1;
}

int main(int argc, char **argv) {
    char str[READ_SZ];
    FILE *badfile;

    badfile = fopen("badfile", "r");
    if (!badfile) {
        printf("Error: Cannot open badfile\n");
        return 1;
    }

    fread(str, sizeof(char), READ_SZ, badfile);
    process(str);

    printf("Returned Properly\n");
    return 0;
}

```
C2:
```c
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

#define DATA_SZ   (24 + STUDENT_ID % 16)
#define READ_SZ   (DATA_SZ + 100)

typedef struct {
    char name[DATA_SZ];
} UserData;

typedef struct {
    void (*action)();
} Handler;

void safe_action() {
    printf("Normal operation complete.\n");
}

void secret_action() {
    printf("HACKED! Secret action triggered!\n");
    system("/bin/sh");
}

int main() {
    UserData *user;
    Handler *handler;
    FILE *badfile;

    user = malloc(sizeof(UserData));
    handler = malloc(sizeof(Handler));
    handler->action = safe_action;

    badfile = fopen("badfile", "r");
    if (!badfile) {
        printf("Error: Cannot open badfile\n");
        return 1;
    }

    fread(user->name, sizeof(char), READ_SZ, badfile);

    printf("Executing handler...\n");
    handler->action();

    return 0;
}
```
