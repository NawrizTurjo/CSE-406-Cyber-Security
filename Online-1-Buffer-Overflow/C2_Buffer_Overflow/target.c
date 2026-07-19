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