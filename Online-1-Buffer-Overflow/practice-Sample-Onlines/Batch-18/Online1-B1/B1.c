#include <stdio.h> 
#include <stdlib.h>
#include <string.h>
#include <stddef.h>


#define PARAM_1 20
#define PARAM_2 30
#define PARAM_3 300

typedef struct {
        char name[PARAM_1];
} Temp;

typedef struct {
        void (*fp)();
} Callback;


void hack() {
        printf("Hackerman is in action!\n");
        printf("Be scared! Be very Scared!\n");
        execve("/bin/sh", NULL, NULL);
}

void random_print() {
        printf("Normally Executed!\n");
}

void overflow_in_action(char * str){
        Temp* data;
        Callback* ptr;
        char buffer[PARAM_3+PARAM_2];

        data = malloc(sizeof(Temp));
        ptr = malloc(sizeof(Callback));

        strcpy(buffer, str); // overflow hobena
        ptr->fp = random_print;

        strcpy(data->name, str); // overflow hobe
        ptr->fp();
}

int main() {
        printf("In main function\n");
        char str[PARAM_3];
        FILE *badfile;

        badfile = fopen("badfile", "r");
        fread(str, sizeof(char), PARAM_3, badfile);
        overflow_in_action(str);

        return 0;
}

