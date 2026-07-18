#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Get the shell
// Expected output:
// Executing...
// $
// Conditions:
// Dont use NOPs

void win(const char *command) {
  printf("Executing...\n");
  system(command);
}

void foo(char *str) {
  char buffer[100];
  strcpy(buffer, str);
}

int main(int argc, char **argv) {
  char str[400];
  FILE *badfile;
  badfile = fopen("badfile", "r");
  fread(str, sizeof(char), 400, badfile);
  foo(str);

  printf("Returned Properly\n");
  return 0;
}
