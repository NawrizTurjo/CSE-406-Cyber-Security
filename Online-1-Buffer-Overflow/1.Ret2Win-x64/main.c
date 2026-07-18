#include <stdio.h>
#include <string.h>

// Expected output:
// Congratulations! You won
//
// Conditions:
// Can't use -m32, -z execstack

void win(void) { printf("Congratulations! You won\n"); }

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
