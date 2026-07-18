#include <stdio.h>
#include <string.h>

// Get shell access
//
//
// Conditions:
// cant use NOPS

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
