#include <stdio.h>
#include <string.h>

// Expected output:
// Admin, take your pass
// Welcome admin
//
// Condition:
// Cant use -z execstack
// Can't segfault, return 0

int is_admin = 0;

void win(void) {
  printf("Admin, take your pass\n");
  is_admin = 1;
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

  if (is_admin) {
    printf("Welcome admin\n");
  } else {
    printf("You imposter!\n");
  }
  return 0;
}
