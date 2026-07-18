#include <stdio.h>
#include <string.h>

// Expected output:
// Welcome admin
//
// Conditions:
// cant use -m32, -z execstack
// No segfault, should return 0

char username[100];
char password[100];

int main(int argc, char **argv) {
  FILE *badfile;
  badfile = fopen("badfile", "r");
  fread(username, sizeof(char), 400, badfile);

  if (strncmp(username, "admin", 5) == 0 &&
      strncmp(password, "admin", 5) == 0) {
    puts("Welcome admin");
  }

  return 0;
}
