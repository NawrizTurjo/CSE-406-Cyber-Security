#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Expected output:
// Welcome admin
//
// Conditions:
// cant use -m32, -z execstack
// No segfault, should return 0

int main(int argc, char **argv) {
  char *username;
  char *password;

  FILE *badfile;
  badfile = fopen("badfile", "r");

  username = malloc(10);
  password = malloc(10);

  fread(username, sizeof(char), 400, badfile);

  if (strncmp(username, "admin", 5) == 0 &&
      strncmp(password, "admin", 5) == 0) {
    puts("Welcome admin");
  }

  return 0;
}
