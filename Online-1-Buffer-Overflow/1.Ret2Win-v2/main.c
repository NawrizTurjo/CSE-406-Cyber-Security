#include <stdio.h>
#include <string.h>

// Expected output:
// You reached the gate, let's see if you have the secret key
// That's the right key! Welcome chief
//
// Condition:
// Cant use -z execstack

void win(int key1, int key2) {
  printf("You reached the gate, let's see if you have the secret key\n");
  if (key1 == 0xdeadbeef && key2 == 0xcafebabe) {
    printf("That's the right key! Welcome chief\n");
  } else {
    printf("You imposter!\n");
  }
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
