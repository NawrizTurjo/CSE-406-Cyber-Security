#include <stdio.h>
#include <string.h>

// Expected output:
// Who are you fellow human being?
// Oh admin! Go ahead, take your key
// Welcome admin
//
// Condition:
// Cant use -z execstack
// Can't segfault, return 0

int is_admin = 0;

void win(int key1, int key2) {
  printf("Who are you fellow human being?\n");
  if (key1 == 0xbabadada && key2 == 0xabbadada) {
    printf("Oh admin! Go ahead, take your key\n");
  } else {
    printf("Lol peasent!\n");
  }
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
