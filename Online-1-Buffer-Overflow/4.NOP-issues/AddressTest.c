#include <stdio.h>
#include <stdlib.h>

int x = 4, y = 5;
int w, z;

int foo(void) { return 2; }

int bar(void) { return 0; }

int main(int argc, char **argv) {
  static int y;
  void *a = malloc(8), *b = malloc(8);
  puts(argv[0]);
  system("env");
  printf("stack\na = %p\nb = %p\n\n", &a, &b);
  printf("heap\nc = %p\nd = %p\n\n", a, b);
  printf("code\nmain = %p\nfoo=%p\nbar=%p\n\n", main, foo, bar);
  printf("data\nx = %p\ny = %p\n\n", &x, &y);
  printf("bss\nw = %p\nz = %p\n\n", &w, &z);
  return 0;
}
