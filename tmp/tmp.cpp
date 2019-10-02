#include <stdio.h>

extern int foo(int* x);

int main(int argc, char**) {
  char buf[9];
  char* base = argc == 2 ? buf + 1 : buf;
  int* x = reinterpret_cast<int*>(base);
  int* y = reinterpret_cast<int*>(base + 4);

  *x = 2;
  *y = 42;

  return foo(x);
}
