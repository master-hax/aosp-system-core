#undef __BIONIC_FORTIFY
#include <fcntl.h>

int main() {
  open("foo", O_RDONLY);
}
