#include <fcntl.h>
#include <unistd.h>

int main() {
  int fd = open("/data/local/tmp/foo", O_CREAT | O_RDWR, 0755);
  close(fd);
  close(fd);
}
