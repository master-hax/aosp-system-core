#include <fcntl.h>
#include <sys/socket.h>
#include <unistd.h>

#include "fdsan_wrappers.h"

extern "C" int __real_dup(int fd) {
  return dup(fd);
}

extern "C" int __real_dup3(int oldfd, int newfd, int flags) {
  return dup3(oldfd, newfd, flags);
}

extern "C" int __real_fcntl(int fd, int cmd, void* arg) {
  return fcntl(fd, cmd, arg);
}

extern "C" int __real_open(const char* path, int flags, int mode) {
  return open(path, flags, mode);
}

extern "C" int __real_close(int fd) {
  return close(fd);
}

extern "C" int __real_socket(int domain, int type, int protocol) {
  return socket(domain, type, protocol);
}
