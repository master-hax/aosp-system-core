#pragma once

extern "C" int __real_dup(int fd);
extern "C" int __real_dup3(int oldfd, int newfd, int flags);
extern "C" int __real_fcntl(int fd, int cmd, void* arg);
extern "C" int __real_open(const char* path, int flags, int mode);
extern "C" int __real_close(int fd);
extern "C" int __real_socket(int domain, int type, int protocol);
