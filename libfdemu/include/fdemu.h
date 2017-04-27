#pragma once

/*
 * Copyright (C) 2017 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

// Windows has file descriptors, but they're an emulation layer on top of the actual kernel
// primitive (HANDLE). open on Windows takes a single-byte character string, not UTF-8, so we need
// to use the native function (CreateFileW) to properly support Unicode filenames. The type used
// for sockets also doesn't match POSIX (HANDLE instead of int).
//
// To paper over the differences, we implement our own file descriptor emulation layer, plus UTF-8
// versions of file system functions.

#if defined(_WIN32)
#include <ws2tcpip.h>
#include <windows.h>
#else
#include <sys/poll.h>
#include <sys/socket.h>
#endif

#include <fcntl.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#if defined(_WIN32)
// Undefine some of mingw's helper macros.
#undef fstat
#endif

// X macro for defining the functions we care about.
#define FDEMU_FUNCTIONS()                                                                 \
  FDEMU_FUNCTION(int, close, FD fd);                                                      \
  FDEMU_FUNCTION(FD, dup, FD fd);                                                         \
  FDEMU_FUNCTION(FD, dup2, FD oldfd, FD newfd);                                           \
                                                                                          \
  FDEMU_FUNCTION(ssize_t, read, FD fd, char* buf, size_t len);                            \
  FDEMU_FUNCTION(ssize_t, write, FD fd, const char* buf, size_t len);                     \
                                                                                          \
  FDEMU_FUNCTION(ssize_t, lseek, FD fd, off_t offset, int whence);                        \
                                                                                          \
  FDEMU_FUNCTION(int, fstat, FD fd, struct stat* st);                                     \
                                                                                          \
  FDEMU_FUNCTION(FD, socket, int domain, int type, int protocol);                         \
  FDEMU_FUNCTION(FD, accept, FD sockfd, struct sockaddr* addr, socklen_t* addrlen);       \
  FDEMU_FUNCTION(FD, connect, FD sockfd, const struct sockaddr* addr, socklen_t addrlen); \
  FDEMU_FUNCTION(int, shutdown, FD sockfd, int how);                                      \
                                                                                          \
  FDEMU_FUNCTION(int, getsockname, FD sockfd, struct sockaddr* addr, socklen_t* addrlen); \
  FDEMU_FUNCTION(int, getpeername, FD sockfd, struct sockaddr* addr, socklen_t* addrlen); \
                                                                                          \
  FDEMU_FUNCTION(FD, open, const char* path, int flags, ...);                             \
  FDEMU_FUNCTION(int, unlink, const char* path);                                          \
  FDEMU_FUNCTION(int, poll, struct pollfd* fds, size_t nfds, int timeout);

namespace fdemu {

// Wrapper type, to ensure separation between native file descriptors and emulated ones.
class FD {
 public:
  explicit FD(int value) : value(value) {}

  bool operator==(int fd) const { return fd == value; }

  bool operator!=(int fd) const { return fd != value; }

  bool operator==(const FD& rhs) const { return value == rhs.value; }

  bool operator!=(const FD& rhs) const { return value != rhs.value; }

  static FD Invalid() { return FD(-1); }

  int value;
};

struct stat {
  // FIXME: Fill in the rest of the fields.
  mode_t st_mode;
  off_t st_size;
};

struct pollfd {
  FD fd;
  short events;
  short revents;
};

#define FDEMU_FUNCTION(ret, name, ...) ret name(__VA_ARGS__)
FDEMU_FUNCTIONS()
#undef FDEMU_FUNCTION

}  // namespace fdemu
