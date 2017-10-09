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

extern "C" int __openat(int fd, const char* pathname, int flags, int mode);
extern "C" int __real___openat(int fd, const char* pathname, int flags, int mode) {
  return __openat(fd, pathname, flags, mode);
}

extern "C" int __real_close(int fd) {
  return close(fd);
}

extern "C" int __real_socket(int domain, int type, int protocol) {
  return socket(domain, type, protocol);
}
