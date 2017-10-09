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

#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <unistd.h>

#include "fdsan.h"
#include "fdsan_wrappers.h"

// Record that a file descriptor has been opened.
int fdsan_open(int fd) {
  FdEvent event = {};
  event.type = FdEventType::Open;
  return fdsan_record(fd, event);
}

int fdsan_socket(int fd, int domain, int type, int protocol) {
  FdEvent event = {};
  event.type = FdEventType::Socket;
  event.data.socket.domain = domain;
  event.data.socket.socket_type = type;
  event.data.socket.protocol = protocol;
  return fdsan_record(fd, event);
}

int fdsan_dup(int oldfd, int newfd) {
  FdEvent event = {};
  event.type = FdEventType::Dup;
  event.data.dup.from = oldfd;
  return fdsan_record(newfd, event);
}

template <typename T>
static T fdsan_check_result(const char* function_name, int fd, T rc) {
  if (rc == -1 && errno == EBADF) {
    fdsan_report(function_name, fd);
    return rc;
  } else {
    return rc;
  }
}

#define FDSAN_CHECK(symbol, fd, ...) \
  fdsan_check_result(#symbol, fd, __real_##symbol(fd, ##__VA_ARGS__))

extern "C" int dup(int fd) {
  int rc = FDSAN_CHECK(dup, fd);
  return fdsan_dup(fd, rc);
}

extern "C" int dup3(int oldfd, int newfd, int flags) {
  int rc = FDSAN_CHECK(dup3, oldfd, newfd, flags);
  return fdsan_dup(oldfd, rc);
}

extern "C" int fcntl(int fd, int cmd, ...) {
  // This is bit sketchy, but this works on all of our ABIs, because on 32-bit, int is the same size
  // as void*, and all of our 64-bit ABIs will pass the arg in a register.
  va_list args;
  va_start(args, cmd);
  void* arg = va_arg(args, void*);
  va_end(args);

  int rc = FDSAN_CHECK(fcntl, fd, cmd, arg);
  if (cmd == F_DUPFD) {
    return fdsan_dup(fd, rc);
  }

  return rc;
}

extern "C" int __openat(int fd, const char* pathname, int flags, int mode) {
  int rc = FDSAN_CHECK_ALWAYS(__openat, fd, pathname, flags, mode);
  return fdsan_open(rc);
}

extern "C" int socket(int domain, int type, int protocol) {
  int rc = __real_socket(domain, type, protocol);
  return fdsan_socket(rc, domain, type, protocol);
}

extern "C" int close(int fd) {
  int rc = FDSAN_CHECK_ALWAYS(close, fd);

  if (rc == -1 && errno == EBADF) {
    fdsan_report(__FUNCTION__, fd);
    return -1;
  }

  if (fd >= 0 && static_cast<size_t>(fd) < fd_table.size()) {
    FdEvent event;
    event.type = FdEventType::Close;
    fdsan_record(fd, event);
  }

  return rc;
}
