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
#include <stdarg.h>

#include "fdsan.h"
#include "fdsan_wrappers.h"

extern "C" {

int dup(int fd) {
  int rc = FDSAN_CHECK(dup, fd);
  if (rc == -1) {
    return -1;
  }

  return fdsan_record_dup(rc, "dup", fd);
}

int dup2(int oldfd, int newfd) {
  int rc = FDSAN_CHECK(dup2, oldfd, newfd);
  if (rc == -1) {
    return -1;
  }

  return fdsan_record_dup(rc, "dup2", oldfd);
}

int dup3(int oldfd, int newfd, int flags) {
  int rc = FDSAN_CHECK(dup3, oldfd, newfd, flags);
  if (rc == -1) {
    return -1;
  }

  return fdsan_record_dup(rc, "dup3", oldfd);
}

int fcntl(int fd, int cmd, ...) {
  va_list args;
  va_start(args, cmd);
  void* arg = va_arg(args, void*);
  if (cmd == F_DUPFD) {
    int rc = FDSAN_CHECK(fcntl, fd, cmd, arg);
    if (rc == -1) {
      return -1;
    }

    return fdsan_record_dup(rc, "fcntl", fd);
  }

  return __real_fcntl(fd, cmd, arg);
}

}  // extern "C"
