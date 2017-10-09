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

extern "C" {

#if defined(__BIONIC__)
int __openat(int fd, const char* pathname, int flags, int mode) {
  int rc = FDSAN_CHECK(openat, fd, pathname, flags, mode);
  return fdsan_record_create(rc, "__openat");
}

int __openat_2(int fd, const char* pathname, int flags) {
  int rc = FDSAN_CHECK(openat, fd, pathname, flags, 0);
  return fdsan_record_create(rc, "__openat_2");
}
#endif

static bool needs_mode(int flags) {
  return ((flags & O_CREAT) == O_CREAT) || ((flags & O_TMPFILE) == O_TMPFILE);
}

static int force_O_LARGEFILE(int flags) {
#if defined(__LP64__)
  return flags;  // No need, and aarch64's strace gets confused.
#else
  return flags | O_LARGEFILE;
#endif
}

#undef openat
int openat(int fd, const char* pathname, int flags, ...) {
  mode_t mode = 0;
  if (needs_mode(flags)) {
    va_list args;
    va_start(args, flags);
    mode = static_cast<mode_t>(va_arg(args, int));
    va_end(args);
  }

  int rc = __real_openat(fd, pathname, flags, mode);
  return fdsan_record_create(rc, "openat");
}

int openat64(int fd, const char* pathname, int flags, ...) {
  mode_t mode = 0;
  if (needs_mode(flags)) {
    va_list args;
    va_start(args, flags);
    mode = static_cast<mode_t>(va_arg(args, int));
    va_end(args);
  }

  int rc = __real_openat(fd, pathname, force_O_LARGEFILE(flags), mode);
  return fdsan_record_create(rc, "openat64");
}

#undef open
int open(const char* pathname, int flags, ...) {
  mode_t mode = 0;
  if (needs_mode(flags)) {
    va_list args;
    va_start(args, flags);
    mode = static_cast<mode_t>(va_arg(args, int));
    va_end(args);
  }

  int rc = __real_openat(AT_FDCWD, pathname, flags, mode);
  return fdsan_record_create(rc, "open");
}

int open64(const char* pathname, int flags, ...) {
  mode_t mode = 0;
  if (needs_mode(flags)) {
    va_list args;
    va_start(args, flags);
    mode = static_cast<mode_t>(va_arg(args, int));
    va_end(args);
  }

  int rc = __real_openat(AT_FDCWD, pathname, force_O_LARGEFILE(flags), mode);
  return fdsan_record_create(rc, "open64");
}

#undef creat
int creat(const char* pathname, mode_t mode) {
  int rc = __real_openat(AT_FDCWD, pathname, O_CREAT | O_TRUNC | O_WRONLY, mode);
  return fdsan_record_create(rc, "creat");
}

int creat64(const char* pathname, mode_t mode) {
  int rc = __real_openat(AT_FDCWD, pathname, force_O_LARGEFILE(O_CREAT | O_TRUNC | O_WRONLY), mode);
  return fdsan_record_create(rc, "creat64");
}

}  // extern "C"
