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
#include <stdlib.h>
#include <string.h>

#include <async_safe/log.h>

#include "fdsan.h"
#include "fdsan_wrappers.h"

extern "C" int close(int fd) {
  char buf[PATH_MAX + 1];
  async_safe_format_buffer(buf, sizeof(buf), "/proc/self/fd/%d", fd);
  ssize_t len = readlink(buf, buf, sizeof(buf) - 1);
  if (len == -1) {
    if (errno == 0) {
      strncpy(buf, "<nonexistent>", sizeof(buf));
    } else {
      async_safe_format_buffer(buf, sizeof(buf), "readlink failed: %s", strerror(errno));
    }
  } else {
    buf[len] = '\0';
  }

  int rc = FDSAN_CHECK_ALWAYS(close, fd);
  if (rc == -1) {
    return -1;
  }

  fdsan_record_close(fd, buf);
  return rc;
}
