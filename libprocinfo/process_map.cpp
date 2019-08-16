/*
 * Copyright (C) 2019 The Android Open Source Project
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

#include <procinfo/process_map.h>

#include <fcntl.h>
#include <string.h>
#include <unistd.h>

#include <procinfo/process.h>

namespace android {
namespace procinfo {

// In order to avoid allocating a buffer, this function is not reentrant.
bool ReadMapFileAsyncSafe(const char* map_file,
                          const std::function<void(uint64_t, uint64_t, uint16_t, uint64_t, ino_t,
                                                   const char*)>& callback) {
  int fd = open(map_file, O_RDONLY | O_CLOEXEC);
  if (fd == -1) {
    return false;
  }

  // Global buffer.
  static char buffer[65535];

  size_t start = 0;
  size_t read_bytes = 0;
  char* line = nullptr;
  bool read_complete = false;
  while (true) {
    while (read_bytes > 0) {
      char* newline = reinterpret_cast<char*>(memchr(&buffer[start], '\n', read_bytes));
      if (newline == nullptr) {
        break;
      }
      *newline = '\0';
      line = &buffer[start];
      start = newline - buffer + 1;
      read_bytes -= newline - line + 1;

      // Ignore the return code, errors are okay.
      ReadMapFileContent(line, callback);
    }
    if (read_complete) {
      close(fd);
      return true;
    }

    if (start > 0) {
      if (read_bytes > 0) {
        memmove(buffer, &buffer[start], read_bytes);
      }
      start = 0;
    }
    ssize_t bytes =
        TEMP_FAILURE_RETRY(read(fd, buffer + read_bytes, sizeof(buffer) - read_bytes - 1));
    if (bytes <= 0) {
      if (read_bytes == 0) {
        close(fd);
        return bytes == 0;
      }
      // Treat the last piece of data as the last line.
      buffer[start + read_bytes] = '\n';
      bytes = 1;
      read_complete = true;
    }
    read_bytes += bytes;
  }
}

} /* namespace procinfo */
} /* namespace android */
