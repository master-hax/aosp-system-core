/*
 * Copyright (C) 2018 The Android Open Source Project
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

#pragma once

#include <sys/mman.h>
#include <sys/types.h>

#include <functional>
#include <string>

#include <android-base/file.h>

namespace android {
namespace procinfo {

static inline bool ReadMapFile(
    const std::string& map_file,
    const std::function<void(uint64_t, uint64_t, uint16_t, uint64_t, const char*)>& callback) {
  std::string content;
  if (!android::base::ReadFileToString(map_file, &content)) {
    return false;
  }
  uint64_t start_addr;
  uint64_t end_addr;
  uint16_t flags;
  uint64_t pgoff;
  char* next_line = &content[0];
  while (next_line != nullptr) {
    char* p = next_line;
    next_line = strchr(next_line, '\n');
    if (next_line != nullptr) {
      *next_line = '\0';
      next_line++;
    }
    // Parse line like: 00400000-00409000 r-xp 00000000 fc:00 426998  /usr/lib/gvfs/gvfsd-http
    char* end;
    // start_addr
    start_addr = strtoull(p, &end, 16);
    if (end == p || *end != '-') {
      continue;
    }
    p = end + 1;
    // end_addr
    end_addr = strtoull(p, &end, 16);
    if (end == p || *end != ' ') {
      continue;
    }
    p = end + 1;
    while (*p == ' ') {
      p++;
    }
    // flags
    flags = 0;
    while (*p != ' ' && *p != '\0') {
      if (*p == 'r') {
        flags |= PROT_READ;
      } else if (*p == 'w') {
        flags |= PROT_WRITE;
      } else if (*p == 'x') {
        flags |= PROT_EXEC;
      }
      p++;
    }
    while (*p == ' ') {
      p++;
    }
    // pgoff
    pgoff = strtoull(p, &end, 16);
    if (end == p || *end != ' ') {
      continue;
    }
    p = end + 1;
    while (*p == ' ') {
      p++;
    }
    // major:minor
    while (*p != ' ' && *p != '\0') {
      p++;
    }
    while (*p == ' ') {
      p++;
    }
    // inode
    while (*p != ' ' && *p != '\0') {
      p++;
    }
    while (*p == ' ') {
      p++;
    }
    // filename
    callback(start_addr, end_addr, flags, pgoff, p);
  }
  return true;
}

static inline bool ReadProcessMaps(
    pid_t pid,
    const std::function<void(uint64_t, uint64_t, uint16_t, uint64_t, const char*)>& callback) {
  return ReadMapFile("/proc/" + std::to_string(pid) + "/maps", callback);
}

} /* namespace procinfo */
} /* namespace android */
