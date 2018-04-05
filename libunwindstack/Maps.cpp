/*
 * Copyright (C) 2016 The Android Open Source Project
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
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <unistd.h>

#include <android-base/unique_fd.h>

#include <algorithm>
#include <cctype>
#include <memory>
#include <string>
#include <vector>

#include <unwindstack/Elf.h>
#include <unwindstack/Maps.h>
#include <unwindstack/Memory.h>

namespace unwindstack {

MapInfo* Maps::Find(uint64_t pc) {
  if (maps_.empty()) {
    return nullptr;
  }
  size_t first = 0;
  size_t last = maps_.size();
  while (first < last) {
    size_t index = (first + last) / 2;
    MapInfo* cur = maps_[index];
    if (pc >= cur->start && pc < cur->end) {
      return cur;
    } else if (pc < cur->start) {
      last = index;
    } else {
      first = index + 1;
    }
  }
  return nullptr;
}

// Assumes that line does not end in '\n'.
static MapInfo* InternalParseLine(const char* line) {
  // Do not use a sscanf implementation since it is not performant.

  // Example linux /proc/<pid>/maps lines:
  // 6f000000-6f01e000 rwxp 00000000 00:0c 16389419   /system/lib/libcomposer.so
  char* str;
  const char* old_str = line;
  uint64_t start = strtoull(old_str, &str, 16);
  if (old_str == str || *str++ != '-') {
    return nullptr;
  }

  old_str = str;
  uint64_t end = strtoull(old_str, &str, 16);
  if (old_str == str || !std::isspace(*str++)) {
    return nullptr;
  }

  while (std::isspace(*str)) {
    str++;
  }

  // Parse permissions data.
  if (*str == '\0') {
    return nullptr;
  }
  uint16_t flags = 0;
  if (*str == 'r') {
    flags |= PROT_READ;
  } else if (*str != '-') {
    return nullptr;
  }
  str++;
  if (*str == 'w') {
    flags |= PROT_WRITE;
  } else if (*str != '-') {
    return nullptr;
  }
  str++;
  if (*str == 'x') {
    flags |= PROT_EXEC;
  } else if (*str != '-') {
    return nullptr;
  }
  str++;
  if (*str != 'p' && *str != 's') {
    return nullptr;
  }
  str++;

  if (!std::isspace(*str++)) {
    return nullptr;
  }

  old_str = str;
  uint64_t offset = strtoull(old_str, &str, 16);
  if (old_str == str || !std::isspace(*str)) {
    return nullptr;
  }

  // Ignore the 00:00 values.
  old_str = str;
  (void)strtoull(old_str, &str, 16);
  if (old_str == str || *str++ != ':') {
    return nullptr;
  }
  if (std::isspace(*str)) {
    return nullptr;
  }

  // Skip the inode.
  old_str = str;
  (void)strtoull(str, &str, 16);
  if (old_str == str || !std::isspace(*str++)) {
    return nullptr;
  }

  // Skip decimal digit.
  old_str = str;
  (void)strtoull(old_str, &str, 10);
  if (old_str == str || (!std::isspace(*str) && *str != '\0')) {
    return nullptr;
  }

  while (std::isspace(*str)) {
    str++;
  }
  if (*str == '\0') {
    return new MapInfo(start, end, offset, flags, "");
  }

  // Save the name data.
  std::string name(str);

  // Mark a device map in /dev/ and not in /dev/ashmem/ specially.
  if (name.substr(0, 5) == "/dev/" && name.substr(5, 7) != "ashmem/") {
    flags |= MAPS_FLAGS_DEVICE_MAP;
  }
  return new MapInfo(start, end, offset, flags, name);
}

bool Maps::Parse() {
  int fd = open(GetMapsFile().c_str(), O_RDONLY | O_CLOEXEC);
  if (fd == -1) {
    return false;
  }

  bool return_value = true;
  char buffer[2048];
  size_t leftover = 0;
  while (true) {
    ssize_t bytes = read(fd, &buffer[leftover], 2048 - leftover);
    if (bytes == -1) {
      return_value = false;
      break;
    }
    if (bytes == 0) {
      break;
    }

    bytes += leftover;
    char* line = buffer;
    while (bytes > 0) {
      char* newline = static_cast<char*>(memchr(line, '\n', bytes));
      if (newline == nullptr) {
        memmove(buffer, line, bytes);
        break;
      }
      *newline = '\0';

      MapInfo* map_info = InternalParseLine(line);
      if (map_info == nullptr) {
        return_value = false;
        break;
      }
      maps_.push_back(map_info);

      bytes -= newline - line + 1;
      line = newline + 1;
    }
    leftover = bytes;
  }
  close(fd);
  return return_value;
}

void Maps::Add(uint64_t start, uint64_t end, uint64_t offset, uint64_t flags,
               const std::string& name, uint64_t load_bias) {
  MapInfo* map_info = new MapInfo(start, end, offset, flags, name);
  map_info->load_bias = load_bias;
  maps_.push_back(map_info);
}

void Maps::Sort() {
  std::sort(maps_.begin(), maps_.end(),
            [](const MapInfo* a, const MapInfo* b) { return a->start < b->start; });
}

Maps::~Maps() {
  for (auto& map : maps_) {
    delete map;
  }
}

bool BufferMaps::Parse() {
  const char* start_of_line = buffer_;
  do {
    std::string line;
    const char* end_of_line = strchr(start_of_line, '\n');
    if (end_of_line == nullptr) {
      line = start_of_line;
    } else {
      line = std::string(start_of_line, end_of_line - start_of_line);
      end_of_line++;
    }

    MapInfo* map_info = InternalParseLine(line.c_str());
    if (map_info == nullptr) {
      return false;
    }
    maps_.push_back(map_info);

    start_of_line = end_of_line;
  } while (start_of_line != nullptr && *start_of_line != '\0');
  return true;
}

const std::string RemoteMaps::GetMapsFile() const {
  return "/proc/" + std::to_string(pid_) + "/maps";
}

const std::string LocalUpdatableMaps::GetMapsFile() const {
  return "/proc/self/maps";
}

bool LocalUpdatableMaps::Reparse() {
  // New maps will be added at the end without deleting the old ones.
  size_t last_map_idx = maps_.size();
  if (!Parse()) {
    // Delete any maps added by the Parse call.
    for (size_t i = last_map_idx; i < maps_.size(); i++) {
      delete maps_[i];
    }
    maps_.resize(last_map_idx);
    return false;
  }

  size_t total_entries = maps_.size();
  size_t search_map_idx = 0;
  for (size_t new_map_idx = last_map_idx; new_map_idx < maps_.size(); new_map_idx++) {
    MapInfo* new_map_info = maps_[new_map_idx];
    uint64_t start = new_map_info->start;
    uint64_t end = new_map_info->end;
    uint64_t flags = new_map_info->flags;
    std::string* name = &new_map_info->name;
    for (size_t old_map_idx = search_map_idx; old_map_idx < last_map_idx; old_map_idx++) {
      MapInfo* info = maps_[old_map_idx];
      if (start == info->start && end == info->end && flags == info->flags && *name == info->name) {
        // No need to check
        search_map_idx = old_map_idx + 1;
        delete new_map_info;
        maps_[new_map_idx] = nullptr;
        total_entries--;
        break;
      } else if (info->start > start) {
        // Stop, there isn't going to be a match.
        search_map_idx = old_map_idx;
        break;
      }

      // Never delete these maps, they may be in use. The assumption is
      // that there will only every be a handfull of these so waiting
      // to destroy them is not too expensive.
      saved_maps_.push_back(info);
      maps_[old_map_idx] = nullptr;
      total_entries--;
    }
    if (search_map_idx >= last_map_idx) {
      break;
    }
  }

  // Now move out any of the maps that never were found.
  for (size_t i = search_map_idx; i < last_map_idx; i++) {
    saved_maps_.push_back(maps_[i]);
    maps_[i] = nullptr;
    total_entries--;
  }

  // Sort all of the values such that the nullptrs wind up at the end, then
  // resize them away.
  std::sort(maps_.begin(), maps_.end(), [](const auto* a, const auto* b) {
    if (a == nullptr) {
      return false;
    } else if (b == nullptr) {
      return true;
    }
    return a->start < b->start;
  });
  maps_.resize(total_entries);

  return true;
}

LocalUpdatableMaps::~LocalUpdatableMaps() {
  for (auto map_info : saved_maps_) {
    delete map_info;
  }
}

}  // namespace unwindstack
