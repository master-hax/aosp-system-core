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

#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/mman.h>

#include <memory>
#include <string>
#include <vector>

#include <android-base/stringprintf.h>

#include "Maps.h"

const MapInfo* Maps::Find(uint64_t pc) {
  if (maps_.empty()) {
    return nullptr;
  }
  size_t first = 0;
  size_t last = maps_.size() - 1;
  MapInfo* map = nullptr;
  while (first <= last) {
    size_t index = (first + last) / 2;
    MapInfo* cur = &maps_[index];
    if (pc >= cur->start && pc < cur->end) {
      map = cur;
      break;
    } else if (pc < cur->start) {
      last = index - 1;
    } else {
      first = index + 1;
    }
  }
  return map;
}

std::string MapsRemote::GetMapsFile() {
  return "/proc/" + std::to_string(pid_) + "/maps";
}

bool Maps::ParseLine(const char* line, MapInfo* map_info) {
  char permissions[5];
  int name_pos;
  // Linux /proc/<pid>/maps lines:
  // 6f000000-6f01e000 rwxp 00000000 00:0c 16389419   /system/lib/libcomposer.so
  if (sscanf(line, "%" SCNx64 "-%" SCNx64 " %4s %" SCNx64 " %*x:%*x %*d %n",
             &map_info->start, &map_info->end, permissions, &map_info->offset, &name_pos) != 4) {
    return false;
  }
  map_info->flags = PROT_NONE;
  if (permissions[0] == 'r') {
    map_info->flags |= PROT_READ;
  }
  if (permissions[1] == 'w') {
    map_info->flags |= PROT_WRITE;
  }
  if (permissions[2] == 'x') {
    map_info->flags |= PROT_EXEC;
  }

  map_info->name = &line[name_pos];
  size_t length = map_info->name.length() - 1;
  if (map_info->name[length] == '\n') {
    map_info->name.erase(length);
  }
  return true;
}

bool Maps::Parse() {
  std::unique_ptr<FILE, decltype(&fclose)> fp(fopen(GetMapsFile().c_str(), "re"), fclose);
  if (fp.get() == nullptr) {
    return false;
  }

  std::vector<char> line(8192);
  while (fgets(line.data(), line.size(), fp.get())) {
    MapInfo map_info;
    if (!ParseLine(line.data(), &map_info)) {
      return false;
    }

    maps_.push_back(map_info);
  }

  return true;
}

bool MapsBuffer::Parse() {
  const char* start_of_line = buffer_;
  do {
    std::string line;
    const char* end_of_line = strchr(start_of_line, '\n');
    if (end_of_line == nullptr) {
      line = start_of_line;
    } else {
      end_of_line++;
      line = std::string(start_of_line, end_of_line - start_of_line);
    }

    MapInfo map_info;
    if (!ParseLine(line.c_str(), &map_info)) {
      return false;
    }
    maps_.push_back(map_info);

    start_of_line = end_of_line;
  } while (start_of_line != nullptr && *start_of_line != '\0');
  return true;
}
