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
#include <string.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <unistd.h>

#include <android-base/unique_fd.h>
#include <procinfo/process_map.h>

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
    const auto& cur = maps_[index];
    if (pc >= cur->start && pc < cur->end) {
      return cur.get();
    } else if (pc < cur->start) {
      last = index;
    } else {
      first = index + 1;
    }
  }
  return nullptr;
}

bool Maps::Parse() {
  MapInfo* prev_map = nullptr;
  MapInfo* prev_real_map = nullptr;
  return android::procinfo::ReadMapFile(
      GetMapsFile(),
      [&](uint64_t start, uint64_t end, uint16_t flags, uint64_t pgoff, ino_t, const char* name) {
        // Mark a device map in /dev/ and not in /dev/ashmem/ specially.
        if (strncmp(name, "/dev/", 5) == 0 && strncmp(name + 5, "ashmem/", 7) != 0) {
          flags |= unwindstack::MAPS_FLAGS_DEVICE_MAP;
        }
        maps_.emplace_back(new MapInfo(prev_map, prev_real_map, start, end, pgoff, flags, name));
        prev_map = maps_.back().get();
        if (!prev_map->IsBlank()) {
          prev_real_map = prev_map;
        }
      });
}

void Maps::Add(uint64_t start, uint64_t end, uint64_t offset, uint64_t flags,
               const std::string& name, uint64_t load_bias) {
  MapInfo* prev_map = maps_.empty() ? nullptr : maps_.back().get();
  MapInfo* prev_real_map = prev_map;
  while (prev_real_map != nullptr && prev_real_map->IsBlank()) {
    prev_real_map = prev_real_map->prev_map;
  }

  auto map_info =
      std::make_unique<MapInfo>(prev_map, prev_real_map, start, end, offset, flags, name);
  map_info->load_bias = load_bias;
  maps_.emplace_back(std::move(map_info));
}

void Maps::Sort() {
  std::sort(maps_.begin(), maps_.end(),
            [](const std::unique_ptr<MapInfo>& a, const std::unique_ptr<MapInfo>& b) {
              return a->start < b->start; });

  // Set the prev_map values on the info objects.
  MapInfo* prev_map = nullptr;
  MapInfo* prev_real_map = nullptr;
  for (const auto& map_info : maps_) {
    map_info->prev_map = prev_map;
    map_info->prev_real_map = prev_real_map;
    prev_map = map_info.get();
    if (!prev_map->IsBlank()) {
      prev_real_map = prev_map;
    }
  }
}

bool BufferMaps::Parse() {
  std::string content(buffer_);
  MapInfo* prev_map = nullptr;
  MapInfo* prev_real_map = nullptr;
  return android::procinfo::ReadMapFileContent(
      &content[0],
      [&](uint64_t start, uint64_t end, uint16_t flags, uint64_t pgoff, ino_t, const char* name) {
        // Mark a device map in /dev/ and not in /dev/ashmem/ specially.
        if (strncmp(name, "/dev/", 5) == 0 && strncmp(name + 5, "ashmem/", 7) != 0) {
          flags |= unwindstack::MAPS_FLAGS_DEVICE_MAP;
        }
        maps_.emplace_back(new MapInfo(prev_map, prev_real_map, start, end, pgoff, flags, name));
        prev_map = maps_.back().get();
        if (!prev_map->IsBlank()) {
          prev_real_map = prev_map;
        }
      });
}

const std::string RemoteMaps::GetMapsFile() const {
  return "/proc/" + std::to_string(pid_) + "/maps";
}

const std::string LocalUpdatableMaps::GetMapsFile() const {
  return "/proc/self/maps";
}

bool LocalUpdatableMaps::Reparse() {
  auto old_maps = std::move(maps_);
  maps_.clear();

  if (!Parse()) {
    maps_ = std::move(old_maps);
    return false;
  }

  // remove any entries from maps_ that already exist in old_maps (duplicates), and move any entries
  // in old_maps that don't have entries in maps_ to saved_maps_
  // at the end of this, old_maps will contain only entries that still exist, maps_ will contain
  // only new entries, and saved_maps_ will contain the entries that no longer exist
  auto new_map_iter = maps_.begin();
  auto old_map_iter = old_maps.begin();
  while (old_map_iter != old_maps.end()) {
    auto found_new_map = std::find_if(new_map_iter, maps_.end(), [&] (auto& new_map) {
      auto const& old_map = *old_map_iter;
      return new_map->start == old_map->start
          && new_map->end == old_map->end
          && new_map->flags == old_map->flags
          && new_map->name == old_map->name;
    });
    if (found_new_map != maps_.end()) {
      // duplicate entry, keep the old one
      new_map_iter = maps_.erase(found_new_map);
      old_map_iter++;
    } else {
      // old entry doesn't exist in the new map, move it to saved_maps_ so it doesn't get deleted
      // (someone may still be using it)
      saved_maps_.push_back(std::move(*old_map_iter));
      old_map_iter = old_maps.erase(old_map_iter);
    }
  }

  std::move(old_maps.begin(), old_maps.end(), std::back_inserter(maps_));

  Sort(); // this will rebuild the prev_map and prev_real_map links along with correctly sorting

  return true;
}

}  // namespace unwindstack
