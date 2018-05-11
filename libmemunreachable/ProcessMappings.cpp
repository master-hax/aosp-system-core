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

#include <fcntl.h>
#include <inttypes.h>
#include <string.h>
#include <unistd.h>

#include <android-base/unique_fd.h>
#include <procinfo/process_map.h>

#include "ProcessMappings.h"

namespace android {

bool ProcessMappings(pid_t pid, allocator::vector<Mapping>& mappings) {
  return android::procinfo::ReadProcessMaps(
      pid, [&](uint64_t start, uint64_t end, uint16_t flags, uint64_t, const char* name) {
        mappings.resize(mappings.size() + 1);
        Mapping& mapping = mappings.back();
        mapping.begin = start;
        mapping.end = end;
        mapping.read = flags & PROT_READ;
        mapping.write = flags & PROT_WRITE;
        mapping.execute = flags & PROT_EXEC;
        strlcpy(mapping.name, name, sizeof(mapping.name));
      });
}

}  // namespace android
