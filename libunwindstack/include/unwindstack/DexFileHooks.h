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

#include <stdint.h>

#include <memory>
#include <string>
#include <vector>

namespace unwindstack {
namespace hooks {

class DexFileImpl {};

// These functions define the interface to hook in a dex file reader at load
// time. If none is provided by a loaded library, there's a weakly linked
// default implementation that trivially fails for all calls.

// Interpretes a chunk of memory as a dex file. As long as size is too small,
// returns with a new size to try again with. Returns < 0 on error, 0 on
// success in which case *dex_file is set to the result, to be owned by the
// caller.
int64_t DexFileFromMemory(const DexFileImpl** dex_file, const uint8_t* data, size_t size);

bool DexFileFromFile(const DexFileImpl** dex_file, uint64_t dex_file_offset_in_file,
                     const std::string& name);

// Gets info about the method whose instructions are at dex_offset, relative
// to the dex file start. [method_offset_start; method_offset_end) is set to
// the range of its code, also as offsets relative to the dex file start.
bool GetMethodInformation(const DexFileImpl* dex_file, uint64_t dex_offset,
                          std::string* method_name, uint64_t* method_offset_start,
                          uint64_t* method_offset_end);

void FreeDexFile(const DexFileImpl* dex_file);

}  // namespace hooks
}  // namespace unwindstack
