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

#include <stddef.h>
#include <stdint.h>

extern "C" {

typedef void DexFileImpl;

// These functions define the interface to hook in a dex file reader at load
// time. If none is provided by a loaded library, there's a default
// implementation that trivially returns without any dex file info.

struct DexFileHooks {
  // Interpretes a chunk of memory as a dex file. As long as size is too small,
  // returns with a new size to try again with. Returns < 0 on error, 0 on
  // success in which case *dex_file is set to the result, to be owned by the
  // caller.
  int64_t (*DexFileFromMemory)(DexFileImpl** dex_file, const uint8_t* data, size_t size);

  bool (*DexFileFromFile)(DexFileImpl** dex_file, uint64_t dex_file_offset_in_file,
                          const char* name);

  // Gets info about the method whose instructions include dex_offset, which is
  // an offset relative to the dex file start. If the call is successful:
  // *method_name is set to a string whose storage will be freed by FreeDexFile.
  // *method_offset is set to the offset from the start of the method
  // instruction block for dex_offset. Thread unsafe.
  bool (*GetMethodInformation)(DexFileImpl* dex_file, uint64_t dex_offset, const char** method_name,
                               uint64_t* method_offset);

  void (*FreeDexFile)(DexFileImpl* dex_file);
};

}  // extern "C"

namespace unwindstack {

// This may only be called once to replace the default null implementation.
// Thread unsafe.
void SetDexFileHooks(const DexFileHooks* dex_file_hooks);

// Thread unsafe wrt SetDexFileHooks.
const DexFileHooks* GetDexFileHooks();

}  // namespace unwindstack
