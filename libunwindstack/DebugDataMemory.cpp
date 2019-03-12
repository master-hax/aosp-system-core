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

#include <7zCrc.h>
#include <Xz.h>
#include <XzCrc64.h>

#include "DebugDataMemory.h"

namespace unwindstack {

Memory* CreateGnuDebugdataMemory(Memory* memory, uint64_t offset, uint64_t size) {
  // TODO: Only call these initialization functions once.
  CrcGenerateTable();
  Crc64GenerateTable();

  std::vector<uint8_t> src(size);
  if (!memory->ReadFully(offset, src.data(), size)) {
    return nullptr;
  }

  ISzAlloc alloc;
  CXzUnpacker state;
  alloc.Alloc = [](ISzAllocPtr, size_t size) { return malloc(size); };
  alloc.Free = [](ISzAllocPtr, void* ptr) { return free(ptr); };

  XzUnpacker_Construct(&state, &alloc);

  std::unique_ptr<MemoryBuffer> dst(new MemoryBuffer);
  int return_val;
  size_t src_offset = 0;
  size_t dst_offset = 0;
  ECoderStatus status;
  dst->Resize(5 * size);
  do {
    size_t src_remaining = src.size() - src_offset;
    size_t dst_remaining = dst->Size() - dst_offset;
    if (dst_remaining < 2 * size) {
      dst->Resize(dst->Size() + 2 * size);
      dst_remaining += 2 * size;
    }
    return_val = XzUnpacker_Code(&state, dst->GetPtr(dst_offset), &dst_remaining, &src[src_offset],
                                 &src_remaining, true, CODER_FINISH_ANY, &status);
    src_offset += src_remaining;
    dst_offset += dst_remaining;
  } while (return_val == SZ_OK && status == CODER_STATUS_NOT_FINISHED);
  XzUnpacker_Free(&state);
  if (return_val != SZ_OK || !XzUnpacker_IsStreamWasFinished(&state)) {
    return nullptr;
  }

  // Shrink back down to the exact size.
  dst->Resize(dst_offset);

  return dst.release();
}

}  // namespace unwindstack
