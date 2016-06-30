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

#include <stdint.h>

#include <algorithm>

#include <7zCrc.h>
#include <Xz.h>
#include <XzCrc64.h>

#include "DwarfDebugFrame.h"
#include "DwarfGnuDebugdata.h"
#include "DwarfMemory.h"
#include "DwarfSection.h"
#include "DwarfStructs.h"
#include "Memory.h"

template <typename AddressType>
bool DwarfGnuDebugdata<AddressType>::Init(uint64_t offset, uint64_t size) {
  offset_ = offset;
  end_offset_ = offset + size;

  memory_.clear_func_offset();
  memory_.clear_text_offset();
  memory_.set_data_offset(offset);
  memory_.set_cur_offset(offset);

  // These should only be called once.
  CrcGenerateTable();
  Crc64GenerateTable();

  std::vector<uint8_t> src(size);
  memory_.set_cur_offset(offset_);
  if (!memory_.ReadBytes(src.data(), size)) {
    return false;
  }

  ISzAlloc alloc;
  CXzUnpacker state;
  alloc.Alloc = [](void*, size_t size) { return malloc(size); };
  alloc.Free = [](void*, void* ptr) { return free(ptr); };

  XzUnpacker_Construct(&state, &alloc);

  int return_val;
  size_t src_offset = 0;
  size_t dst_offset = 0;
  ECoderStatus status;
  raw_.resize(5 * size);
  do {
    size_t src_remaining = src.size() - src_offset;
    size_t dst_remaining = raw_.size() - dst_offset;
    if (dst_remaining < 2 * size) {
      raw_.resize(raw_.size() + 2 * size);
      dst_remaining += 2 * size;
    }
    return_val = XzUnpacker_Code(&state, &raw_[dst_offset], &dst_remaining, &src[src_offset],
                                 &src_remaining, CODER_FINISH_ANY, &status);
    src_offset += src_remaining;
    dst_offset += dst_remaining;
  } while (return_val == SZ_OK && status == CODER_STATUS_NOT_FINISHED);
  XzUnpacker_Free(&state);
  if (return_val != SZ_OK || !XzUnpacker_IsStreamWasFinished(&state)) {
    return false;
  }

  // Shrink back down to the exact size.
  raw_.resize(dst_offset);

  return true;
}

// Explicitly instantiate DwarfGnuDebugdata.
template class DwarfGnuDebugdata<uint32_t>;
template class DwarfGnuDebugdata<uint64_t>;
