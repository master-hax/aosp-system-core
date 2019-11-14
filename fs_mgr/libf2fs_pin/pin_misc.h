/*
 * Copyright (C) 2020 The Android Open Source Project
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

#include "libf2fs_pin/pin.h"
#include "pin_impl.h"

#include <sys/stat.h>
#include <cstdint>

//  Read write from some devices fails unless the memory buffer address is sector aligned

class SectorAlignedMemory {
  public:
    static constexpr size_t kSectorSize = 4096;
    static constexpr size_t kSize = 64 * 1024;
    uint64_t* Address() {
        uintptr_t va = (uintptr_t)mem;
        va &= ~(kSectorSize - 1);  // ensure va is kSectorSize aligned
        va += kSectorSize;         // ensure it is inside mem[]
        return (uint64_t*)va;
    }

  private:
    uint64_t mem[kSize / sizeof(uint64_t) + kSectorSize];  // extra sector to align
};

bool WritePattern(const char* file, int file_fd, off_t file_size);
bool VerifyPattern(const char* bdev, int bdev_fd, const char* file, int file_fd, off_t file_size);
bool EnsurePinned(const char* bdev, const char* file, bool verify_file);
bool CreatePinned(const char* bdev, const char* file, off_t file_size, bool init_file);
