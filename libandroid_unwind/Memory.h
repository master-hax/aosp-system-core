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

#ifndef _LIBANDROID_UNWIND_MEMORY_H
#define _LIBANDROID_UNWIND_MEMORY_H

#include <stdint.h>
#include <sys/types.h>
#include <unistd.h>

#include <string>

#include <android-base/unique_fd.h>

class Memory {
 public:
  Memory() = default;
  virtual ~Memory() = default;

  virtual bool Read(uint64_t offset, void* dst, size_t size) = 0;

  inline bool Read(uint64_t offset, void* start, void* field, size_t size) {
    return Read(offset + reinterpret_cast<uintptr_t>(field) - reinterpret_cast<uintptr_t>(start),
                field, size);
  }
  inline bool Read32(uint64_t offset, uint32_t* dst) {
    return Read(offset, dst, sizeof(uint32_t));
  }
  inline bool Read64(uint64_t offset, uint64_t* dst) {
    return Read(offset, dst, sizeof(uint64_t));
  }
};

class MemoryFileAtOffset : public Memory {
 public:
  MemoryFileAtOffset() = default;
  virtual ~MemoryFileAtOffset();

  bool Init(const std::string& file, uint64_t offset);

  bool Read(uint64_t offset, void* dst, size_t size) override;

 private:
  size_t size_ = 0;
  size_t offset_ = 0;
  uint8_t* data_ = nullptr;
};

class MemoryMapRemote : public Memory {
 public:
  MemoryMapRemote() = default;
  virtual ~MemoryMapRemote() = default;

  bool Init(pid_t pid);

  bool Read(uint64_t offset, void* dst, size_t size) override;

 private:
  pid_t pid_ = 0;
};

class MemoryMapLocal : public MemoryMapRemote {
 public:
  MemoryMapLocal() = default;
  virtual ~MemoryMapLocal() = default;

  inline bool Init() { return MemoryMapRemote::Init(getpid()); }
};

#endif  // _LIBANDROID_UNWIND_MEMORY_H

