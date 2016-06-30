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

constexpr bool kMemoryStatsEnabled = true;

class Memory {
 public:
  Memory() = default;
  virtual ~Memory() = default;

  virtual bool Read(uint64_t addr, void* dst, size_t size) = 0;

  inline bool Read(uint64_t addr, void* start, void* field, size_t size) {
    return Read(addr + reinterpret_cast<uintptr_t>(field) - reinterpret_cast<uintptr_t>(start),
                field, size);
  }
  inline bool Read32(uint64_t addr, uint32_t* dst) {
    return Read(addr, dst, sizeof(uint32_t));
  }
  inline bool Read64(uint64_t addr, uint64_t* dst) {
    return Read(addr, dst, sizeof(uint64_t));
  }

  uint64_t num_read_calls() { return num_read_calls_; }
  uint64_t bytes_read() { return bytes_read_; }

 protected:
  uint64_t num_read_calls_ = 0;
  uint64_t bytes_read_ = 0;
};

class MemoryFileAtOffset : public Memory {
 public:
  MemoryFileAtOffset() = default;
  virtual ~MemoryFileAtOffset();

  bool Init(const std::string& file, uint64_t offset);

  bool Read(uint64_t addr, void* dst, size_t size) override;

 protected:
  size_t size_ = 0;
  size_t offset_ = 0;
  uint8_t* data_ = nullptr;
};

class MemoryOffline : public MemoryFileAtOffset {
 public:
  MemoryOffline() = default;
  virtual ~MemoryOffline() = default;

  bool Init(const std::string& file, uint64_t offset);

  bool Read(uint64_t addr, void* dst, size_t size) override;

 private:
  uint64_t start_;
};

class MemoryByPid : public Memory {
 public:
  MemoryByPid(pid_t pid) : pid_(pid) {}
  virtual ~MemoryByPid() = default;

  bool Read(uint64_t addr, void* dst, size_t size) override;

 private:
  pid_t pid_ = 0;
};

class MemoryByPidRange : public MemoryByPid {
 public:
  MemoryByPidRange(pid_t pid, uint64_t begin, uint64_t end)
      : MemoryByPid(pid), begin_(begin), length_(end - begin_) {}
  virtual ~MemoryByPidRange() = default;

  inline bool Read(uint64_t addr, void* dst, size_t size) override {
    if (addr + size <= length_) {
      return MemoryByPid::Read(addr + begin_, dst, size);
    } else {
      num_read_calls_++;
    }
    return false;
  }

 private:
  uint64_t begin_;
  uint64_t length_;
};

#endif  // _LIBANDROID_UNWIND_MEMORY_H
