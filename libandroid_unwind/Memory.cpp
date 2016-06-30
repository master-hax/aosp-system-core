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
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <unistd.h>

#include <memory>

#include <android-base/unique_fd.h>

#include "Memory.h"

bool Memory::ReadString(uint64_t addr, std::string* string, uint64_t max_read) {
  string->clear();
  uint64_t bytes_read = 0;
  while (max_read == 0 || bytes_read < max_read) {
    uint8_t value;
    if (!Read(addr, &value, sizeof(value))) {
      return false;
    }
    if (value == '\0') {
      return true;
    }
    string->push_back(value);
    addr++;
    bytes_read++;
  }
  return false;
}

MemoryFileAtOffset::~MemoryFileAtOffset() {
  if (data_) {
    munmap(data_, size_);
    data_ = nullptr;
  }
}

bool MemoryFileAtOffset::Init(const std::string& file, uint64_t offset) {
  android::base::unique_fd fd(TEMP_FAILURE_RETRY(open(file.c_str(), O_RDONLY | O_CLOEXEC)));
  if (fd == -1) {
    return false;
  }
  struct stat buf;
  if (fstat(fd, &buf) == -1) {
    return false;
  }
  if (offset >= static_cast<uint64_t>(buf.st_size)) {
    return false;
  }

  offset_ = offset & (getpagesize() - 1);
  uint64_t aligned_offset = offset & ~(getpagesize() - 1);
  size_ = buf.st_size - aligned_offset;
  void* map = mmap(nullptr, size_, PROT_READ, MAP_PRIVATE, fd, aligned_offset);
  if (map == MAP_FAILED) {
    return false;
  }

  data_ = reinterpret_cast<uint8_t*>(map);

  return true;
}

bool MemoryFileAtOffset::Read(uint64_t addr, void* dst, size_t size) {
  num_read_calls_++;
  if (addr + size > offset_ + size_) {
    return false;
  }
  bytes_read_ += size;
  memcpy(dst, &data_[addr + offset_], size);
  return true;
}

bool MemoryByPid::Read(uint64_t addr, void* dst, size_t size) {
  struct iovec local_io;
  local_io.iov_base = dst;
  local_io.iov_len = size;

  struct iovec remote_io;
  remote_io.iov_base = reinterpret_cast<void*>(static_cast<uintptr_t>(addr));
  remote_io.iov_len = size;

  num_read_calls_++;
  ssize_t bytes_read = process_vm_readv(pid_, &local_io, 1, &remote_io, 1, 0);
  if (bytes_read == -1) {
    return false;
  }
  bytes_read_ += static_cast<size_t>(bytes_read);
  return static_cast<size_t>(bytes_read) == size;
}

bool MemoryOffline::Init(const std::string& file, uint64_t offset) {
  if (!MemoryFileAtOffset::Init(file, offset)) {
    return false;
  }
  // The first uint64_t value is the start of memory.
  if (!MemoryFileAtOffset::Read(0, &start_, sizeof(start_))) {
    return false;
  }
  // Subtract the first 64 bit value from the total size.
  size_ -= sizeof(start_);
  return true;
}

bool MemoryOffline::Read(uint64_t addr, void* dst, size_t size) {
  num_read_calls_++;
  if (addr < start_ || addr + size > start_ + offset_ + size_) {
    return false;
  }
  bytes_read_ += size;
  memcpy(dst, &data_[addr + offset_ - start_ + sizeof(start_)], size);
  return true;
}
