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
#include <unistd.h>

#include <memory>

#include <android-base/unique_fd.h>

#include "Memory.h"

MemoryFileAtOffset::~MemoryFileAtOffset() {
  if (data_) {
    munmap(data_, size_);
    data_ = nullptr;
  }
}

bool MemoryFileAtOffset::Init(const std::string& file, uint64_t offset) {
  android::base::unique_fd fd(TEMP_FAILURE_RETRY(open(file.c_str(), O_RDONLY)));
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

bool MemoryFileAtOffset::Read(uint64_t offset, void* dst, size_t size) {
  if (offset + size > size_ + offset_) {
    return false;
  }
  memcpy(dst, &data_[offset + offset_], size);
  return true;
}

bool MemoryMapLocal::Init() {
  fd_.reset(open("/proc/self/mem", O_RDONLY));
  return fd_ != -1;
}

bool MemoryMapLocal::Read(uint64_t offset, void* dst, size_t size) {
  if (TEMP_FAILURE_RETRY(lseek(fd_, offset, SEEK_SET)) == static_cast<off_t>(-1)) {
    return false;
  }
  ssize_t bytes = TEMP_FAILURE_RETRY(read(fd_, dst, size));
  return static_cast<size_t>(bytes) == size;
}
