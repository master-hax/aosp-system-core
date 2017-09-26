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
#include <sys/ptrace.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>

#include <algorithm>
#include <memory>

#include <android-base/unique_fd.h>

#include <unwindstack/Memory.h>

#include "Check.h"

static ssize_t PartialReadHelper(const void* src_base, size_t src_len, uint64_t offset, void* dst,
                                 size_t len) {
  if (offset >= src_len) {
    errno = EFAULT;
    return -1;
  }

  size_t bytes_left = src_len - static_cast<size_t>(offset);
  const char* actual_base = static_cast<const char*>(src_base) + offset;
  size_t actual_len = std::min(bytes_left, len);

  memcpy(dst, actual_base, actual_len);
  return actual_len;
}

static ssize_t ProcessVmRead(pid_t pid, void* dst, const void* remote_src, size_t len) {
  struct iovec dst_iov = {
    .iov_base = dst,
    .iov_len = len,
  };

  // Split up the remote read across page boundaries.
  // From the manpage:
  //   A partial read/write may result if one of the remote_iov elements points to an invalid
  //   memory region in the remote process.
  //
  //   Partial transfers apply at the granularity of iovec elements.  These system calls won't
  //   perform a partial transfer that splits a single iovec element.
  constexpr size_t kMaxIovecs = 64;
  struct iovec src_iovs[kMaxIovecs];
  size_t iovecs_used = 0;

  const char* cur = static_cast<const char*>(remote_src);
  while (len > 0) {
    if (iovecs_used == kMaxIovecs) {
      errno = EINVAL;
      return -1;
    }

    src_iovs[iovecs_used].iov_base = const_cast<char*>(cur);

    uintptr_t addr = reinterpret_cast<uint64_t>(cur);
    uintptr_t misalignment = addr & (getpagesize() - 1);
    src_iovs[iovecs_used].iov_len = getpagesize() - misalignment;
    src_iovs[iovecs_used].iov_len = std::min(src_iovs[iovecs_used].iov_len, len);

    len -= src_iovs[iovecs_used].iov_len;
    cur += src_iovs[iovecs_used].iov_len;
    ++iovecs_used;
  }

  return process_vm_readv(pid, &dst_iov, 1, src_iovs, iovecs_used, 0);
}

namespace unwindstack {

bool Memory::Read(uint64_t addr, void* dst, size_t size) {
  ssize_t rc = PartialRead(addr, dst, size);
  if (rc == -1) {
    return false;
  }

  return static_cast<size_t>(rc) == size;
}

bool Memory::ReadString(uint64_t addr, std::string* string, uint64_t max_read) {
  string->clear();
  uint64_t bytes_read = 0;
  while (bytes_read < max_read) {
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

std::shared_ptr<Memory> Memory::CreateProcessMemory(pid_t pid) {
  if (pid == getpid()) {
    return std::shared_ptr<Memory>(new MemoryLocal());
  }
  return std::shared_ptr<Memory>(new MemoryRemote(pid));
}

ssize_t MemoryBuffer::PartialRead(uint64_t addr, void* dst, size_t size) {
  return PartialReadHelper(raw_.data(), raw_.size(), addr, dst, size);
}

uint8_t* MemoryBuffer::GetPtr(size_t offset) {
  if (offset < raw_.size()) {
    return &raw_[offset];
  }
  return nullptr;
}

MemoryFileAtOffset::~MemoryFileAtOffset() {
  Clear();
}

void MemoryFileAtOffset::Clear() {
  if (data_) {
    munmap(&data_[-offset_], size_ + offset_);
    data_ = nullptr;
  }
}

bool MemoryFileAtOffset::Init(const std::string& file, uint64_t offset, uint64_t size) {
  // Clear out any previous data if it exists.
  Clear();

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
  if (aligned_offset > static_cast<uint64_t>(buf.st_size) ||
      offset > static_cast<uint64_t>(buf.st_size)) {
    return false;
  }

  size_ = buf.st_size - aligned_offset;
  uint64_t max_size;
  if (!__builtin_add_overflow(size, offset_, &max_size) && max_size < size_) {
    // Truncate the mapped size.
    size_ = max_size;
  }
  void* map = mmap(nullptr, size_, PROT_READ, MAP_PRIVATE, fd, aligned_offset);
  if (map == MAP_FAILED) {
    return false;
  }

  data_ = &reinterpret_cast<uint8_t*>(map)[offset_];
  size_ -= offset_;

  return true;
}

ssize_t MemoryFileAtOffset::PartialRead(uint64_t addr, void* dst, size_t size) {
  return PartialReadHelper(data_, size_, addr, dst, size);
}

ssize_t MemoryRemote::PartialRead(uint64_t addr, void* dst, size_t size) {
  if (addr > UINTPTR_MAX) {
    errno = EOVERFLOW;
    return -1;
  }

  return ProcessVmRead(pid_, dst, reinterpret_cast<void*>(addr), size);
}

ssize_t MemoryLocal::PartialRead(uint64_t addr, void* dst, size_t size) {
  return ProcessVmRead(getpid(), dst, reinterpret_cast<void*>(addr), size);
}

MemoryRange::MemoryRange(const std::shared_ptr<Memory>& memory, uint64_t begin, uint64_t end)
    : memory_(memory), begin_(begin), length_(end - begin) {
  CHECK(end > begin);
}

ssize_t MemoryRange::PartialRead(uint64_t addr, void* dst, size_t size) {
  if (addr > length_) {
    errno = EOVERFLOW;
    return -1;
  }

  uint64_t end;
  if (__builtin_add_overflow(addr, size, &end)) {
    errno = EOVERFLOW;
    return -1;
  }

  end = std::min(end, length_);
  size = end - addr;

  uint64_t shifted_addr;
  if (__builtin_add_overflow(addr, begin_, &shifted_addr)) {
    errno = EOVERFLOW;
    return -1;
  }

  return memory_->PartialRead(shifted_addr, dst, size);
}

bool MemoryOffline::Init(const std::string& file, uint64_t offset) {
  auto memory_file = std::make_shared<MemoryFileAtOffset>();
  if (!memory_file->Init(file, offset)) {
    return false;
  }

  // The first uint64_t value is the start of memory.
  uint64_t start;
  if (!memory_file->Read(0, &start, sizeof(start))) {
    return false;
  }

  uint64_t size = memory_file->Size();
  if (__builtin_sub_overflow(size, sizeof(start), &size) ||
      __builtin_sub_overflow(size, start, &size)) {
    return false;
  }

  memory_ = std::make_unique<MemoryRange>(memory_file, start, memory_file->Size());
  return true;
}

ssize_t MemoryOffline::PartialRead(uint64_t addr, void* dst, size_t size) {
  if (!memory_) {
    errno = EBADF;
    return -1;
  }

  return memory_->PartialRead(addr, dst, size);
}

}  // namespace unwindstack
