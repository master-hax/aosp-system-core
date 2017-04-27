#pragma once

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

#include "fdemu.h"

#include <sys/types.h>

#include <memory>
#include <mutex>
#include <vector>

#include <android-base/logging.h>
#include <android-base/thread_annotations.h>
#include <android-base/unique_fd.h>

namespace fdemu {

struct FDTable;
struct FileDescription;

struct FDEntry {
  enum class State {
    kEmpty,
    kAllocated,
    kPopulated,
  };

  State state = State::kEmpty;
  std::shared_ptr<FileDescription> value;
};

struct FDReservation {
  FDReservation(FDTable* table, FD fd) : table_(table), fd_(fd) {}
  ~FDReservation();

  FDReservation(const FDReservation& copy) = delete;
  FDReservation(FDReservation&& move) : FDReservation(move.table_, move.fd_) {
    move.table_ = nullptr;
    move.fd_ = FD::Invalid();
  }

  static FDReservation Invalid() { return FDReservation(nullptr, FD::Invalid()); }

  operator bool() const { return table_ != nullptr && fd_ != FD::Invalid(); }

  FD Populate(std::shared_ptr<FileDescription> description);

 private:
  FDTable* table_;
  FD fd_;
};

struct FDTable {
 public:
  FDTable(size_t size) : fds_(size), size_(size) { PreallocateStdio(); }

  std::mutex& Lock() RETURN_CAPABILITY(mutex_) {
    return mutex_;
  }

  bool IsValidFd(FD fd) {
    return fd.value >= 0 && static_cast<size_t>(fd.value) < size_;
  }

  const FDEntry& GetEntry(FD fd) REQUIRES(mutex_) {
    CHECK(IsValidFd(fd));
    return fds_[fd.value];
  }

  void UpdateEntry(FD fd, FDEntry entry) REQUIRES(mutex_) {
    CHECK(IsValidFd(fd));
    fds_[fd.value] = entry;
  }

  std::shared_ptr<FileDescription> GetFileDescription(FD fd) REQUIRES(mutex_);

  // Reserve a file descriptor slot and return an accessor class to it.
  FDReservation Allocate() EXCLUDES(mutex_);
  FDReservation AllocateLocked() REQUIRES(mutex_);

  // Implementations of file descriptor functions.
  int Close(FD fd) EXCLUDES(mutex_);
  FD Dup(FD fd) EXCLUDES(mutex_);
  FD Dup2(FD oldfd, FD newfd) EXCLUDES(mutex_);

  static FDTable& Global;

 private:
  // Preallocate 0, 1, and 2 for stdin, stdout, stderr.
  void PreallocateStdio() REQUIRES(mutex_);

  std::mutex mutex_;
  std::vector<FDEntry> fds_ GUARDED_BY(mutex_);
  const size_t size_;
};

// A FileDescription is the referent of one or more file descriptors.
struct FileDescription {
  FileDescription(FDTable& table) : table_(table) {}

  virtual ~FileDescription() {}

  virtual ssize_t read(char* buf, size_t len) = 0;
  virtual ssize_t write(const char* buf, size_t len) = 0;
  virtual ssize_t lseek(off_t offset, int whence) = 0;
  virtual int fstat(struct stat* st) = 0;

  virtual FD accept(struct sockaddr* addr, socklen_t* addrlen) = 0;
  virtual FD connect(struct sockaddr* addr, socklen_t addrlen) = 0;
  virtual int shutdown(int how) = 0;

  FDTable& table_;
};

#define FDEMU_FUNCTION(ret, name, ...) ret name(FDTable& table, __VA_ARGS__)
FDEMU_FUNCTIONS()
#undef FDEMU_FUNCTION

}  // namespace fdemu
