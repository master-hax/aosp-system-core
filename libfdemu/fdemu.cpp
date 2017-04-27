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

#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <limits>
#include <memory>
#include <mutex>
#include <vector>

#include <android-base/logging.h>

#include "fdemu.h"
#include "fdemu-internal.h"

namespace fdemu {

static constexpr size_t kDefaultFDTableSize = 1024;

FDTable& FDTable::Global = *new FDTable(kDefaultFDTableSize);

std::shared_ptr<FileDescription> FDTable::GetFileDescription(FD fd) {
  if (!IsValidFd(fd)) {
    errno = EBADF;
    return nullptr;
  }

  const FDEntry& entry = GetEntry(fd);
  switch (entry.state) {
    case FDEntry::State::kEmpty:
    case FDEntry::State::kAllocated:
      errno = EBADF;
      return nullptr;

    case FDEntry::State::kPopulated:
      return entry.value;
  }

  abort();
}

FDReservation FDTable::Allocate() {
  std::lock_guard<std::mutex> lock(Lock());
  return AllocateLocked();
}

FDReservation FDTable::AllocateLocked() {
  // TODO: Keep track of the lowest available FD.
  for (size_t i = 0; i < size_; ++i) {
    if (fds_[i].state == FDEntry::State::kEmpty) {
      CHECK(fds_[i].value == nullptr);
      fds_[i].state = FDEntry::State::kAllocated;
      return FDReservation(this, FD(i));
    }
  }

  errno = ENFILE;
  return FDReservation::Invalid();
}

int FDTable::Close(FD fd) {
  std::lock_guard<std::mutex> lock(Lock());
  const FDEntry& entry = GetEntry(fd);
  switch (entry.state) {
    case FDEntry::State::kEmpty:
    case FDEntry::State::kAllocated:
      // Nothing was there, or nothing is there yet.
      errno = EBADF;
      return -1;

    case FDEntry::State::kPopulated:
      FDEntry new_entry;
      new_entry.state = FDEntry::State::kEmpty;
      new_entry.value = nullptr;
      UpdateEntry(fd, new_entry);
      return 0;
  }

  abort();
}

FD FDTable::Dup(FD fd) {
  if (!IsValidFd(fd)) {
    errno = EBADF;
    return FD::Invalid();
  }

  std::lock_guard<std::mutex> lock(Lock());
  FDReservation slot = AllocateLocked();
  if (!slot) {
    return FD::Invalid();
  }

  std::shared_ptr<FileDescription> desc = GetFileDescription(fd);
  if (!desc) {
    return FD::Invalid();
  }
  return slot.Populate(std::move(desc));
}

FD FDTable::Dup2(FD oldfd, FD newfd) {
  if (!IsValidFd(oldfd) || !IsValidFd(newfd)) {
    errno = EBADF;
    return FD::Invalid();
  }

  std::lock_guard<std::mutex> lock(Lock());
  std::shared_ptr<FileDescription> desc = GetFileDescription(oldfd);
  if (!desc) {
    return FD::Invalid();
  }

  FDEntry new_entry;
  new_entry.state = FDEntry::State::kPopulated;
  new_entry.value = std::move(desc);
  UpdateEntry(newfd, new_entry);
  return newfd;
}

FDReservation::~FDReservation() {
  if (!table_) {
    CHECK(fd_ == FD::Invalid());
    return;
  }

  std::lock_guard<std::mutex> lock(table_->Lock());
  const FDEntry& entry = table_->GetEntry(fd_);
  CHECK(entry.state != FDEntry::State::kEmpty);
  if (entry.state == FDEntry::State::kAllocated) {
    CHECK(entry.value == nullptr);
    FDEntry new_entry;
    new_entry.state = FDEntry::State::kEmpty;
    new_entry.value = nullptr;
    table_->UpdateEntry(fd_, new_entry);
  } else {
    CHECK(entry.state == FDEntry::State::kPopulated);
    CHECK(entry.value != nullptr);
  }
}

FD FDReservation::Populate(std::shared_ptr<FileDescription> description) {
  std::lock_guard<std::mutex> lock(table_->Lock());
  const FDEntry& entry = table_->GetEntry(fd_);
  CHECK(entry.state == FDEntry::State::kAllocated);
  CHECK(entry.value == nullptr);

  FDEntry new_entry;
  new_entry.state = FDEntry::State::kPopulated;
  new_entry.value = description;
  table_->UpdateEntry(fd_, new_entry);
  return fd_;
}

// Exported implementations of fdemu functions.
int close(FD fd) {
  return close(FDTable::Global, fd);
}

int close(FDTable& table, FD fd) {
  return table.Close(fd);
}

FD dup(FD fd) {
  return dup(FDTable::Global, fd);
}

FD dup(FDTable& table, FD fd) {
  return table.Dup(fd);
}

FD dup2(FD oldfd, FD newfd) {
  return dup2(FDTable::Global, oldfd, newfd);
}

FD dup2(FDTable& table, FD oldfd, FD newfd) {
  return table.Dup2(oldfd, newfd);
}

// The implementation of open(FDTable&, const char*, ...) is in platform-specific sysdeps files.

FD open(const char* path, int flags, ...) {
  va_list ap;
  va_start(ap, flags);
  int mode = va_arg(ap, int);
  return open(FDTable::Global, path, flags, mode);
}

ssize_t read(FD fd, char* buf, size_t len) {
  return read(FDTable::Global, fd, buf, len);
}

ssize_t read(FDTable& table, FD fd, char* buf, size_t len) {
  std::lock_guard<std::mutex> lock(table.Lock());
  std::shared_ptr<FileDescription> desc = table.GetFileDescription(fd);
  if (!desc) {
    return -1;
  }
  return desc->read(buf, len);
}

ssize_t write(FD fd, const char* buf, size_t len) {
  return write(FDTable::Global, fd, buf, len);
}

ssize_t write(FDTable& table, FD fd, const char* buf, size_t len) {
  std::lock_guard<std::mutex> lock(table.Lock());
  std::shared_ptr<FileDescription> desc = table.GetFileDescription(fd);
  if (!desc) {
    return -1;
  }
  return desc->write(buf, len);
}

}  // namespace fdemu
