/*
 * Copyright (C) 2015 The Android Open Source Project
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

#include "base/fd_file.h"

#include <errno.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "base/logging.h"

namespace android {
namespace base {

FdFile::FdFile() : fd_(-1) {
}

FdFile::FdFile(int fd) : fd_(fd) {
}

FdFile::~FdFile() {
  if (fd_ != -1) {
    Close();
  }
}

bool FdFile::Open(const std::string& path, int flags) {
  return Open(path, flags, 0640);
}

bool FdFile::Open(const std::string& path, int flags, mode_t mode) {
  CHECK_EQ(fd_, -1) << path;
  fd_ = TEMP_FAILURE_RETRY(open(path.c_str(), flags, mode));
  if (fd_ == -1) {
    return false;
  }
  file_path_ = path;
  return true;
}

bool FdFile::Close() {
  CHECK_NE(fd_, -1);
  if (close(fd_) == -1) {
    return false;
  }

  fd_ = -1;
  file_path_ = "";
  return true;
}

bool FdFile::Flush() {
  return TEMP_FAILURE_RETRY(fsync(fd_)) == 0;
}

ssize_t FdFile::Read(char* buf, size_t byte_count, off_t offset) const {
  return TEMP_FAILURE_RETRY(pread(fd_, buf, byte_count, offset));
}

bool FdFile::SetLength(off_t new_length) {
  return TEMP_FAILURE_RETRY(ftruncate(fd_, new_length)) == 0;
}

off_t FdFile::GetLength() const {
  struct stat s;
  if (TEMP_FAILURE_RETRY(fstat(fd_, &s)) == -1) {
    return -1;
  }

  return s.st_size;
}

ssize_t FdFile::Write(const char* buf, size_t byte_count, off_t offset) {
  return TEMP_FAILURE_RETRY(pwrite(fd_, buf, byte_count, offset));
}

int FdFile::fd() const {
  return fd_;
}

bool FdFile::is_opened() const {
  return fd_ >= 0;
}

std::string FdFile::file_path() const {
  return file_path_;
}

}  // namespace base
}  // namespace android
