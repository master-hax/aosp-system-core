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
  Close();
}

bool FdFile::Open(const std::string &path, int flags) {
  return Open(path, flags, 0640);
}

bool FdFile::Open(const std::string &path, int flags, mode_t mode) {
  CHECK_EQ(fd_, -1) << path;
  LOG(DEBUG) << "Opening file '" << path << "'";
  fd_ = TEMP_FAILURE_RETRY(open(path.c_str(), flags, mode));
  if (fd_ == -1) {
    PLOG(ERROR) << "Failed to open file '" << path << "'";
    return false;
  }
  file_path_ = path;
  return true;
}

int FdFile::Close() {
  if (fd_ == -1) {
    LOG(INFO) << "File '" << file_path_ << "' is already closed.";
    return 0;
  }

  int result = close(fd_);  // Do not retry close() on EINTR.
  if (result == -1) {
    PLOG(WARNING) << "Failed closing file " << fd_ << " '" << file_path_ << "'";
    return -errno;
  } else {
    fd_ = -1;
    file_path_ = "";
    return 0;
  }
}

int FdFile::Flush() {
  int rc = TEMP_FAILURE_RETRY(fdatasync(fd_));
  return (rc == -1) ? -errno : rc;
}

ssize_t FdFile::Read(char *buf, size_t byte_count, off_t offset) const {
  ssize_t rc = TEMP_FAILURE_RETRY(pread(fd_, buf, byte_count, offset));
  return (rc == -1) ? -errno : rc;
}

int FdFile::SetLength(off_t new_length) {
  int rc = TEMP_FAILURE_RETRY(ftruncate(fd_, new_length));
  return (rc == -1) ? -errno : rc;
}

off_t FdFile::GetLength() const {
  struct stat s;
  int rc = TEMP_FAILURE_RETRY(fstat(fd_, &s));
  return (rc == -1) ? -errno : s.st_size;
}

ssize_t FdFile::Write(const char *buf, size_t byte_count, off_t offset) {
  ssize_t rc = TEMP_FAILURE_RETRY(pwrite(fd_, buf, byte_count, offset));
  return (rc == -1) ? -errno : rc;
}

int FdFile::fd() const {
  return fd_;
}

bool FdFile::is_opened() const {
  return fd_ != -1;
}

std::string FdFile::file_path() const {
  return file_path_;
}

}  // namespace base
}  // namespace android
