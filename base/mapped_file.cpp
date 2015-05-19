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

#include "base/mapped_file.h"

#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <algorithm>
#include <string>

#include "base/logging.h"

namespace android {
namespace base {

MappedFile::~MappedFile() {
  Close();
}

int MappedFile::Close() {
  if (is_mapped()) {
    Unmap();
  }
  return FdFile::Close();
}

bool MappedFile::MapReadOnly() {
  CHECK(is_opened());
  CHECK(!is_mapped());
  struct stat st;
  int result = TEMP_FAILURE_RETRY(fstat(fd(), &st));
  if (result == -1) {
    PLOG(WARNING) << "Failed to stat file '" << file_path() << "'";
    return false;
  }
  file_size_ = st.st_size;
  do {
    mapped_file_ = mmap(NULL, file_size_, PROT_READ, MAP_PRIVATE, fd(), 0);
  } while (mapped_file_ == MAP_FAILED && errno == EINTR);
  if (mapped_file_ == MAP_FAILED) {
    PLOG(WARNING) << "Failed to mmap file '" << file_path() << "' of size "
                  << file_size_ << " bytes to memory";
    return false;
  }
  map_mode_ = kMapReadOnly;
  LOG(DEBUG) << "Mapped read-only file '" << file_path() << "' of size "
             << file_size_ << " bytes to memory";
  return true;
}

bool MappedFile::MapReadWrite(off_t file_size) {
  CHECK(is_opened());
  CHECK(!is_mapped());
  int result = TEMP_FAILURE_RETRY(ftruncate(fd(), file_size));
  if (result == -1) {
    PLOG(ERROR) << "Failed to truncate file '" << file_path()
                << "' to size " << file_size;
    return false;
  }
  file_size_ = file_size;
  do {
    mapped_file_ =
        mmap(NULL, file_size_, PROT_READ | PROT_WRITE, MAP_SHARED, fd(), 0);
  } while (mapped_file_ == MAP_FAILED && errno == EINTR);
  if (mapped_file_ == MAP_FAILED) {
    PLOG(WARNING) << "Failed to mmap file '" << file_path() << "' of size "
                  << file_size_ << " bytes to memory";
    return false;
  }
  map_mode_ = kMapReadWrite;
  LOG(DEBUG) << "Mapped read-write file '" << file_path() << "' of size "
             << file_size << " bytes to memory";
  return true;
}

bool MappedFile::Unmap() {
  CHECK(is_mapped());
  int result = TEMP_FAILURE_RETRY(munmap(mapped_file_, file_size_));
  if (result == -1) {
    PLOG(WARNING) << "Failed unmap file '" << file_path() << "' of size "
                  << file_size_;
    return false;
  } else {
    LOG(DEBUG) << "Unmapped file '" << file_path() << "' of size " << file_size_;
    mapped_file_ = NULL;
    file_size_ = -1;
    return true;
  }
}

ssize_t MappedFile::Read(char* buf, size_t byte_count, off_t offset) const {
  if (is_mapped()) {
    if (offset < 0) {
      errno = EINVAL;
      return -errno;
    }
    ssize_t read_size =
        std::max(static_cast<off_t>(0),
                 std::min(static_cast<off_t>(byte_count), file_size_ - offset));
    if (read_size > 0) {
      memcpy(buf, data() + offset, read_size);
    }
    return read_size;
  } else {
    return FdFile::Read(buf, byte_count, offset);
  }
}

int MappedFile::SetLength(off_t new_length) {
  CHECK(!is_mapped());
  return FdFile::SetLength(new_length);
}

off_t MappedFile::GetLength() const {
  if (is_mapped()) {
    return file_size_;
  } else {
    return FdFile::GetLength();
  }
}

int MappedFile::Flush() {
  int rc = is_mapped() ?
      TEMP_FAILURE_RETRY(msync(mapped_file_, file_size_, 0)) : FdFile::Flush();
  return rc == -1 ? -errno : 0;
}

ssize_t MappedFile::Write(const char* buf, size_t byte_count, off_t offset) {
  if (is_mapped()) {
    CHECK_EQ(kMapReadWrite, map_mode_);
    if (offset < 0) {
      errno = EINVAL;
      return -errno;
    }
    ssize_t write_size =
        std::max(static_cast<off_t>(0),
                 std::min(static_cast<off_t>(byte_count), file_size_ - offset));
    if (write_size > 0) {
      memcpy(data() + offset, buf, write_size);
    }
    return write_size;
  } else {
    return FdFile::Write(buf, byte_count, offset);
  }
}

bool MappedFile::is_mapped() const {
  return mapped_file_ != NULL && mapped_file_ != MAP_FAILED;
}

char* MappedFile::data() const {
  CHECK(is_mapped());
  return static_cast<char*>(mapped_file_);
}

}  // namespace base
}  // namespace android
