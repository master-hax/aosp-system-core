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

#ifndef BASE_MAPPED_FILE_H
#define BASE_MAPPED_FILE_H

#include <fcntl.h>

#include <string>

#include "base/fd_file.h"

namespace android {
namespace base {

// Random access file which handles an mmap(2), munmap(2) pair in C++
// RAII style. When a file is mmapped, the random access file
// interface accesses the mmapped memory directly; otherwise, the
// standard file I/O is used. Whenever a function fails, it returns
// false and errno is set to the corresponding error code.
class MappedFile : public FdFile {
 public:
  // File modes used in Open().
  enum FileMode {
    kReadOnlyMode = O_RDONLY,
    kReadWriteMode = O_CREAT | O_RDWR,
  };

  MappedFile() : FdFile(), file_size_(-1), mapped_file_(NULL) {
  }
  // Creates a MappedFile using the given file descriptor. Takes ownership of
  // the file descriptor.
  explicit MappedFile(int fd) : FdFile(fd), file_size_(-1), mapped_file_(NULL) {
  }

  // Unmaps and closes the file if needed, ignoring any failures.
  virtual ~MappedFile();

  // Maps an opened file to memory in the read-only mode.
  bool MapReadOnly();

  // Maps an opened file to memory in the read-write mode. Before the
  // file is mapped, it is truncated to 'file_size' bytes.
  bool MapReadWrite(off_t file_size);

  // Unmaps a mapped file so that, e.g., SetLength() may be invoked.
  bool Unmap();

  // RandomAccessFile API.
  // The functions below require that the file is open, but it doesn't
  // have to be mapped.
  int Close() override;
  ssize_t Read(char* buf, size_t byte_count, off_t offset) const override;
  // SetLength() requires that the file is not mmapped.
  int SetLength(off_t new_length) override;
  off_t GetLength() const override;
  int Flush() override;
  // Write() requires that, if the file is mmapped, it is mmapped in
  // the read-write mode. Writes past the end of file are discarded.
  ssize_t Write(const char* buf, size_t byte_count, off_t offset) override;

  // Returns true if the file has been mmapped.
  bool is_mapped() const;

  // Returns a pointer to the start of the memory mapping once the
  // file is successfully mapped; crashes otherwise.
  char* data() const;

 private:
  enum MapMode {
    kMapReadOnly = 1,
    kMapReadWrite = 2,
  };

  mutable off_t file_size_;  // May be updated in GetLength().
  void* mapped_file_;
  MapMode map_mode_;

  DISALLOW_COPY_AND_ASSIGN(MappedFile);
};

}  // namespace base
}  // namespace android

#endif  // BASE_MAPPED_FILE_H
