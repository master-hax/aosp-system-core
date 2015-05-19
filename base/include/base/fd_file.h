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

#ifndef BASE_FD_FILE_H
#define BASE_FD_FILE_H

#include <fcntl.h>

#include <string>

#include "base/random_access_file.h"
#include "base/macros.h"

namespace android {
namespace base {

// A RandomAccessFile implementation backed by a file descriptor.
//
// Not thread safe.
class FdFile : public RandomAccessFile {
 public:
  FdFile();
  // Creates an FdFile using the given file descriptor. Takes ownership of the
  // file descriptor.
  explicit FdFile(int fd);

  // Destroys an FdFile, closing the file descriptor if Close hasn't already
  // been called. (If you care about the return value of Close, call it
  // yourself; this is meant to handle failure cases and read-only accesses.
  // Note though that calling Close and checking its return value is still no
  // guarantee that data actually made it to stable storage.)
  virtual ~FdFile();

  // Opens file 'file_path' using 'flags' and 'mode'.
  bool Open(const std::string& file_path, int flags);
  bool Open(const std::string& file_path, int flags, mode_t mode);

  // RandomAccessFile API.
  int Close() override;
  ssize_t Read(char* buf, size_t byte_count, off_t offset) const override;
  int SetLength(off_t new_length) override;
  off_t GetLength() const override;
  ssize_t Write(const char* buf, size_t byte_count, off_t offset) override;
  int Flush() override;

  // Bonus API.
  int fd() const;
  bool is_opened() const;
  std::string file_path() const;

 private:
  int fd_;
  std::string file_path_;

  DISALLOW_COPY_AND_ASSIGN(FdFile);
};

}  // namespace base
}  // namespace android

#endif  // BASE_FD_FILE_H
