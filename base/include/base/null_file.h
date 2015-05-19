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

#ifndef BASE_NULL_FILE_H
#define BASE_NULL_FILE_H

#include "base/macros.h"
#include "base/random_access_file.h"

namespace android {
namespace base {

// A RandomAccessFile implementation equivalent to /dev/null. Writes are
// discarded, and there's no data to be read. Callers could use FdFile in
// conjunction with /dev/null, but that's not portable and costs a file
// descriptor. NullFile is "free".
//
// Thread safe.
class NullFile : public RandomAccessFile {
 public:
  NullFile();
  virtual ~NullFile();

  // RandomAccessFile API.
  int Close() override;
  int Flush() override;
  ssize_t Read(char* buf, size_t byte_count, off_t offset) const override;
  int SetLength(off_t new_length) override;
  off_t GetLength() const override;
  ssize_t Write(const char* buf, size_t byte_count, off_t offset) override;

 private:
  DISALLOW_COPY_AND_ASSIGN(NullFile);
};

}  // namespace base
}  // namespace android

#endif  // BASE_NULL_FILE_H
