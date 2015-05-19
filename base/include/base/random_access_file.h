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

#ifndef BASE_RANDOM_ACCESS_FILE_H
#define BASE_RANDOM_ACCESS_FILE_H

#if defined(_WIN32)
#error "RandomAccessFile is not supported on Windows."
#endif

#include <sys/types.h>

static_assert(sizeof(off_t) == 8,
              "RandomAccessFile uses a 64-bit off_t. Use _FILE_OFFSET_BITS=64");

namespace android {
namespace base {

// A file interface supporting random-access reading and writing of content,
// along with the ability to set the length of a file (smaller or greater than
// its current extent).
//
// This interface does not support a stream position (i.e. every read or write
// must specify an offset). This interface does not imply any buffering policy.
//
// All operations return >= 0 on success or -errno on failure.
//
// Implementations never return EINTR; callers are spared the need to manually
// retry interrupted operations.
//
// Any concurrent access to files should be externally synchronized.
class RandomAccessFile {
 public:
  virtual ~RandomAccessFile() { }

  virtual int Close() = 0;

  // Reads 'byte_count' bytes into 'buf' starting at offset 'offset' in the
  // file. Returns the number of bytes actually read.
  virtual ssize_t Read(char* buf, size_t byte_count, off_t offset) const = 0;

  // Sets the length of the file to 'new_length'. If this is smaller than the
  // file's current extent, data is discarded. If this is greater than the
  // file's current extent, it is as if a write of the relevant number of zero
  // bytes occurred. Returns 0 on success.
  virtual int SetLength(off_t new_length) = 0;

  // Returns the current size of this file.
  virtual off_t GetLength() const = 0;

  // Writes 'byte_count' bytes from 'buf' starting at offset 'offset' in the
  // file. Zero-byte writes are acceptable, and writes past the end are as if
  // a write of the relevant number of zero bytes also occurred. Returns the
  // number of bytes actually written.
  virtual ssize_t Write(const char* buf, size_t byte_count, off_t offset) = 0;

  // Flushes file data.
  virtual int Flush() = 0;
};

}  // namespace base
}  // namespace android

#endif  // BASE_RANDOM_ACCESS_FILE_H
