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

#include "base/null_file.h"

#include <errno.h>

namespace android {
namespace base {

NullFile::NullFile() {
}

NullFile::~NullFile() {
}

int NullFile::Close() {
  return 0;
}

int NullFile::Flush() {
  return 0;
}

ssize_t NullFile::Read(char*, size_t, off_t offset) const {
  if (offset < 0) {
    return -EINVAL;
  }
  return 0;
}

int NullFile::SetLength(off_t new_length) {
  if (new_length < 0) {
    return -EINVAL;
  }
  return 0;
}

off_t NullFile::GetLength() const {
  return 0;
}

ssize_t NullFile::Write(const char*, size_t byte_count, off_t offset) {
  if (offset < 0) {
    return -EINVAL;
  }
  return byte_count;
}

}  // namespace base
}  // namespace android
