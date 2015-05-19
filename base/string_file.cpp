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

#include "base/string_file.h"

#include <errno.h>

#include <algorithm>

#include "base/logging.h"

namespace android {
namespace base {

StringFile::StringFile() {
}

StringFile::~StringFile() {
}

int StringFile::Close() {
  return 0;
}

int StringFile::Flush() {
  return 0;
}

ssize_t StringFile::Read(char* buf, size_t byte_count, off_t offset) const {
  CHECK(buf);

  if (offset < 0) {
    return -EINVAL;
  }

  const ssize_t available_bytes =
      std::min(static_cast<off_t>(byte_count), GetLength() - offset);
  if (available_bytes < 0) {
    return 0;  // Not an error, but nothing for us to do, either.
  }
  memcpy(buf, data_.data() + offset, available_bytes);
  return available_bytes;
}

int StringFile::SetLength(off_t new_length) {
  if (new_length < 0) {
    return -EINVAL;
  }
  data_.resize(new_length);
  return 0;
}

off_t StringFile::GetLength() const {
  return data_.size();
}

ssize_t StringFile::Write(const char* buf, size_t byte_count, off_t offset) {
  CHECK(buf);

  if (offset < 0) {
    return -EINVAL;
  }

  if (byte_count == 0) {
    return 0;
  }

  // FUSE seems happy to allow writes past the end. (I'd guess it doesn't
  // synthesize a write of zero bytes so that we're free to implement sparse
  // files.) GNU as(1) seems to require such writes. Those files are small.
  const off_t bytes_past_end = offset - GetLength();
  if (bytes_past_end > 0) {
    data_.append(bytes_past_end, '\0');
  }

  data_.replace(offset, byte_count, buf, byte_count);
  return byte_count;
}

void StringFile::Assign(const std::experimental::string_view& new_data) {
  data_.assign(new_data.data(), new_data.size());
}

const std::experimental::string_view StringFile::ToStringView() const {
  return data_;
}

}  // namespace base
}  // namespace android
