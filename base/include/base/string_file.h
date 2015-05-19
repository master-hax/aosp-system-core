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

#ifndef BASE_STRING_FILE_H
#define BASE_STRING_FILE_H

#include <experimental/string_view>
#include <string>

#include "base/macros.h"
#include "base/random_access_file.h"

namespace android {
namespace base {

// A RandomAccessFile implementation backed by a string. (That is, all data is
// kept in memory.)
//
// Not thread safe.
class StringFile : public RandomAccessFile {
 public:
  StringFile();
  virtual ~StringFile();

  // RandomAccessFile API.
  bool Close() override;
  bool Flush() override;
  ssize_t Read(char* buf, size_t byte_count, off_t offset) const override;
  bool SetLength(off_t new_length) override;
  off_t GetLength() const override;
  ssize_t Write(const char* buf, size_t byte_count, off_t offset) override;

  // Bonus API.
  void Assign(const std::experimental::string_view& new_data);
  const std::experimental::string_view ToStringView() const;

 private:
  std::string data_;

  DISALLOW_COPY_AND_ASSIGN(StringFile);
};

}  // namespace base
}  // namespace android

#endif  // BASE_STRING_FILE_H
