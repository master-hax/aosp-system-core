// Copyright (C) 2015 The Android Open Source Project
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "input_stream.h"

#include <stdio.h>
#include <unistd.h>

namespace init {

// ---- FileInputStream ----

FileInputStream::FileInputStream(int fd) : fd_(fd), buf_(kBlockSize) {}

FileInputStream::~FileInputStream() {}

bool FileInputStream::GetData(const void** data, size_t* size) {
  ssize_t bytes_read = read(fd_, &buf_[0], kBlockSize);
  if (bytes_read <= 0) {
    // EOF or error
    return false;
  }
  *data = &buf_[0];
  *size = bytes_read;
  return true;
}

// ---- DataInputStream ----

DataInputStream::DataInputStream(const void* data, size_t size)
    : data_(data), size_(size), pos_(0) {}

DataInputStream::~DataInputStream() {}

bool DataInputStream::GetData(const void** data, size_t* size) {
  // TODO(leecam): debug assert data and size pointers
  if (pos_ < size_) {
    // Just return everything in first call to GetData
    *data = data_;
    *size = size_;
    pos_ += size_;
    return true;
  }
  return false;
}

}  // namespace init