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

#include <stddef.h>

#include <vector>

namespace init {

// Abstract class used to provide a stream of bytes.
// This abstraction allows for different implementations,
// for example: from static buffers for unit tests or
// data from file descriptors.
// C++ streams are not used as they require a copy, this
// InputStream is zero copy and returns pointers into the
// orginal data.
class InputStream {
 public:
  InputStream() {}
  virtual ~InputStream() {}

  // Returns false if there is no data remaining.
  // Returned data is owned by this class. It must not
  // be used passed the lifetime of the InputStream.
  // It is only valid until the next call to GetData.
  virtual bool GetData(const void** data, size_t* size) = 0;
};

// InputStream for reading from files.
class FileInputStream : public InputStream {
 public:
  FileInputStream(int fd);
  ~FileInputStream();

  bool GetData(const void** data, size_t* size);
  static const size_t kBlockSize = 1024;

 private:
  int fd_;
  std::vector<char> buf_;
};

// InputStream for reading from existing buffers.
// Note: No copy is made, buffer must out live
// DataInputStream object.
class DataInputStream : public InputStream {
 public:
  DataInputStream(const void* data, size_t size);
  ~DataInputStream();

  bool GetData(const void** data, size_t* size);

 private:
  const void* data_;
  size_t size_;
  size_t pos_;
};

}  // namespace
