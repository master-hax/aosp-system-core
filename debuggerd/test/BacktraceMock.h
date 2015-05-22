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

#ifndef _DEBUGGERD_TEST_BACKTRACE_MOCK_H
#define _DEBUGGERD_TEST_BACKTRACE_MOCK_H

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ucontext.h>

#include <string>

#include <backtrace/Backtrace.h>
#include <backtrace/BacktraceMap.h>

class BacktraceMapMock : public BacktraceMap {
 public:
  BacktraceMapMock() : BacktraceMap(0) {}
  virtual ~BacktraceMapMock() {}
};


class BacktraceMock : public Backtrace {
 public:
  BacktraceMock(BacktraceMapMock* map) : Backtrace(0, 0, map) {
    if (map_ == nullptr) {
      abort();
    }
  }
  virtual ~BacktraceMock() {
    delete buffer_;
  }

  virtual bool Unwind(size_t, ucontext_t*) { return false; }
  virtual bool ReadWord(uintptr_t, word_t*) { return false;}

  virtual std::string GetFunctionNameRaw(uintptr_t, uintptr_t*) { return ""; }

  virtual size_t Read(uintptr_t addr, uint8_t* buffer, size_t bytes) {
    if (buffer_ == nullptr) {
      return 0;
    }
    size_t offset = 0;
    if (last_read_addr_ > 0) {
      offset = addr - last_read_addr_;
    }
    size_t bytes_available = bytes_total_ - offset;

    if (bytes_partial_read_ > 0) {
      // Do a partial read.
      if (bytes > bytes_partial_read_) {
        bytes = bytes_partial_read_;
      }
      bytes_partial_read_ -= bytes;
    } else if (bytes > bytes_available) {
      bytes = bytes_available;
    }

    if (bytes > 0) {
      memcpy(buffer, buffer_ + offset, bytes);
    }

    last_read_addr_ = addr;
    return bytes;
  }

  void SetReadData(uint8_t* buffer, size_t bytes) {
    if (buffer_) {
      delete[] buffer_;
    }
    buffer_ = new uint8_t[bytes];
    memcpy(buffer_, buffer, bytes);
    bytes_total_ = bytes;
    bytes_partial_read_ = 0;
    last_read_addr_ = 0;
  }

  void SetPartialReadAmount(size_t bytes) {
    if (bytes > bytes_total_) {
      abort();
    }
    bytes_partial_read_ = bytes;
  }

 private:
  uint8_t* buffer_ = nullptr;
  size_t bytes_total_ = 0;
  size_t bytes_partial_read_ = 0;
  uintptr_t last_read_addr_ = 0;
};

#endif //  _DEBUGGERD_TEST_BACKTRACE_MOCK_H
