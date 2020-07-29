// Copyright (C) 2019 The Android Open Source Project
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

#pragma once

#include <memory>

#include <libsnapshot/cow_format.h>

namespace android {
namespace snapshot {

class ICowOpIter;

// Interface for reading from a snapuserd COW.
class ICowReader {
  public:
    virtual ~ICowReader() {}

    // Return the file header.
    virtual bool GetHeader(CowHeader* header) = 0;

    // Return an iterator for retrieving CowOperation entries.
    virtual std::unique_ptr<ICowOpIter> GetOpIter() = 0;

    // Get raw bytes from the data section.
    virtual bool GetRawBytes(uint64_t offset, void* buffer, size_t len) = 0;
};

// Iterate over a sequence of COW operations.
class ICowOpIter {
  public:
    virtual ~ICowOpIter() {}

    // True if there are more items to read, false otherwise.
    virtual bool Done() = 0;

    // Read the current operation.
    virtual const CowOperation& Get() = 0;

    // Advance to the next item.
    virtual void Next() = 0;
};

class CowReader : public ICowReader {
  public:
    // Instantiate a COW reader; returns null if the file could not be read or
    // if the file format is corrupted.
    static std::unique_ptr<CowReader> New(android::base::unique_fd&& fd);
    static std::unique_ptr<CowReader> New(android::base::borrowed_fd fd);

    bool GetHeader(CowHeader* header) override;
    std::unique_ptr<ICowOpIter> GetOpIter() override;
    bool GetRawBytes(uint64_t offset, void* buffer, size_t len) override;

  private:
    CowReader(android::base::unique_fd&& owned_fd, android::base::borrowed_fd fd);

    bool Parse();

  private:
    android::base::unique_fd owned_fd_;
    android::base::borrowed_fd fd_;
    CowHeader header_;
    uint64_t fd_size_;
};

}  // namespace snapshot
}  // namespace android
