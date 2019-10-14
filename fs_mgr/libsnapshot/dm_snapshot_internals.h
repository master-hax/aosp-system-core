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

#include <cstdint>
#include <vector>

namespace android {
namespace snapshot {

class DmSnapCowSizeCalculator {
  public:
    DmSnapCowSizeCalculator(unsigned int sector_bytes, unsigned int chunk_sectors)
        : sector_bytes_(sector_bytes),
          chunk_sectors_(chunk_sectors),
          exceptions_per_chunk(chunk_sectors_ * sector_bytes_ / (64 * 2 / 8)) {}

    void WriteByte(uint64_t address) { WriteSector(address / sector_bytes_); }
    void WriteSector(uint64_t sector) { WriteChunk(sector / chunk_sectors_); }
    void WriteChunk(uint64_t chunk_id) {
        if (modified_chunks_.size() <= chunk_id) {
            modified_chunks_.resize(chunk_id + 1, false);
        }
        modified_chunks_[chunk_id] = true;
    }

    uint64_t cow_size_bytes() const { return cow_size_sectors() * sector_bytes_; }
    uint64_t cow_size_sectors() const { return cow_size_chunks() * chunk_sectors_; }
    uint64_t cow_size_chunks() const {
        uint64_t modified_chunks_count = 0;
        uint64_t cow_chunks = 0;

        for (const auto& c : modified_chunks_) {
            if (c) ++modified_chunks_count;
        }

        /* disk header + padding = 1 chunk */
        cow_chunks += 1;

        /* snapshot modified chunks */
        cow_chunks += modified_chunks_count;

        /* snapshot chunks index metadata */
        cow_chunks += 1 + modified_chunks_count / exceptions_per_chunk;

        return cow_chunks;
    }

  private:
    const uint64_t sector_bytes_;
    const uint64_t chunk_sectors_;
    const uint64_t exceptions_per_chunk;
    std::vector<bool> modified_chunks_;
};

}  // namespace snapshot
}  // namespace android
