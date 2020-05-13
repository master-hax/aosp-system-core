/*
 * Copyright (C) 2020 The Android Open Source Project
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

#pragma once

#include <sys/types.h>

#include <vector>

#include "LogWriter.h"
#include "SerializedLogEntry.h"

class SerializedLogChunk {
  public:
    SerializedLogChunk(size_t size) : contents_(size) {}

    void IncDecompressedRef();
    void DecDecompressedRef();

    // Must have no readers referencing this.  Return true if there are no logs.
    bool ClearUidLogs(uid_t uid);

    bool CanLog(size_t len);
    SerializedLogEntry* Log(uint64_t sequence, log_time realtime, uid_t uid, pid_t pid, pid_t tid,
                            const char* msg, uint16_t len);

    // If this buffer has been compressed, we only consider its compressed size when accounting for
    // memory consumption for pruning.  This is since the uncompressed log is only by used by
    // readers, and thus not a representation of how much these logs cost to keep in memory.
    size_t PruneSize() const { return compressed_log_.size() ?: contents_.size(); }

    const uint8_t* data() const { return contents_.data(); }
    int write_position() const { return write_position_; }
    uint64_t highest_sequence_number() const { return highest_sequence_number_; }

  private:
    // The decompressed contents of this log buffer.  Deallocated when the ref_count reaches 0.
    std::vector<uint8_t> contents_;
    int write_position_ = 0;
    uint32_t decompress_ref_count_ = 1;
    uint64_t highest_sequence_number_ = 1;
    std::vector<uint8_t> compressed_log_;
};
