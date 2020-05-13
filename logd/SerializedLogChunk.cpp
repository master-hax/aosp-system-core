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

#include "SerializedLogChunk.h"

#include <android-base/logging.h>

#include "CompressionEngine.h"

void SerializedLogChunk::IncDecompressedRef() {
    if (++decompress_ref_count_ != 1) {
        return;
    }
    contents_.resize(write_position_);
    CompressionEngine::GetInstance().Decompress(compressed_log_, contents_);
}

void SerializedLogChunk::DecDecompressedRef() {
    CHECK(decompress_ref_count_ != 0);
    if (--decompress_ref_count_ != 0) {
        return;
    }
    if (compressed_log_.empty()) {
        CompressionEngine::GetInstance().Compress(contents_, write_position_, compressed_log_);
    }
    contents_.resize(0);
}

bool SerializedLogChunk::ClearUidLogs(uid_t uid) {
    CHECK(decompress_ref_count_ == 0);
    if (write_position_ == 0) {
        return true;
    }

    IncDecompressedRef();

    int read_position = 0;
    int new_write_position = 0;
    while (read_position < write_position_) {
        auto* element = reinterpret_cast<SerializedLogEntry*>(contents_.data() + read_position);
        if (element->uid() == uid) {
            read_position += element->total_len();
            continue;
        }
        size_t element_total_len = element->total_len();
        if (read_position != new_write_position) {
            memmove(contents_.data() + new_write_position, contents_.data() + read_position,
                    element_total_len);
        }
        read_position += element_total_len;
        new_write_position += element_total_len;
    }

    if (new_write_position == 0) {
        return true;
    }

    // Clear the old compressed logs and set write_position_ appropriately for DecDecompressedRef()
    // to compress the new partially cleared log.
    if (new_write_position != write_position_) {
        compressed_log_.clear();
        write_position_ = new_write_position;
    }

    DecDecompressedRef();
    return false;
}

bool SerializedLogChunk::CanLog(size_t len) {
    return write_position_ + len <= contents_.size();
}

SerializedLogEntry* SerializedLogChunk::Log(uint64_t sequence, log_time realtime, uid_t uid,
                                            pid_t pid, pid_t tid, const char* msg, uint16_t len) {
    auto new_log_position = contents_.data() + write_position_;
    auto* element =
            new (new_log_position) SerializedLogEntry(uid, pid, tid, sequence, realtime, len);
    memcpy(element->msg(), msg, len);
    write_position_ += element->total_len();
    highest_sequence_number_ = sequence;
    return element;
}