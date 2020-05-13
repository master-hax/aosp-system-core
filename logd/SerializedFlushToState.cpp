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

#include "SerializedFlushToState.h"

#include <android-base/logging.h>

SerializedFlushToState::SerializedFlushToState(uint64_t start, LogMask log_mask,
                                               std::list<SerializedLogChunk>* logs)
    : FlushToState(start, log_mask), logs_(logs) {
    log_id_for_each(i) {
        if (((1 << i) & log_mask) == 0) {
            continue;
        }
        LogPosition log_position;
        auto it = logs[i].begin();
        while (it != logs[i].end() && start > it->highest_sequence_number()) {
            it++;
        }
        if (it == logs[i].end()) {
            it--;
        }
        it->IncDecompressedRef();
        log_position.buffer_it = it;
        // FlushTo() will traverse the buffer until getting to the appropriate element, so no
        // need to duplicate that logic here.
        log_position.read_offset = 0;

        log_positions_[i].emplace(log_position);

        AddMinHeapEntry(i);
    }
}

SerializedFlushToState::~SerializedFlushToState() {
    log_id_for_each(i) {
        if (log_positions_[i]) {
            log_positions_[i]->buffer_it->DecDecompressedRef();
        }
    }
}

void SerializedFlushToState::AddMinHeapEntry(log_id_t log_id) {
    auto& buffer_it = log_positions_[log_id]->buffer_it;
    auto read_offset = log_positions_[log_id]->read_offset;

    // If there is another log to read in this buffer, add it to the min heap.
    if (read_offset < buffer_it->write_position()) {
        auto* element =
                reinterpret_cast<const SerializedLogEntry*>(buffer_it->data() + read_offset);
        min_heap_.emplace(log_id, element);
    } else if (read_offset == buffer_it->write_position()) {
        // If there are no more logs to read in this buffer and it's the last buffer, then
        // set logs_needed_from_next_position_ to wait until more logs get logged.
        if (buffer_it == std::prev(logs_[log_id].end())) {
            logs_needed_from_next_position_[log_id] = true;
        } else {
            // Otherwise, if there is another buffer piece, move to that and do the same check.
            buffer_it->DecDecompressedRef();
            buffer_it++;
            buffer_it->IncDecompressedRef();
            log_positions_[log_id]->read_offset = 0;
            if (buffer_it->write_position() == 0) {
                logs_needed_from_next_position_[log_id] = true;
            } else {
                auto* element = reinterpret_cast<const SerializedLogEntry*>(buffer_it->data());
                min_heap_.emplace(log_id, element);
            }
        }
    } else {
        // read_offset > logs_write_position_[i] should never happen.
        CHECK(false);
    }
}

void SerializedFlushToState::CheckForNewLogs() {
    log_id_for_each(i) {
        if (!logs_needed_from_next_position_[i]) {
            continue;
        }
        logs_needed_from_next_position_[i] = false;
        // If it wasn't possible to insert, logs_needed_from_next_position will be set to true.
        AddMinHeapEntry(i);
    }
}

MinHeapElement SerializedFlushToState::PopNextUnreadLog() {
    auto top = min_heap_.top();
    min_heap_.pop();

    auto* element = top.element;
    auto log_id = top.log_id;

    log_positions_[log_id]->read_offset += element->total_len();

    AddMinHeapEntry(log_id);

    return top;
}
