/*
 * Copyright (C) 2023 The Android Open Source Project
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

#include "debugstore/debug_store_events.h"

#include <sstream>

namespace android {

DebugStoreEvent::DebugStoreEvent() : id(0), name(), timestamp(), type(EventType::INVALID), data() {}

DebugStoreEvent::DebugStoreEvent(uint64_t id, const std::string& name, const Timestamp timestamp,
                                 EventType type, const std::vector<KeyValuePair>& data)
    : id(id), name(name), timestamp(timestamp), type(type), data(data) {}

uint64_t DebugStoreEvent::get_id() const {
    return id;
}

DebugStoreEvent::Timestamp DebugStoreEvent::get_timestamp() const {
    return timestamp;
}

std::string DebugStoreEvent::get_name() const {
    return name;
}

EventType DebugStoreEvent::get_type() const {
    return type;
}

// Converts the event to a string representation.
// Example event string format:
// ID:[event_id],T:[timestamp],N:[event_name],D:[key1]=[value1];[key2]=[value2]
//
// This format provides a concise, human-readable representation of the event.
std::string DebugStoreEvent::to_string() const {
    std::ostringstream oss;
    oss << "ID:" << id << ",T:"
        << std::chrono::duration_cast<std::chrono::milliseconds>(timestamp.time_since_epoch())
                    .count();
    if (!name.empty()) {
        oss << ",N:" << name;
    }
    if (!data.empty()) {
        oss << ",D:";
        for (const auto& kv : data) {
            oss << kv.first << "=" << kv.second << ";";
        }
        // Remove last semicolon
        std::string result = oss.str();
        return result.substr(0, result.size() - 1);
    }

    return oss.str();
}

}  // namespace android
