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

#ifndef _ANDROID_DEBUGSTORE_EVENTS_H
#define _ANDROID_DEBUGSTORE_EVENTS_H

#include <chrono>
#include <string>
#include <utility>
#include <vector>

namespace android {

enum class EventType {
    INVALID,
    DURATION_START,
    DURATION_END,
    POINT,
};

class DebugStoreEvent {
  public:
    using KeyValuePair = std::pair<std::string, std::string>;
    using Timestamp = std::chrono::time_point<std::chrono::steady_clock>;

    DebugStoreEvent();
    DebugStoreEvent(uint64_t id, const std::string& name, const Timestamp timestamp, EventType type,
                    const std::vector<KeyValuePair>& data);

    uint64_t get_id() const;
    Timestamp get_timestamp() const;
    std::string get_name() const;
    EventType get_type() const;
    std::string to_string() const;

  private:
    uint64_t id;
    std::string name;
    Timestamp timestamp;
    EventType type;
    std::vector<KeyValuePair> data;
};

}  // namespace android

#endif  // _ANDROID_DEBUGSTORE_EVENTS_H
