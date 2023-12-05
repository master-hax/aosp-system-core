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

#ifndef _ANDROID_DEBUGSTORE_H
#define _ANDROID_DEBUGSTORE_H

#include <atomic>
#include <chrono>
#include <map>
#include "debug_store_events.h"
#include "debug_store_storage.h"

namespace android {
class DebugStore {
  public:
    // Default constants for the debug store configuration.
    // Default limit for the number of events stored.
    static constexpr size_t DEFAULT_EVENT_LIMIT = 16;
    // Default maximum delay for mutex locking when adding an event to the store in milliseconds.
    static constexpr uint64_t MAX_DELAY_MS = 20;
    // A special ID indicating non-closable events.
    static constexpr uint64_t NON_CLOSABLE_ID = 0;

    static DebugStore* Create(size_t event_limit = DEFAULT_EVENT_LIMIT,
                              uint64_t max_delay_ms = MAX_DELAY_MS);
    static bool IsEnabled();
    static DebugStore* GetInstance();

    DebugStore(const DebugStore&) = delete;
    DebugStore& operator=(const DebugStore&) = delete;
    uint64_t begin(const std::string& name,
                   const std::vector<DebugStoreEvent::KeyValuePair>& attributes =
                           std::vector<DebugStoreEvent::KeyValuePair>());
    void record(const std::string& name,
                const std::vector<DebugStoreEvent::KeyValuePair>& attributes =
                        std::vector<DebugStoreEvent::KeyValuePair>());
    void end(uint64_t id, const std::vector<DebugStoreEvent::KeyValuePair>& attributes =
                                  std::vector<DebugStoreEvent::KeyValuePair>());

    std::string to_string() const;

  private:
    DebugStore(size_t event_limit, uint64_t max_delay_ms);

    uint64_t generate_id();
    // Static instance for the singleton pattern.
    static std::atomic<DebugStore*> instance;
    // Used to generate unique IDs for events.
    std::atomic<uint64_t> id_generator;
    // Counts the total number of events stored, over the store's lifetime.
    std::atomic<uint64_t> total_entries;
    DebugStoreStorage<DebugStoreEvent> event_store;
};
}  // namespace android
#endif  // _ANDROID_DEBUGSTORE_H
