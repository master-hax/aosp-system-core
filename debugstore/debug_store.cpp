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

#include "debugstore/debug_store.h"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <functional>
#include <mutex>
#include <sstream>
#include <vector>

namespace android {

std::atomic<DebugStore*> DebugStore::instance{nullptr};

DebugStore* DebugStore::GetInstance() {
    return instance.load(std::memory_order_acquire);
}
bool DebugStore::IsEnabled() {
    return instance.load(std::memory_order_acquire) != nullptr;
}

DebugStore* DebugStore::Create(size_t event_limit, uint64_t max_delay_ms) {
    DebugStore* expected = nullptr;
    DebugStore* new_instance = new DebugStore(event_limit, max_delay_ms);
    if (!instance.compare_exchange_strong(expected, new_instance, std::memory_order_release)) {
        delete new_instance;
    }
    return instance.load(std::memory_order_acquire);
}

DebugStore::DebugStore(size_t event_limit, uint64_t max_delay_ms)
    : id_generator(1), total_entries(0), event_store(event_limit, max_delay_ms) {}

uint64_t DebugStore::begin(const std::string& name,
                           const std::vector<DebugStoreEvent::KeyValuePair>& data) {
    uint64_t id = generate_id();
    if (event_store.emplace(id, name, std::chrono::steady_clock::now(), EventType::DURATION_START,
                            data)) {
        total_entries.fetch_add(1, std::memory_order_relaxed);
        return id;
    }
    return NON_CLOSABLE_ID;
}

void DebugStore::record(const std::string& name,
                        const std::vector<DebugStoreEvent::KeyValuePair>& data) {
    event_store.emplace(NON_CLOSABLE_ID, name, std::chrono::steady_clock::now(), EventType::POINT,
                        data);
}

void DebugStore::end(uint64_t id, const std::vector<DebugStoreEvent::KeyValuePair>& data) {
    if (id != NON_CLOSABLE_ID) {
        event_store.emplace(id, "", std::chrono::steady_clock::now(), EventType::DURATION_END,
                            data);
    }
}

// Converts the state of the DebugStore to a string representation.
// Example store string format:
// [total_entries],[lock_misses],[uptime_now]::ID:[event_id],T:[timestamp],N:[event_name],
// D:[key1]=[value1];[key2]=[value2]||ID:[event_id],T:[timestamp]||ID:[event_id],T:[timestamp],
// N:[event_name],D:[key1]=[value1]||...
//
// This format provides a concise overview of all events stored in the DebugStore.
std::string DebugStore::to_string() const {
    std::ostringstream ss;
    ss << total_entries.load(std::memory_order_relaxed) << "," << event_store.get_lock_misses()
       << ","
       << std::chrono::duration_cast<std::chrono::milliseconds>(
                  std::chrono::steady_clock::now().time_since_epoch())
                    .count()
       << "::";
    if (!event_store.visit([&ss](const auto& e) { ss << e.to_string() << "||"; })) {
        // The event store couldn't acquire it's lock within the specified time limit.
        ss << "-";
    }

    return ss.str();
}

uint64_t DebugStore::generate_id() {
    uint64_t id;
    do {
        id = id_generator.fetch_add(1, std::memory_order_relaxed);
    } while (id == NON_CLOSABLE_ID);

    return id;
}

}  // namespace android
