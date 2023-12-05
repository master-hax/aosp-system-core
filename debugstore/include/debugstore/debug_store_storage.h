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

#ifndef _ANDROID_DEBUGSTORE_STORAGE_H
#define _ANDROID_DEBUGSTORE_STORAGE_H

#include <algorithm>
#include <atomic>
#include <chrono>
#include <functional>
#include <mutex>
#include <sstream>
#include <vector>

template <typename T>
class DebugStoreStorage {
  private:
    std::vector<T> storage;
    mutable std::timed_mutex mutex;
    // Maximum time to wait for acquiring the mutex, in milliseconds.
    std::chrono::milliseconds max_delay_ms;
    size_t next;
    // Counts how many times the lock was not acquired within the max delay.
    std::atomic<uint64_t> lock_misses_counter;
    bool has_looped;

  public:
    DebugStoreStorage(size_t size, uint64_t max_delay_ms)
        : DebugStoreStorage(size, std::chrono::milliseconds(max_delay_ms)) {}

    DebugStoreStorage(size_t size, std::chrono::milliseconds max_delay)
        : storage(size),
          max_delay_ms(max_delay),
          next(0),
          lock_misses_counter(0),
          has_looped(false) {}

    template <typename... Args>
    bool emplace(Args&&... args) {
        // Attempts to insert a new element into the storage.
        // If the lock on the storage cannot be acquired within the specified max_delay_ms,
        // it indicates contention or delay in accessing the storage.
        // In such a case, the method increments the lock_misses_counter to track the frequency of
        // these missed lock acquisition attempts, since we don't want to introduce any significant
        // latency to the calling methods.
        // This counter is used to monitor the performance and contention of the storage access.
        std::unique_lock<std::timed_mutex> lock(mutex, std::defer_lock);
        if (!lock.try_lock_for(max_delay_ms)) {
            lock_misses_counter.fetch_add(1, std::memory_order_relaxed);
            return false;
        }
        // If the lock is acquired successfully, the new element is added to the storage,
        // and the method returns true.
        storage[next] = T(std::forward<Args>(args)...);
        next = (next + 1) % storage.size();
        has_looped = has_looped || next == 0;
        return true;
    }

    bool visit(const std::function<void(const T&)>& func) const {
        std::unique_lock<std::timed_mutex> lock(mutex, std::defer_lock);
        if (!lock.try_lock_for(max_delay_ms)) {
            return false;
        }

        // Copies items to the local storage to minimize the locked period.
        std::vector<T> local_storage;
        local_storage.reserve(has_looped ? storage.size() : next);

        if (has_looped) {
            std::copy(storage.begin() + next, storage.end(), std::back_inserter(local_storage));
        }
        std::copy(storage.begin(), storage.begin() + next, std::back_inserter(local_storage));
        lock.unlock();

        for (const auto& item : local_storage) {
            func(item);
        }
        return true;
    }

    uint64_t get_lock_misses() const { return lock_misses_counter.load(std::memory_order_relaxed); }

    size_t size() const { return has_looped ? storage.size() : next; }
};
#endif  // _ANDROID_DEBUGSTORE_STORAGE_H
