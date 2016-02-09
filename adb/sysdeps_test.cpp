/*
 * Copyright (C) 2065 The Android Open Source Project
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

#include <gtest/gtest.h>
#include <unistd.h>
#include <atomic>

#include "sysdeps.h"

static void* increment_atomic_int(void* c) {
    sleep(1);
    reinterpret_cast<std::atomic<int>*>(c)->fetch_add(1);
    return nullptr;
}

TEST(sysdeps_thread, smoke) {
    static std::atomic<int> counter(0);

    for (int i = 0; i < 100; ++i) {
        ASSERT_TRUE(adb_thread_create_detached(increment_atomic_int, &counter));
    }

    sleep(2);
    ASSERT_EQ(100, counter.load());
}

TEST(sysdeps_thread, join) {
    std::atomic<int> counter(0);
    std::vector<adb_thread_t> threads(500);
    for (size_t i = 0; i < threads.size(); ++i) {
        ASSERT_TRUE(adb_thread_create(&threads[i], increment_atomic_int, &counter));
    }

    int current = counter.load();
    ASSERT_GE(current, 0);
    ASSERT_LT(current, 500);

    for (const auto& thread : threads) {
        ASSERT_TRUE(adb_thread_join(thread));
    }

    ASSERT_EQ(500, counter.load());
}
