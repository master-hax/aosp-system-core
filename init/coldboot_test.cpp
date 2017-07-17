/*
 * Copyright (C) 2017 The Android Open Source Project
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

#include "coldboot.h"

#include <chrono>
#include <map>
#include <thread>
#include <vector>

#include <gtest/gtest.h>

using namespace android::init;
using namespace std::chrono_literals;

// Ensure that we process an inclusive range of uevent SEQNUMs with the ColdBoot class.
TEST(ueventd, MultiThreadUeventSocketRead) {
    UeventListener uevent_listener;

    std::mutex map_lock;
    std::map<std::thread::id, std::vector<unsigned long long>> uevents_handled;

    auto num_threads = std::thread::hardware_concurrency() ?: 4;
    ColdBoot cold_boot(uevent_listener, num_threads,
                       [&map_lock, &uevents_handled](const Uevent& uevent) {
                           auto id = std::this_thread::get_id();
                           if (!uevents_handled.count(id)) {
                               std::lock_guard<std::mutex> guard(map_lock);
                               uevents_handled[id] = std::vector<unsigned long long>();
                           }

                           uevents_handled[id].emplace_back(uevent.seq_num);
                           // Introduce some artificial delay to mimic real work being done
                           std::this_thread::sleep_for(2ms);
                       });

    cold_boot.Run();
    cold_boot.Join();

    EXPECT_EQ(num_threads, uevents_handled.size());

    std::vector<unsigned long long> all_seq_nums;
    for (const auto& [id, seq_nums] : uevents_handled) {
        ASSERT_GT(seq_nums.size(), 0UL);
        for (const auto seq_num : seq_nums) {
            all_seq_nums.emplace_back(seq_num);
        }
    }

    std::sort(all_seq_nums.begin(), all_seq_nums.end());

    for (auto it = std::next(all_seq_nums.begin()); it != all_seq_nums.end(); ++it) {
        EXPECT_EQ(*it, *(it - 1) + 1);
    }
}
