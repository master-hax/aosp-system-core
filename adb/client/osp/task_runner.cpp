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

#include "client/osp/task_runner.h"

#include <chrono>

#include <android-base/logging.h>
#include <android-base/threads.h>
#include <platform/api/time.h>

#include "fdevent/fdevent.h"

using android::base::ScopedLockAssertion;
using namespace openscreen;

namespace mdns {

AdbOspTaskRunner::AdbOspTaskRunner() {
    check_main_thread();
    thread_id_ = android::base::GetThreadId();
    task_handler_ = std::thread([this]() { TaskExecutorWorker(); });
}

AdbOspTaskRunner::~AdbOspTaskRunner() {
    if (task_handler_.joinable()) {
        terminate_loop_ = true;
        cv_.notify_one();
        task_handler_.join();
    }
}

void AdbOspTaskRunner::PostPackagedTask(Task task) {
    PostPackagedTaskWithDelay(std::move(task), openscreen::Clock::duration::zero());
}

void AdbOspTaskRunner::PostPackagedTaskWithDelay(Task task, Clock::duration delay) {
    {
        std::lock_guard<std::mutex> lock(mutex_);
        tasks_.emplace_back(std::move(task), delay);
    }
    cv_.notify_one();
}

bool AdbOspTaskRunner::IsRunningOnTaskRunner() {
    return (*thread_id_ == android::base::GetThreadId());
}

void AdbOspTaskRunner::TaskExecutorWorker() {
    for (;;) {
        {
            std::unique_lock<std::mutex> lock(mutex_);
            ScopedLockAssertion assume_locked(mutex_);
            cv_.wait(lock,
                     [this]() REQUIRES(mutex_) { return (terminate_loop_ || !tasks_.empty()); });
            if (terminate_loop_) {
                return;
            }

            // Move posted tasks into a separate queue for processing so we don't block
            // other tasks from being posted.
            running_tasks_.swap(tasks_);
        }

        while (!running_tasks_.empty()) {
            auto& task_with_delay = running_tasks_.front();
            // Using sleep to delay
            if (task_with_delay.second > openscreen::Clock::duration::zero()) {
                std::this_thread::sleep_for(task_with_delay.second);
            }

            std::packaged_task<int()> waitable_task([&] {
                auto task = std::move(task_with_delay.first);
                task();
                return 0;
            });

            fdevent_run_on_main_thread([&]() { waitable_task(); });

            waitable_task.get_future().wait();
            running_tasks_.pop_front();
        }
    }
}
}  // namespace mdns
