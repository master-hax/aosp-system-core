/*
 * Copyright (C) 2020 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#pragma once

#include <mutex>

#include <android-base/thread_annotations.h>

extern std::mutex logd_lock;

// std::unique_lock does not have thread annotations, so we need our own.
class SCOPED_CAPABILITY UniqueLock {
  public:
    UniqueLock(std::mutex& lock) ACQUIRE(lock) : lock_(lock) { lock_.lock(); }
    ~UniqueLock() RELEASE() { lock_.unlock(); }

    void lock() ACQUIRE() { lock_.lock(); }
    void unlock() RELEASE() { lock_.unlock(); }

  private:
    std::mutex& lock_;
};
