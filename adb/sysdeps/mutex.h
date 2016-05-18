#pragma once

/*
 * Copyright (C) 2016 The Android Open Source Project
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

#if defined(_WIN32)

#include <windows.h>

#include <android-base/macros.h>

#include "adb.h"

// The prebuilt version of mingw we use doesn't support mutex or recursive_mutex.
// Therefore, implement our own using the Windows primitives.
// Put them directly into the std namespace, so that when they're actually available, the build
// breaks until they're removed.

#include <mutex>
namespace std {

// CRITICAL_SECTION is recursive, so just wrap it in a Mutex-compatible class.
class recursive_mutex {
  public:
    recursive_mutex() {
        InitializeCriticalSection(&mutex_);
    }

    ~recursive_mutex() {
        DeleteCriticalSection(&mutex_);
    }

    void lock() {
        EnterCriticalSection(&mutex_);
    }

    bool try_lock() {
        return TryEnterCriticalSection(&mutex_);
    }

    void unlock() {
        LeaveCriticalSection(&mutex_);
    }

  private:
    CRITICAL_SECTION mutex_;

    DISALLOW_COPY_AND_ASSIGN(recursive_mutex);
};

class mutex {
  public:
    mutex() {
    }

    ~mutex() {
    }

    void lock() {
        mutex_.lock();
        if (++lock_count_ != 1) {
            fatal("non-recursive mutex locked reentrantly");
        }
    }

    void unlock() {
        if (lock_count_-- == 0) {
            fatal("recursive mutex unlocked too many times?");
        }
        mutex_.unlock();
    }

    bool try_lock() {
        if (mutex_.try_lock()) {
            if (++lock_count_ != 1) {
                fatal("non-recursive mutex locked reentrantly");
            }
            return true;
        }
        return false;
    }

  private:
    recursive_mutex mutex_;
    size_t lock_count_ = 0;
};

}

#endif
