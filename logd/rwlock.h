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

#include <pthread.h>

#include <android-base/macros.h>
#include <android-base/thread_annotations.h>

// As of the end of May 2020, std::shared_mutex is *not* simply a pthread_rwlock, but rather a
// combination of std::mutex and std::condition variable, which is obviously less efficient.  This
// immitates what std::shared_mutex should be doing and is compatible with std::shared_lock and
// std::unique_lock.

class SHARED_CAPABILITY("mutex") RwLock {
  public:
    RwLock() {}
    ~RwLock() {}

    void lock() ACQUIRE() { pthread_rwlock_wrlock(&rwlock_); }
    void lock_shared() ACQUIRE_SHARED() { pthread_rwlock_rdlock(&rwlock_); }

    void unlock() RELEASE() { pthread_rwlock_unlock(&rwlock_); }
    void unlock_shared() RELEASE_SHARED() { pthread_rwlock_unlock(&rwlock_); }

  private:
    pthread_rwlock_t rwlock_ = PTHREAD_RWLOCK_INITIALIZER;
};

#if 0
class SCOPED_CAPABILITY SharedLock {
  public:
    SharedLock(RwLock& lock) ACQUIRE_SHARED(lock) : lock_(lock) { lock_.lock_shared(); }
    ~SharedLock() RELEASE_SHARED() { lock_.unlock(); }

    void lock() ACQUIRE_SHARED() { lock_.lock_shared(); }
    void unlock() RELEASE_SHARED() { lock_.unlock_shared(); }

    DISALLOW_IMPLICIT_CONSTRUCTORS(SharedLock);

  private:
    RwLock& lock_;
};

class SCOPED_CAPABILITY SharedLock {
  public:
    SharedLock(RwLock& lock) ACQUIRE_SHARED(lock) : lock_(lock) { lock_.lock_shared(); }
    ~SharedLock() RELEASE() { lock_.unlock(); }

    void lock() ACQUIRE_SHARED(lock_) { lock_.lock_shared(); }
    void unlock() RELEASE_SHARED(lock_) { lock_.unlock_shared(); }

    DISALLOW_IMPLICIT_CONSTRUCTORS(SharedLock);

  private:
    RwLock& lock_;
};
#endif