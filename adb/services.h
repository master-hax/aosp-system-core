/*
 * Copyright (C) 2015 The Android Open Source Project
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

#ifndef SERVICES_H_
#define SERVICES_H_

#include <atomic>
#include <mutex>
#include <thread>

#include <android-base/thread_annotations.h>

#include "adb_unique_fd.h"
#include "fdevent.h"
#include "socket.h"
#include "types.h"

constexpr char kShellServiceArgRaw[] = "raw";
constexpr char kShellServiceArgPty[] = "pty";
constexpr char kShellServiceArgShellProtocol[] = "v2";

struct ServiceSocket : public asocket {
    ServiceSocket();

    virtual ~ServiceSocket();

    virtual bool HandleInput() EXCLUDES(mutex_) = 0;
    virtual bool InputEmpty();
    virtual bool ReadInput(IOVector* out, size_t length) EXCLUDES(mutex_);

    void Write(IOVector data) EXCLUDES(mutex_);

  private:
    void Close();

    // Wake up the service thread.
    void Notify() EXCLUDES(mutex_);

    // Wait to be notified.
    void Wait() EXCLUDES(mutex_);

    std::atomic<bool> closed_;
    std::thread thread_;
    unique_fd thread_notify_read_;
    unique_fd thread_notify_write_;

  protected:
    std::mutex mutex_;
    IOVector input_queue_ GUARDED_BY(mutex_);

  private:
    bool ready_ GUARDED_BY(mutex_) = false;
    IOVector output_queue_ GUARDED_BY(mutex_);
};

#endif  // SERVICES_H_
