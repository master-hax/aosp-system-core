/*
 * Copyright (C) 2019 The Android Open Source Project
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *  * Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *  * Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
 * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
 * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <android/fd_track.h>

#include <array>
#include <mutex>
#include <vector>

#include <android-base/logging.h>
#include <android-base/thread_annotations.h>
#include <unwindstack/LocalUnwinder.h>

struct FdEntry {
  std::mutex mutex;
  std::vector<unwindstack::LocalFrameData> backtrace GUARDED_BY(mutex);
};

static void fd_hook(android_fd_track_event* event);

static constexpr size_t kFdTableSize = 512;
static constexpr size_t kStackDepth = 10;

static bool installed = false;
static std::array<FdEntry, kFdTableSize> stack_traces;
static unwindstack::LocalUnwinder& Unwinder() {
  static unwindstack::LocalUnwinder unwinder;
  return unwinder;
}

__attribute__((constructor)) static void ctor() {
  if (Unwinder().Init()) {
    android_fd_track_hook_t expected = nullptr;
    installed = android_fd_track_compare_exchange_hook(&expected, &fd_hook);
  }
}

__attribute__((destructor)) static void dtor() {
  if (installed) {
    android_fd_track_hook_t expected = &fd_hook;
    android_fd_track_compare_exchange_hook(&expected, nullptr);
  }
}

FdEntry* GetFdEntry(int fd) {
  if (fd >= 0 && fd < static_cast<int>(kFdTableSize)) {
    return &stack_traces[fd];
  }
  return nullptr;
}

thread_local bool active = false;
static void fd_hook(android_fd_track_event* event) {
  if (active) {
    return;
  }

  active = true;
  if (event->type == ANDROID_FD_TRACK_EVENT_TYPE_CREATE) {
    if (FdEntry* entry = GetFdEntry(event->fd); entry) {
      std::lock_guard<std::mutex> lock(entry->mutex);
      entry->backtrace.clear();
      Unwinder().Unwind(&entry->backtrace, kStackDepth);
    }
  } else if (event->type == ANDROID_FD_TRACK_EVENT_TYPE_CLOSE) {
    if (FdEntry* entry = GetFdEntry(event->fd); entry) {
      std::lock_guard<std::mutex> lock(entry->mutex);
      entry->backtrace.clear();
    }
  }
  active = false;
}

extern "C" void fdtrack_dump() {
  active = true;
  for (int fd = 0; fd < static_cast<int>(stack_traces.size()); ++fd) {
    FdEntry* entry = GetFdEntry(fd);
    if (!entry) {
      continue;
    }

    std::lock_guard<std::mutex> lock(entry->mutex);
    if (entry->backtrace.empty()) {
      continue;
    }

    LOG(INFO) << "fd " << fd << ":";
    for (size_t i = 2; i < entry->backtrace.size(); ++i) {
      auto& frame = entry->backtrace[i];
      LOG(INFO) << "  " << i << ": " << frame.function_name << "+" << frame.function_offset;
    }
  }
  active = false;
}
