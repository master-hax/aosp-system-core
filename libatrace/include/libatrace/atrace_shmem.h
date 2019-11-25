/*
 * Copyright (C) 2019 The Android Open Source Project
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

#pragma once

#include <atomic>

namespace android {
namespace atrace {

struct AtraceShmemPage {
  std::atomic<uint32_t> atrace_sequence_number;
  std::atomic<uint64_t> atrace_requested_tags;
  // Some words reserved for future extensions
  char reserved[1024];
  char enabled_cmdlines[7152];
};

static_assert(sizeof(AtraceShmemPage) % 4096 == 0, "shmem needs to be whole pages");

}
}
