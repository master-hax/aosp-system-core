/*
 * Copyright (C) 2024 The Android Open Source Project
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
#if defined(__aarch64__)

#include <stdint.h>
#include <sys/mman.h>
#include "bionic/page.h"
#include "bionic/mte.h"
#include "unwindstack/Memory.h"

#include <android-base/test_utils.h>
#include "gtest/gtest.h"

#include "libdebuggerd/tombstone.h"

struct ScopedUnmap {
  void* ptr;
  size_t size;
  ~ScopedUnmap() { munmap(ptr, size); }
};

static void* __allocate_stack_mte_ringbuffer(size_t n) {
  return stack_mte_ringbuffer_allocate(n, nullptr);
}

class MteStackHistoryTest : public ::testing::TestWithParam<int> {};

TEST_P(MteStackHistoryTest, TestEmpty) {
  SKIP_WITH_HWASAN;
  int size_cls = GetParam();
  size_t size = stack_mte_ringbuffer_size(size_cls);
  void* data = __allocate_stack_mte_ringbuffer(size_cls);
  ScopedUnmap s{data, size};
  // The MTE TLS is at TLS - 3, so we allocate 3 placeholders.
  void* tls[4] = {data};
  auto memory = unwindstack::Memory::CreateProcessMemory(getpid());
  read_stack_history(memory.get(), reinterpret_cast<uintptr_t>(&tls[3]),
                     [&](uintptr_t, uintptr_t, uintptr_t) { ADD_FAILURE(); });
}

TEST_P(MteStackHistoryTest, TestFull) {
  SKIP_WITH_HWASAN;
  int size_cls = GetParam();
  size_t size = stack_mte_ringbuffer_size(size_cls);
  char* data = static_cast<char*>(__allocate_stack_mte_ringbuffer(size_cls));
  ScopedUnmap s{data, size};
  uintptr_t itr = 1;
  for (char* d = data; d < &data[size]; d += 16) {
    uintptr_t taggedfp = ((itr & 15) << 56) | itr;
    uintptr_t pc = itr;
    memcpy(d, &pc, sizeof(pc));
    memcpy(d + 8, &taggedfp, sizeof(taggedfp));
    ++itr;
  }
  // The MTE TLS is at TLS - 3, so we allocate 3 placeholders.
  // Because the buffer is full, and we point at one past the last inserted element,
  // due to wrap-around we point at the beginning of the buffer.
  void* tls[4] = {data};
  auto memory = unwindstack::Memory::CreateProcessMemory(getpid());
  size_t calls = 0;
  read_stack_history(memory.get(), reinterpret_cast<uintptr_t>(&tls[3]),
                     [&](uintptr_t pc, uintptr_t fp, uintptr_t tag) {
                       EXPECT_EQ(pc, --itr);
                       EXPECT_EQ(pc, fp);
                       EXPECT_EQ(pc & 15, tag);
                       ++calls;
                     });
  EXPECT_EQ(calls, size / 16);
}

TEST_P(MteStackHistoryTest, TestHalfFull) {
  SKIP_WITH_HWASAN;
  int size_cls = GetParam();
  size_t size = stack_mte_ringbuffer_size(size_cls);
  size_t half_size = size / 2;

  char* data = static_cast<char*>(__allocate_stack_mte_ringbuffer(size_cls));
  ScopedUnmap s{data, size};

  uintptr_t itr = 1;
  for (char* d = data; d < &data[half_size]; d += 16) {
    uintptr_t taggedfp = ((itr & 15) << 56) | itr;
    uintptr_t pc = itr;
    memcpy(d, &pc, sizeof(pc));
    memcpy(d + 8, &taggedfp, sizeof(taggedfp));
    ++itr;
  }
  // The MTE TLS is at TLS - 3, so we allocate 3 placeholders.
  void* tls[4] = {&data[half_size]};
  auto memory = unwindstack::Memory::CreateProcessMemory(getpid());
  size_t calls = 0;
  read_stack_history(memory.get(), reinterpret_cast<uintptr_t>(&tls[3]),
                     [&](uintptr_t pc, uintptr_t fp, uintptr_t tag) {
                       EXPECT_EQ(pc, --itr);
                       EXPECT_EQ(pc, fp);
                       EXPECT_EQ(pc & 15, tag);
                       ++calls;
                     });
  EXPECT_EQ(calls, half_size / 16);
}

INSTANTIATE_TEST_SUITE_P(MteStackHistoryTestInstance, MteStackHistoryTest, testing::Range(0, 8));

#endif
