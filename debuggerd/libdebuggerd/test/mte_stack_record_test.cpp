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
#include "unwindstack/Memory.h"

#include "gtest/gtest.h"

#include "libdebuggerd/tombstone.h"

struct ScopedUnmap {
  void* ptr;
  size_t size;
  ~ScopedUnmap() { munmap(ptr, size); }
};

static void* __allocate_stack_mte_ringbuffer(size_t n) {
  if (n > 7) return nullptr;
  // Allocation needs to be aligned to 2*size to make the fancy code-gen work.
  // So we allocate 3*size - pagesz bytes, which will always contain size bytes
  // aligned to 2*size, and unmap the unneeded part.
  //
  // In the worst case, we get an allocation that is one page past the properly
  // aligned address, in which case we have to unmap the previous
  // 2*size - pagesz bytes. In that case, we still have size properly aligned
  // bytes left.
  size_t size = (1 << n) * 4096;
  size_t pgsize = page_size();

  size_t alloc_size = __BIONIC_ALIGN(3 * size - pgsize, pgsize);
  void* allocation_ptr =
      mmap(nullptr, alloc_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (allocation_ptr == MAP_FAILED) return nullptr;
  uintptr_t allocation = reinterpret_cast<uintptr_t>(allocation_ptr);

  size_t alignment = 2 * size;
  uintptr_t aligned_allocation = __BIONIC_ALIGN(allocation, alignment);
  if (allocation != aligned_allocation) {
    munmap(reinterpret_cast<void*>(allocation), aligned_allocation - allocation);
  }
  if (aligned_allocation + size != allocation + alloc_size) {
    munmap(reinterpret_cast<void*>(aligned_allocation + size),
           (allocation + alloc_size) - (aligned_allocation + size));
  }

  // We store the size in the top byte of the pointer (which is ignored)
  return reinterpret_cast<void*>(aligned_allocation | ((1ULL << n) << 56ULL));
}

class MteStackHistoryTest : public ::testing::TestWithParam<int> {};

TEST_P(MteStackHistoryTest, TestEmpty) {
  int size_cls = GetParam();
  size_t size = (1 << size_cls) * 4096;
  void* data = __allocate_stack_mte_ringbuffer(size_cls);
  ScopedUnmap s{data, size};
  // The MTE TLS is at TLS - 3, so we allocate 3 placeholders.
  void* tls[4] = {data};
  auto memory = unwindstack::Memory::CreateProcessMemory(getpid());
  read_stack_history(memory.get(), reinterpret_cast<uintptr_t>(&tls[3]),
                     [&](uintptr_t, uintptr_t, uintptr_t) { ADD_FAILURE(); });
}

TEST_P(MteStackHistoryTest, TestFull) {
  int size_cls = GetParam();
  size_t size = (1 << size_cls) * 4096;
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
  int size_cls = GetParam();
  size_t size = (1 << size_cls) * 4096;
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
