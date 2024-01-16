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

#include "libdebuggerd/scudo.h"

#include "libdebuggerd/utility.h"
#include "scudo/interface.h"
#include "unwindstack/Memory.h"

#include <android-base/macros.h>
#include <bionic/macros.h>
#include <sys/mman.h>
#include <sys/uio.h>
#include <unistd.h>

#include <memory>

static std::unique_ptr<char[]> AllocAndReadFully(unwindstack::Memory* process_memory, uint64_t addr,
                                                 size_t size) {
  auto buf = std::make_unique<char[]>(size);
  if (!process_memory->ReadFully(addr, buf.get(), size)) {
    return std::unique_ptr<char[]>();
  }
  return buf;
}

ssize_t ReadSelf(void* addr, void* dst, size_t size) {
  struct iovec src_iovs[] = {{.iov_base = reinterpret_cast<void*>(addr), .iov_len = size}};
  struct iovec dst_iov = {.iov_base = dst, .iov_len = size};
  return process_vm_readv(getpid(), &dst_iov, 1, src_iovs, 1, 0);
}

static long ReadTag(uintptr_t addr) {
#if defined(__aarch64__)
  char x;
  if (ReadSelf(reinterpret_cast<void*>(addr), &x, 1) != 1) {
    return -1;
  }
  __asm__ __volatile__(".arch_extension mte; ldg %0, [%0]" : "+r"(addr) : : "memory");
  return (addr >> 56) & 0xf;
#else
  (void)(addr);
  return -1;
#endif
}

bool GetScudoErrorInfo(unwindstack::Memory* process_memory, const ProcessInfo& process_info,
                       scudo_error_info* error_info, bool in_process) {
  if (!process_info.has_fault_address) {
    return false;
  }

  uintptr_t untagged_fault_addr = process_info.untagged_fault_address;
  uintptr_t fault_page = untagged_fault_addr & ~(getpagesize() - 1);

  uintptr_t memory_begin = fault_page - getpagesize() * 16;
  if (memory_begin > fault_page) {
    return false;
  }

  uintptr_t memory_end = fault_page + getpagesize() * 16;
  if (memory_end < fault_page) {
    return false;
  }

  auto memory_size = memory_end - memory_begin;
  auto memory_tags_size = memory_size / kTagGranuleSize;

  std::unique_ptr<char[]> region_info;
  std::unique_ptr<char[]> ring_buffer;
  std::unique_ptr<char[]> stack_depot;
  std::unique_ptr<char[]> memory;
  std::unique_ptr<char[]> memory_tags;

  char* region_info_ptr;
  char* ring_buffer_ptr;
  char* stack_depot_ptr;
  char* memory_ptr;
  char* memory_tags_ptr;

  if (in_process) {
    region_info_ptr = reinterpret_cast<char*>(process_info.scudo_region_info);
    ring_buffer_ptr = reinterpret_cast<char*>(process_info.scudo_ring_buffer);
    stack_depot_ptr = reinterpret_cast<char*>(process_info.scudo_stack_depot);

    // We don't know whether all the memory is mapped, so we read page per page
    // using preadv.
    memory_ptr = reinterpret_cast<char*>(
        mmap(nullptr, memory_size, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0));
    if (memory_ptr == MAP_FAILED) {
      return false;
    }
    for (auto i = memory_begin; i != memory_end; i += getpagesize()) {
      ReadSelf(reinterpret_cast<void*>(i), memory_ptr + i - memory_begin, getpagesize());
    }

    memory_tags_ptr = reinterpret_cast<char*>(mmap(
        nullptr, memory_tags_size, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0));
    if (memory_tags_ptr == MAP_FAILED) {
      munmap(memory_ptr, memory_size);
      return false;
    }
    for (auto i = memory_begin; i != memory_end; i += kTagGranuleSize) {
      memory_tags_ptr[(i - memory_begin) / kTagGranuleSize] = ReadTag(i);
    }
  } else {
    region_info = AllocAndReadFully(process_memory, process_info.scudo_region_info,
                                    __scudo_get_region_info_size());

    region_info_ptr = region_info.get();
    if (process_info.scudo_ring_buffer_size != 0) {
      ring_buffer = AllocAndReadFully(process_memory, process_info.scudo_ring_buffer,
                                      process_info.scudo_ring_buffer_size);
      ring_buffer_ptr = ring_buffer.get();
    }
    if (process_info.scudo_stack_depot_size != 0) {
      stack_depot = AllocAndReadFully(process_memory, process_info.scudo_stack_depot,
                                      process_info.scudo_stack_depot_size);
      stack_depot_ptr = stack_depot.get();
    }
    if (!region_info) {
      return false;
    }
    memory = std::make_unique<char[]>(memory_end - memory_begin);
    for (auto i = memory_begin; i != memory_end; i += getpagesize()) {
      process_memory->ReadFully(i, memory.get() + i - memory_begin, getpagesize());
    }
    memory_ptr = memory.get();

    memory_tags = std::make_unique<char[]>(memory_tags_size);

    for (auto i = memory_begin; i != memory_end; i += kTagGranuleSize) {
      memory_tags[(i - memory_begin) / kTagGranuleSize] = process_memory->ReadTag(i);
    }
    memory_tags_ptr = memory_tags.get();
  }
  __scudo_get_error_info(error_info, process_info.maybe_tagged_fault_address, stack_depot_ptr,
                         process_info.scudo_stack_depot_size, region_info_ptr, ring_buffer_ptr,
                         process_info.scudo_ring_buffer_size, memory_ptr, memory_tags_ptr,
                         memory_begin, memory_end - memory_begin);
  if (in_process) {
    munmap(memory_ptr, memory_size);
    munmap(memory_tags_ptr, memory_tags_size);
  }
  return true;
}
