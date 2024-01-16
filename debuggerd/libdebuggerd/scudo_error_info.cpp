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

#include "scudo/interface.h"
#include "unwindstack/Memory.h"

#include <android-base/macros.h>
#include <bionic/macros.h>
#include <unistd.h>

static std::unique_ptr<char[]> AllocAndReadFully(unwindstack::Memory* process_memory, uint64_t addr,
                                                 size_t size) {
  auto buf = std::make_unique<char[]>(size);
  if (!process_memory->ReadFully(addr, buf.get(), size)) {
    return std::unique_ptr<char[]>();
  }
  return buf;
}

bool GetScudoErrorInfo(unwindstack::Memory* process_memory, const ProcessInfo& process_info,
                       scudo_error_info* error_info) {
  if (!process_info.has_fault_address) {
    return false;
  }

  auto region_info = AllocAndReadFully(process_memory, process_info.scudo_region_info,
                                       __scudo_get_region_info_size());
  std::unique_ptr<char[]> ring_buffer;
  if (process_info.scudo_ring_buffer_size != 0) {
    ring_buffer = AllocAndReadFully(process_memory, process_info.scudo_ring_buffer,
                                    process_info.scudo_ring_buffer_size);
  }
  std::unique_ptr<char[]> stack_depot;
  if (process_info.scudo_stack_depot_size != 0) {
    stack_depot = AllocAndReadFully(process_memory, process_info.scudo_stack_depot,
                                    process_info.scudo_stack_depot_size);
  }
  if (!region_info) {
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

  auto memory = std::make_unique<char[]>(memory_end - memory_begin);
  for (auto i = memory_begin; i != memory_end; i += getpagesize()) {
    process_memory->ReadFully(i, memory.get() + i - memory_begin, getpagesize());
  }

  auto memory_tags = std::make_unique<char[]>((memory_end - memory_begin) / kTagGranuleSize);
  for (auto i = memory_begin; i != memory_end; i += kTagGranuleSize) {
    memory_tags[(i - memory_begin) / kTagGranuleSize] = process_memory->ReadTag(i);
  }
  __scudo_get_error_info(error_info, process_info.maybe_tagged_fault_address, stack_depot.get(),
                         process_info.scudo_stack_depot_size, region_info.get(), ring_buffer.get(),
                         process_info.scudo_ring_buffer_size, memory.get(), memory_tags.get(),
                         memory_begin, memory_end - memory_begin);
  return true;
}