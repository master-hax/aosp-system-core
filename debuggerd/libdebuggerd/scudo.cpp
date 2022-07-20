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

#include <stdint.h>
#include <unistd.h>

#include <memory>
#include <vector>

#include <unwindstack/AndroidUnwinder.h>
#include <unwindstack/Memory.h>

#include "libdebuggerd/scudo.h"
#include "libdebuggerd/tombstone.h"

#include "scudo/interface.h"

#include "tombstone.pb.h"

static std::unique_ptr<char[]> AllocAndReadFully(unwindstack::Memory* process_memory, uint64_t addr,
                                                 size_t size) {
  auto buf = std::make_unique<char[]>(size);
  if (!process_memory->ReadFully(addr, buf.get(), size)) {
    return std::unique_ptr<char[]>();
  }
  return buf;
}

static bool GetErrorInfo(unwindstack::Memory* process_memory, const ProcessInfo& process_info,
                         scudo_error_info& error_info) {
  if (!process_info.has_fault_address) {
    return false;
  }

  uintptr_t page_size = getpagesize();

  uintptr_t untagged_fault_addr = process_info.untagged_fault_address;
  uintptr_t fault_page = untagged_fault_addr & ~(page_size - 1);

  // Attempt to get 16 pages before the fault page and 16 pages after.
  uintptr_t extra_bytes_to_read = page_size * 16;
  if (fault_page <= extra_bytes_to_read) {
    // The fault page is too low in the address space, this is not valid.
    return false;
  }
  uintptr_t memory_begin = fault_page - extra_bytes_to_read;

  uintptr_t memory_end = fault_page;
  if (__builtin_add_overflow(memory_end, extra_bytes_to_read, &memory_end)) {
    // Assume an address too close to the top of memory is not valid.
    return false;
  }

  // Don't try and read until we've verified the fault address.
  auto stack_depot = AllocAndReadFully(process_memory, process_info.scudo_stack_depot,
                                       __scudo_get_stack_depot_size());
  auto region_info = AllocAndReadFully(process_memory, process_info.scudo_region_info,
                                       __scudo_get_region_info_size());
  auto ring_buffer = AllocAndReadFully(process_memory, process_info.scudo_ring_buffer,
                                       __scudo_get_ring_buffer_size());
  if (!stack_depot || !region_info || !ring_buffer) {
    return false;
  }

  std::vector<char> memory(memory_end - memory_begin, 0);
  for (auto address = memory_begin; address < memory_end;) {
    uint64_t bytes_read =
        process_memory->Read(address, &memory[address - memory_begin], memory_end - address);
    if (bytes_read == 0) {
      address += page_size;
    } else {
      // Round up to the next page size
      address += (bytes_read + page_size - 1) & ~(page_size - 1);
    }
  }

  auto memory_tags = std::make_unique<char[]>((memory_end - memory_begin) / kTagGranuleSize);
  for (auto i = memory_begin; i < memory_end; i += kTagGranuleSize) {
    memory_tags[(i - memory_begin) / kTagGranuleSize] = process_memory->ReadTag(i);
  }

  __scudo_get_error_info(&error_info, process_info.maybe_tagged_fault_address, stack_depot.get(),
                         region_info.get(), ring_buffer.get(), memory.data(), memory_tags.get(),
                         memory_begin, memory_end - memory_begin);

  return error_info.reports[0].error_type != UNKNOWN;
}

static void FillInCause(Cause* cause, const scudo_error_report* report,
                        unwindstack::AndroidUnwinder* unwinder, uintptr_t untagged_fault_address) {
  MemoryError* memory_error = cause->mutable_memory_error();
  HeapObject* heap_object = memory_error->mutable_heap();

  memory_error->set_tool(MemoryError_Tool_SCUDO);
  switch (report->error_type) {
    case USE_AFTER_FREE:
      memory_error->set_type(MemoryError_Type_USE_AFTER_FREE);
      break;
    case BUFFER_OVERFLOW:
      memory_error->set_type(MemoryError_Type_BUFFER_OVERFLOW);
      break;
    case BUFFER_UNDERFLOW:
      memory_error->set_type(MemoryError_Type_BUFFER_UNDERFLOW);
      break;
    default:
      memory_error->set_type(MemoryError_Type_UNKNOWN);
      break;
  }

  heap_object->set_address(report->allocation_address);
  heap_object->set_size(report->allocation_size);

  heap_object->set_allocation_tid(report->allocation_tid);
  for (size_t i = 0; i < arraysize(report->allocation_trace) && report->allocation_trace[i]; ++i) {
    unwindstack::FrameData frame_data = unwinder->BuildFrameFromPcOnly(report->allocation_trace[i]);
    BacktraceFrame* f = heap_object->add_allocation_backtrace();
    fill_in_backtrace_frame(f, frame_data);
  }

  heap_object->set_deallocation_tid(report->deallocation_tid);
  for (size_t i = 0; i < arraysize(report->deallocation_trace) && report->deallocation_trace[i];
       ++i) {
    unwindstack::FrameData frame_data =
        unwinder->BuildFrameFromPcOnly(report->deallocation_trace[i]);
    BacktraceFrame* f = heap_object->add_deallocation_backtrace();
    fill_in_backtrace_frame(f, frame_data);
  }

  set_human_readable_cause(cause, untagged_fault_address);
}

bool ScudoAddCauseProtosIfNeeded(Tombstone* tombstone, unwindstack::AndroidUnwinder* unwinder,
                                 const ProcessInfo& process_info) {
  scudo_error_info error_info = {};
  if (!GetErrorInfo(unwinder->GetProcessMemory().get(), process_info, error_info)) {
    return false;
  }

  for (size_t i = 0; i < arraysize(error_info.reports); i++) {
    const auto& report = error_info.reports[i];
    if (report.error_type == UNKNOWN) {
      continue;
    }
    FillInCause(tombstone->add_causes(), &report, unwinder, process_info.untagged_fault_address);
  }
  return true;
}
