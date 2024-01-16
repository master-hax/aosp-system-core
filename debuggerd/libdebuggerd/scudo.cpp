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
#include "libdebuggerd/tombstone.h"

#include "scudo/interface.h"
#include "unwindstack/AndroidUnwinder.h"
#include "unwindstack/Memory.h"

#include <android-base/macros.h>
#include <bionic/macros.h>
#include <unistd.h>

#include "tombstone.pb.h"

ScudoCrashData::ScudoCrashData(unwindstack::Memory* process_memory,
                               const ProcessInfo& process_info) {
  if (!process_info.has_fault_address) {
    return;
  }
  untagged_fault_addr_ = process_info.untagged_fault_address;
  GetScudoErrorInfo(process_memory, process_info, &error_info_);
}

bool ScudoCrashData::CrashIsMine() const {
  return error_info_.reports[0].error_type != UNKNOWN;
}

void ScudoCrashData::FillInCause(Cause* cause, const scudo_error_report* report,
                                 unwindstack::AndroidUnwinder* unwinder) const {
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

  set_human_readable_cause(cause, untagged_fault_addr_);
}

void ScudoCrashData::AddCauseProtos(Tombstone* tombstone,
                                    unwindstack::AndroidUnwinder* unwinder) const {
  size_t report_num = 0;
  while (report_num < sizeof(error_info_.reports) / sizeof(error_info_.reports[0]) &&
         error_info_.reports[report_num].error_type != UNKNOWN) {
    FillInCause(tombstone->add_causes(), &error_info_.reports[report_num++], unwinder);
  }
}
