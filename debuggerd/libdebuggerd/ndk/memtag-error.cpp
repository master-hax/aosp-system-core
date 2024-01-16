/*
 * Copyright (C) 2023 The Android Open Source Project
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

#include "android/memtag-error.h"
#include <stdio.h>
#include <unistd.h>
#include <memory>

#if defined(USE_SCUDO) && defined(__aarch64__)
#include "debuggerd/handler.h"
#include "libdebuggerd/scudo.h"
#include "libdebuggerd/types.h"
#include "scudo/interface.h"
#include "unwindstack/AndroidUnwinder.h"
#include "unwindstack/Memory.h"

constexpr auto kNumStackFrames = 64;
constexpr auto kNumCauses = 3;

struct AMemtagCrashInfo {
  uintptr_t fault_address;
  pid_t crashing_process;
  pid_t crashing_thread;
  debugger_process_info proc_info;
};

struct AMemtagStackTrace {
  uintptr_t (*stack)[kNumStackFrames];
};
struct AMemtagCause {
  scudo_error_report* report;
  AMemtagStackTrace allocation_stack;
  AMemtagStackTrace free_stack;
};

struct AMemtagError {
  scudo_error_info scudo_error;
  AMemtagCause causes[kNumCauses];
};

static AMemtagError g_error;
static AMemtagCrashInfo g_crash_info;

const AMemtagCrashInfo* AMemtagCrashInfo_get(uintptr_t fault_address) {
  g_crash_info = {
      .fault_address = fault_address,
      .crashing_process = getpid(),
      .crashing_thread = gettid(),
      .proc_info = debuggerd_get_callbacks()->get_process_info(),
  };
  return &g_crash_info;
}

const AMemtagCrashInfo* AMemtagCrashInfo_createFromBytes(const char* bytes) {
  // This is mostly to make users not have to care about alignment.
  memcpy(&g_crash_info, bytes, sizeof(g_crash_info));
  return &g_crash_info;
}

const char* _Nonnull AMemtagCrashInfo_toBytes(const AMemtagCrashInfo* _Nonnull info) {
  return reinterpret_cast<const char*>(info);
}

size_t AMemtagCrashInfo_byteSize(const AMemtagCrashInfo*) {
  return sizeof(AMemtagCrashInfo);
}

const AMemtagError* AMemtagError_get(const AMemtagCrashInfo* info) {
  ProcessInfo process_info = {};
  process_info.scudo_stack_depot = reinterpret_cast<uintptr_t>(info->proc_info.scudo_stack_depot);
  process_info.scudo_stack_depot_size = info->proc_info.scudo_stack_depot_size;
  process_info.scudo_region_info = reinterpret_cast<uintptr_t>(info->proc_info.scudo_region_info);
  process_info.scudo_ring_buffer = reinterpret_cast<uintptr_t>(info->proc_info.scudo_ring_buffer);
  process_info.scudo_ring_buffer_size = info->proc_info.scudo_ring_buffer_size;
  process_info.has_fault_address = true;
  process_info.maybe_tagged_fault_address = info->fault_address;
  process_info.untagged_fault_address = untag_address(process_info.maybe_tagged_fault_address);
  g_error = {};
  bool in_process = getpid() == info->crashing_process;
  unwindstack::Memory* memory = nullptr;
  std::shared_ptr<unwindstack::Memory> proc_mem;
  if (!in_process) {
    proc_mem = unwindstack::Memory::CreateProcessMemory(info->crashing_process);
    memory = proc_mem.get();
  }
  if (!GetScudoErrorInfo(memory, process_info, &g_error.scudo_error, in_process)) return nullptr;
  for (int i = 0; i < kNumCauses; ++i) {
    g_error.causes[i] = {&g_error.scudo_error.reports[i],
                         {&g_error.scudo_error.reports[i].allocation_trace},
                         {&g_error.scudo_error.reports[i].deallocation_trace}};
  }
  return &g_error;
}

const AMemtagCause* AMemtagError_getCause(const AMemtagError* err, size_t n) {
  if (n >= kNumCauses || err->causes[n].report->error_type == 0) {
    return nullptr;
  }
  return &err->causes[n];
}

AMemtagCauseType AMemtagCause_getType(const AMemtagCause* cause) {
  switch (cause->report->error_type) {
    case USE_AFTER_FREE:
      return AMEMTAG_CAUSE_TYPE_USE_AFTER_FREE;
    case BUFFER_OVERFLOW:
    case BUFFER_UNDERFLOW:
      return AMEMTAG_CAUSE_TYPE_OUT_OF_BOUNDS;
    case UNKNOWN:
    default:
      return AMEMTAG_CAUSE_TYPE_UNKNOWN;
  }
}

uintptr_t AMemtagCause_getAllocationAddress(const AMemtagCause* cause) {
  return cause->report->allocation_address;
}

const AMemtagStackTrace* AMemtagCause_getAllocationStack(const AMemtagCause* cause) {
  return &cause->allocation_stack;
}

pid_t AMemtagCause_getAllocationTid(const AMemtagCause* cause) {
  return cause->report->allocation_tid;
}

const AMemtagStackTrace* AMemtagCause_getFreeStack(const AMemtagCause* cause) {
  if (cause->report->error_type != USE_AFTER_FREE) return nullptr;
  return &cause->free_stack;
}

pid_t AMemtagCause_getFreeTid(const AMemtagCause* cause) {
  if (cause->report->error_type != USE_AFTER_FREE) return 0;
  return cause->report->deallocation_tid;
}

uintptr_t AMemtagStackTrace_getPC(const AMemtagStackTrace* stack, int n) {
  if (n >= kNumStackFrames) {
    return 0;
  }
  return *(stack->stack)[n];
}

#else
const AMemtagCrashInfo* AMemtagCrashInfo_get(uintptr_t) {
  return nullptr;
}

const AMemtagError* AMemtagError_get(const AMemtagCrashInfo*) {
  return nullptr;
}

const AMemtagCrashInfo* AMemtagCrashInfo_createFromBytes(const char* bytes) {
  // Impossible to obtain a bytes originally returned by AMemtagCrashInfo_toBytes.
  abort();
}

const char* _Nonnull AMemtagCrashInfo_toBytes(const AMemtagCrashInfo* _Nonnull info) {
  // Impossible to obtain a Nonnull info.
  abort();
}

size_t AMemtagCrashInfo_byteSize(const AMemtagCrashInfo*) {
  return 0;
}

const AMemtagCause* AMemtagError_getCause(const AMemtagError*, size_t) {
  return nullptr;
}

AMemtagCauseType AMemtagCause_getType(const AMemtagCause*) {
  return AMEMTAG_CAUSE_TYPE_UNKNOWN;
}

uintptr_t AMemtagCause_getAllocationAddress(const AMemtagCause*) {
  return 0;
}

const AMemtagStackTrace* AMemtagCause_getAllocationStack(const AMemtagCause*) {
  return nullptr;
}

pid_t AMemtagCause_getAllocationTid(const AMemtagCause*) {
  return 0;
}

// ONLY FOR AMEMTAG_CAUSE_TYPE_USE_AFTER_FREE
const AMemtagStackTrace* AMemtagCause_getFreeStack(const AMemtagCause*) {
  return nullptr;
}
pid_t AMemtagCause_getFreeTid(const AMemtagCause*) {
  return 0;
}

uintptr_t AMemtagStackTrace_getPC(const AMemtagStackTrace*, int) {
  return 0;
}
#endif
