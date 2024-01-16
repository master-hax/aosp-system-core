#include "android/memtag-error.h"
#include <unistd.h>
#include <cstdio>

#ifdef USE_SCUDO
#include "debuggerd/handler.h"
#include "libdebuggerd/scudo.h"
#include "libdebuggerd/types.h"
#include "scudo/interface.h"
#include "unwindstack/AndroidUnwinder.h"

struct AMemtagCrashInfo {
  uintptr_t fault_address;
  pid_t crashing_process;
  pid_t crashing_thread;
  debugger_process_info proc_info;
};

struct AMemtagStackTrace {
  uintptr_t (*stack)[64];
};
struct AMemtagCause {
  scudo_error_report* report;
  AMemtagStackTrace allocation_stack;
  AMemtagStackTrace free_stack;
};

struct AMemtagError {
  scudo_error_info scudo_error;
  AMemtagCause causes[3];
};

static AMemtagError g_error;
static AMemtagCrashInfo g_crash_info;

AMemtagCrashInfo* AMemtagCrashInfo_get(uintptr_t fault_address) {
  g_crash_info = {
      .fault_address = fault_address,
      .crashing_process = getpid(),
      .crashing_thread = gettid(),
      .proc_info = debuggerd_get_callbacks()->get_process_info(),
  };
  return &g_crash_info;
}
size_t AMemtagCrashInfo_getSize(AMemtagCrashInfo*) {
  return sizeof(AMemtagCrashInfo);
}

AMemtagError* AMemtagError_get(AMemtagCrashInfo* info) {
  auto proc_memory = unwindstack::Memory::CreateProcessMemory(info->crashing_process);
  ProcessInfo process_info;
  process_info.scudo_stack_depot = reinterpret_cast<uintptr_t>(info->proc_info.scudo_stack_depot);
  process_info.scudo_stack_depot_size = info->proc_info.scudo_stack_depot_size;
  process_info.scudo_region_info = reinterpret_cast<uintptr_t>(info->proc_info.scudo_region_info);
  process_info.scudo_ring_buffer = reinterpret_cast<uintptr_t>(info->proc_info.scudo_ring_buffer);
  process_info.scudo_ring_buffer_size = info->proc_info.scudo_ring_buffer_size;
  process_info.has_fault_address = true;
  process_info.maybe_tagged_fault_address = info->fault_address;
  process_info.untagged_fault_address = untag_address(process_info.maybe_tagged_fault_address);
  GetScudoErrorInfo(proc_memory.get(), process_info, &g_error.scudo_error);
  for (int i = 0; i < 3; ++i) {
    g_error.causes[i] = {&g_error.scudo_error.reports[i],
                         {&g_error.scudo_error.reports[i].allocation_trace},
                         {&g_error.scudo_error.reports[i].deallocation_trace}};
  }
  return &g_error;
}

size_t AMemtagError_getHumanReadable(AMemtagError*, char*, size_t) {
  return 0;
}

AMemtagCause* AMemtagError_getCause(AMemtagError* err, size_t n) {
  if (n > 2 || err->causes[n].report->error_type == 0) {
    return nullptr;
  }
  return &err->causes[n];
}

AMemtagCauseType AMemtagCause_getType(AMemtagCause* cause) {
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

  return AMEMTAG_CAUSE_TYPE_UNKNOWN;
}

uintptr_t AMemtagCause_getAllocationAddress(AMemtagCause* cause) {
  return cause->report->allocation_address;
}

AMemtagStackTrace* AMemtagCause_getAllocationStack(AMemtagCause* cause) {
  return &cause->allocation_stack;
}

pid_t AMemtagCause_getAllocationTid(AMemtagCause* cause) {
  return cause->report->allocation_tid;
}

// ONLY FOR AMEMTAG_CAUSE_TYPE_USE_AFTER_FREE
AMemtagStackTrace* AMemtagCause_getFreeStack(AMemtagCause* cause) {
  return &cause->free_stack;
}
pid_t AMemtagCause_getFreeTid(AMemtagCause* cause) {
  return cause->report->deallocation_tid;
}

uintptr_t AMemtagStackTrace_getPC(AMemtagStackTrace* stack, int n) {
  if (n >= 64) {
    return 0;
  }
  return *(stack->stack)[n];
}

#else
AMemtagCrashInfo* AMemtagCrashInfo_get(uintptr_t) {
  return nullptr;
}

AMemtagError* AMemtagError_get(AMemtagCrashInfo*) {
  return nullptr;
}

size_t AMemtagError_getHumanReadable(AMemtagError*, char*, size_t) {
  return 0;
}

AMemtagCause* AMemtagError_getCause(AMemtagError*, size_t) {
  return nullptr;
}

AMemtagCauseType AMemtagCause_getType(AMemtagCause*) {
  return AMEMTAG_CAUSE_TYPE_UNKNOWN;
}

uintptr_t AMemtagCause_getAllocationAddress(AMemtagCause*) {
  return 0;
}

AMemtagStackTrace* AMemtagCause_getAllocationStack(AMemtagCause*) {
  return nullptr;
}

pid_t AMemtagCause_getAllocationTid(AMemtagCause*) {
  return 0;
}

// ONLY FOR AMEMTAG_CAUSE_TYPE_USE_AFTER_FREE
AMemtagStackTrace* AMemtagCause_getFreeStack(AMemtagCause*) {
  return nullptr;
}
pid_t AMemtagCause_getFreeTid(AMemtagCause*) {
  return 0;
}

uintptr_t AMemtagStackTrace_getPC(AMemtagStackTrace*, int) {
  return 0;
}
#endif