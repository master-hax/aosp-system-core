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

// API to get details about crashes caused by MTE faults (SIGSEGV with
// SEGV_MTESERR).
//

#include <stddef.h>
#include <stdint.h>
#include <sys/cdefs.h>
#include <unistd.h>

__BEGIN_DECLS

typedef enum : int16_t {
  AMEMTAG_CAUSE_TYPE_UNKNOWN,
  AMEMTAG_CAUSE_TYPE_OUT_OF_BOUNDS,
  AMEMTAG_CAUSE_TYPE_USE_AFTER_FREE
} AMemtagCauseType;

struct AMemtagCrashInfo;
struct AMemtagError;
struct AMemtagCause;
struct AMemtagStackTrace;

// Call this in the crashing process to record the necessary information.
// Copy this to your crash dumper process.
// This is async-safe.
AMemtagCrashInfo* _Nullable AMemtagCrashInfo_get(uintptr_t fault_address);

// The size of the structure returned by AMemtagCrashInfo_get.
// This is async-safe.
size_t AMemtagCrashInfo_getSize(AMemtagCrashInfo* _Nonnull);

// Inspect the crashed process to collect more details about the MTE crash.
// This is async-safe only if called in the crashing process.
AMemtagError* _Nullable AMemtagError_get(AMemtagCrashInfo* _Nonnull);

// Return potential cause for MTE crash, or nullptr. The second argument
// specifies which cause to return, if there are multiple. If there are no
// more causes, returns nullptr.
// This is async-safe.
AMemtagCause* _Nullable AMemtagError_getCause(AMemtagError* _Nonnull, size_t);

// Return which type of memory-safety caused the crash.
// This is async-safe.
AMemtagCauseType AMemtagCause_getType(AMemtagCause* _Nonnull);

// Return the address for beginning of the allocation that was involved
// in this memory-safety violation.
// This is async-safe.
uintptr_t AMemtagCause_getAllocationAddress(AMemtagCause* _Nonnull);

// Return stack trace where the relevant allocation was allocated.
// This is async-safe.
AMemtagStackTrace* _Nullable AMemtagCause_getAllocationStack(AMemtagCause* _Nonnull);
// Return thread id that allocated.
// This is async-safe.
pid_t AMemtagCause_getAllocationTid(AMemtagCause* _Nonnull);

// Only for AMEMTAG_CAUSE_TYPE_USE_AFTER_FREE:
// Return stack trace that freed the relevant allocation.
// This is async-safe.
AMemtagStackTrace* _Nullable AMemtagCause_getFreeStack(AMemtagCause* _Nonnull);
// Only for AMEMTAG_CAUSE_TYPE_USE_AFTER_FREE:
// Return thread id that freed.
// This is async-safe.
pid_t AMemtagCause_getFreeTid(AMemtagCause* _Nonnull);

// Get PC of zero-indexed frame of stack trace, or 0 if end reached.
// This is async-safe.
uintptr_t AMemtagStackTrace_getPC(AMemtagStackTrace* _Nonnull, int n);

__END_DECLS
