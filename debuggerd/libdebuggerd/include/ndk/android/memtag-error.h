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

/**
 * API to get details about crashes caused by Memory Tagging faults.
 * Currently, this supports MTE fauls on ARM64 (SIGSEGV with SEGV_MTESERR).
 *
 * This API is designed with two use-cases in mind:
 * 1. (recommended) out-of-process crash handling.
 *    * in the SIGSEGV handler, call AMemtagCrashInfo_get.
 *    * fork off the crash handling process, and transfer the byte string obtained by
 *      AMemtagCrashInfo_toBytes to it.
 *    * exec the crash handling binary, while passing in the byte string (might contain NUL,
 *       so use a pipe rather than as an argument).
 *    * use AMemtagCrashInfo_createFromBytes in the crash handling binary.
 *    * use AMemtagError_get to inspect the crashed process, which needs to be suspended.
 *    * get the required information from the AMemtagError.
 * 2. (not recommended) in-process crash handling:
 *     in-process crash handling is inherently less stable, because the crashed process is in
 *     an undefined state, but it is easier to implement. in the SIGSEGV handler (for si_code
 * SEGV_MTESERR):
 *    * call AMemtagCrashInfo_get.
 *    * call AMemtagError_get.
 *    * get the required information from the AMemtagError.
 * @defgroup MemtagError
 * @{
 */

/**
 * @file memtag-error.h
 */

#include <stddef.h>
#include <stdint.h>
#include <sys/cdefs.h>
#include <unistd.h>

#if !defined(__INTRODUCED_IN)
#define __INTRODUCED_IN(__api_level) /* nothing */
#endif

__BEGIN_DECLS

typedef enum : int16_t {
  AMEMTAG_CAUSE_TYPE_UNKNOWN,
  AMEMTAG_CAUSE_TYPE_OUT_OF_BOUNDS,
  AMEMTAG_CAUSE_TYPE_USE_AFTER_FREE
} AMemtagCauseType;

typedef struct AMemtagCrashInfo AMemtagCrashInfo;
typedef struct AMemtagError AMemtagError;
typedef struct AMemtagCause AMemtagCause;
typedef struct AMemtagStackTrace AMemtagStackTrace;

/**
 * Record the necessary information about the process to allow getting
 * details about the MTE crash.
 *
 * Call this in the signal handler for the crashing process.
 *
 * Calling this invalidates the return value of previous calls to this and
 * AMemtagCrashInfo_createFromBytes in the process.
 *
 * Introduced in API 35.
 * This is async-safe.
 *
 * \param fault_address the address that caused the SIGSEGV.
 */
const AMemtagCrashInfo* _Nullable AMemtagCrashInfo_get(uintptr_t fault_address) __INTRODUCED_IN(35);

/**
 * Convert AMemtagCrashInfo to a byte string.
 *
 * See also AMemtagCrash_byteSize.
 *
 * Introduced in API 35.
 * This is async-safe.
 */
const char* _Nonnull AMemtagCrashInfo_toBytes(const AMemtagCrashInfo* _Nonnull) __INTRODUCED_IN(35);

/**
 * Size of the byte string returned by AMemtagCrashInfo_toBytes.
 *
 * Introduced in API 35.
 * This is async-safe.
 */
size_t AMemtagCrashInfo_byteSize(const AMemtagCrashInfo* _Nonnull) __INTRODUCED_IN(35);

/**
 * Convert byte string of size returned by AMemtagCrashInfo_byteSize back to AMemtagCrashInfo.
 *
 * The byte string MUST have originally been returned by AMemtagCrashInfo_toBytes.
 * It can be copied, sent over pipe etc., but you MUST NOT call this function on
 * arbitrary strings.
 *
 * Calling this invalidates the return value of previous calls to this and
 * AMemtagCrashInfo_get in the process.
 *
 * Introduced in API 35.
 * This is async-safe.
 */
const AMemtagCrashInfo* _Nonnull AMemtagCrashInfo_createFromBytes(const char* _Nonnull)
    __INTRODUCED_IN(35);

/**
 * Inspect the crashed process to collect more details about the MTE crash.
 *
 * Calling this invalidates the return value of previous calls this.
 *
 * Introduced in API 35.
 * This is async-safe only if called in the crashing process.
 */
const AMemtagError* _Nullable AMemtagError_get(const AMemtagCrashInfo* _Nonnull)
    __INTRODUCED_IN(35);

/**
 * Return potential cause for MTE crash, or nullptr.
 *
 * \param n specifies which cause to return, if there are multiple. If there are no
 *          more causes, returns nullptr.
 *
 * Introduced in API 35.
 * This is async-safe.
 */
const AMemtagCause* _Nullable AMemtagError_getCause(const AMemtagError* _Nonnull, size_t n)
    __INTRODUCED_IN(35);

/**
 * Return which type of memory-safety violation caused the crash.
 *
 * Introduced in API 35.
 * This is async-safe.
 */
AMemtagCauseType AMemtagCause_getType(const AMemtagCause* _Nonnull) __INTRODUCED_IN(35);

/**
 * Return the address for beginning of the allocation that was involved
 * in this memory-safety violation.
 *
 * Introduced in API 35.
 * This is async-safe.
 */
uintptr_t AMemtagCause_getAllocationAddress(const AMemtagCause* _Nonnull) __INTRODUCED_IN(35);

/**
 * Return stack trace where the relevant allocation was allocated.
 *
 * Introduced in API 35.
 * This is async-safe.
 */
const AMemtagStackTrace* _Nullable AMemtagCause_getAllocationStack(const AMemtagCause* _Nonnull)
    __INTRODUCED_IN(35);

/**
 * Return thread id that allocated the memory involved in the memory-safety violation.
 *
 * Introduced in API 35.
 * This is async-safe.
 */
pid_t AMemtagCause_getAllocationTid(const AMemtagCause* _Nonnull) __INTRODUCED_IN(35);

/**
 * Return stack trace that freed the relevant allocation.
 *
 * If AMemtagCause_getType is not AMEMTAG_CAUSE_TYPE_USE_AFTER_FREE, return nullptr.
 *
 * Introduced in API 35.
 * This is async-safe.
 */
const AMemtagStackTrace* _Nullable AMemtagCause_getFreeStack(const AMemtagCause* _Nonnull)
    __INTRODUCED_IN(35);

/**
 * Return thread id that freed.
 *
 * If AMemtagCause_getType is not AMEMTAG_CAUSE_TYPE_USE_AFTER_FREE, return 0.
 *
 * Introduced in API 35.
 * This is async-safe.
 */
pid_t AMemtagCause_getFreeTid(const AMemtagCause* _Nonnull) __INTRODUCED_IN(35);

/**
 * Get PC of zero-indexed frame of stack trace, or 0 if end reached.
 *
 * \param n index of frame in the stack trace, starting from topmost.
 * \return absolute PC of the frame, or 0 if past the end of the stack trace.
 *
 * Introduced in API 35.
 * This is async-safe.
 */
uintptr_t AMemtagStackTrace_getPC(const AMemtagStackTrace* _Nonnull, int n) __INTRODUCED_IN(35);

__END_DECLS

/** @} */
