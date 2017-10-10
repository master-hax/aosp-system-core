/*
 * Copyright (C) 2017 The Android Open Source Project
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

#ifndef _LIBUNWINDSTACK_UNWIND_H
#define _LIBUNWINDSTACK_UNWIND_H

#include <stdint.h>

// C++ interface: https://itanium-cxx-abi.github.io/cxx-abi/abi-eh.html

// Forward declaration of opaque type.
struct _Unwind_Context;

typedef enum {
  _URC_NO_REASON = 0,
  _URC_FOREIGN_EXCEPTION_CAUGHT = 1,
  _URC_FATAL_PHASE2_ERROR = 2,
  _URC_FATAL_PHASE1_ERROR = 3,
  _URC_NORMAL_STOP = 4,
  _URC_END_OF_STACK = 5,
  _URC_HANDLER_FOUND = 6,
  _URC_INSTALL_CONTEXT = 7,
  _URC_CONTINUE_UNWIND = 8,
} _Unwind_Reason_Code;

typedef int _Unwind_Action;
static const _Unwind_Action _UA_SEARCH_PHASE = 1;
static const _Unwind_Action _UA_CLEANUP_PHASE = 2;
static const _Unwind_Action _UA_HANDLER_FRAME = 4;
static const _Unwind_Action _UA_FORCE_UNWIND = 8;
#if defined(_GNU_SOURCE)
// GNU extension
static const _Unwind_Action _UA_END_OF_STACK = 16;
#endif

typedef void (*_Unwind_Exception_Cleanup_Fn)(_Unwind_Reason_Code reason, struct _Unwind_Exception*);

struct _Unwind_Exception {
  uint64 exception_class;
  _Unwind_Exception_Cleanup_Fn exception_cleanup;
  uint64 private_1;
  uint64 private_2;
};

typedef _Unwind_Reason_Code (*_Unwind_Stop_Fn)(int version, _Unwind_Action actions,
                                               uint64 exceptionClass,
                                               struct _Unwind_Exception* exceptionObject,
                                               struct _Unwind_Context* context,
                                               void* stop_parameter);

_Unwind_Reason_Code _Unwind_RaiseException(struct _Unwind_Exception* exception_object);

_Unwind_Reason_Code _Unwind_ForcedUnwind(struct _Unwind_Exception* exception_object,
                                         _Unwind_Stop_Fn stop, void* stop_parameter);

void _Unwind_Resume(struct _Unwind_Exception* exception_object);

void _Unwind_DeleteException(struct _Unwind_Exception* exception_object);

uint64 _Unwind_GetGR(struct _Unwind_Context* context, int index);

void _Unwind_SetGR(struct _Unwind_Context* context, int index, uint64 new_value);

uint64 _Unwind_GetIP(struct _Unwind_Context* context);

void _Unwind_SetIP(struct _Unwind_Context* context, uint64 new_value);

uint64 _Unwind_GetLanguageSpecificData(struct _Unwind_Context* context);

uint64 _Unwind_GetRegionStart(struct _Unwind_Context* context);

#if defined(_GNU_SOURCE)
// GNU extensions defined here:
// https://refspecs.linuxfoundation.org/LSB_3.1.0/LSB-Core-S390/LSB-Core-S390/libgcc-s.html

_Unwind_Reason_Code _Unwind_Resume_or_Rethrow(struct _Unwind_Exception*);

unsigned long _Unwind_GetBSP(struct _Unwind_Context*);

unsigned long _Unwind_GetCFA(struct _Unwind_Context*);

unsigned long _Unwind_GetIPInfo(struct _Unwind_Context*, int*);

void* _Unwind_FindEnclosingFunction(void*);

typedef _Unwind_Reason_Code (*_Unwind_Trace_Fn)(struct _Unwind_Context*, void*);

_Unwind_Reason_Code _Unwind_Backtrace(_Unwind_Trace_Fn, void*) :
#endif

#endif  // _LIBUNWINDSTACK_UNWIND_H
