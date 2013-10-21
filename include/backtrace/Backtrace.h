/*
 * Copyright (C) 2013 The Android Open Source Project
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

#ifndef _BACKTRACE_BACKTRACE_H
#define _BACKTRACE_BACKTRACE_H

#include <backtrace/backtrace.h>

#include <string>

class Backtrace;

class BacktraceImpl {
public:
  virtual ~BacktraceImpl() { }

  virtual bool Unwind(size_t num_ignore_frames) = 0;

  virtual char* GetProcName(uintptr_t pc, uintptr_t* offset) = 0;

  void SetParent(Backtrace* backtrace) { backtrace_obj_ = backtrace; }

protected:
  backtrace_t* GetBacktraceData();

  Backtrace* backtrace_obj_;
};

class Backtrace {
public:
  Backtrace(BacktraceImpl* impl);
  virtual ~Backtrace();

  // Get the current stack trace.
  virtual bool Unwind(size_t num_ignore_frames) {
    return impl_->Unwind(num_ignore_frames);
  }

  // Get the procedure name and offset into the function given the pc. If
  // NULL is returned, then proc_offset is not set. The returned string
  // must be freed by the caller using free.
  virtual char* GetProcName(uintptr_t pc, uintptr_t* offset) {
    return impl_->GetProcName(pc, offset);
  }

  // Get information about the map associated with a pc. If NULL is returned,
  // then map_start is not set.
  virtual const char* GetMapInfo(uintptr_t pc, uintptr_t* map_start);

  // Finds the memory map associated with the given ptr.
  virtual const backtrace_map_info_t* FindMapInfo(uintptr_t ptr);

  // Read the data at a specific address.
  virtual bool ReadWord(uintptr_t ptr, uint32_t* out_value) = 0;

  // Create a string representing the formatted line of backtrace information
  // for a single frame.
  virtual std::string FormatFrameData(size_t frame_num);

  pid_t Pid() { return backtrace_.pid; }
  pid_t Tid() { return backtrace_.tid; }
  size_t NumFrames() { return backtrace_.num_frames; }

  const backtrace_t* GetBacktrace() { return &backtrace_; }

  const backtrace_frame_data_t* GetFrame(size_t frame_num) {
    return &backtrace_.frames[frame_num];
  }

  // Return a demangled representation of symbol_name. If symbol_name is
  // NULL, return NULL. The name returned must be freed by the caller.
  static char* Demangle(const char* symbol_name);

protected:
  virtual bool VerifyReadWordArgs(uintptr_t ptr, uint32_t* out_value);

  BacktraceImpl* impl_;

  backtrace_map_info_t* map_info_;

  backtrace_t backtrace_;

  friend class BacktraceImpl;
};

// Create the correct Backtrace object based on what is to be unwound.
// If pid < 0 or equals the current pid, then the Backtrace object corresponds
// to the current process.
// If pid < 0 or equals the current pid and tid >= 0, then the Backtrace object
// corresponds to a thread in the current process.
// If pid >= 0 and tid < 0, then the Backtrace object corresponds to a
// different process.
// Tracing a thread in a different process is not supported.
Backtrace* BacktraceCreateObj(pid_t pid, pid_t tid);

#endif // _BACKTRACE_BACKTRACE_H
