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

#ifndef _LIBBACKTRACE_UNWIND_STACK_H
#define _LIBBACKTRACE_UNWIND_STACK_H

#include <stdint.h>

#include <string>

#include <backtrace/Backtrace.h>
#include <backtrace/BacktraceMap.h>

class UnwindStack : Backtrace {
 public:
  UnwindStack(pid_t pid, pid_t tid, BacktraceMap* map) : Backtrace(pid, tid, map) {}
  virtual ~UnwindStack() = default;

  std::string GetFunctionNameRaw(uintptr_t pc, uintptr_t* offset) override;

  virtual SetRegs(uint32_t machine_type) = 0;

  bool Unwind(size_t num_ignore_frames, ucontext_t* ucontext) override;

 private:
  bool Unwind(size_t num_ignore_frames);

  std::unique_ptr<Regs> regs_;
};

class UnwindStackCurrent : UnwindStack {
 public:
  UnwindStackCurrent(BacktraceMap* map) : UnwindStack(getpid(), getpid(), map) {}
  virtual ~UnwindStackCurrent() = default;

  SetRegsFromContext(ucontext_t* context, uint32_t machine_type) override;
};

class UnwindStackRemote : UnwindStack {
 public:
  UnwindStackRemote(pid_t pid, pid_t tid, BacktraceMap* map) : UnwindStack(pid, tid, map) {}
  virtual ~UnwindStackRemote() = default;

  SetRegs(uint32_t machine_type) override;
};

#endif  // _LIBBACKTRACE_UNWIND_STACK_H
