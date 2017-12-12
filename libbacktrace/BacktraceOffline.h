/*
 * Copyright (C) 2015 The Android Open Source Project
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

#ifndef _LIBBACKTRACE_UNWIND_OFFLINE_H
#define _LIBBACKTRACE_UNWIND_OFFLINE_H

#include <sys/types.h>

#include <backtrace/Backtrace.h>
#include <backtrace/BacktraceMap.h>

class BacktraceOffline : public Backtrace {
 public:
  BacktraceOffline(pid_t pid, pid_t tid, BacktraceMap* map);
  virtual ~BacktraceOffline() = default;

  void SetArch(ArchEnum arch) override;

 protected:
  ArchEnum arch_;
};

#endif  // _LIBBACKTRACE_BACKTRACE_OFFLINE_H
