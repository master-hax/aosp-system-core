/*
 * Copyright (C) 2014 The Android Open Source Project
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

#ifndef _LIBBACKTRACE_UNWIND_MAP_H
#define _LIBBACKTRACE_UNWIND_MAP_H

#include <backtrace/BacktraceMap.h>

// Due to the way libunwind implements local/remote code, do not include
// libunwind.h here. It must be included before this header file in the
// source code.

class UnwindMap : public BacktraceMap {
public:
  UnwindMap(pid_t pid);
  virtual ~UnwindMap();

  virtual bool Build();

  unw_map_cursor_t* GetMapCursor() { return &map_cursor_; }

private:
  unw_map_cursor_t map_cursor_;
};

#endif // _LIBBACKTRACE_UNWIND_MAP_H
