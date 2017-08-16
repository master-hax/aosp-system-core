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

#ifndef _BACKTRACE_BACKTRACE_MAP_BASIC_H
#define _BACKTRACE_BACKTRACE_MAP_BASIC_H

#include <deque>

#include <backtrace/BacktraceMap.h>

class BacktraceMapBasic : public BacktraceMap {
 public:
  BacktraceMapBasic(pid_t pid, const std::vector<backtrace_map_t>& maps);
  BacktraceMapBasic(pid_t pid) : BacktraceMap(pid) {}
  virtual ~BacktraceMapBasic() = default;

  backtrace_map_t Get(size_t index) override { return maps_[index]; }
  size_t NumMaps() override { return maps_.size(); }
  void FillIn(uintptr_t addr, backtrace_map_t* map) override;
  bool Build() override;

 protected:
  virtual bool ParseLine(const char* line, backtrace_map_t* map);

  std::deque<backtrace_map_t> maps_;
};

#endif  // _BACKTRACE_BACKTRACE_MAP_H
