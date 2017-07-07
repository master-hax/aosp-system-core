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

#include <stdint.h>

#include <gtest/gtest.h>

#include <memory>
#include <sstream>
#include <string>

#include "Elf.h"
#include "MapInfo.h"
#include "Maps.h"
#include "Memory.h"
#include "Regs.h"
#include "RegsGetLocal.h"

static std::string ErrorMsg(const char** function_names, size_t index,
                            std::stringstream& unwind_stream) {
  return std::string(
             "Unwind completed without finding all frames\n"
             "  Looking for function: ") +
         function_names[index] + "\n" + "Unwind data:\n" + unwind_stream.str();
}

// This test assumes that this code is compiled with optimizations turned
// off. If this doesn't happen, then all of the calls will be optimized
// away.
extern "C" void InnerFunction() {
  const char* function_names[] = {
      "InnerFunction", "MiddleFunction", "OuterFunction",
  };
  size_t function_name_index = 0;

  LocalMaps maps;
  ASSERT_TRUE(maps.Parse());
  std::unique_ptr<Regs> regs(Regs::CreateFromLocal());
  RegsGetLocal(regs.get());
  MemoryLocal memory;

  std::stringstream unwind_stream;
  unwind_stream << std::hex;
  for (size_t frame_num = 0; frame_num < 64; frame_num++) {
    ASSERT_NE(0U, regs->pc()) << ErrorMsg(function_names, function_name_index, unwind_stream);
    MapInfo* map_info = maps.Find(regs->pc());
    ASSERT_TRUE(map_info != nullptr) << ErrorMsg(function_names, function_name_index, unwind_stream);

    Elf* elf = map_info->GetElf(getpid(), true);
    uint64_t rel_pc = regs->GetRelPc(elf, map_info);
    uint64_t adjusted_rel_pc = rel_pc;
    if (frame_num != 0) {
      adjusted_rel_pc = regs->GetAdjustedPc(rel_pc, elf);
    }
    unwind_stream << "  PC: 0x" << regs->pc() << " Rel: 0x" << adjusted_rel_pc;
    unwind_stream << " Map: ";
    if (!map_info->name.empty()) {
      unwind_stream << map_info->name;
    } else {
      unwind_stream << " anonymous";
    }
    unwind_stream << "<" << map_info->start << "-" << map_info->end << ">";

    std::string name;
    uint64_t func_offset;
    if (elf->GetFunctionName(adjusted_rel_pc, &name, &func_offset)) {
      if (name == function_names[function_name_index]) {
        function_name_index++;
        if (function_name_index == sizeof(function_names) / sizeof(const char*)) {
          return;
        }
      }
      unwind_stream << " " << name;
    }
    unwind_stream << "\n";
    ASSERT_TRUE(elf->Step(rel_pc + map_info->elf_offset, regs.get(), &memory))
        << ErrorMsg(function_names, function_name_index, unwind_stream);
  }
  ASSERT_TRUE(false) << ErrorMsg(function_names, function_name_index, unwind_stream);
}

extern "C" void MiddleFunction() {
  InnerFunction();
}

extern "C" void OuterFunction() {
  MiddleFunction();
}

TEST(RegsGetLocal, local_unwind) {
  OuterFunction();
}
