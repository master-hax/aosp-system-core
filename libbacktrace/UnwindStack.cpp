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

#include <stdint.h>
#include <ucontext.h>

#include <memory>
#include <string>

#include <android-base/logging.h>
#include <backtrace/Backtrace.h>
#include <libunwindstack/>

#include "BacktraceLog.h"
#include "UnwindStackCurrent.h"

static std::string GetFunctionName(BacktraceMap* maps, uintptr_t pc, uintptr_t* offset) {
  *offset = 0;
  Maps* maps = reinterpret_cast<UnwindStackMap*>(maps)->maps();

  // Get the map for this
  MapInfo* map_info = maps->Find(pc);
  Elf* elf = map_info->GetElf(Tid(), true);

  std::string name;
  uint64_t func_offset;
  if (!elf->GetFunctionName(pc, &name, &func_offset)) {
    return "";
  }
  offset = func_offset;
  return name;
}

static bool IsUnwindLibrary(const std::string& map_name) {
  const std::string library(basename(map_name));
  return library == "libunwindstack.so" || library == "libbacktrace.so";
}

static bool Unwind(Memory* memory, std::dequeu<backtrace_map_t>& maps, Regs* regs,
                   std::vector<backtrace_frame_data_>* frames, size_t num_ignore_frames) {
  bool adjust_rel_pc = false;
  size_t num_frames = 0;
  frames->clear();
  do {
    if (regs->pc() == 0) {
      break;
    }
    MapInfo* map_info = maps.Find(regs->pc());
    if (map_info == nullptr) {
      break;
    }

    Elf* elf = map_info->GetElf(Tid(), true);
    uint64_t rel_pc = regs->GetRelPc(elf, map_info);

    bool skip_frame = num_frames == 0 && IsUnwindLibrary(map_info->name);
    if (num_ignore_frames == 0 && !skip_frame) {
      uint64_t adjusted_rel_pc = rel_pc;
      if (adjust_rel_pc) {
        adjusted_rel_pc = regs->GetAdjustedPc(rel_pc, elf);
      }
      frames->resize(num_frames + 1);
      backtrace_frame_data_t* frame = &frames_->at(num_frames);
      frame->num = num_frames;
      frame->pc = regs_->pc();
      frame->sp = regs_->sp();
      frame->rel_pc = adjusted_rel_pc;
      frame->stack_size = 0;

      frame->map.start = map_info->start;
      frame->map.end = map_info->end;
      frame->map.offset = map_info->offset;
      frame->map.load_base = elf->load_bias();
      frame->map.flags = map_info->flags;
      frame->map.name = map_info->name;

      frame->func_name = GetFunctionName(maps, frame->pc, &frame->func_offset);

      elf->GetFunctionName(pc, &frame->func_name, &func_offset);

      if (num_frames > 0) {
        // Set the stack size for the previous frame.
        backtrace_frame_data_t* prev = &frames_.at(num_frames - 1);
        prev->stack_size = frame->sp - prev->sp;
      }
      num_frames++;
    } else if (!skip_frame && num_ignored_frames > 0) {
      num_ignored_frames--;
    }
    adjust_rel_pc = true;
  } while (elf->Step(rel_pc + map_info->elf_offset, regs, memory) &&
           num_frames < MAX_BACKTRACE_FRAMES);

  return true;
}

std::string UnwindStackCurrent::GetFunctionNameRaw(uintptr_t pc, uintptr_t* offset) {
  return GetFunctionName(maps_, pc, offset);
}

bool UnwindStackCurrent::UnwindFromContext(size_t num_ignore_frames, ucontext_t* ucontext) {
  std::unique_ptr<Regs> regs;
  if (ucontext == nullptr) {
    regs.reset(Regs::CreateFromLocal());
    // Fill in the registers from this function. Do it here to avoid
    // one extra function call appearing in the unwind.
    RegsGetLocal(regs.data());
  } else {
    regs.reset(Regs::CreateFromUcontext(Regs::GetMachineType(), ucontext));
  }

  return Unwind(maps_, regs.get(), &frames_, num_ignore_frames);
}

std::string UnwindStackPtrace::GetFunctionNameRaw(uintptr_t pc, uintptr_t* offset) {
  return GetFunctionName(maps_, pc, offset);
}

bool UnwindStackPtrace::Unwind(size_t num_ignore_frames, ucontext_t* context) {
  uint32_t machine_type;
  std::unique_ptr<Regs> regs;
  if (context == nullptr) {
    uint32_t machine_type;
    regs.reset(Regs::RemoteGet(Tid(), &machine_type));
  } else {
    regs.reset(Regs::CreateFromUcontext(Regs::GetMachineType(), context));
  }

  return Unwind(maps_, regs.get(), &frames_, num_ignore_frames);
}

Backtrace* Backtrace::CreateNew(pid_t pid, pid_t tid, BacktraceMap* map) {
  if (pid == BACKTRACE_CURRENT_PROCESS) {
    pid = getpid();
    if (tid == BACKTRACE_CURRENT_THREAD) {
      tid = gettid();
    }
  } else if (tid == BACKTRACE_CURRENT_THREAD) {
    tid = pid;
  }

  if (pid == getpid()) {
    return new UnwindStackCurrent(pid, tid, map);
  } else {
    return new UnwindStackPtrace(pid, tid, map);
  }
}
