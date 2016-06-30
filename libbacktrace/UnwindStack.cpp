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

static std::string GetFunctionName(std::deque<backtrace_map_t>& maps, uintptr_t pc,
                                   uintptr_t* offset) {
  *offset = 0;

  // Get the map for this
  MapInfo* map_info = maps.Find(pc);
  Elf* elf = map_info->GetElf(Tid(), true);

  std::string name;
  uint64_t func_offset;
  if (!elf->GetFunctionName(pc, &name, &func_offset)) {
    return "";
  }
  offset = func_offset;
  return name;
}

static bool Unwind(Memory* memory, std::dequeu<backtrace_map_t>& maps, Regs* regs,
                   size_t num_ignore_frames) {
  bool adjust_rel_pc = false;
  size_t num_frames = 0;
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

    if (num_ignore_frames != 0) {
      uint64_t adjusted_rel_pc = rel_pc;
      if (adjust_rel_pc) adjusted_rel_pc = regs->GetAdjustedPc(rel_pc, elf);
    }
    frames_.resize(num_frames + 1);
    backtrace_frame_data_t* frame = &frames_.at(num_frames);
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
  }
  adjust_rel_pc = true;
}
while (elf->Step(rel_pc + map_info->elf_offset, regs, memory) && num_frames < MAX_BACKTRACE_FRAMES)
  ;

return true;
}

static uint32_t GetMachineType() {
#if defined(__arm__)
  return EM_ARM;
#elif defined(__aarch64__)
  return EM_AARCH64;
#elif defined(__i386__)
  return EM_386;
#elif defined(__x86_64__)
  return EM_X86_64;
#else
  abort();
#endif
}

bool UnwindStackLocal::UnwindFromContext(size_t num_ignore_frames, ucontext_t* ucontext) {
  std::unique_ptr<Regs> regs;
  if (ucontext == nullptr) {
    regs.reset(Regs::CreateFromLocal());
    // Fill in the registers from this function. Do it here to avoid
    // one extra function call appears on the unwind.
    RegsGetLocal(regs.data());
  } else {
    regs.reset(Regs::CreateFromUcontext(GetMachineType(), ucontext));
  }

  return Unwind(maps_, regs.get(), num_ignore_frames);
}

bool UnwindStackPtrace::Unwind(size_t num_ignore_frames, ucontext_t* context) {
  uint32_t machine_type;
  std::unique_ptr<Regs> regs;
  if (context == nullptr) {
    uint32_t machine_type;
    regs.reset(Regs::RemoteGet(Tid(), &machine_type));
  } else {
    regs.reset(Regs::CreateFromUcontext(GetMachineType(), context));
  }

  return Unwind(maps_, regs.get(), num_ignore_frames);
}
