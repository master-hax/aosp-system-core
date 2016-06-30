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

std::string UnwindCurrentStack::GetFunctionNameRaw(uintptr_t pc, uintptr_t* offset) {
  *offset = 0;

  // Get the map for this
  MapInfo* map_info = maps_.Find(pc);
  Elf* elf = map_info->elf;
  if (elf == nullptr) {
    elf = new Elf(map_info->CreateMemory(pid_));
    if (elf->Init()) {
      return "";
    }
    map_info->elf = elf;
  }

  std::string name;
  uint64_t func_offset;
  if (!elf->GetFunctionName(pc, &name, &func_offset)) {
    return "";
  }
  offset = func_offset;
  return name;
}

bool UnwindStack::Init() {
#if defined()
  regs_.reset(new RegsX86());
#elif defined()
  regs_.reset(new RegsX86_64());
#elif defined()
  regs_.reset(new RegsArm());
#elif defined()
  regs_.reset(new RegsArm64());
#else
  return false;
#endif
}

bool UnwindStackCurrent::SetRegs(uint32_t machine_type) {
  if (regs_.get() == nullptr) {
    switch (machine_type) {
      case EM_386:
        regs_.reset(new RegsX86());
      case EM_X86_64:
        regs_.reset(new RegsX86_64());
      case EM_ARM:
        regs_.reset(new RegsArm());
      case EM_AARCH64:
        regs_.reset(new RegsArm64());
      default:
        return false;
    }
  }
  LocalGetRegs(regs_->RawData());

  return true;
}

bool UnwindStackRemote::SetRegsFromContext(uint32_t machine_type) {
  uint32_t detected_machine_type;
  regs_.reset(Regs::RemoteGet(pid_, &detected_machine_type));
  return machine_type == detected_machine_type;
}

bool UnwindStack::Unwind(size_t num_ignore_frames, ucontext_t* context) {
  uint32_t machine_type;
#if defined(__arm__)
  machine_type = EM_ARM;
#elif defined(__aarch64__)
  machine_type = EM_AARCH64;
#elif defined(__i386__)
  machine_type = EM_386;
#elif defined(__x86_64__)
  machine_type = EM_X86_64;
#else
  machine_type = EM_NONE;
#endif
  if (context != nullptr) {
    regs_.reset(Regs::CreateFromUcontext(machine_type, context));
  } else {
    SetRegs(machine_type);
  }

  return InternalUnwind(num_ignore_frames);
}

bool UnwindStack::InternalUnwind(size_t num_ignore_frames) {
  size_t num_frames = 0;
  do {
    MapInfo* map_info = maps_.Find(regs_->pc());
    Elf* elf = map_info->GetElf(Tid(), true);

    frames_.resize(num_frames + 1);
    backtrace_frame_data_t* frame = &frames_.at(num_frames);
    frame->num = num_frames;
    frame->pc = regs_->pc();
    frame->sp = regs_->sp();
    frame->stack_size = 0;

    frame->map.start = map_info->start;
    frame->map.end = map_info->end;
    frame->map.offset = map_info->offset;
    frame->map.load_base = elf->load_bias();
    frame->map.flags = map_info->flags;
    frame->map.name = map_info->name;

    uint64_t relative_pc =

        // Check to see if we should skip this frame because it's coming
        // from within the library, and we are doing a local unwind.
        if (ucontext != nullptr || num_frames != 0 || !DiscardFrame(*frame)) {
      if (num_ignore_frames == 0) {
        // GetFunctionName is an expensive call, only do it if we are
        // keeping the frame.
        frame->func_name = GetFunctionName(frame->pc, &frame->func_offset, &frame->map);
        if (num_frames > 0) {
          // Set the stack size for the previous frame.
          backtrace_frame_data_t* prev = &frames_.at(num_frames - 1);
          prev->stack_size = frame->sp - prev->sp;
        }
        num_frames++;
      } else {
        num_ignore_frames--;
        // Set the number of frames to zero to remove the frame added
        // above. By definition, if we still have frames to ignore
        // there should only be one frame in the vector.
        CHECK(num_frames == 0);
        frames_.resize(0);
      }
    }
    // If the pc is in a device map, then don't try to step.
    if (frame->map.flags & PROT_DEVICE_MAP) {
      break;
    }
    // Verify the sp is not in a device map too.
    map_info = maps_.Find(frame->sp);
    if (map_info != nullptr && (map.flags & PROT_DEVICE_MAP)) {
      break;
    }
    uint64_t rel_pc = regs_->GetRelPc(elf, map_info) : uint64_t adjusted_rel_pc = rel_pc;
    if (frame_num != 0) {
      frame->rel_pc = regs_->GetAdjustedPc(rel_pc, elf);
    } else {
      frame->rel_pc = rel_pc;
    }
  } while (elf->Step(rel_pc + map_info->elf_offset, regs_, memory_) &&
           num_frames < MAX_BACKTRACE_FRAMES);

  return true;
}
