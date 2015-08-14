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

#include "BacktraceOffline.h"

extern "C" {
#define UNW_REMOTE_ONLY
#include <dwarf.h>
}

#include <stdint.h>
#include <string.h>
#include <sys/types.h>
#include <ucontext.h>
#include <unistd.h>

#include <string>

#include <backtrace/Backtrace.h>
#include <backtrace/BacktraceMap.h>

#include "BacktraceLog.h"

void Space::Clear() {
  start = 0;
  end = 0;
  data = nullptr;
}

size_t Space::Read(uint64_t addr, uint8_t* buffer, size_t size) {
  if (addr >= start && addr < end) {
    size_t read_size = std::min(size, static_cast<size_t>(end - addr));
    memcpy(buffer, data + (addr - start), read_size);
    return read_size;
  }
  return 0;
}

static int FindProcInfo(unw_addr_space_t addr_space, unw_word_t ip, unw_proc_info* proc_info,
                        int need_unwind_info, void* arg) {
  BacktraceOffline* backtrace = reinterpret_cast<BacktraceOffline*>(arg);
  bool result = backtrace->FindProcInfo(addr_space, ip, proc_info, need_unwind_info);
  return result ? 0 : -UNW_EINVAL;
}

static void PutUnwindInfo(unw_addr_space_t, unw_proc_info_t*, void*) {
}

static int GetDynInfoListAddr(unw_addr_space_t, unw_word_t*, void*) {
  return -UNW_ENOINFO;
}

static int AccessMem(unw_addr_space_t, unw_word_t addr, unw_word_t* value, int write, void* arg) {
  if (write == 1) {
    return -UNW_EINVAL;
  }
  BacktraceOffline* backtrace = reinterpret_cast<BacktraceOffline*>(arg);
  size_t read_size = backtrace->Read(addr, reinterpret_cast<uint8_t*>(value), sizeof(unw_word_t));
  return (read_size == sizeof(unw_word_t) ? 0 : -UNW_EINVAL);
}

static int AccessReg(unw_addr_space_t, unw_regnum_t unwind_reg, unw_word_t* value, int write,
                     void* arg) {
  if (write == 1) {
    return -UNW_EINVAL;
  }
  BacktraceOffline* backtrace = reinterpret_cast<BacktraceOffline*>(arg);
  uint64_t reg_value;
  bool result = backtrace->ReadReg(unwind_reg, &reg_value);
  if (result) {
    *value = static_cast<unw_word_t>(reg_value);
  }
  return result ? 0 : -UNW_EINVAL;
}

static int AccessFpReg(unw_addr_space_t, unw_regnum_t, unw_fpreg_t*, int, void*) {
  return -UNW_EINVAL;
}

static int Resume(unw_addr_space_t, unw_cursor_t*, void*) {
  return -UNW_EINVAL;
}

static int GetProcName(unw_addr_space_t, unw_word_t, char*, size_t, unw_word_t*, void*) {
  return -UNW_EINVAL;
}

static unw_accessors_t accessors = {
    .find_proc_info = FindProcInfo,
    .put_unwind_info = PutUnwindInfo,
    .get_dyn_info_list_addr = GetDynInfoListAddr,
    .access_mem = AccessMem,
    .access_reg = AccessReg,
    .access_fpreg = AccessFpReg,
    .resume = Resume,
    .get_proc_name = GetProcName,
};

bool BacktraceOffline::Unwind(size_t num_ignore_frames, ucontext_t* context) {
  if (context != nullptr) {
    BACK_LOGW("Unwinding frome a specified context not supported yet.");
    return false;
  }

  unw_addr_space_t addr_space = unw_create_addr_space(&accessors, 0);
  unw_cursor_t cursor;
  int ret = unw_init_remote(&cursor, addr_space, this);
  if (ret != 0) {
    BACK_LOGW("unw_init_remote failed %d", ret);
    unw_destroy_addr_space(addr_space);
    return false;
  }
  size_t num_frames = 0;
  do {
    unw_word_t pc;
    ret = unw_get_reg(&cursor, UNW_REG_IP, &pc);
    if (ret < 0) {
      BACK_LOGW("Failed to read IP %d", ret);
      break;
    }
    unw_word_t sp;
    ret = unw_get_reg(&cursor, UNW_REG_SP, &sp);
    if (ret < 0) {
      BACK_LOGW("Failed to read SP %d", ret);
      break;
    }

    if (num_ignore_frames == 0) {
      frames_.resize(num_frames + 1);
      backtrace_frame_data_t* frame = &frames_[num_frames];
      frame->num = num_frames;
      frame->pc = static_cast<uintptr_t>(pc);
      frame->sp = static_cast<uintptr_t>(sp);
      frame->stack_size = 0;

      if (num_frames > 0) {
        backtrace_frame_data_t* prev = &frames_[num_frames - 1];
        prev->stack_size = frame->sp - prev->sp;
      }
      frame->func_name = GetFunctionName(frame->pc, &frame->func_offset);
      FillInMap(frame->pc, &frame->map);
      num_frames++;

    } else {
      num_ignore_frames--;
    }
    ret = unw_step(&cursor);
  } while (ret > 0 && num_frames < MAX_BACKTRACE_FRAMES);

  unw_destroy_addr_space(addr_space);
  return true;
}

bool BacktraceOffline::ReadWord(uintptr_t ptr, word_t* out_value) {
  size_t bytes_read = Read(ptr, reinterpret_cast<uint8_t*>(out_value), sizeof(word_t));
  return bytes_read == sizeof(word_t);
}

size_t BacktraceOffline::Read(uintptr_t addr, uint8_t* buffer, size_t bytes) {
  size_t read_size = eh_frame_hdr_space_.Read(addr, buffer, bytes);
  if (read_size != 0) {
    return read_size;
  }
  read_size = eh_frame_space_.Read(addr, buffer, bytes);
  if (read_size != 0) {
    return read_size;
  }
  read_size = callbacks_.ReadStack(addr, buffer, bytes);
  return read_size;
}

static bool FileOffsetToVaddr(
    const std::vector<BacktraceOfflineCallbacks::DebugFrameInfo::EhFrame::ProgramHeader>&
        program_headers,
    uint64_t file_offset, uint64_t* vaddr) {
  for (auto& header : program_headers) {
    if (file_offset >= header.file_offset && file_offset < header.file_offset + header.file_size) {
      // TODO: Consider load_bias?
      *vaddr = file_offset - header.file_offset + header.vaddr;
      return true;
    }
  }
  return false;
}

static bool OmitEncodedValue(uint8_t encode, const uint8_t*& p) {
  if (encode == DW_EH_PE_omit) {
    return 0;
  }
  uint8_t format = encode & 0x0f;
  switch (format) {
    case DW_EH_PE_ptr:
      p += sizeof(unw_word_t);
      break;
    case DW_EH_PE_uleb128:
    case DW_EH_PE_sleb128:
      while ((*p & 0x80) != 0) {
        ++p;
      }
      ++p;
      break;
    case DW_EH_PE_udata2:
    case DW_EH_PE_sdata2:
      p += 2;
      break;
    case DW_EH_PE_udata4:
    case DW_EH_PE_sdata4:
      p += 4;
      break;
    case DW_EH_PE_udata8:
    case DW_EH_PE_sdata8:
      p += 8;
      break;
    default:
      return false;
  }
  return true;
}

static bool GetFdeTableOffsetInEhFrameHdr(const std::vector<uint8_t>& data,
                                          uint64_t* table_offset_in_eh_frame_hdr) {
  const uint8_t* p = data.data();
  const uint8_t* end = p + data.size();
  if (p + 4 > end) {
    return false;
  }
  uint8_t version = *p++;
  if (version != 1) {
    return false;
  }
  uint8_t eh_frame_ptr_encode = *p++;
  uint8_t fde_count_encode = *p++;
  uint8_t fde_table_encode = *p++;

  if (fde_table_encode != (DW_EH_PE_datarel | DW_EH_PE_sdata4)) {
    return false;
  }

  if (!OmitEncodedValue(eh_frame_ptr_encode, p) || !OmitEncodedValue(fde_count_encode, p)) {
    return false;
  }
  if (p >= end) {
    return false;
  }
  *table_offset_in_eh_frame_hdr = p - data.data();
  return true;
}

bool BacktraceOffline::FindProcInfo(unw_addr_space_t addr_space, uint64_t ip,
                                    unw_proc_info_t* proc_info, int need_unwind_info) {
  backtrace_map_t map;
  FillInMap(ip, &map);
  if (!BacktraceMap::IsValid(map)) {
    return false;
  }
  const std::string& filename = map.name;
  BacktraceOfflineCallbacks::DebugFrameInfo* debug_frame = callbacks_.GetDebugFrameInfo(filename);
  if (debug_frame == nullptr) {
    return false;
  }
  if (debug_frame->is_eh_frame) {
    if (debug_frame->eh_frame.fde_table_offset_in_eh_frame_hdr == 0) {
      if (!GetFdeTableOffsetInEhFrameHdr(debug_frame->eh_frame.eh_frame_hdr_data,
                                         &debug_frame->eh_frame.fde_table_offset_in_eh_frame_hdr)) {
        return false;
      }
    }
    uint64_t ip_offset = ip - map.start + map.offset;
    uint64_t ip_vaddr;  // vaddr in the elf file.
    bool result = FileOffsetToVaddr(debug_frame->eh_frame.program_headers, ip_offset, &ip_vaddr);
    if (!result) {
      return false;
    }
    // Calculate the addresses where .eh_frame_hdr and .eh_frame stay when the process was running.
    eh_frame_hdr_space_.start = (ip - ip_vaddr) + debug_frame->eh_frame.eh_frame_hdr_vaddr;
    eh_frame_hdr_space_.end =
        eh_frame_hdr_space_.start + debug_frame->eh_frame.eh_frame_hdr_data.size();
    eh_frame_hdr_space_.data = debug_frame->eh_frame.eh_frame_hdr_data.data();

    eh_frame_space_.start = (ip - ip_vaddr) + debug_frame->eh_frame.eh_frame_vaddr;
    eh_frame_space_.end = eh_frame_space_.start + debug_frame->eh_frame.eh_frame_data.size();
    eh_frame_space_.data = debug_frame->eh_frame.eh_frame_data.data();

    unw_dyn_info di;
    memset(&di, '\0', sizeof(di));
    di.start_ip = map.start;
    di.end_ip = map.end;
    di.format = UNW_INFO_FORMAT_REMOTE_TABLE;
    di.u.rti.name_ptr = 0;
    // It is required by libunwind to be eh_frame_hdr's address in memory?
    di.u.rti.segbase = eh_frame_hdr_space_.start;
    di.u.rti.table_data =
        eh_frame_hdr_space_.start + debug_frame->eh_frame.fde_table_offset_in_eh_frame_hdr;
    di.u.rti.table_len = (eh_frame_hdr_space_.end - di.u.rti.table_data) / sizeof(unw_word_t);
    // return dwarf_search_unwind_table(addr_space, ip, &di, proc_info, need_unwind_info, this) ==
    // 0;
    int ret = dwarf_search_unwind_table(addr_space, ip, &di, proc_info, need_unwind_info, this);
    return ret == 0;
  }

  eh_frame_hdr_space_.Clear();
  eh_frame_space_.Clear();
  unw_dyn_info_t di;
  unw_word_t segbase = map.start - map.offset;
  int found = dwarf_find_debug_frame(0, &di, ip, segbase, filename.c_str(), map.start, map.end);
  if (found == 1) {
    int ret = dwarf_search_unwind_table(addr_space, ip, &di, proc_info, need_unwind_info, this);
    return ret == 0;
  }
  return false;
}

bool BacktraceOffline::ReadReg(size_t reg_index, uint64_t* value) {
  // return callbacks_.ReadReg(reg_index, value);
  return callbacks_.ReadReg(reg_index, value);
}

std::string BacktraceOffline::GetFunctionNameRaw(uintptr_t, uintptr_t* offset) {
  // We don't have enough information to support this. And it is expensive.
  *offset = 0;
  return "";
}
