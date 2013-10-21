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

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <unistd.h>

#include <sstream>
#include <string>

#include <backtrace/Backtrace.h>
#include <cutils/log.h>

#include "Backtrace.h"
#include "thread_utils.h"

//-------------------------------------------------------------------------
// BacktraceImpl functions.
//-------------------------------------------------------------------------
backtrace_t* BacktraceImpl::GetBacktraceData() {
  return &backtrace_obj_->backtrace_;
}

//-------------------------------------------------------------------------
// Backtrace functions.
//-------------------------------------------------------------------------
Backtrace::Backtrace(BacktraceImpl* impl) : impl_(impl), map_info_(NULL) {
  impl_->SetParent(this);
  backtrace_.num_frames = 0;
  backtrace_.pid = -1;
  backtrace_.tid = -1;
}

Backtrace::~Backtrace() {
  for (size_t i = 0; i < NumFrames(); i++) {
    if (backtrace_.frames[i].proc_name) {
      free(backtrace_.frames[i].proc_name);
      backtrace_.frames[i].proc_name = NULL;
    }
  }

  if (map_info_) {
    backtrace_destroy_map_info_list(map_info_);
    map_info_ = NULL;
  }

  if (impl_) {
    delete impl_;
    impl_ = NULL;
  }
}

bool Backtrace::VerifyReadWordArgs(uintptr_t ptr, uint32_t* out_value) {
  if (ptr & 3) {
    ALOGW("Backtrace::verifyReadWordArgs: invalid pointer %p", (void*)ptr);
    *out_value = (uint32_t)-1;
    return false;
  }
  return true;
}

const char* Backtrace::GetMapInfo(uintptr_t pc, uintptr_t* map_start) {
  const backtrace_map_info_t* map_info = FindMapInfo(pc);
  if (map_info) {
    if (map_start) {
      *map_start = map_info->start;
    }
    return map_info->name;
  }
  return NULL;
}

const backtrace_map_info_t* Backtrace::FindMapInfo(uintptr_t ptr) {
  return backtrace_find_map_info(map_info_, ptr);
}

std::string Backtrace::FormatFrameData(size_t frame_num) {
  backtrace_frame_data_t* frame = &backtrace_.frames[frame_num];
  const char* map_name;
  if (frame->map_name) {
    map_name = frame->map_name;
  } else {
    map_name = "<unknown>";
  }
  uintptr_t relative_pc;
  if (frame->map_offset) {
    relative_pc = frame->map_offset;
  } else {
    relative_pc = frame->pc;
  }

  // The format of the string is:
  //  #00 pc 012345678  mapName (proc_name+proc_offset)
  std::stringstream stream;
  stream << "#";
  stream.width(2);
  stream.fill('0');
  stream << frame_num << " pc ";
  stream.width(sizeof(uintptr_t)*2);
  stream << std::hex << relative_pc;
  stream.width(0);
  stream << "  " << map_name;
  if (frame->proc_name) {
    stream << " (" << frame->proc_name;
    if (frame->proc_offset) {
      stream << std::dec << "+" << frame->proc_offset;
    }
    stream << ")";
  }

  return stream.str();
}

__BEGIN_DECLS
extern char* __cxa_demangle (const char* mangled, char* buf, size_t* len,
                             int* status);
__END_DECLS

char* Backtrace::Demangle(const char* symbol_name) {
  if (symbol_name) {
#if defined(__APPLE__)
    // Mac OS' __cxa_demangle demangles "f" as "float"; last tested on 10.7.
    if (symbol_name[0] != '_') {
      return NULL;
    }
#endif
    char* name = __cxa_demangle(symbol_name, 0, 0, 0);
    if (!name) {
      name = strdup(symbol_name);
    }
    return name;
  }
  return NULL;
}

//-------------------------------------------------------------------------
// BacktraceCurrent functions.
//-------------------------------------------------------------------------
BacktraceCurrent::BacktraceCurrent(BacktraceImpl* impl) : Backtrace(impl) {
  map_info_ = backtrace_create_map_info_list(-1);

  backtrace_.pid = getpid();
}

BacktraceCurrent::~BacktraceCurrent() {
}

bool BacktraceCurrent::ReadWord(uintptr_t ptr, uint32_t* out_value) {
  if (!VerifyReadWordArgs(ptr, out_value)) {
    return false;
  }

  const backtrace_map_info_t* map_info = FindMapInfo(ptr);
  if (map_info && map_info->is_readable) {
    *out_value = *reinterpret_cast<uint32_t*>(ptr);
    return true;
  } else {
    ALOGW("BacktraceCurrent::readWord: pointer %p not in a readbale map", reinterpret_cast<void*>(ptr));
    *out_value = static_cast<uint32_t>(-1);
    return false;
  }
}

//-------------------------------------------------------------------------
// BacktracePtrace functions.
//-------------------------------------------------------------------------
BacktracePtrace::BacktracePtrace(BacktraceImpl* impl, pid_t pid, pid_t tid)
    : Backtrace(impl) {
  map_info_ = backtrace_create_map_info_list(tid);

  backtrace_.pid = pid;
  backtrace_.tid = tid;
}

BacktracePtrace::~BacktracePtrace() {
}

bool BacktracePtrace::ReadWord(uintptr_t ptr, uint32_t* out_value) {
  if (!VerifyReadWordArgs(ptr, out_value)) {
    return false;
  }

#if defined(__APPLE__)
  ALOGW("BacktracePtrace::readWord: MacOS does not support reading from another pid.\n");
  return false;
#else
  // ptrace() returns -1 and sets errno when the operation fails.
  // To disambiguate -1 from a valid result, we clear errno beforehand.
  errno = 0;
  *out_value = ptrace(PTRACE_PEEKTEXT, Tid(), reinterpret_cast<void*>(ptr), NULL);
  if (*out_value == static_cast<uint32_t>(-1) && errno) {
    ALOGW("BacktracePtrace::readWord: invalid pointer 0x%08x reading from tid %d, "
          "ptrace() errno=%d", ptr, Tid(), errno);
    return false;
  }
  return true;
#endif
}

//-------------------------------------------------------------------------
// Common interface functions.
//-------------------------------------------------------------------------
Backtrace* BacktraceCreateObj(pid_t pid, pid_t tid) {
  if (pid < 0 || pid == getpid()) {
    if (tid < 0 || tid == gettid()) {
      return CreateCurrentObj();
    } else {
      return CreateThreadObj(tid);
    }
  } else if (tid < 0) {
    return CreatePtraceObj(pid, pid);
  } else {
    return CreatePtraceObj(pid, tid);
  }
}

bool backtrace_create_context(
    backtrace_context_t* context, pid_t pid, pid_t tid, size_t num_ignore_frames) {
  Backtrace* backtrace = BacktraceCreateObj(pid, tid);
  if (!backtrace) {
    return false;
  }
  if (!backtrace->Unwind(num_ignore_frames)) {
    delete backtrace;
    return false;
  }

  context->data = backtrace;
  context->backtrace = backtrace->GetBacktrace();
  return true;
}

void backtrace_destroy_context(backtrace_context_t* context) {
  if (context->data) {
    Backtrace* backtrace = reinterpret_cast<Backtrace*>(context->data);
    delete backtrace;
    context->data = NULL;
  }
  context->backtrace = NULL;
}

const backtrace_t* backtrace_get_data(backtrace_context_t* context) {
  if (context && context->data) {
    Backtrace* backtrace = reinterpret_cast<Backtrace*>(context->data);
    return backtrace->GetBacktrace();
  }
  return NULL;
}

bool backtrace_read_word(const backtrace_context_t* context, uintptr_t ptr, uint32_t* value) {
  if (context->data) {
    Backtrace* backtrace = reinterpret_cast<Backtrace*>(context->data);
    return backtrace->ReadWord(ptr, value);
  }
  return true;
}

const char* backtrace_get_map_info(const backtrace_context_t* context, uintptr_t pc, uintptr_t* map_start) {
  if (context->data) {
    Backtrace* backtrace = reinterpret_cast<Backtrace*>(context->data);
    return backtrace->GetMapInfo(pc, map_start);
  }
  return NULL;
}

char* backtrace_get_proc_name(const backtrace_context_t* context, uintptr_t pc, uintptr_t* proc_offset) {
  if (context->data) {
    Backtrace* backtrace = reinterpret_cast<Backtrace*>(context->data);
    return backtrace->GetProcName(pc, proc_offset);
  }
  return NULL;
}

void backtrace_format_frame_data(
    const backtrace_context_t* context, size_t frame_num, char* buf,
    size_t buf_size) {
  if (buf_size == 0 || buf == NULL) {
    ALOGW("backtrace_format_frame_data: bad call buf %p buf_size %zu\n",
          buf, buf_size);
    return;
  }
  if (context->data) {
    Backtrace* backtrace = reinterpret_cast<Backtrace*>(context->data);
    std::string line = backtrace->FormatFrameData(frame_num);
    if (line.size() > buf_size) {
      memcpy(buf, line.c_str(), buf_size-1);
      buf[buf_size] = '\0';
    } else {
      memcpy(buf, line.c_str(), line.size()+1);
    }
  }
}
