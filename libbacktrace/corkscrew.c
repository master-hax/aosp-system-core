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

#define LOG_TAG "libbacktrace"

#include <string.h>

#include <cutils/log.h>
#include <backtrace/backtrace.h>

#include <corkscrew/backtrace.h>
#include <backtrace-arch.h>

#define __USE_GNU
#include <dlfcn.h>

#include "common.h"
#include "demangle.h"
#include "thread.h"

bool backtrace_get_data(backtrace_t* backtrace, pid_t pid) {
  backtrace->num_frames = 0;
  if (pid < 0) {
    pid = getpid();
  }
  backtrace->pid = pid;
  backtrace->tid = -1;
  backtrace->private_data = NULL;
  backtrace->map_info_list = backtrace_create_map_info_list(pid);

  backtrace_frame_t frames[MAX_BACKTRACE_FRAMES];
  ssize_t num_frames;
  if (pid == getpid()) {
    // Get data for the current thread.
    num_frames = unwind_backtrace(frames, 0, MAX_BACKTRACE_FRAMES);
  } else {
    // Get data for a different thread.
    ptrace_context_t* ptrace_context = load_ptrace_context(pid);
    backtrace->private_data = ptrace_context;

    num_frames = unwind_backtrace_ptrace(
        pid, ptrace_context, frames, 0, MAX_BACKTRACE_FRAMES);
  }
  if (num_frames < 0) {
      ALOGW("%s::%s(): unwind_backtrace_ptrace failed %d\n",
            __FILE__, __FUNCTION__, num_frames);
      backtrace_free_data(backtrace);
      return false;
  }

  backtrace->num_frames = num_frames;
  backtrace_frame_data_t* frame;
  uintptr_t map_start;
  for (size_t i = 0; i < backtrace->num_frames; i++) {
    frame = &backtrace->frames[i];
    frame->pc = frames[i].absolute_pc;
    frame->sp = frames[i].stack_top;
    frame->stack_size = frames[i].stack_size;

    frame->map_offset = 0;
    frame->map_name = backtrace_get_map_info(backtrace, frame->pc, &map_start);
    if (frame->map_name) {
      frame->map_offset = frame->pc - map_start;
    }

    frame->proc_offset = 0;
    frame->proc_name = backtrace_get_proc_name(backtrace, frame->pc, &frame->proc_offset);
  }

  return true;
}

void backtrace_free_data(backtrace_t* backtrace) {
  free_frame_data(backtrace);

  if (backtrace->map_info_list) {
    backtrace_destroy_map_info_list(backtrace->map_info_list);
    backtrace->map_info_list = NULL;
  }

  if (backtrace->private_data) {
    ptrace_context_t* ptrace_context = (ptrace_context_t*)backtrace->private_data;
    free_ptrace_context(ptrace_context);
    backtrace->private_data = NULL;
  }
}

char* backtrace_get_proc_name(const backtrace_t* backtrace, uintptr_t pc,
    uintptr_t* offset) {
  const char* symbol_name = NULL;
  *offset = 0;
  if (backtrace->pid == getpid()) {
    // Get information about the current thread.
    Dl_info info;
    const backtrace_map_info_t* map_info;
    map_info = backtrace_find_map_info(backtrace->map_info_list, pc);
    if (map_info && dladdr((const void*)pc, &info) && info.dli_sname) {
      *offset = pc - map_info->start - (uintptr_t)info.dli_saddr + (uintptr_t)info.dli_fbase;
      symbol_name = info.dli_sname;
    }
  } else {
    // Get information about a different thread.
    ptrace_context_t* ptrace_context = (ptrace_context_t*)backtrace->private_data;
    const map_info_t* map_info;
    const symbol_t* symbol;
    find_symbol_ptrace(ptrace_context, pc, &map_info, &symbol);
    if (symbol) {
      if (map_info) {
        *offset = pc - map_info->start - symbol->start;
      }
      symbol_name = symbol->name;
    }
  }

  char* name = NULL;
  if (symbol_name) {
    name = demangle_symbol_name(symbol_name);
    if (!name) {
      name = strdup(symbol_name);
    }
  }
  return name;
}

void init_thread_entry(tid_list_t* entry) {
  entry->data = (map_info_t*)load_map_info_list(getpid());
}

void destroy_thread_entry(tid_list_t* entry) {
  free_map_info_list((map_info_t*)entry->data);
}

void gather_thread_frame_data(tid_list_t* entry, siginfo_t* siginfo,
                              void* sigcontext) {
  backtrace_frame_t frames[MAX_BACKTRACE_FRAMES];
  ssize_t num_frames = unwind_backtrace_signal_arch(
      siginfo, sigcontext, (map_info_t*)entry->data, frames, 0,
      MAX_BACKTRACE_FRAMES);
  if (num_frames <= 0) {
    entry->backtrace->num_frames = 0;
  } else {
    entry->backtrace->num_frames = num_frames;
    backtrace_frame_data_t* frame;
    for (size_t i = 0; i < entry->backtrace->num_frames; i++) {
      frame = &entry->backtrace->frames[i];
      frame->pc = frames[i].absolute_pc;
      frame->sp = frames[i].stack_top;
      frame->stack_size = frames[i].stack_size;

      frame->map_offset = 0;
      frame->map_name = NULL;
      frame->map_offset = 0;

      frame->proc_offset = 0;
      frame->proc_name = NULL;
    }
  }
}

