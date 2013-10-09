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

#include <sys/types.h>
#include <unistd.h>

#include <backtrace/backtrace.h>

#include "common.h"
#include "thread.h"
#include "unwind.h"

bool backtrace_get_data(backtrace_t* backtrace, pid_t pid) {
  backtrace->num_frames = 0;
  if (pid < 0) {
    pid = getpid();
  }
  backtrace->pid = pid;

  backtrace->map_info_list = backtrace_create_map_info_list(pid);
  if (pid == getpid()) {
    return local_get_data(backtrace);
  } else {
    return remote_get_data(backtrace);
  }
}

/* Free any memory related to the frame data. */
void backtrace_free_data(backtrace_t* backtrace) {
  free_frame_data(backtrace);

  if (backtrace->map_info_list) {
    backtrace_destroy_map_info_list(backtrace->map_info_list);
    backtrace->map_info_list = NULL;
  }

  if (backtrace->pid == getpid()) {
    local_free_data(backtrace);
  } else {
    remote_free_data(backtrace);
  }
}

char* backtrace_get_proc_name(const backtrace_t* backtrace, uintptr_t pc,
                              uintptr_t* offset) {
  if (backtrace->pid == getpid()) {
    return local_get_proc_name(backtrace, pc, offset);
  } else {
    return remote_get_proc_name(backtrace, pc, offset);
  }
}

void init_thread_entry(tid_list_t* entry) {
}

void destroy_thread_entry(tid_list_t* entry) {
}
