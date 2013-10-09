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

#ifndef _THREAD_H
#define _THREAD_H

#include <signal.h>

#include <backtrace/backtrace.h>

typedef struct tid_list_t {
  int32_t state;
  backtrace_t* backtrace;
  void* data;

  struct tid_list_t* next;
  struct tid_list_t* prev;
} tid_list_t;

void init_thread_entry(tid_list_t* entry);

void gather_thread_frame_data(tid_list_t* entry, siginfo_t* siginfo,
                              void* sigcontext);

void destroy_thread_entry(tid_list_t* entry);

#endif /* _THREAD_H */
