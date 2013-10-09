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

#include <errno.h>
#include <inttypes.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#include <cutils/atomic.h>
#include <cutils/log.h>
#include <backtrace/backtrace.h>

#include "thread.h"
#include "tid.h"

static const int32_t STATE_WAITING = 0;
static const int32_t STATE_DUMPING = 1;
static const int32_t STATE_DONE = 2;
static const int32_t STATE_CANCEL = 3;

static tid_list_t* g_tid_list = NULL;

static pthread_mutex_t g_backtrace_mutex = PTHREAD_MUTEX_INITIALIZER;

static void signal_handler(int n __attribute__((unused)), siginfo_t* siginfo,
                              void* sigcontext) {
  if (pthread_mutex_lock(&g_backtrace_mutex) == 0) {
    tid_list_t* entry = NULL;
    tid_list_t* tid_list = g_tid_list;
    pid_t pid = getpid();
    pid_t tid = gettid();
    while (tid_list) {
      if (tid_list->backtrace->pid == pid && tid_list->backtrace->tid == tid) {
        entry = tid_list;
        break;
      }
      tid_list = tid_list->next;
    }
    pthread_mutex_unlock(&g_backtrace_mutex);
    if (!entry) {
      ALOGW("%s::%s(): Unable to find pid %d tid %d information\n",
            __FILE__, __FUNCTION__, pid, tid);
      return;
    }

    if (android_atomic_acquire_cas(STATE_WAITING, STATE_DUMPING, &entry->state) == 0) {
      gather_thread_frame_data(entry, siginfo, sigcontext);
    }
    android_atomic_release_store(STATE_DONE, &entry->state);
  }
}

void remove_tid_entry(tid_list_t* entry) {
  pthread_mutex_lock(&g_backtrace_mutex);
  if (g_tid_list == entry) {
    g_tid_list = entry->next;
  } else {
    if (entry->next) {
      entry->next->prev = entry->prev;
    }
    entry->prev->next = entry->next;
  }
  pthread_mutex_unlock(&g_backtrace_mutex);
}

void finish_thread_gather(backtrace_t* backtrace) {
  backtrace_frame_data_t* frame;
  uintptr_t map_start;
  for (size_t i = 0; i < backtrace->num_frames; i++) {
    frame = &backtrace->frames[i];

    frame->map_offset = 0;
    frame->map_name = backtrace_get_map_info(backtrace, frame->pc, &map_start);
    if (frame->map_name) {
      frame->map_offset = frame->pc - map_start;
    }

    frame->proc_offset = 0;
    frame->proc_name = backtrace_get_proc_name(backtrace, frame->pc, &frame->proc_offset);
  }
}

bool dump_thread_state(tid_list_t* entry) {
  entry->state = STATE_WAITING;

  if (tgkill(entry->backtrace->pid, entry->backtrace->tid, SIGURG) != 0) {
    ALOGW("%s::%s(): tgkill failed %d\n", __FILE__, __FUNCTION__, errno);
    return false;
  }

  int wait_millis = 250;
  int32_t state;
  while (true) {
    state = android_atomic_acquire_load(&entry->state);
    if (state != STATE_WAITING) {
      break;
    }
    if (wait_millis--) {
      usleep(1000);
    } else {
      break;
    }
  }

  bool cancelled = false;
  if (state == STATE_WAITING) {
    if (android_atomic_acquire_cas(state, STATE_CANCEL, &entry->state) == 0) {
      ALOGW("%s::%s(): Cancelled dump of thread %d\n", __FILE__, __FUNCTION__,
            entry->backtrace->tid);
      state = STATE_CANCEL;
      cancelled = true;
    } else {
      state = android_atomic_acquire_load(&entry->state);
    }
  }

  // Wait for at most one minute for the dump to finish.
  wait_millis = 60000;
  while (true) {
    state = android_atomic_acquire_load(&entry->state);
    if (state == STATE_DONE) {
      break;
    }
    if (wait_millis--) {
      usleep(1000);
    } else {
      ALOGW("%s::%s(): dump didn't finish in 60 seconds.\n",
            __FILE__, __FUNCTION__);
      break;
    }
  }
  return !cancelled;
}

bool backtrace_get_thread_data(backtrace_t* backtrace, pid_t tid) {
  if (tid == gettid()) {
    return backtrace_get_data(backtrace, -1);
  }

  backtrace->num_frames = 0;
  backtrace->pid = getpid();
  backtrace->tid = tid;
  backtrace->private_data = NULL;
  backtrace->map_info_list = backtrace_create_map_info_list(backtrace->pid);

  struct sigaction act, oldact;
  memset(&act, 0, sizeof(act));
  act.sa_sigaction = signal_handler;
  act.sa_flags = SA_RESTART | SA_SIGINFO | SA_ONSTACK;
  sigemptyset(&act.sa_mask);

  // Lock while we add an entry for this tid to our global list.
  tid_list_t* entry = (tid_list_t*)malloc(sizeof(tid_list_t));
  if (entry == NULL) {
    ALOGW("%s::%s(): Failed to allocate memory for backtrace entry.\n",
          __FILE__, __FUNCTION__);
    return false;
  }
  entry->backtrace = backtrace;
  entry->prev = NULL;
  entry->data = NULL;

  pthread_mutex_lock(&g_backtrace_mutex);
  tid_list_t* tid_list = g_tid_list;
  while (tid_list != NULL) {
    if (tid_list->backtrace->pid == backtrace->pid && tid_list->backtrace->tid == backtrace->tid) {
      // There is already an entry for this pid/tid, this is bad.
      ALOGW("%s::%s(): Already added entry for pid %d tid %d\n",
            __FILE__, __FUNCTION__, backtrace->pid, backtrace->tid);
      pthread_mutex_unlock(&g_backtrace_mutex);
      return false;
    }
    tid_list = tid_list->next;
  }
  // Add the entry to the list.
  entry->next = g_tid_list;
  if (g_tid_list) {
    g_tid_list->prev = entry;
  }
  g_tid_list = entry;
  pthread_mutex_unlock(&g_backtrace_mutex);

  init_thread_entry(entry);

  bool retval = false;
  if (sigaction(SIGURG, &act, &oldact) == 0) {
    retval = dump_thread_state(entry);
  } else {
    ALOGW("%s::%s(): sigaction failed %d\n", __FILE__, __FUNCTION__, errno);
  }

  if (retval) {
    finish_thread_gather(backtrace);
  } else {
    backtrace_free_data(backtrace);
  }

  remove_tid_entry(entry);

  destroy_thread_entry(entry);

  free(entry);

  return true;
}
