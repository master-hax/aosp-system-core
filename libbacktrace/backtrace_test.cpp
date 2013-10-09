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
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define __STDC_FORMAT_MACROS
#include <inttypes.h>

#include <backtrace/backtrace.h>

#include <cutils/atomic.h>
#include <gtest/gtest.h>

#include "tid.h"

// Number of microseconds per milliseconds.
#define US_PER_MSEC             1000

// Number of nanoseconds in a second.
#define NS_PER_SEC              1000000000ULL

// Number of simultaneous dumping operations to perform.
#define NUM_THREADS  20

typedef struct {
  pid_t tid;
  int32_t state;
  pthread_t threadId;
} thread_t;

typedef struct {
  thread_t thread;
  backtrace_t backtrace;
  int32_t *now;
  int32_t done;
} dump_thread_t;

extern "C" {
// Prototypes for functions in the test library.
int test_level_one(int, int, int, int, void (*)(void*), void*);

int test_recursive_call(int, void (*)(void*), void*);
}

uint64_t nano_time() {
  struct timespec t = { 0, 0 };
  clock_gettime(CLOCK_MONOTONIC, &t);
  return static_cast<uint64_t>(t.tv_sec * NS_PER_SEC + t.tv_nsec);
}

void dump_frames(const backtrace_t* backtrace) {
  if (backtrace->num_frames == 0) {
    printf("    No frames to dump\n");
  } else {
    char line[512];
    for (size_t i = 0; i < backtrace->num_frames; i++) {
      backtrace_format_frame_data(&backtrace->frames[i], i, line, sizeof(line));
      printf("    %s\n", line);
    }
  }
}

void wait_for_stop(pid_t pid) {
  uint64_t start = nano_time();

  siginfo_t si;
  while (ptrace(PTRACE_GETSIGINFO, pid, 0, &si) < 0 && (errno == EINTR || errno == ESRCH)) {
    if ((nano_time() - start) > NS_PER_SEC) {
      printf("The process did not get to a stopping point in 1 second.\n");
      break;
    }
    usleep(US_PER_MSEC);
  }
}

bool ready_level_backtrace(pid_t pid, backtrace_t* backtrace) {
  if (backtrace_get_data(backtrace, pid)) {
    // See if test_level_four is in the backtrace.
    bool found = false;
    for (size_t i = 0; i < backtrace->num_frames; i++) {
      if (backtrace->frames[i].proc_name != NULL &&
          strcmp(backtrace->frames[i].proc_name, "test_level_four") == 0) {
        found = true;
        break;
      }
    }

    return found;
  }
  return false;
}

void verify_level_dump(backtrace_t* backtrace) {
  ASSERT_GT(backtrace->num_frames, static_cast<size_t>(0));
  ASSERT_LT(backtrace->num_frames, static_cast<size_t>(MAX_BACKTRACE_FRAMES));

  // Look through the frames starting at the highest to find the
  // frame we want.
  size_t frame_num = 0;
  for (size_t i = backtrace->num_frames-1; i > 2; i--) {
    if (backtrace->frames[i].proc_name != NULL &&
        strcmp(backtrace->frames[i].proc_name, "test_level_one") == 0) {
      frame_num = i;
      break;
    }
  }
  ASSERT_GT(frame_num, static_cast<size_t>(0));

  ASSERT_TRUE(NULL != backtrace->frames[frame_num].proc_name);
  ASSERT_STREQ(backtrace->frames[frame_num].proc_name, "test_level_one");
  ASSERT_TRUE(NULL != backtrace->frames[frame_num-1].proc_name);
  ASSERT_STREQ(backtrace->frames[frame_num-1].proc_name, "test_level_two");
  ASSERT_TRUE(NULL != backtrace->frames[frame_num-2].proc_name);
  ASSERT_STREQ(backtrace->frames[frame_num-2].proc_name, "test_level_three");
  ASSERT_TRUE(NULL != backtrace->frames[frame_num-3].proc_name);
  ASSERT_STREQ(backtrace->frames[frame_num-3].proc_name, "test_level_four");

  backtrace_free_data(backtrace);
}

void verify_level_backtrace(void*) {
  backtrace_t backtrace;

  ASSERT_TRUE(backtrace_get_data(&backtrace, -1));

  verify_level_dump(&backtrace);
}

bool ready_max_backtrace(pid_t pid, backtrace_t* backtrace) {
  if (backtrace_get_data(backtrace, pid)) {
    return (backtrace->num_frames == MAX_BACKTRACE_FRAMES);
  }
  return false;
}

void verify_max_backtrace(void*) {
  backtrace_t backtrace;

  ASSERT_TRUE(backtrace_get_data(&backtrace, -1));
}

void verify_max_dump(backtrace_t* backtrace) {
  ASSERT_EQ(backtrace->num_frames, static_cast<size_t>(MAX_BACKTRACE_FRAMES));

  backtrace_free_data(backtrace);
}

void thread_set_state(void* data) {
  thread_t* thread = reinterpret_cast<thread_t*>(data);
  android_atomic_acquire_store(1, &thread->state);
  volatile int i = 0;
  while (true) {
    i++;
  }
}

void verify_thread_test(pid_t tid, void (*verify_func)(backtrace_t*)) {
  backtrace_t backtrace;

  backtrace_get_thread_data(&backtrace, tid);

  verify_func(&backtrace);

  backtrace_free_data(&backtrace);
}

bool wait_for_non_zero(int32_t *value, uint64_t seconds) {
  uint64_t start = nano_time();

  do {
    if (android_atomic_acquire_load(value)) {
      return true;
    }
  } while ((nano_time() - start) < seconds * NS_PER_SEC);
  return false;
}

TEST(libbacktrace, local_trace) {
  ASSERT_NE(test_level_one(1, 2, 3, 4, verify_level_backtrace, NULL), 0);
}

TEST(libbacktrace, local_max_trace) {
  ASSERT_NE(test_recursive_call(MAX_BACKTRACE_FRAMES+10, verify_max_backtrace, NULL), 0);
}

void verify_proc_test(pid_t pid, bool (*ready_func)(pid_t, backtrace_t*),
                      void (*verify_func)(backtrace_t*)) {

  backtrace_t backtrace;
  bool complete = false;
  uint64_t start = nano_time();
  while (!complete) {
    if (ptrace(PTRACE_ATTACH, pid, 0, 0) == 0) {
      // Wait for the process to get to a stopping point.
      wait_for_stop(pid);

      if (ready_func(pid, &backtrace)) {
        verify_func(&backtrace);
        complete = true;
      } else {
        backtrace_free_data(&backtrace);
      }
      ASSERT_TRUE(ptrace(PTRACE_DETACH, pid, 0, 0) == 0);
    }
    if (!complete) {
      // If 5 seconds have passed, then we are done.
      if ((nano_time() - start) > 5 * NS_PER_SEC) {
        break;
      }
      usleep(US_PER_MSEC);
    }
  }

  kill(pid, SIGKILL);
  int status;
  ASSERT_EQ(waitpid(pid, &status, 0), pid);
  ASSERT_TRUE(complete);
}

TEST(libbacktrace, ptrace_trace) {
  pid_t pid;
  if ((pid = fork()) == 0) {
    ASSERT_NE(test_level_one(1, 2, 3, 4, NULL, NULL), 0);
    exit(1);
  }
  verify_proc_test(pid, ready_level_backtrace, verify_level_dump);
}

TEST(libbacktrace, ptrace_max_trace) {
  pid_t pid;
  if ((pid = fork()) == 0) {
    ASSERT_NE(test_recursive_call(MAX_BACKTRACE_FRAMES+10, NULL, NULL), 0);
    exit(1);
  }
  verify_proc_test(pid, ready_max_backtrace, verify_max_dump);
}

void verify_level_thread(void*) {
  backtrace_t backtrace;

  ASSERT_TRUE(backtrace_get_thread_data(&backtrace, gettid()));

  verify_level_dump(&backtrace);
}

TEST(libbacktrace, thread_current_level) {
  ASSERT_NE(test_level_one(1, 2, 3, 4, verify_level_thread, NULL), 0);
}

void verify_max_thread(void*) {
  backtrace_t backtrace;

  ASSERT_TRUE(backtrace_get_thread_data(&backtrace, gettid()));

  verify_max_dump(&backtrace);
}

TEST(libbacktrace, thread_current_max) {
  ASSERT_NE(test_recursive_call(MAX_BACKTRACE_FRAMES+10, verify_max_thread, NULL), 0);
}

void* thread_level_run(void *data) {
  thread_t* thread = reinterpret_cast<thread_t*>(data);

  thread->tid = gettid();
  if (test_level_one(1, 2, 3, 4, thread_set_state, data) != 0) {
    printf("This should never happend.\n");
  }
  return NULL;
}

TEST(libbacktrace, thread_level_trace) {
  pthread_attr_t attr;
  pthread_attr_init(&attr);
  pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);

  thread_t thread_data = { 0, 0, 0 };
  pthread_t thread;
  ASSERT_TRUE(pthread_create(&thread, &attr, thread_level_run, &thread_data) == 0);

  // Wait 2 seconds for the tid to be set.
  ASSERT_TRUE(wait_for_non_zero(&thread_data.state, 2));
  backtrace_t backtrace;

  backtrace_get_thread_data(&backtrace, thread_data.tid);

  verify_level_dump(&backtrace);

  backtrace_free_data(&backtrace);

  sighandler_t handler = signal(SIGALRM, SIG_IGN);
  pthread_kill(thread, SIGALRM);
  pthread_join(thread, NULL);
  signal(SIGALRM, handler);
}

void* thread_max_run(void *data) {
  thread_t* thread = reinterpret_cast<thread_t*>(data);

  thread->tid = gettid();
  if (test_recursive_call(MAX_BACKTRACE_FRAMES+10, thread_set_state, data) != 0) {
    printf("This should never happend.\n");
  }
  return NULL;
}

TEST(libbacktrace, thread_max_trace) {
  pthread_attr_t attr;
  pthread_attr_init(&attr);
  pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);

  thread_t thread_data = { 0, 0, 0 };
  pthread_t thread;
  ASSERT_TRUE(pthread_create(&thread, &attr, thread_max_run, &thread_data) == 0);

  // Wait for the tid to be set.
  ASSERT_TRUE(wait_for_non_zero(&thread_data.state, 2));

  backtrace_t backtrace;

  backtrace_get_thread_data(&backtrace, thread_data.tid);

  verify_max_dump(&backtrace);

  backtrace_free_data(&backtrace);

  sighandler_t handler = signal(SIGALRM, SIG_IGN);
  pthread_kill(thread, SIGALRM);
  pthread_join(thread, NULL);
  signal(SIGALRM, handler);
}

void* thread_dump(void* data) {
  dump_thread_t* dump = reinterpret_cast<dump_thread_t*>(data);
  while (true) {
    if (android_atomic_acquire_load(dump->now)) {
      break;
    }
  }

  dump->backtrace.num_frames = 0;

  backtrace_get_thread_data(&dump->backtrace, dump->thread.tid);

  android_atomic_acquire_store(1, &dump->done);

  return NULL;
}

TEST(libbacktrace, thread_multiple_dump) {
  // Dump NUM_THREADS simultaneously.
  thread_t* runners = new thread_t[NUM_THREADS];
  dump_thread_t* dumpers = new dump_thread_t[NUM_THREADS];

  pthread_attr_t attr;
  pthread_attr_init(&attr);
  pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
  for (size_t i = 0; i < NUM_THREADS; i++) {
    // Launch the runners, they will spin in hard loops doing nothing.
    runners[i].tid = 0;
    runners[i].state = 0;
    ASSERT_TRUE(pthread_create(&runners[i].threadId, &attr, thread_max_run, &runners[i]) == 0);
  }

  // Wait for tids to be set.
  for (size_t i = 0; i < NUM_THREADS; i++) {
    ASSERT_TRUE(wait_for_non_zero(&runners[i].state, 10));
  }

  // Start all of the dumpers at once, they will spin until they are signalled
  // to begin their dump run.
  int32_t dump_now = 0;
  for (size_t i = 0; i < NUM_THREADS; i++) {
    dumpers[i].thread.tid = runners[i].tid;
    dumpers[i].thread.state = 0;
    dumpers[i].done = 0;
    dumpers[i].now = &dump_now;

    ASSERT_TRUE(pthread_create(&dumpers[i].thread.threadId, &attr, thread_dump, &dumpers[i]) == 0);
  }

  // Start all of the dumpers going at once.
  android_atomic_acquire_store(1, &dump_now);

  for (size_t i = 0; i < NUM_THREADS; i++) {
    ASSERT_TRUE(wait_for_non_zero(&dumpers[i].done, 10));
    pthread_join(dumpers[i].thread.threadId, NULL);
    ASSERT_EQ(dumpers[i].backtrace.num_frames,
              static_cast<size_t>(MAX_BACKTRACE_FRAMES));
  }
}
