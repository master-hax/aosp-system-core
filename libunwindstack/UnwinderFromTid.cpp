/*
 * Copyright (C) 2017 The Android Open Source Project
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
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <ucontext.h>

#include <mutex>
#include <unordered_map>

#define THREAD_SIGNAL SIGUSR1
#include <sys/syscall.h>
#include <unistd.h>
static inline int gettid() {
  return syscall(__NR_gettid);
}
static inline int tgkill(int tgid, int tid, int sig) {
  return syscall(__NR_tgkill, tgid, tid, sig);
}

namespace unwindstack {

class ErrnoRestorer {
 public:
  ErrnoRestorer() : saved_errno_(errno) {}
  ~ErrnoRestorer() { errno = saved_errno_; }

 private:
  int saved_errno_;
};

enum ThreadStatus : uint8_t {
  GET_UCONTEXT = 0,
  UCONTEXT_COPIED,
  UNWIND_FINISHED,
  SIGNAL_HANDLER_FINISHED,
};

struct Thread {
  uint32_t count = 0;
  pthread_mutex_t handshake_mutex = PTHREAD_MUTEX_INITIALIZER;
  pthread_cond_t handshake_cond;
  ucontext_t ucontext;
  ThreadStatus status = GET_UCONTEXT;
  uint32_t seq = 0;
  pid_t tid;

  Thread() {
    pthread_condattr_t attr;
    pthread_condattr_init(&attr);
    pthread_condattr_setclock(&attr, CLOCK_MONOTONIC);
    pthread_cond_init(&handshake_cond, &attr);
  }

  ~Thread() {
    // Remove self from the list.
    pthread_cond_destroy(&handshake_cond);
  }

  void SetStatus(ThreadStatus new_status) {
    pthread_mutex_lock(&handshake_mutex);
    status = new_status;
    pthread_mutex_unlock(&handshake_mutex);
    pthread_cond_signal(&handshake_cond);
  }

  bool WaitForStatus(ThreadStatus new_status) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    ts.tv_sec += 10;
    pthread_mutex_lock(&handshake_mutex);
    while (status != new_status) {
      int ret = pthread_cond_timedwait(&handshake_cond, &handshake_mutex, &ts);
      if (ret != 0) {
        printf("Failed to wait.\n");
        pthread_mutex_unlock(&handshake_mutex);
        return false;
      }
    }
    pthread_mutex_unlock(&handshake_mutex);
    return true;
  }
};

std::mutex thread_mutex;
std::unordered_map<pid_t, Thread> tids;
std::unordered_map<pid_t, std::shared_ptr<Thread>> tids;

void ThreadSignalHandler(int, siginfo_t*, void* sigcontext) {
  ErrnoRestorer restore;

  printf("Signal handler called for %d\n", gettid());
  Thread* thread;
  {
    std::lock_guard<std::mutex> guard(thread_mutex);
    auto thread_entry = tids.find(gettid());
    if (thread_entry == tids.end()) {
      // Error message.
      printf("Tid %d not expecting signal.\n", gettid());
      return;
    }
    thread = &thread_entry->second;
  }

  // Copy the context data to the thread object.
  memcpy(&thread->ucontext.uc_mcontext, sigcontext, sizeof(thread->ucontext.uc_mcontext));

  // Unlock to let the original thread doing the unwind move forward.
  printf("Sending context data.\n");
  thread->SetStatus(UCONTEXT_COPIED);

  if (!thread->WaitForStatus(UNWIND_FINISHED)) {
    // The unwind took too long, so bail.
    return;
  }
  // Remove the value.
  // thread->SetStatus(SIGNAL_HANDLER_FINISHED);
}

bool SignalHandlerValid = false;

bool UnwindFromThread(pid_t tid) {
  // Set up the signal handling once.
  static std::once_flag flag;
  std::call_once(flag, []() {
    struct sigaction action = {};
    action.sa_sigaction = ThreadSignalHandler;
    action.sa_flags = SA_RESTART | SA_SIGINFO | SA_ONSTACK;
    sigemptyset(&action.sa_mask);
    if (sigaction(THREAD_SIGNAL, &action, nullptr) == 0) {
      SignalHandlerValid = true;
    }
    printf("Sighandler installed.\n");
  });

  if (!SignalHandlerValid) {
    // Error
    printf("Failed to install signal handler.\n");
    return false;
  }

  Thread* thread;
  {
    // This should be fine since all uses of this lock are in the other
    // code, and we are going to intentionally pause the thread while
    // doing the unwind.
    std::lock_guard<std::mutex> guard(thread_mutex);
    thread = &tids[tid];
#if 0
    if (thread->count != 0) {
      printf("Reusing tid %d\n", tid);
      thread->status = GET_UCONTEXT;
    }
#endif
    thread->count++;
  }

  // Send the signal.
  if (tgkill(getpid(), tid, THREAD_SIGNAL) != 0) {
    // sigaction(THREAD_SIGNAL, &action, nullptr);
    // Decrement the entry and clean it up.
    printf("Failed to kill\n");
    return false;
  }

  // Wait for the signal handler to fire and get the context data.
  printf("Waiting for ucontext.\n");
  if (!thread->WaitForStatus(UCONTEXT_COPIED)) {
    printf("Failed to get ucontext for %d from signal handler\n", tid);
    return false;
  }

  // Do the unwind.
  // Regs* regs = Regs::CreateFromLocalUcontext(thread->ucontext);

  thread->SetStatus(UNWIND_FINISHED);

  if (!thread->WaitForStatus(SIGNAL_HANDLER_FINISHED)) {
    printf("Signal handler never finished.\n");
    return false;
  }

  {
    // This should be fine since all uses of this lock are in the other
    // code, and we are going to intentionally pause the thread while
    // doing the unwind.
    std::lock_guard<std::mutex> guard(thread_mutex);
    thread->count--;
    if (thread->count == 0) {
      printf("Erasing tid %d\n", tid);
      pthread_cond_destroy(&thread->handshake_cond);
      tids.erase(tid);
    }
  }
}

}  // namespace unwindstack

#include <thread>
#include <vector>

int main() {
  pid_t tid = 0;
  std::thread t1([&tid]() {
    tid = gettid();
    sleep(10);
  });

  sleep(1);

  std::vector<std::thread*> threads;
  for (size_t i = 0; i < 30; i++) {
    threads.push_back(new std::thread([=]() { unwindstack::UnwindFromThread(tid); }));
  }

  unwindstack::UnwindFromThread(tid);

  for (auto* thread : threads) {
    thread->join();
  }
  t1.join();
}
