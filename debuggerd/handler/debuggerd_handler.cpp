/*
 * Copyright (C) 2008 The Android Open Source Project
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *  * Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *  * Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
 * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
 * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include "debuggerd/handler.h"

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <linux/futex.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

#include "private/bionic_futex.h"
#include "private/libc_logging.h"

// see man(2) prctl, specifically the section about PR_GET_NAME
#define MAX_TASK_NAME_LEN (16)

#if defined(__LP64__)
#define CRASH_DUMP_NAME "crash_dump64"
#else
#define CRASH_DUMP_NAME "crash_dump32"
#endif

#define CRASH_DUMP_PATH "/system/bin/" CRASH_DUMP_NAME

static debuggerd_callbacks_t g_callbacks;

// Mutex to ensure only one crashing thread dumps itself.
static pthread_mutex_t crash_mutex = PTHREAD_MUTEX_INITIALIZER;

// Don't use __libc_fatal because it exits via abort, which might put us back into a signal handler.
static void __noreturn __printflike(1, 2) fatal(const char* fmt, ...) {
  va_list args;
  va_start(args, fmt);
  __libc_format_log_va_list(ANDROID_LOG_FATAL, "libc", fmt, args);
  _exit(1);
}

static void __noreturn __printflike(1, 2) fatal_errno(const char* fmt, ...) {
  int err = errno;
  va_list args;
  va_start(args, fmt);

  char buf[4096];
  vsnprintf(buf, sizeof(buf), fmt, args);
  fatal("%s: %s", buf, strerror(err));
}

/*
 * Writes a summary of the signal to the log file.  We do this so that, if
 * for some reason we're not able to contact debuggerd, there is still some
 * indication of the failure in the log.
 *
 * We could be here as a result of native heap corruption, or while a
 * mutex is being held, so we don't want to use any libc functions that
 * could allocate memory or hold a lock.
 */
static void log_signal_summary(int signum, const siginfo_t* info) {
  char thread_name[MAX_TASK_NAME_LEN + 1];  // one more for termination
  if (prctl(PR_GET_NAME, reinterpret_cast<unsigned long>(thread_name), 0, 0, 0) != 0) {
    strcpy(thread_name, "<name unknown>");
  } else {
    // short names are null terminated by prctl, but the man page
    // implies that 16 byte names are not.
    thread_name[MAX_TASK_NAME_LEN] = 0;
  }

  if (signum == DEBUGGER_SIGNAL) {
    __libc_format_log(ANDROID_LOG_FATAL, "libc", "Requested dump for tid %d (%s)", gettid(),
                      thread_name);
    return;
  }

  const char* signal_name = "???";
  bool has_address = false;
  switch (signum) {
    case SIGABRT:
      signal_name = "SIGABRT";
      break;
    case SIGBUS:
      signal_name = "SIGBUS";
      has_address = true;
      break;
    case SIGFPE:
      signal_name = "SIGFPE";
      has_address = true;
      break;
    case SIGILL:
      signal_name = "SIGILL";
      has_address = true;
      break;
    case SIGSEGV:
      signal_name = "SIGSEGV";
      has_address = true;
      break;
#if defined(SIGSTKFLT)
    case SIGSTKFLT:
      signal_name = "SIGSTKFLT";
      break;
#endif
    case SIGSYS:
      signal_name = "SIGSYS";
      break;
    case SIGTRAP:
      signal_name = "SIGTRAP";
      break;
  }

  // "info" will be null if the siginfo_t information was not available.
  // Many signals don't have an address or a code.
  char code_desc[32];  // ", code -6"
  char addr_desc[32];  // ", fault addr 0x1234"
  addr_desc[0] = code_desc[0] = 0;
  if (info != nullptr) {
    __libc_format_buffer(code_desc, sizeof(code_desc), ", code %d", info->si_code);
    if (has_address) {
      __libc_format_buffer(addr_desc, sizeof(addr_desc), ", fault addr %p", info->si_addr);
    }
  }

  __libc_format_log(ANDROID_LOG_FATAL, "libc", "Fatal signal %d (%s)%s%s in tid %d (%s)", signum,
                    signal_name, code_desc, addr_desc, gettid(), thread_name);
}

/*
 * Returns true if the handler for signal "signum" has SA_SIGINFO set.
 */
static bool have_siginfo(int signum) {
  struct sigaction old_action;
  if (sigaction(signum, nullptr, &old_action) < 0) {
    __libc_format_log(ANDROID_LOG_WARN, "libc", "Failed testing for SA_SIGINFO: %s",
                      strerror(errno));
    return false;
  }
  return (old_action.sa_flags & SA_SIGINFO) != 0;
}

struct debugger_thread_info {
  bool crash_dump_started;
  pid_t crashing_tid;
  pid_t pseudothread_tid;
  int signal_number;
  siginfo_t* info;
};

// Logging and contacting debuggerd requires free file descriptors, which we might not have.
// Work around this by spawning a "thread" that shares its parent's address space, but not its file
// descriptor table, so that we can close random file descriptors without affecting the original
// process. Note that this doesn't go through pthread_create, so TLS is shared with the spawning
// process.
static void* pseudothread_stack;

static void start_crash_dump(const debugger_thread_info* thread_info, int status_write,
                             int pid_write, int continue_read) {
  // Now running in the orphan...
  pid_t pid = syscall(__NR_getpid);
  if (TEMP_FAILURE_RETRY(write(pid_write, &pid, sizeof(pid))) != sizeof(pid)) {
    fatal("failed to write pid to fd %d in debuggerd signal handler: %s", pid_write, strerror(errno));
  }

  // Wait until the psuedothread tells us to continue.
  __libc_format_log(ANDROID_LOG_FATAL, "libc", "reading continue");
  char dummy;
  TEMP_FAILURE_RETRY(read(continue_read, &dummy, sizeof(dummy)));

  __libc_format_log(ANDROID_LOG_FATAL, "libc", "ptracing");
  int rc = ptrace(PTRACE_SEIZE, thread_info->crashing_tid, 0, 0);
  if (rc != 0) {
    fatal("failed to PTRACE_SEIZE parent: %s", strerror(errno));
  }

  TEMP_FAILURE_RETRY(dup2(status_write, STDOUT_FILENO));
  close(status_write);

  __libc_format_log(ANDROID_LOG_FATAL, "libc", "execing");
  char buf[10];
  snprintf(buf, sizeof(buf), "%d", thread_info->crashing_tid);
  execl(CRASH_DUMP_PATH, CRASH_DUMP_NAME, buf, nullptr);
  fatal_errno("exec failed");
}

static int debuggerd_dispatch_pseudothread(void* arg) {
  debugger_thread_info* thread_info = static_cast<debugger_thread_info*>(arg);

  for (int i = 0; i < 1024; ++i) {
    close(i);
  }

  int devnull = TEMP_FAILURE_RETRY(open("/dev/null", O_RDWR));

  // devnull will be 0.
  TEMP_FAILURE_RETRY(dup2(devnull, STDOUT_FILENO));
  TEMP_FAILURE_RETRY(dup2(devnull, STDERR_FILENO));

  // Fork twice to orphan the child we're creating, so that the parent doesn't
  // get left with mysterious children it never created. (Except with clone
  // instead of fork in order to avoid calling pthread_atfork handlers.)

  // Create three pipes to communicate with the orphan.
  //  status_pipe: pipe that's passed to crash_dump to report the dump status.
  //  pid_pipe: pipe for the orphan to report its pid
  //  continue_pipe: pipe for the psuedothread to tell the orphan to continue
  int status_pipe[2];
  int pid_pipe[2];
  int continue_pipe[2];

  // Explicitly not CLOEXEC, the write end gets passed to crash_dump.
  if (pipe2(status_pipe, 0) != 0) {
    fatal_errno("failed to create status pipe");
  }

  if (pipe2(pid_pipe, O_CLOEXEC) != 0) {
    fatal_errno("failed to create pid pipe");
  }

  if (pipe2(continue_pipe, O_CLOEXEC) != 0) {
    fatal_errno("failed to create continue pipe");
  }

  pid_t forkpid = clone(nullptr, nullptr, SIGCHLD, nullptr);
  if (forkpid == -1) {
    __libc_format_log(ANDROID_LOG_FATAL, "libc", "failed to fork in debuggerd signal handler: %s",
                      strerror(errno));
  } else if (forkpid == 0) {
    // Intermediate worker that dies immediately after forking.
    close(status_pipe[0]);
    close(pid_pipe[0]);
    close(continue_pipe[1]);

    pid_t worker = clone(nullptr, nullptr, SIGCHLD, nullptr);
    if (worker == -1) {
      fatal("failed to fork again in debuggerd signal handler: %s", strerror(errno));
    } else if (worker == 0) {
      start_crash_dump(thread_info, status_pipe[1], pid_pipe[1], continue_pipe[0]);
      fatal("unreachable");
    }
    _exit(0);
  }

  // Original psuedothread:
  pid_t worker;
  ssize_t rc;

  close(status_pipe[1]);
  close(pid_pipe[1]);
  close(continue_pipe[0]);

  // Wait for the intermediate worker to exit.
  siginfo_t child_siginfo;
  if (TEMP_FAILURE_RETRY(waitid(P_PID, forkpid, &child_siginfo, WEXITED)) != 0) {
    __libc_format_log(ANDROID_LOG_FATAL, "libc", "failed to wait for crash_dump helper: %s",
                      strerror(errno));
    goto exit;
  }

  __libc_format_log(ANDROID_LOG_FATAL, "libc", "reading pid");

  // Read the pid of the worker.
  rc = TEMP_FAILURE_RETRY(read(pid_pipe[0], &worker, sizeof(worker)));
  if (rc != sizeof(worker)) {
    __libc_format_log(ANDROID_LOG_FATAL, "libc", "failed to read worker pid");
    goto exit;
  }

  if (prctl(PR_SET_PTRACER, worker) != 0) {
    __libc_format_log(ANDROID_LOG_FATAL, "libc", "failed to set ptracer: %s", strerror(errno));
  }

  __libc_format_log(ANDROID_LOG_FATAL, "libc", "writing continue");
  if (TEMP_FAILURE_RETRY(write(continue_pipe[1], "", 1)) != 1) {
    __libc_format_log(ANDROID_LOG_FATAL, "libc", "failed to tell worker to continue");
    goto exit;
  }

  __libc_format_log(ANDROID_LOG_FATAL, "libc", "reading response");
  // Read the response from crash_dump.
  char buf[4];
  rc = TEMP_FAILURE_RETRY(read(status_pipe[0], &buf, sizeof(buf)));
  if (rc == -1) {
    __libc_format_log(ANDROID_LOG_FATAL, "libc", "read of IPC pipe failed: %s", strerror(errno));
  } else if (rc == 0) {
    __libc_format_log(ANDROID_LOG_FATAL, "libc", "crash_dump helper failed to exec");
  } else if (rc != 1) {
    __libc_format_log(ANDROID_LOG_FATAL, "libc", "read of IPC pipe returned unexpected value: %zd",
                      rc);
  } else {
    if (buf[0] != '\1') {
      __libc_format_log(ANDROID_LOG_FATAL, "libc", "crash_dump helper reported failure");
    } else {
      thread_info->crash_dump_started = true;
    }
  }

  __libc_format_log(ANDROID_LOG_FATAL, "libc", "psuedothread done");
exit:
  close(status_pipe[0]);
  close(pid_pipe[0]);
  close(continue_pipe[1]);

  syscall(__NR_exit, thread_info->crash_dump_started ? 0 : 1);
  return 0;
}

static void resend_signal(siginfo_t* info, bool crash_dump_started) {
  // Signals can either be fatal or nonfatal.
  // For fatal signals, crash_dump will send us the signal we crashed with
  // before resuming us, so that processes using waitpid on us will see that we
  // exited with the correct exit status (e.g. so that sh will report
  // "Segmentation fault" instead of "Killed"). For this to work, we need
  // to deregister our signal handler for that signal before continuing.
  if (info->si_signo != DEBUGGER_SIGNAL) {
    signal(info->si_signo, SIG_DFL);
  }

  // We need to return from our signal handler so that crash_dump can see the
  // signal via ptrace and dump the thread that crashed. However, returning
  // does not guarantee that the signal will be thrown again, even for SIGSEGV
  // and friends, since the signal could have been sent manually. We blocked
  // all signals when registering the handler, so resending the signal (using
  // rt_tgsigqueueinfo(2) to preserve SA_SIGINFO) will cause it to be delivered
  // when our signal handler returns.
  if (crash_dump_started || info->si_signo != DEBUGGER_SIGNAL) {
    int rc = syscall(SYS_rt_tgsigqueueinfo, getpid(), gettid(), info->si_signo, info);
    if (rc != 0) {
      fatal_errno("failed to resend signal during crash");
    }
  }

  if (info->si_signo == DEBUGGER_SIGNAL) {
    pthread_mutex_unlock(&crash_mutex);
  }
}

// Handler that does crash dumping by forking and doing the processing in the child.
// Do this by ptracing the relevant thread, and then execing debuggerd to do the actual dump.
static void debuggerd_signal_handler(int signal_number, siginfo_t* info, void*) {
  int ret = pthread_mutex_lock(&crash_mutex);
  if (ret != 0) {
    __libc_format_log(ANDROID_LOG_INFO, "libc", "pthread_mutex_lock failed: %s", strerror(ret));
    return;
  }

  // It's possible somebody cleared the SA_SIGINFO flag, which would mean
  // our "info" arg holds an undefined value.
  if (!have_siginfo(signal_number)) {
    info = nullptr;
  }

  struct siginfo si = {};
  if (!info) {
    memset(&si, 0, sizeof(si));
    si.si_signo = signal_number;
    si.si_code = SI_USER;
    si.si_pid = getpid();
    si.si_uid = getuid();
    info = &si;
  } else if (info->si_code >= 0 || info->si_code == SI_TKILL) {
    // rt_tgsigqueueinfo(2)'s documentation appears to be incorrect on kernels
    // that contain commit 66dd34a (3.9+). The manpage claims to only allow
    // negative si_code values that are not SI_TKILL, but 66dd34a changed the
    // check to allow all si_code values in calls coming from inside the house.
  }

  log_signal_summary(signal_number, info);

  if (prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) == 1) {
    // The process has NO_NEW_PRIVS enabled, so we can't transition to the crash_dump context.
    __libc_format_log(ANDROID_LOG_INFO, "libc",
                      "Suppressing debuggerd output because prctl(PR_GET_NO_NEW_PRIVS)==1");
    resend_signal(info, false);
    return;
  }

  void* abort_message = nullptr;
  if (g_callbacks.get_abort_message) {
    abort_message = g_callbacks.get_abort_message();
  }
  // Populate si_value with the abort message address, if found.
  if (abort_message) {
    info->si_value.sival_ptr = abort_message;
  }

  debugger_thread_info thread_info = {
    .crash_dump_started = false,
    .pseudothread_tid = -1,
    .crashing_tid = gettid(),
    .signal_number = signal_number,
    .info = info
  };

  // Essentially pthread_create without CLONE_FILES (see debuggerd_dispatch_pseudothread).
  pid_t child_pid =
    clone(debuggerd_dispatch_pseudothread, pseudothread_stack,
          CLONE_THREAD | CLONE_SIGHAND | CLONE_VM | CLONE_CHILD_SETTID | CLONE_CHILD_CLEARTID,
          &thread_info, nullptr, nullptr, &thread_info.pseudothread_tid);
  if (child_pid == -1) {
    fatal_errno("failed to spawn debuggerd dispatch thread");
  }

  // Wait for the child to start...
  __futex_wait(&thread_info.pseudothread_tid, -1, nullptr);

  // and then wait for it to finish.
  __futex_wait(&thread_info.pseudothread_tid, child_pid, nullptr);

  // Signals can either be fatal or nonfatal.
  // For fatal signals, crash_dump will PTRACE_CONT us with the signal we
  // crashed with, so that processes using waitpid on us will see that we
  // exited with the correct exit status (e.g. so that sh will report
  // "Segmentation fault" instead of "Killed"). For this to work, we need
  // to deregister our signal handler for that signal before continuing.
  if (signal_number != DEBUGGER_SIGNAL) {
    signal(signal_number, SIG_DFL);
  }

  resend_signal(info, thread_info.crash_dump_started);
}

void debuggerd_init(debuggerd_callbacks_t* callbacks) {
  if (callbacks) {
    g_callbacks = *callbacks;
  }

  void* thread_stack_allocation =
    mmap(nullptr, PAGE_SIZE * 3, PROT_NONE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
  if (thread_stack_allocation == MAP_FAILED) {
    fatal_errno("failed to allocate debuggerd thread stack");
  }

  char* stack = static_cast<char*>(thread_stack_allocation) + PAGE_SIZE;
  if (mprotect(stack, PAGE_SIZE, PROT_READ | PROT_WRITE) != 0) {
    fatal_errno("failed to mprotect debuggerd thread stack");
  }

  // Stack grows negatively, set it to the last byte in the page...
  stack = (stack + PAGE_SIZE - 1);
  // and align it.
  stack -= 15;
  pseudothread_stack = stack;

  struct sigaction action;
  memset(&action, 0, sizeof(action));
  sigfillset(&action.sa_mask);
  action.sa_sigaction = debuggerd_signal_handler;
  action.sa_flags = SA_RESTART | SA_SIGINFO;

  // Use the alternate signal stack if available so we can catch stack overflows.
  action.sa_flags |= SA_ONSTACK;
  debuggerd_register_handlers(&action);
}
