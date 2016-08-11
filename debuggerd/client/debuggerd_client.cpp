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

#include "debuggerd/client.h"

#include <errno.h>
#include <inttypes.h>
#include <pthread.h>
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
#include <unistd.h>

#include "private/libc_logging.h"

// see man(2) prctl, specifically the section about PR_GET_NAME
#define MAX_TASK_NAME_LEN (16)

#if defined(__LP64__)
#define CRASH_DUMP_PATH "/system/bin/crash_dump64"
#else
#define CRASH_DUMP_PATH "/system/bin/crash_dump32"
#endif

static debuggerd_callbacks_t g_callbacks;

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
    case SIGTRAP:
      signal_name = "SIGTRAP";
      break;
  }

  char thread_name[MAX_TASK_NAME_LEN + 1];  // one more for termination
  if (prctl(PR_GET_NAME, reinterpret_cast<unsigned long>(thread_name), 0, 0, 0) != 0) {
    strcpy(thread_name, "<name unknown>");
  } else {
    // short names are null terminated by prctl, but the man page
    // implies that 16 byte names are not.
    thread_name[MAX_TASK_NAME_LEN] = 0;
  }

  // "info" will be null if the siginfo_t information was not available.
  // Many signals don't have an address or a code.
  char code_desc[32];  // ", code -6"
  char addr_desc[32];  // ", fault addr 0x1234"
  addr_desc[0] = code_desc[0] = 0;
  if (info != nullptr) {
    // For a rethrown signal, this si_code will be right and the one debuggerd shows will
    // always be SI_TKILL.
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
  struct sigaction old_action, new_action;

  memset(&new_action, 0, sizeof(new_action));
  new_action.sa_handler = SIG_DFL;
  new_action.sa_flags = SA_RESTART;
  sigemptyset(&new_action.sa_mask);

  if (sigaction(signum, &new_action, &old_action) < 0) {
    __libc_format_log(ANDROID_LOG_WARN, "libc", "Failed testing for SA_SIGINFO: %s",
                      strerror(errno));
    return false;
  }
  bool result = (old_action.sa_flags & SA_SIGINFO) != 0;

  if (sigaction(signum, &old_action, nullptr) == -1) {
    __libc_format_log(ANDROID_LOG_WARN, "libc", "Restore failed in test for SA_SIGINFO: %s",
                      strerror(errno));
  }
  return result;
}

// Handler that does crash dumping by forking and doing the processing in the child.
// Do this by ptracing the relevant thread, and then execing debuggerd to do the actual dump.
static void debuggerd_signal_handler(int signal_number, siginfo_t* info, void*) {
  // It's possible somebody cleared the SA_SIGINFO flag, which would mean
  // our "info" arg holds an undefined value.
  if (!have_siginfo(signal_number)) {
    info = nullptr;
  }

  log_signal_summary(signal_number, info);

  int tid = gettid();

  // Use a pipe to coordinate the dumping of the process.
  int pipefds[2];
  if (pipe2(pipefds, O_CLOEXEC) != 0) {
    __libc_format_log(ANDROID_LOG_FATAL, "libc",
                      "failed to create pipe in debuggerd_signal_handler: %s", strerror(errno));
  }

  // Don't use fork(2) to avoid calling pthread_atfork handlers.
  int forkpid = clone(nullptr, nullptr, SIGCHLD, nullptr);
  if (forkpid == -1) {
    __libc_format_log(ANDROID_LOG_FATAL, "libc", "failed to fork in debuggerd_signal_handler: %s",
                      strerror(errno));
  } else if (forkpid == 0) {
    // ptrace our parent, any relevant threads, and then exec debuggerd to dump stacks.
    close(pipefds[0]);
    pid_t parent = getppid();
    if (ptrace(PTRACE_ATTACH, parent) != 0) {
      __libc_format_log(ANDROID_LOG_ERROR, "libc", "failed to ptrace parent: %s", strerror(errno));
      if (TEMP_FAILURE_RETRY(write(pipefds[1], "", 1)) != 1) {
        kill(parent, SIGKILL);
      }
      _exit(1);
    }

    char buf[10];
    snprintf(buf, sizeof(buf), "%d", tid);

    execl(CRASH_DUMP_PATH, CRASH_DUMP_PATH, buf, nullptr);
  }

  // In the parent, close the write end of the pipe, and try to read the pipe.
  // If the pipe closes, the helper was succesfully execed. If we succesfully read
  // data, something went wrong.
  close(pipefds[1]);
  char dummy;
  ssize_t rc = TEMP_FAILURE_RETRY(read(pipefds[0], &dummy, 1));
  if (rc != 0) {
    if (rc == -1) {
      __libc_format_log(ANDROID_LOG_FATAL, "libc", "failed to read in debuggerd_signal_handler: %s",
                        strerror(errno));
    }
  }

  // We need to return from the signal handler so that debuggerd can dump the
  // thread that crashed, but returning here does not guarantee that the signal
  // will be thrown again, even for SIGSEGV and friends, since the signal could
  // have been sent manually. Resend the signal with rt_tgsigqueueinfo(2) to
  // preserve the SA_SIGINFO contents.
  signal(signal_number, SIG_DFL);

  struct siginfo si;
  if (!info) {
    memset(&si, 0, sizeof(si));
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

  rc = syscall(SYS_rt_tgsigqueueinfo, getpid(), gettid(), signal_number, info);
  if (rc != 0) {
    __libc_format_log(ANDROID_LOG_FATAL, "libc", "failed to resend signal during crash: %s",
                      strerror(errno));
    _exit(1);
  }

  close(pipefds[0]);
}

void debuggerd_init(debuggerd_callbacks_t* callbacks) {
  if (callbacks) {
    g_callbacks = *callbacks;
  }

  struct sigaction action;
  memset(&action, 0, sizeof(action));
  sigemptyset(&action.sa_mask);
  action.sa_sigaction = debuggerd_signal_handler;
  action.sa_flags = SA_RESTART | SA_SIGINFO;

  // Use the alternate signal stack if available so we can catch stack overflows.
  action.sa_flags |= SA_ONSTACK;

  sigaction(SIGABRT, &action, nullptr);
  sigaction(SIGBUS, &action, nullptr);
  sigaction(SIGFPE, &action, nullptr);
  sigaction(SIGILL, &action, nullptr);
  sigaction(SIGSEGV, &action, nullptr);
#if defined(SIGSTKFLT)
  sigaction(SIGSTKFLT, &action, nullptr);
#endif
  sigaction(SIGTRAP, &action, nullptr);
  sigaction(DEBUGGER_SIGNAL, &action, nullptr);
}
