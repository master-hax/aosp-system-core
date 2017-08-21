/*
 * Copyright 2016, The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <arpa/inet.h>
#include <dirent.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sys/capability.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/un.h>
#include <syscall.h>
#include <unistd.h>

#include <limits>
#include <map>
#include <memory>
#include <set>
#include <vector>

#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/parseint.h>
#include <android-base/properties.h>
#include <android-base/stringprintf.h>
#include <android-base/strings.h>
#include <android-base/unique_fd.h>
#include <cutils/sockets.h>
#include <log/log.h>
#include <private/android_filesystem_config.h>
#include <procinfo/process.h>

#define ATRACE_TAG ATRACE_TAG_BIONIC
#include <utils/Trace.h>

#include "backtrace.h"
#include "tombstone.h"
#include "utility.h"

#include "debuggerd/handler.h"
#include "protocol.h"
#include "tombstoned/tombstoned.h"
#include "util.h"

using android::base::unique_fd;
using android::base::ReadFileToString;
using android::base::StringPrintf;
using android::base::Trim;

static std::string get_process_name(pid_t pid) {
  std::string result = "<unknown>";
  ReadFileToString(StringPrintf("/proc/%d/cmdline", pid), &result);
  return result;
}

static std::string get_thread_name(pid_t tid) {
  std::string result = "<unknown>";
  ReadFileToString(StringPrintf("/proc/%d/comm", tid), &result);
  return Trim(result);
}

static bool pid_contains_tid(int pid_proc_fd, pid_t tid) {
  struct stat st;
  std::string task_path = StringPrintf("task/%d", tid);
  return fstatat(pid_proc_fd, task_path.c_str(), &st, 0) == 0;
}

static pid_t get_tracer(pid_t tracee) {
  // Check to see if the thread is being ptraced by another process.
  android::procinfo::ProcessInfo process_info;
  if (android::procinfo::GetProcessInfo(tracee, &process_info)) {
    return process_info.tracer;
  }
  return -1;
}

// Attach to a thread, and verify that it's still a member of the given process
static bool ptrace_seize_thread(int pid_proc_fd, pid_t tid, std::string* error) {
  if (ptrace(PTRACE_SEIZE, tid, 0, 0) != 0) {
    if (errno == EPERM) {
      pid_t tracer = get_tracer(tid);
      if (tracer != -1) {
        *error = StringPrintf("failed to attach to thread %d, already traced by %d (%s)", tid,
                              tracer, get_process_name(tracer).c_str());
        return false;
      }
    }

    *error = StringPrintf("failed to attach to thread %d: %s", tid, strerror(errno));
    return false;
  }

  // Make sure that the task we attached to is actually part of the pid we're dumping.
  if (!pid_contains_tid(pid_proc_fd, tid)) {
    if (ptrace(PTRACE_DETACH, tid, 0, 0) != 0) {
      PLOG(FATAL) << "failed to detach from thread " << tid;
    }
    *error = StringPrintf("thread %d is not in process", tid);
    return false;
  }

  return true;
}

static bool activity_manager_notify(pid_t pid, int signal, const std::string& amfd_data) {
  ATRACE_CALL();
  android::base::unique_fd amfd(socket_local_client(
      "/data/system/ndebugsocket", ANDROID_SOCKET_NAMESPACE_FILESYSTEM, SOCK_STREAM));
  if (amfd.get() == -1) {
    PLOG(ERROR) << "unable to connect to activity manager";
    return false;
  }

  struct timeval tv = {
    .tv_sec = 1,
    .tv_usec = 0,
  };
  if (setsockopt(amfd.get(), SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv)) == -1) {
    PLOG(ERROR) << "failed to set send timeout on activity manager socket";
    return false;
  }
  tv.tv_sec = 3;  // 3 seconds on handshake read
  if (setsockopt(amfd.get(), SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) == -1) {
    PLOG(ERROR) << "failed to set receive timeout on activity manager socket";
    return false;
  }

  // Activity Manager protocol: binary 32-bit network-byte-order ints for the
  // pid and signal number, followed by the raw text of the dump, culminating
  // in a zero byte that marks end-of-data.
  uint32_t datum = htonl(pid);
  if (!android::base::WriteFully(amfd, &datum, 4)) {
    PLOG(ERROR) << "AM pid write failed";
    return false;
  }
  datum = htonl(signal);
  if (!android::base::WriteFully(amfd, &datum, 4)) {
    PLOG(ERROR) << "AM signal write failed";
    return false;
  }
  if (!android::base::WriteFully(amfd, amfd_data.c_str(), amfd_data.size() + 1)) {
    PLOG(ERROR) << "AM data write failed";
    return false;
  }

  // 3 sec timeout reading the ack; we're fine if the read fails.
  char ack;
  android::base::ReadFully(amfd, &ack, 1);
  return true;
}

static void drop_capabilities() {
  ATRACE_CALL();
  __user_cap_header_struct capheader;
  memset(&capheader, 0, sizeof(capheader));
  capheader.version = _LINUX_CAPABILITY_VERSION_3;
  capheader.pid = 0;

  __user_cap_data_struct capdata[2];
  memset(&capdata, 0, sizeof(capdata));

  if (capset(&capheader, &capdata[0]) == -1) {
    PLOG(FATAL) << "failed to drop capabilities";
  }

  if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
    PLOG(FATAL) << "failed to set PR_SET_NO_NEW_PRIVS";
  }
}

struct ThreadInfo {
  ucontext_t registers;
  std::string thread_name;
};

static bool GetThreadInfo(pid_t thread, ThreadInfo* thread_info) {
  thread_info->thread_name = get_thread_name(thread);

  // TODO: Fetch registers.
  return true;
}

// Globals used by the abort handler.
static pid_t target_thread = -1;
static bool tombstoned_connected = false;
static unique_fd tombstoned_socket;
static unique_fd output_fd;

static void Initialize(char** argv) {
  android::base::InitLogging(argv);
  android::base::SetAborter([](const char* abort_msg) {
    // If we abort before we get an output fd, contact tombstoned to let any
    // potential listeners know that we failed.
    if (!tombstoned_connected) {
      if (!tombstoned_connect(target_thread, &tombstoned_socket, &output_fd,
                              kDebuggerdAnyIntercept)) {
        // We failed to connect, not much we can do.
        LOG(ERROR) << "failed to connected to tombstoned to report failure";
        _exit(1);
      }
    }

    dprintf(output_fd.get(), "crash_dump failed to dump process");
    if (target_thread != 1) {
      dprintf(output_fd.get(), " %d: %s\n", target_thread, abort_msg);
    } else {
      dprintf(output_fd.get(), ": %s\n", abort_msg);
    }

    _exit(1);
  });

  // Don't try to dump ourselves.
  struct sigaction action = {};
  action.sa_handler = SIG_DFL;
  debuggerd_register_handlers(&action);

  sigset_t mask;
  sigemptyset(&mask);
  if (sigprocmask(SIG_SETMASK, &mask, nullptr) != 0) {
    PLOG(FATAL) << "failed to set signal mask";
  }
}

static void ParseArgs(int argc, char** argv, pid_t* pseudothread_tid, DebuggerdDumpType* dump_type) {
  if (argc != 4) {
    LOG(FATAL) << "wrong number of args: " << argc << " (expected 4)";
  }

  if (!android::base::ParseInt(argv[1], &target_thread, 1, std::numeric_limits<pid_t>::max())) {
    LOG(FATAL) << "invalid target tid: " << argv[1];
  }

  if (!android::base::ParseInt(argv[2], pseudothread_tid, 1, std::numeric_limits<pid_t>::max())) {
    LOG(FATAL) << "invalid pseudothread tid: " << argv[2];
  }

  int dump_type_int;
  if (!android::base::ParseInt(argv[3], &dump_type_int, 0, 1)) {
    LOG(FATAL) << "invalid requested dump type: " << argv[3];
  }
  *dump_type = static_cast<DebuggerdDumpType>(dump_type_int);
}

int main(int argc, char** argv) {
  atrace_begin(ATRACE_TAG, "before reparent");
  pid_t target_process = getppid();

  // Open /proc/`getppid()` before we daemonize.
  std::string target_proc_path = "/proc/" + std::to_string(target_process);
  int target_proc_fd = open(target_proc_path.c_str(), O_DIRECTORY | O_RDONLY);
  if (target_proc_fd == -1) {
    PLOG(FATAL) << "failed to open " << target_proc_path;
  }

  // Make sure getppid() hasn't changed.
  if (getppid() != target_process) {
    LOG(FATAL) << "parent died";
  }
  atrace_end(ATRACE_TAG);

  // Reparent ourselves to init, so that the signal handler can waitpid on the
  // original process to avoid leaving a zombie for non-fatal dumps.
  // Move the input/output pipes off of stdout/stderr, just in case.
  unique_fd output_pipe(dup(STDOUT_FILENO));
  unique_fd input_pipe(dup(STDIN_FILENO));

  if (daemon(1, 0) == -1) {
    PLOG(FATAL) << "failed to daemonize";
  }

  ATRACE_NAME("after reparent");
  pid_t pseudothread_tid;
  DebuggerdDumpType dump_type;

  Initialize(argv);
  ParseArgs(argc, argv, &pseudothread_tid, &dump_type);

  // Die if we take too long.
  //
  // Note: processes with many threads and minidebug-info can take a bit to
  //       unwind, do not make this too small. b/62828735
  alarm(5);

  // Get the process name (aka cmdline).
  std::string process_name = get_process_name(target_thread);

  // Collect the list of open files.
  OpenFilesList open_files;
  {
    ATRACE_NAME("open files");
    populate_open_files_list(target_thread, &open_files);
  }

  // In order to reduce the duration that we pause the process for, we ptrace
  // the threads, fetch their registers and associated information, and then
  // fork a separate process as a snapshot of the process's address space.
  std::set<pid_t> threads;
  if (!android::procinfo::GetProcessTids(target_thread, &threads)) {
    PLOG(FATAL) << "failed to get process threads";
  }

  std::map<pid_t, ThreadInfo> thread_info;
  {
    ATRACE_NAME("ptrace");
    std::string error;
    for (pid_t thread : threads) {
      if (!ptrace_seize_thread(target_proc_fd, thread, &error)) {
        LOG(thread == target_thread ? FATAL : WARNING) << error;
      }

      if (thread == pseudothread_tid || thread == target_thread) {
        continue;
      }

      if (ptrace(PTRACE_INTERRUPT, thread, 0, 0) != 0) {
        PLOG(thread == target_thread ? FATAL : WARNING)
            << "failed to ptrace interrupt thread " << thread;
        ptrace(PTRACE_DETACH, thread, 0, 0);
      }

      ThreadInfo info;
      if (GetThreadInfo(thread, &info)) {
        thread_info[thread] = std::move(info);
      } else {
        PLOG(thread == target_thread ? FATAL : WARNING) << "failed to get thread info";
      }
    }
  }

  // Tell the pseudothread to fork off a copy of the target's address space.
  pid_t vm_pid;
  if (TEMP_FAILURE_RETRY(write(output_pipe.get(), "\1", 1)) != 1) {
    PLOG(FATAL) << "failed to write to pseudothread";
  }

  // TODO: static_assert that pid_t is the same size between 32 and 64 bit for when we cross-unwind.
  ssize_t rc = TEMP_FAILURE_RETRY(read(input_pipe.get(), &vm_pid, sizeof(vm_pid)));
  if (rc == -1) {
    PLOG(FATAL) << "failed to read from pseudothread";
  } else if (rc != sizeof(vm_pid)) {
    LOG(FATAL) << "read incorrect number of bytes from pseudothread, expected " << sizeof(vm_pid)
               << ", got " << rc;
  }

  if (ptrace(PTRACE_SEIZE, vm_pid, 0, 0) != 0) {
    PLOG(FATAL) << "failed to ptrace vm process";
  }

  // Make sure that the vm process is actually forked from the pseudothread.
  // File descriptor table identity should be enough to verify this.
  android::procinfo::ProcessInfo procinfo;
  if (!android::procinfo::GetProcessInfo(vm_pid, &procinfo)) {
    PLOG(FATAL) << "failed to get process info for vm process";
  }

  if (procinfo.ppid != target_process) {
    LOG(FATAL) << "vm process parent mismatch, expected " << target_process << ", actually "
               << procinfo.ppid;
  }

  // DO NOT MERGE WITHOUT FIXING THIS: check that old parent is still alive
  //                                   check kcmp(pseudothread_tid, vm_pid, KCMP_FILES)

  // Immediately after forking the vm process, target tid will resend its signal.
  // Wait for the signal to show up, and then fetch its registers.
  // TODO: Instead of doing this, just send the registers over from the signal handler.
  siginfo_t siginfo = {};
  {
    ATRACE_NAME("wait_for_signal");
    if (!wait_for_signal(target_thread, &siginfo)) {
      printf("failed to wait for signal in tid %d: %s\n", target_thread, strerror(errno));
      exit(1);
    }
  }

  if (!GetThreadInfo(target_thread, &thread_info[target_thread])) {
    LOG(FATAL) << "failed to get thread info for target tid " << target_thread;
  }

  // Drop our capabilities now that we've fetched all of the information we need.
  drop_capabilities();

  {
    ATRACE_NAME("tombstoned_connect");
    LOG(INFO) << "obtaining output fd from tombstoned, type: " << dump_type;
    tombstoned_connected =
        tombstoned_connect(target_thread, &tombstoned_socket, &output_fd, dump_type);
  }

  if (tombstoned_connected) {
    if (TEMP_FAILURE_RETRY(dup2(output_fd.get(), STDOUT_FILENO)) == -1) {
      PLOG(ERROR) << "failed to dup2 output fd (" << output_fd.get() << ") to STDOUT_FILENO";
    }
  } else {
    unique_fd devnull(TEMP_FAILURE_RETRY(open("/dev/null", O_RDWR)));
    TEMP_FAILURE_RETRY(dup2(devnull.get(), STDOUT_FILENO));
    output_fd = std::move(devnull);
  }

  LOG(INFO) << "performing dump of process " << target_process << " (target tid = " << target_thread
            << ")";

  int signo = siginfo.si_signo;
  bool fatal_signal = signo != DEBUGGER_SIGNAL;
  bool backtrace = false;
  uintptr_t abort_address = 0;

  // si_value can represent three things:
  //   0: dump tombstone
  //   1: dump backtrace
  //   everything else: abort message address (implies dump tombstone)
  if (siginfo.si_value.sival_int == 1) {
    backtrace = true;
  } else if (siginfo.si_value.sival_ptr != nullptr) {
    abort_address = reinterpret_cast<uintptr_t>(siginfo.si_value.sival_ptr);
  }

  // TODO: Use seccomp to lock ourselves down.

  std::string amfd_data;
#if 0
  if (backtrace) {
    ATRACE_NAME("dump_backtrace");
    dump_backtrace(output_fd.get(), backtrace_map.get(), target, target_thread, process_name, threads, 0);
  } else {
    ATRACE_NAME("engrave_tombstone");
    engrave_tombstone(output_fd.get(), backtrace_map.get(), backtrace_map_new.get(), &open_files,
                      target, target_thread, process_name, threads, abort_address,
                      fatal_signal ? &amfd_data : nullptr);
  }
#endif

  // We don't actually need to PTRACE_DETACH, as long as our tracees aren't in
  // group-stop state, which is true as long as no stopping signals are sent.

  bool wait_for_gdb = android::base::GetBoolProperty("debug.debuggerd.wait_for_gdb", false);
  if (!fatal_signal || siginfo.si_code == SI_USER) {
    // Don't wait_for_gdb when the process didn't actually crash.
    wait_for_gdb = false;
  }

  // If the process crashed or we need to send it SIGSTOP for wait_for_gdb,
  // get it in a state where it can receive signals, and then send the relevant
  // signal.
  if (wait_for_gdb || fatal_signal) {
    if (ptrace(PTRACE_INTERRUPT, target_thread, 0, 0) != 0) {
      PLOG(ERROR) << "failed to use PTRACE_INTERRUPT on " << target_thread;
    }

    if (tgkill(target_process, target_thread, wait_for_gdb ? SIGSTOP : signo) != 0) {
      PLOG(ERROR) << "failed to resend signal " << signo << " to " << target_thread;
    }
  }

  if (wait_for_gdb) {
    // Use ALOGI to line up with output from engrave_tombstone.
    ALOGI(
        "***********************************************************\n"
        "* Process %d has been suspended while crashing.\n"
        "* To attach gdbserver and start gdb, run this on the host:\n"
        "*\n"
        "*     gdbclient.py -p %d\n"
        "*\n"
        "***********************************************************",
        target_process, target_process);
  }

  if (fatal_signal) {
    // Don't try to notify ActivityManager if it just crashed, or we might hang until timeout.
    if (thread_info[target_process].thread_name != "system_server") {
      activity_manager_notify(target_process, signo, amfd_data);
    }
  }

  // Close stdout before we notify tombstoned of completion.
  close(STDOUT_FILENO);
  if (tombstoned_connected && !tombstoned_notify_completion(tombstoned_socket.get())) {
    LOG(ERROR) << "failed to notify tombstoned of completion";
  }

  return 0;
}
