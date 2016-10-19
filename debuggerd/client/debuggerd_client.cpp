#include <debuggerd/client.h>

#include <fcntl.h>
#include <signal.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <android-base/logging.h>
#include <android-base/stringprintf.h>
#include <android-base/unique_fd.h>
#include <cutils/sockets.h>
#include <debuggerd/handler.h>
#include <debuggerd/protocol.h>
#include <debuggerd/util.h>

using android::base::unique_fd;

static bool send_signal(pid_t pid, bool backtrace) {
  sigval val;
  val.sival_int = backtrace;
  if (sigqueue(pid, DEBUGGER_SIGNAL, val) != 0) {
    LOG(ERROR) << "libdebuggerd_client: failed to send signal to pid " << pid;
    return false;
  }
  return true;
}

static bool check_dumpable(pid_t pid) {
  // /proc/<pid> is owned by the effective UID of the process.
  // Ownership of most of the other files in /proc/<pid> varies based on PR_SET_DUMPABLE.
  // If PR_GET_DUMPABLE would return 0, they're owned by root, instead.
  std::string proc_pid_path = android::base::StringPrintf("/proc/%d/", pid);
  std::string proc_pid_status_path = proc_pid_path + "/status";

  unique_fd proc_pid_fd(open(proc_pid_path.c_str(), O_DIRECTORY | O_RDONLY | O_CLOEXEC));
  if (proc_pid_fd == -1) {
    return false;
  }
  unique_fd proc_pid_status_fd(openat(proc_pid_fd, "status", O_RDONLY | O_CLOEXEC));
  if (proc_pid_status_fd == -1) {
    return false;
  }

  struct stat proc_pid_st;
  struct stat proc_pid_status_st;
  if (fstat(proc_pid_fd.get(), &proc_pid_st) != 0 ||
      fstat(proc_pid_status_fd.get(), &proc_pid_status_st) != 0) {
    return false;
  }

  // We can't figure out if a process is dumpable if its effective UID is root, but that's fine
  // because being root bypasses the PR_SET_DUMPABLE check for ptrace.
  if (proc_pid_st.st_uid == 0) {
    return true;
  }

  if (proc_pid_status_st.st_uid == 0) {
    return false;
  }

  return true;
}

bool debuggerd_trigger_dump(pid_t pid, int output_fd_raw, DebuggerdDumpType dump_type) {
  LOG(INFO) << "libdebuggerd_client: started dumping process " << pid;

  unique_fd output_fd(output_fd_raw);
  if (!check_dumpable(pid)) {
    dprintf(output_fd, "target pid %d is not dumpable\n", pid);
    return false;
  }

  unique_fd sockfd(socket_local_client(kTombstonedInterceptSocketName,
                                       ANDROID_SOCKET_NAMESPACE_RESERVED, SOCK_SEQPACKET));
  if (sockfd == -1) {
    PLOG(ERROR) << "libdebuggerd_client: failed to contact tombstoned";
    return false;
  }

  InterceptRequest req = {.pid = pid };
  unique_fd copy(dup(output_fd));
  if (copy == -1) {
    PLOG(ERROR) << "libdebuggerd_client: dup failed";
    return false;
  }

  if (send_fd(sockfd.get(), &req, sizeof(req), std::move(copy)) != sizeof(req)) {
    PLOG(ERROR) << "libdebuggerd_client: failed to send output fd to tombstoned";
    return false;
  }

  bool backtrace = dump_type == kDebuggerdBacktrace;
  send_signal(pid, backtrace);

  InterceptResponse response;
  ssize_t rc = TEMP_FAILURE_RETRY(read(sockfd.get(), &response, sizeof(response)));
  if (rc == 0) {
    LOG(ERROR) << "libdebuggerd_client: failed to read response from tombstoned: timeout reached?";
    return false;
  } else if (rc != sizeof(response)) {
    LOG(ERROR)
      << "libdebuggerd_client: received packet of unexpected length from tombstoned: expected "
      << sizeof(response) << ", received " << rc;
    return false;
  }

  if (response.success != 1) {
    response.error_message[sizeof(response.error_message) - 1] = '\0';
    LOG(ERROR) << "libdebuggerd_client: tombstoned reported failure: " << response.error_message;
  }

  LOG(INFO) << "libdebuggerd_client: done dumping process " << pid;

  return true;
}
