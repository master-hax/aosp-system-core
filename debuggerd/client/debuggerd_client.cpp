#include <debuggerd/client.h>

#include <signal.h>
#include <stdlib.h>

#include <android-base/logging.h>
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

bool debuggerd_trigger_dump(pid_t pid, int output_fd, DebuggerdDumpType dump_type) {
  LOG(INFO) << "libdebuggerd_client: started dumping process " << pid;
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
