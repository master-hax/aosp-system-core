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

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <array>
#include <deque>
#include <unordered_map>

#include <event2/event.h>
#include <event2/listener.h>
#include <event2/thread.h>

#include <android-base/logging.h>
#include <android-base/stringprintf.h>
#include <android-base/unique_fd.h>
#include <cutils/sockets.h>

#include "debuggerd/handler.h"
#include "debuggerd/protocol.h"
#include "debuggerd/util.h"

#include "intercept_manager.h"

using android::base::StringPrintf;
using android::base::unique_fd;

static InterceptManager* intercept_manager;

enum CrashStatus {
  kCrashStatusRunning,
  kCrashStatusQueued,
};

struct Crash;

class CrashType {
 public:
  const std::string file_name_prefix;
  const std::string dir_path;

  const size_t max_artifacts;
  const size_t max_concurrent_dumps;

  int dir_fd;

  int next_artifact;
  size_t num_concurrent_dumps;

  std::deque<Crash*> queued_requests;

  static CrashType tombstone;
  static CrashType java_trace;

 private:
  CrashType(const std::string& dir_path, const std::string& file_name_prefix, size_t max_artifacts,
            size_t max_concurrent_dumps)
      : file_name_prefix(file_name_prefix),
        dir_path(dir_path),
        max_artifacts(max_artifacts),
        max_concurrent_dumps(max_concurrent_dumps),
        next_artifact(0),
        num_concurrent_dumps(0) {
    // NOTE: The success of this call is being tested externally for now.
    // This is a kludge.
    dir_fd = open(dir_path.c_str(), O_DIRECTORY | O_RDONLY | O_CLOEXEC);
  }

  DISALLOW_COPY_AND_ASSIGN(CrashType);
};

/* static */ CrashType CrashType::tombstone("/data/tombstones", "tombstone_" /* file_name_prefix */,
                                            10 /* max_artifacts */, 1 /* max_concurrent_dumps */);

/* static */ CrashType CrashType::java_trace("/data/anr", "anr_" /* file_name_prefix */,
                                             64 /* max_artifacts */, 4 /* max_concurrent_dumps */);

// Ownership of Crash is a bit messy.
// It's either owned by an active event that must have a timeout, or owned by
// queued_requests, in the case that multiple crashes come in at the same time.
struct Crash {
  ~Crash() {
    event_free(crash_event);
  }

  unique_fd crash_fd;
  pid_t crash_pid;
  event* crash_event = nullptr;

  // Not owned by |Crash|.
  CrashType* crash_type = nullptr;
};

// Forward declare the callbacks so they can be placed in a sensible order.
static void crash_accept_cb(evconnlistener* listener, evutil_socket_t sockfd, sockaddr*, int, void*);
static void crash_request_cb(evutil_socket_t sockfd, short ev, void* arg);
static void crash_completed_cb(evutil_socket_t sockfd, short ev, void* arg);

static void find_oldest_artifact(CrashType* type) {
  size_t oldest_tombstone = 0;
  time_t oldest_time = std::numeric_limits<time_t>::max();

  for (size_t i = 0; i < type->max_artifacts; ++i) {
    std::string path = android::base::StringPrintf("%s/%s%02zu", type->dir_path.c_str(),
                                                   type->file_name_prefix.c_str(), i);
    struct stat st;
    if (stat(path.c_str(), &st) != 0) {
      if (errno == ENOENT) {
        oldest_tombstone = i;
        break;
      } else {
        PLOG(ERROR) << "failed to stat " << path;
        continue;
      }
    }

    if (st.st_mtime < oldest_time) {
      oldest_tombstone = i;
      oldest_time = st.st_mtime;
    }
  }

  type->next_artifact = oldest_tombstone;
}

static unique_fd get_tombstone_fd(CrashType* type) {
  // If kMaxConcurrentDumps is greater than 1, then theoretically the same
  // filename could be handed out to multiple processes. Unlink and create the
  // file, instead of using O_TRUNC, to avoid two processes interleaving their
  // output.
  unique_fd result;
  char buf[PATH_MAX];
  snprintf(buf, sizeof(buf), "%s%02d", type->file_name_prefix.c_str(), type->next_artifact);
  if (unlinkat(type->dir_fd, buf, 0) != 0 && errno != ENOENT) {
    PLOG(FATAL) << "failed to unlink tombstone at " << type->dir_path << buf;
  }

  result.reset(openat(type->dir_fd, buf, O_CREAT | O_EXCL | O_WRONLY | O_APPEND | O_CLOEXEC, 0640));
  if (result == -1) {
    PLOG(FATAL) << "failed to create tombstone at " << type->dir_path << buf;
  }

  type->next_artifact = (type->next_artifact + 1) % type->max_artifacts;
  return result;
}

static void perform_request(Crash* crash) {
  unique_fd output_fd;
  if (!intercept_manager->GetIntercept(crash->crash_pid, &output_fd)) {
    output_fd = get_tombstone_fd(crash->crash_type);
  }

  TombstonedCrashPacket response = {
    .packet_type = CrashPacketType::kPerformDump
  };
  ssize_t rc = send_fd(crash->crash_fd, &response, sizeof(response), std::move(output_fd));
  if (rc == -1) {
    PLOG(WARNING) << "failed to send response to CrashRequest";
    goto fail;
  } else if (rc != sizeof(response)) {
    PLOG(WARNING) << "crash socket write returned short";
    goto fail;
  } else {
    // TODO: Make this configurable by the interceptor?
    struct timeval timeout = { 10, 0 };

    event_base* base = event_get_base(crash->crash_event);
    event_assign(crash->crash_event, base, crash->crash_fd, EV_TIMEOUT | EV_READ,
                 crash_completed_cb, crash);
    event_add(crash->crash_event, &timeout);
  }

  ++crash->crash_type->num_concurrent_dumps;
  return;

fail:
  delete crash;
}

static void dequeue_requests(CrashType* type) {
  std::deque<Crash*>& queued_requests = type->queued_requests;
  while (!queued_requests.empty() && (type->num_concurrent_dumps < type->max_concurrent_dumps)) {
    Crash* next_crash = queued_requests.front();
    queued_requests.pop_front();
    perform_request(next_crash);
  }
}

static void crash_accept_cb(evconnlistener* listener, evutil_socket_t sockfd, sockaddr*, int,
                            void* artifact_type) {
  event_base* base = evconnlistener_get_base(listener);
  Crash* crash = new Crash();

  struct timeval timeout = { 1, 0 };
  event* crash_event = event_new(base, sockfd, EV_TIMEOUT | EV_READ, crash_request_cb, crash);
  crash->crash_fd.reset(sockfd);
  crash->crash_event = crash_event;
  crash->crash_type = reinterpret_cast<CrashType*>(artifact_type);
  event_add(crash_event, &timeout);
}

static void crash_request_cb(evutil_socket_t sockfd, short ev, void* arg) {
  ssize_t rc;
  Crash* crash = static_cast<Crash*>(arg);
  CrashType* type = crash->crash_type;

  TombstonedCrashPacket request = {};

  if ((ev & EV_TIMEOUT) != 0) {
    LOG(WARNING) << "crash request timed out";
    goto fail;
  } else if ((ev & EV_READ) == 0) {
    LOG(WARNING) << "tombstoned received unexpected event from crash socket";
    goto fail;
  }

  rc = TEMP_FAILURE_RETRY(read(sockfd, &request, sizeof(request)));
  if (rc == -1) {
    PLOG(WARNING) << "failed to read from crash socket";
    goto fail;
  } else if (rc != sizeof(request)) {
    LOG(WARNING) << "crash socket received short read of length " << rc << " (expected "
                 << sizeof(request) << ")";
    goto fail;
  }

  if (request.packet_type != CrashPacketType::kDumpRequest) {
    LOG(WARNING) << "unexpected crash packet type, expected kDumpRequest, received  "
                 << StringPrintf("%#2hhX", request.packet_type);
    goto fail;
  }

  crash->crash_pid = request.packet.dump_request.pid;
  LOG(INFO) << "received crash request for pid " << crash->crash_pid;

  if (type->num_concurrent_dumps == type->max_concurrent_dumps) {
    LOG(INFO) << "enqueueing crash request for pid " << crash->crash_pid;
    type->queued_requests.push_back(crash);
  } else {
    perform_request(crash);
  }

  return;

fail:
  delete crash;
}

static void crash_completed_cb(evutil_socket_t sockfd, short ev, void* arg) {
  ssize_t rc;
  Crash* crash = static_cast<Crash*>(arg);
  TombstonedCrashPacket request = {};

  --crash->crash_type->num_concurrent_dumps;

  if ((ev & EV_READ) == 0) {
    goto fail;
  }

  rc = TEMP_FAILURE_RETRY(read(sockfd, &request, sizeof(request)));
  if (rc == -1) {
    PLOG(WARNING) << "failed to read from crash socket";
    goto fail;
  } else if (rc != sizeof(request)) {
    LOG(WARNING) << "crash socket received short read of length " << rc << " (expected "
                 << sizeof(request) << ")";
    goto fail;
  }

  if (request.packet_type != CrashPacketType::kCompletedDump) {
    LOG(WARNING) << "unexpected crash packet type, expected kCompletedDump, received "
                 << uint32_t(request.packet_type);
    goto fail;
  }

fail:
  CrashType* type = crash->crash_type;
  delete crash;

  // If there's something queued up, let them proceed.
  dequeue_requests(type);
}

int main(int, char* []) {
  umask(0137);

  // Don't try to connect to ourselves if we crash.
  struct sigaction action = {};
  action.sa_handler = [](int signal) {
    LOG(ERROR) << "received fatal signal " << signal;
    _exit(1);
  };
  debuggerd_register_handlers(&action);

  if (CrashType::tombstone.dir_fd == -1) {
    PLOG(FATAL) << "failed to open tombstone directory";
  }

  // TODO: Figure out a good way to flag guard this.
  if (CrashType::java_trace.dir_fd == -1) {
    PLOG(WARNING) << "failed to open tombstone directory";
  }

  find_oldest_artifact(&CrashType::tombstone);
  find_oldest_artifact(&CrashType::java_trace);

  int intercept_socket = android_get_control_socket(kTombstonedInterceptSocketName);
  int crash_socket = android_get_control_socket(kTombstonedCrashSocketName);
  int java_trace_socket = android_get_control_socket(kTombstonedJavaTraceSocketName);

  if (intercept_socket == -1 || crash_socket == -1 || java_trace_socket == -1) {
    PLOG(FATAL) << "failed to get socket from init";
  }

  evutil_make_socket_nonblocking(intercept_socket);
  evutil_make_socket_nonblocking(crash_socket);
  evutil_make_socket_nonblocking(java_trace_socket);

  event_base* base = event_base_new();
  if (!base) {
    LOG(FATAL) << "failed to create event_base";
  }

  intercept_manager = new InterceptManager(base, intercept_socket);

  evconnlistener* tombstone_listener = evconnlistener_new(
      base, crash_accept_cb, &CrashType::tombstone, -1, LEV_OPT_CLOSE_ON_FREE, crash_socket);
  if (!tombstone_listener) {
    LOG(FATAL) << "failed to create evconnlistener for tombstones.";
  }

  evconnlistener* java_trace_listener = evconnlistener_new(
      base, crash_accept_cb, &CrashType::java_trace, -1, LEV_OPT_CLOSE_ON_FREE, java_trace_socket);
  if (!java_trace_listener) {
    LOG(FATAL) << "failed to create evconnlistener for java traces.";
  }

  LOG(INFO) << "tombstoned successfully initialized";
  event_base_dispatch(base);
}
