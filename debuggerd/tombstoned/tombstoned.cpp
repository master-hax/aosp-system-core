#define LOG_TAG "tombstoned"

#include <stdio.h>
#include <sys/types.h>

#include <array>
#include <unordered_map>

#include <event2/event.h>
#include <event2/listener.h>
#include <event2/thread.h>

#include <android-base/logging.h>
#include <android-base/stringprintf.h>
#include <android-base/unique_fd.h>
#include <cutils/sockets.h>

#include "debuggerd/protocol.h"
#include "debuggerd/util.h"

#include "intercept_manager.h"

using android::base::StringPrintf;
using android::base::unique_fd;

static constexpr char tombstone_directory[] = "/data/local/tmp/tombstones/";

static InterceptManager* intercept_manager;

static int bind_reserved_socket(const char* name) {
  int sockfd = socket_local_server(name, ANDROID_SOCKET_NAMESPACE_RESERVED, SOCK_SEQPACKET);
  if (sockfd == -1) {
    PLOG(FATAL) << "failed to bind socket at " << name;
  }
  if (evutil_make_socket_nonblocking(sockfd) != 0) {
    PLOG(FATAL) << "failed to make socket nonblocking";
  }
  return sockfd;
}

struct Crash {
  ~Crash() {
    event_free(crash_event);
  }

  event* crash_event = nullptr;
  bool dump_started = false;
};

static void crash_request_cb(evutil_socket_t sockfd, short ev, void* arg) {
  ssize_t rc;
  Crash* crash = static_cast<Crash*>(arg);
  TombstonedCrashPacket request = {};
  TombstonedCrashPacket response = {};

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

  if (!crash->dump_started) {
    unique_fd output_fd;
    if (request.packet_type != CrashPacketType::kDumpRequest) {
      LOG(WARNING) << "unexpected crash packet type, expected kDumpRequest, received  "
                   << StringPrintf("%#2hhX", request.packet_type);
      goto fail;
    }

    LOG(INFO) << "received crash request for pid " << request.packet.dump_request.pid;

    // TODO: Actually create a file.
    output_fd.reset(dup(STDOUT_FILENO));
    response.packet_type = CrashPacketType::kPerformDump;

    // TODO: Implement queueing so that we have a limit on how many processes we dump at once.
    rc = send_fd(sockfd, &response, sizeof(response), std::move(output_fd));
    if (rc == -1) {
      PLOG(WARNING) << "failed to send response to CrashRequest";
      goto fail;
    } else if (rc != sizeof(response)) {
      PLOG(WARNING) << "crash socket write returned short";
      goto fail;
    }

    crash->dump_started = true;
  } else {
    if (request.packet_type != CrashPacketType::kCompletedDump) {
      LOG(WARNING) << "unexpected crash packet type, expected kCompletedDump, received  "
                   << StringPrintf("%#2hhX", request.packet_type);
      goto fail;
    }

    // TODO: Rename the file we created to the right spot.
    goto fail;
  }

  return;

fail:
  close(sockfd);
  delete crash;
}

static void crash_accept_cb(evconnlistener* listener, evutil_socket_t sockfd, sockaddr*, int,
                            void*) {
  event_base* base = evconnlistener_get_base(listener);
  Crash* crash = new Crash();

  struct timeval timeout = { 10, 0 };
  event* crash_event =
    event_new(base, sockfd, EV_TIMEOUT | EV_READ | EV_PERSIST, crash_request_cb, crash);
  crash->crash_event = crash_event;
  event_add(crash_event, &timeout);
}

int main(int, char*[]) {
  int intercept_socket = bind_reserved_socket(kTombstonedInterceptSocketName);
  int crash_socket = bind_reserved_socket(kTombstonedCrashSocketName);

  event_base* base = event_base_new();
  if (!base) {
    LOG(FATAL) << "failed to create event_base";
  }

  intercept_manager = new InterceptManager(base, intercept_socket);

  evconnlistener* listener =
    evconnlistener_new(base, crash_accept_cb, nullptr, -1, LEV_OPT_CLOSE_ON_FREE, crash_socket);
  if (!listener) {
    LOG(FATAL) << "failed to create evconnlistener";
  }

  LOG(INFO) << "tombstoned successfully initialized";
  event_base_dispatch(base);
}
