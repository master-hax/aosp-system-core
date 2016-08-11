#include "intercept_manager.h"

#include <inttypes.h>
#include <sys/types.h>

#include <unordered_map>

#include <event2/event.h>
#include <event2/listener.h>

#include <android-base/logging.h>
#include <android-base/unique_fd.h>
#include <cutils/sockets.h>

#include "debuggerd/protocol.h"
#include "debuggerd/util.h"

using android::base::unique_fd;

static void intercept_close_cb(evutil_socket_t sockfd, short /* ev */, void* arg) {
  auto intercept = reinterpret_cast<Intercept*>(arg);
  InterceptManager* intercept_manager = intercept->intercept_manager;

  // If we can read, either we received unexpected data from the other side, or the other side
  // closed their end of the socket. Either way, kill the intercept.
  close(sockfd);

  // Ownership of intercept differs based on whether we've registered it with InterceptManager.
  if (!intercept->registered) {
    delete intercept;
  } else {
    auto it = intercept_manager->intercepts.find(intercept->intercept_pid);
    if (it == intercept_manager->intercepts.end()) {
      LOG(FATAL) << "intercept close callback called after intercept was already removed?";
    }
    if (it->second.get() != intercept) {
      LOG(FATAL) << "intercept close callback has different Intercept from InterceptManager?";
    }
    intercept_manager->intercepts.erase(it);
  }
}

static void intercept_request_cb(evutil_socket_t sockfd, short ev, void* arg) {
  auto intercept = reinterpret_cast<Intercept*>(arg);
  InterceptManager* intercept_manager = intercept->intercept_manager;

  if ((ev & EV_TIMEOUT) != 0) {
    LOG(WARNING) << "tombstoned didn't receive InterceptRequest before timeout";
    goto fail;
  } else if ((ev & EV_READ) == 0) {
    LOG(WARNING) << "tombstoned received unexpected event on intercept socket";
    goto fail;
  }

  {
    unique_fd rcv_fd;
    InterceptRequest intercept_request;
    ssize_t result = recv_fd(sockfd, &intercept_request, sizeof(intercept_request), &rcv_fd);

    if (result == -1) {
      PLOG(WARNING) << "failed to read from intercept socket";
      goto fail;
    } else if (result != sizeof(intercept_request)) {
      LOG(WARNING) << "intercept socket received short read of length " << result << " (expected "
                   << sizeof(intercept_request) << ")";
      goto fail;
    }

    // We trust the other side, so only do minimal validity checking.
    if (intercept_request.pid <= 0 || intercept_request.pid > std::numeric_limits<pid_t>::max()) {
      InterceptResponse response = {};
      snprintf(response.error_message, sizeof(response.error_message), "invalid pid %" PRId32,
               intercept_request.pid);
      TEMP_FAILURE_RETRY(write(sockfd, &response, sizeof(response)));
      goto fail;
    }

    intercept->intercept_pid = intercept_request.pid;

    // Register the intercept with the InterceptManager.
    if (intercept_manager->intercepts.count(intercept_request.pid) > 0) {
      InterceptResponse response = {};
      snprintf(response.error_message, sizeof(response.error_message),
               "pid %" PRId32 " already intercepted", intercept_request.pid);
      TEMP_FAILURE_RETRY(write(sockfd, &response, sizeof(response)));
      goto fail;
    }

    intercept_manager->intercepts[intercept_request.pid] = std::unique_ptr<Intercept>(intercept);
    intercept->registered = true;

    // Register a different read event on the socket so that we can remove intercepts if the socket
    // closes (e.g. if a user CTRL-C's the process that requested the intercept).
    event_assign(intercept->intercept_event, intercept_manager->base, sockfd, EV_READ,
                 intercept_close_cb, arg);
    event_add(intercept->intercept_event, nullptr);
  }

  return;

fail:
  close(sockfd);
  delete intercept;
}

static void intercept_accept_cb(evconnlistener* listener, evutil_socket_t sockfd, sockaddr*, int,
                                void* arg) {
  Intercept* intercept = new Intercept();
  intercept->intercept_manager = static_cast<InterceptManager*>(arg);
  intercept->sockfd = sockfd;

  struct timeval timeout = { 1, 0 };
  event_base* base = evconnlistener_get_base(listener);
  event* intercept_event =
    event_new(base, sockfd, EV_TIMEOUT | EV_READ, intercept_request_cb, intercept);
  intercept->intercept_event = intercept_event;
  event_add(intercept_event, &timeout);
}

InterceptManager::InterceptManager(event_base* base, int intercept_socket) : base(base) {
  this->listener = evconnlistener_new(base, intercept_accept_cb, this, -1, LEV_OPT_CLOSE_ON_FREE,
                                      intercept_socket);
}

bool InterceptManager::GetIntercept(pid_t pid, android::base::unique_fd* out_fd) {
  auto it = this->intercepts.find(pid);
  if (it == this->intercepts.end()) {
    return false;
  }

  auto intercept = std::move(it->second);
  this->intercepts.erase(it);

  InterceptResponse response = {};
  response.success = 1;
  TEMP_FAILURE_RETRY(write(intercept->sockfd, &response, sizeof(response)));
  *out_fd = std::move(intercept->output_fd);

  return true;
}
