#pragma once

#include <sys/types.h>

#include <unordered_map>

#include <event2/event.h>
#include <event2/listener.h>

#include <android-base/unique_fd.h>

struct InterceptManager;

struct Intercept {
  ~Intercept() {
    event_free(intercept_event);
  }

  InterceptManager* intercept_manager = nullptr;
  event* intercept_event = nullptr;
  android::base::unique_fd sockfd;

  pid_t intercept_pid = -1;
  android::base::unique_fd output_fd;
  bool registered = false;
};

struct InterceptManager {
  event_base* base;
  std::unordered_map<pid_t, std::unique_ptr<Intercept>> intercepts;
  evconnlistener* listener = nullptr;

  InterceptManager(event_base* _Nonnull base, int intercept_socket);
  InterceptManager(InterceptManager& copy) = delete;
  InterceptManager(InterceptManager&& move) = delete;

  bool GetIntercept(pid_t pid, android::base::unique_fd* out_fd);
};
