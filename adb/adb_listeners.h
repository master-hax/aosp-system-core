/*
 * Copyright (C) 2015 The Android Open Source Project
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

#ifndef __ADB_LISTENERS_H
#define __ADB_LISTENERS_H

#include "adb.h"

#include <string>

#include <android-base/macros.h>

// error/status codes for install_listener.
enum InstallStatus {
  INSTALL_STATUS_OK = 0,
  INSTALL_STATUS_INTERNAL_ERROR = -1,
  INSTALL_STATUS_CANNOT_BIND = -2,
  INSTALL_STATUS_CANNOT_REBIND = -3,
  INSTALL_STATUS_LISTENER_NOT_FOUND = -4,
};

InstallStatus install_listener(const std::string& local_name, const char* connect_to,
                               atransport* transport, int no_rebind, int* resolved_tcp_port,
                               std::string* error);

std::string format_listeners();

InstallStatus remove_listener(const char* local_name, atransport* transport);
void remove_all_listeners(void);

// Internal functions are only exposed here for testing purposes.
namespace internal {

// A listener is an entity which binds to a local port and, upon receiving a connection on that
// port, creates an asocket to connect the new local connection to a specific remote service.
//
// TODO: some listeners read from the new connection to determine what exact service to connect to
// on the far side.
class alistener {
  public:
    alistener(const std::string& _local_name, const std::string& _connect_to)
        : local_name(_local_name), connect_to(_connect_to) {
    }

    fdevent fde;
    int fd = -1;

    std::string local_name;
    std::string connect_to;
    atransport* transport = nullptr;
    adisconnect disconnect;

  private:
    DISALLOW_COPY_AND_ASSIGN(alistener);
};

int local_name_to_fd(alistener* listener, int* resolved_tcp_port, std::string* error);

}  // namespace internal

#endif /* __ADB_LISTENERS_H */
