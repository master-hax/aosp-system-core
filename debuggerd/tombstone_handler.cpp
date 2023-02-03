/*
 * Copyright 2023, The Android Open Source Project
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

#include "tombstoned/tombstoned.h"

#include <unistd.h>

#include <android-base/logging.h>
#include <android-base/properties.h>
#include <android-base/unique_fd.h>
#include <cutils/sockets.h>
#include <linux/vm_sockets.h>
#include "util.h"

using android::base::unique_fd;

bool IsMicrodroid() {
  static bool is_microdroid = android::base::GetProperty("ro.hardware", "") == "microdroid";
  return is_microdroid;
}

bool connect_tombstone_server_microdroid(unique_fd* text_output_fd, unique_fd* proto_output_fd,
                                         DebuggerdDumpType dump_type) {
  // We do not wait for the property to be set, the default behaviour is not export tombstones.
  if (!android::base::GetBoolProperty("export_tombstones.enabled", false)) {
    LOG(FATAL) << "exporting tombstones is not enabled";
    return false;
  }

  // Microdroid supports handling requests originating from crash_dump which
  // supports limited dump types. Java traces and incept management are not supported.
  switch (dump_type) {
    case kDebuggerdNativeBacktrace:
    case kDebuggerdTombstone:
    case kDebuggerdTombstoneProto:
      break;

    default:
      LOG(FATAL) << "invalid requested dump type: " << dump_type;
  }

  unique_fd vsock_output_fd(TEMP_FAILURE_RETRY(socket(AF_VSOCK, SOCK_STREAM, 0)));
  unique_fd vsock_proto_fd(TEMP_FAILURE_RETRY(socket(AF_VSOCK, SOCK_STREAM, 0)));
  struct sockaddr_vm sa = (struct sockaddr_vm){
      .svm_family = AF_VSOCK,
      .svm_port = 2000,
      .svm_cid = 2,
  };

  TEMP_FAILURE_RETRY(connect(vsock_output_fd, (struct sockaddr*)&sa, sizeof(sa)));
  if (dump_type == kDebuggerdTombstoneProto) {
    TEMP_FAILURE_RETRY(connect(vsock_proto_fd, (struct sockaddr*)&sa, sizeof(sa)));
  }

  *text_output_fd = std::move(vsock_output_fd);
  if (proto_output_fd) {
    *proto_output_fd = std::move(vsock_proto_fd);
  }
  return true;
}

bool notify_completion_microdroid(int vsock_out, int vsock_proto) {
  if (shutdown(vsock_out, SHUT_WR) || shutdown(vsock_proto, SHUT_WR)) return false;
  return true;
}

bool connect_tombstone_server(pid_t pid, unique_fd* tombstoned_socket, unique_fd* text_output_fd,
                              DebuggerdDumpType dump_type) {
  if (IsMicrodroid()) {
    return connect_tombstone_server_microdroid(text_output_fd, nullptr, dump_type);
  }
  return tombstoned_connect(pid, tombstoned_socket, text_output_fd, dump_type);
}

bool connect_tombstone_server(pid_t pid, unique_fd* tombstoned_socket, unique_fd* text_output_fd,
                              unique_fd* proto_output_fd, DebuggerdDumpType dump_type) {
  if (IsMicrodroid()) {
    return connect_tombstone_server_microdroid(text_output_fd, proto_output_fd, dump_type);
  }
  return tombstoned_connect(pid, tombstoned_socket, text_output_fd, proto_output_fd, dump_type);
}

bool notify_completion(int tombstoned_socket, int vsock_out, int vsock_proto) {
  if (IsMicrodroid()) {
    return notify_completion_microdroid(vsock_out, vsock_proto);
  }
  return tombstoned_notify_completion(tombstoned_socket);
}
