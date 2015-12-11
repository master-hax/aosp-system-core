/*
 * Copyright (C) 2016 The Android Open Source Project
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

#include "nvram_ipc.h"

#include <string.h>
#include <unistd.h>

#define LOG_TAG "TrustyNvramProxy"
#include <log/log.h>
#include <trusty/tipc.h>

namespace nvram {
namespace {

// Response buffer size. This puts a size limit for the maximum size of
// responses from the Trusty app. Larger responses will be truncated and fail to
// decode subsequently.
const size_t kResponseBufferSize = 4096;

// Character device to open for Trusty IPC connections.
const char kTrustyDeviceName[] = "/dev/trusty-ipc-dev0";

// App identifier of the NVRAM app.
const char kTrustyNvramAppId[] = "com.android.trusty.nvram";

}  // namespace

TrustyNvramProxy::~TrustyNvramProxy() {
  if (tipc_nvram_fd_ != -1) {
    tipc_close(tipc_nvram_fd_);
    tipc_nvram_fd_ = -1;
  }
}

bool TrustyNvramProxy::Execute(const Request& request, Response* response) {
  if (!Connect()) {
    return false;
  }

  Blob request_buffer;
  if (!Encode(request, &request_buffer)) {
    ALOGE("Failed to encode NVRAM request.\n");
    return false;
  }

  ssize_t rc =
      write(tipc_nvram_fd_, request_buffer.data(), request_buffer.size());
  if (rc < 0) {
    ALOGE("Failed to send NVRAM request: %s\n", strerror(-rc));
    return false;
  }
  if (static_cast<size_t>(rc) != request_buffer.size()) {
    ALOGE("Failed to send full request buffer: %zd\n", rc);
    return false;
  }

  Blob response_buffer;
  if (!response_buffer.Resize(kResponseBufferSize)) {
    ALOGE("Failed to allocate response buffer\n.");
    return false;
  }

  rc = read(tipc_nvram_fd_, response_buffer.data(), response_buffer.size());
  if (rc < 0) {
    ALOGE("Failed to read NVRAM response: %s\n", strerror(-rc));
    return false;
  }

  if (static_cast<size_t>(rc) >= response_buffer.size()) {
    ALOGE("NVRAM response exceeds response buffer size.\n");
    return false;
  }

  if (!Decode(response_buffer.data(), static_cast<size_t>(rc), response)) {
    ALOGE("Failed to decode NVRAM response.\n");
    return false;
  }

  return true;
}

bool TrustyNvramProxy::Connect() {
  if (tipc_nvram_fd_ != -1) {
    return true;
  }

  int rc = tipc_connect(kTrustyDeviceName, kTrustyNvramAppId);
  if (rc < 0) {
    ALOGE("Failed to connect to Trusty NVRAM app: %s\n", strerror(-rc));
    return false;
  }

  tipc_nvram_fd_ = rc;
  return true;
}

}  // namespace nvram
