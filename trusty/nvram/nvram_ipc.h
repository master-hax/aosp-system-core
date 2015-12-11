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

#ifndef NVRAM_IPC_H_
#define NVRAM_IPC_H_

#include <nvram/nvram_messages.h>

namespace nvram {

// A simple RAII wrapper for interacting with the Trusty NVRAM app.
class TrustyNvramProxy {
 public:
  TrustyNvramProxy() = default;
  ~TrustyNvramProxy();

  // Encodes |request|, sends it to the Trusty NVRAM app, and decodes the
  // response into |response|. Returns true if I/O was successful (but note
  // that |response| may still indicate an NVRAM error), false if there are any
  // encoding/decoding or communication errors.
  bool Execute(const nvram::Request& request, nvram::Response* response);

 private:
  // Connects the IPC channel to the Trusty app if it is not already open.
  // Returns true if the channel is open, false on errors.
  bool Connect();

  // The file descriptor for the IPC connection to the Trusty app.
  int tipc_nvram_fd_ = -1;
};

}  // namespace nvram

#endif  // NVRAM_IPC_H_
