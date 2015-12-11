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

// Make a connection to the Trusty NVRAM app.
bool Connect();

// Send a command to the Trusty NVRAM app.
bool ExecuteRequest(const nvram::Request& request, nvram::Response* response);

// Break the connection the Trusty NVRAM app.
bool Disconnect();

}  // namespace nvram

#endif  // NVRAM_IPC_H_
