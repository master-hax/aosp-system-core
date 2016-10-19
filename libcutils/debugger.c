/*
 * Copyright (C) 2012 The Android Open Source Project
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

#include <cutils/debugger.h>

#include <debuggerd/client.h>

int dump_backtrace_to_file(pid_t tid, int fd) {
  return debuggerd_trigger_dump(tid, fd, kDebuggerdBacktrace) ? 0 : -1;
}

int dump_backtrace_to_file_timeout(pid_t tid, int fd, int timeout_secs) {
  // TODO: Actually timeout.
  (void)timeout_secs;
  return dump_backtrace_to_file(tid, fd);
}
