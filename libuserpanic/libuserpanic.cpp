/*
 * Copyright (C) 2021 The Android Open Source Project
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

#include <android/userpanic.h>

#include <sys/reboot.h>
#include <sys/syscall.h>

#include <android-base/file.h>
#include <android-base/logging.h>

#include <string>

static void write_to_file(const std::string& content, const std::string& path)
{
    if (!android::base::WriteStringToFile(content, path)) {
        PLOG(ERROR) << "Failed to write " << path;
    }
}

void android_panic_kernel(const char* title)
{
    std::string req_buf;
    struct __packed {
      char cmd;
      char version;
      uint32_t title_len;
    } req_header = {
      'c', 0, static_cast<uint32_t>(strlen(title))
    };

    req_buf.append(reinterpret_cast<char*>(&req_header), sizeof(req_header));
    req_buf.append(title);

    write_to_file(req_buf, "/dev/userspace_panic");
    write_to_file("c", "/proc/sysrq-trigger");
    /*
     * Successful writes should cause a reboot synchronously and never return.
     * But if it fails, returns to caller to handle the failure.
     */
}
