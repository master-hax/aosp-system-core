/*
 * Copyright (C) 2019 The Android Open Source Project
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

#include <errno.h>
#include <stdlib.h>
#include <unistd.h>

#include <string>
#include <vector>

// General trampoline from executable to shell script
int main(int argc, char* argv[]) {
    const auto outdir = getenv("ANDROID_HOST_OUT") ?: "out/host/linux-x86";
    const auto serial = getenv("ANDROID_SERIAL");

    std::string host_cmd("-");
    host_cmd += argv[0];

    std::string shell_cmd(outdir);
    shell_cmd += "/bin/adb-remount-test.sh";
    if (serial) {
        shell_cmd += " --serial ";
        shell_cmd += serial;
    }
    shell_cmd += " --no-color";
    for (int i = 1; i < argc; ++i) {
        shell_cmd += " ";
        shell_cmd += argv[i];
    }

    std::vector<const char*> av;
    av.push_back(host_cmd.c_str());
    av.push_back("-c");
    av.push_back(shell_cmd.c_str());
    av.push_back(nullptr);
    return execv("/bin/sh", const_cast<char* const*>(av.data()));
}
