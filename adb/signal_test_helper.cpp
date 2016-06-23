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

#include <err.h>
#include <fcntl.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <string>

static int output_fd = STDOUT_FILENO;
void handler(int signal) {
    std::string signal_number = std::to_string(signal) + "\n";
    if (write(output_fd, signal_number.c_str(), signal_number.length()) < 0) {
        err(1, "failed to write");
    }
    exit(0);
}

int main(int argc, char* argv[]) {
    if (argc == 2) {
        output_fd = open(argv[1], O_WRONLY | O_CREAT | O_TRUNC, 0700);
        if (output_fd < 0) {
            err(1, "failed to open output path '%s'", argv[1]);
        }
    }

    signal(SIGHUP, handler);
    signal(SIGINT, handler);
    while (true) {
        sleep(1);
    }
}
