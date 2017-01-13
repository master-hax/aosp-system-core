/*
 * Copyright (C) 2017 The Android Open Source Project
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

#include <stdlib.h>
#include <sys/types.h>

#include <algorithm>
#include <chrono>

#include <android-base/logging.h>
#include <android-base/file.h>

#include "daemon/usb.h"

#include "bench_adb.h"

using android::base::ReadFully;
using android::base::WriteFully;
using namespace std::chrono_literals;

int adb_trace_mask = 0;

int main() {
    usb_handle handle;
    if (!init_functionfs(&handle)) {
        PLOG(FATAL) << "failed to initialize USB";
    }

    LOG(INFO) << "waiting for commands";

    // bulk_in/out are from the perspective of the host.
    int source = handle.bulk_out;
    int sink = handle.bulk_in;
    BenchmarkCommand cmd;
    Timer timer;
    while (true) {
        char buf[TRANSFER_LENGTH];
        if (!ReadFully(source, &cmd, sizeof(cmd))) {
            PLOG(FATAL) << "failed to read command";
        }

        switch (cmd) {
            case BenchmarkCommand::EXIT:
                LOG(INFO) << "commanded to exit";
                exit(0);

            case BenchmarkCommand::READ: {
                uint32_t length;
                if (!ReadFully(source, &length, sizeof(length))) {
                    PLOG(FATAL) << "failed to read length for read";
                }

                LOG(INFO) << "commanded to read " << length << " bytes";

                timer.start();
                size_t left = length;
                while (left > 0) {
                    size_t read_length = std::min(sizeof(buf), left);
                    if (!ReadFully(source, buf, read_length)) {
                        PLOG(FATAL) << "failed to read";
                    }
                    left -= read_length;
                }
                auto duration = timer.end();
                double seconds = duration / 1.0s;
                double mib_per_second = length / seconds / 1024 / 1024;

                LOG(INFO) << "read " << length << " bytes in " << (duration / 1.0s) << "s ("
                          << mib_per_second << " MiB/s)";
                break;
            }

            case BenchmarkCommand::WRITE: {
                uint32_t length;
                if (!ReadFully(source, &length, sizeof(length))) {
                    PLOG(FATAL) << "failed to read length for write";
                }

                LOG(INFO) << "commanded to write " << length << " bytes";

                memset(buf, 'x', sizeof(buf));
                timer.start();
                size_t left = length;
                while (left > 0) {
                    size_t write_length = std::min(sizeof(buf), left);
                    if (!WriteFully(sink, buf, write_length)) {
                        PLOG(FATAL) << "failed to write";
                    }
                    left -= write_length;
                }
                auto duration = timer.end();
                double seconds = duration / 1.0s;
                double mib_per_second = length / seconds / 1024 / 1024;

                LOG(INFO) << "wrote  " << length << " bytes in " << (duration / 1.0s) << "s ("
                          << mib_per_second << " MiB/s)";
                break;
            }
        }
    }
}
