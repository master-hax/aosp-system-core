/*
 * Copyright (C) 2018-2020 The Android Open Source Project
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

#include "f2fs_pin/pin.h"
#include "pin_impl.h"
#include "pin_misc.h"

#include <errno.h>
#include <linux/fiemap.h>
#include <linux/fs.h>
#include <linux/magic.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <sys/fcntl.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/types.h>
#include <sys/vfs.h>
#include <time.h>
#include <unistd.h>
#include <cstdint>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

bool CommandEnsure(const char* cmd, const char* bdev, const char* file, bool verify_file) {
    bool result = EnsurePinned(bdev, file, verify_file);
    if (!result) std::cerr << cmd << ": EnsurePinned() failed\n";
    return result;
}

bool CommandCreate(const char* cmd, const char* bdev, const char* file, off_t file_size,
                   bool init_file) {
    bool result = CreatePinned(bdev, file, file_size, init_file);
    if (!result) std::cerr << cmd << ": CreatePinned() failed\n";
    return result;
}

bool CommandSupport(const char* cmd, const char* bdev) {
    std::string bdev_string(bdev);
    auto result = android::f2fs_pin::BdevFileSystemSupportsReliablePinning(bdev_string);
    if (!result) {
        PrintErrorResult("reliable pinning not supported", result);
        std::cerr << cmd << ": BdevFileSystemSupportsReliablePinning() failed\n";
        return false;
    }
    return true;
}

bool StrToSize(const char* sizestr, off_t* size) {
    char* endptr = nullptr;
    errno = 0;  // to use strtoull(3) errno has to be cleared first
    unsigned long long llsz = strtoull(sizestr, &endptr, 0);

    if (errno || endptr == sizestr || !endptr || llsz > INT64_MAX) return false;

    if (*endptr) {
        if (endptr[1]) return false;
        unsigned int shift;
        switch (*endptr) {
            default:
                return false;
            case 'k':
                shift = 10;
                break;
            case 'm':
                shift = 20;
                break;
            case 'g':
                shift = 30;
                break;
            case 't':
                shift = 40;
                break;
        }
        if (llsz > (INT64_MAX >> shift)) return false;
        llsz <<= shift;
    }

    *size = off_t(llsz);
    return true;
}

void UsageAndExit(const char* cmd) {
    std::cerr << "\n"
                 "usage: "
              << cmd
              << " --create bdev file size\n"
                 "usage: "
              << cmd
              << " --create-init bdev file size\n"
                 "usage: "
              << cmd
              << " --ensure bdev file\n"
                 "usage: "
              << cmd
              << " --verify bdev file\n"
                 "usage: "
              << cmd
              << " --support bdev\n"
                 "\n"
                 "  --create bdev file size\n"
                 "\n"
                 "    Create file of size bytes, size must be a multiple of 2MB, and pin it.\n"
                 "\n"
                 "    The size in decimal, hex or octal; units of k, m and g (KiB, MiB,\n"
                 "    and GiB respectively) can be appended to it, e.g.: 64m, 0x1000, 0177k.\n"
                 "\n"
                 "  --create-init bdev file size\n"
                 "\n"
                 "    Same as --create, also initialize file to a pattern for validation and\n"
                 "    validate its extent map and contents through bdev.\n"
                 "\n"
                 "  --ensure bdev file\n"
                 "\n"
                 "    If file is not reliably pinned produce an error.\n"
                 "\n"
                 "  --verify bdev file\n"
                 "\n"
                 "    Same as --ensure, also verify data of file initialized with --create-init\n"
                 "\n"
                 "  --support bdev\n"
                 "\n"
                 "    Determine if bdev supports reliable pinning\n"
                 "\n";

    exit(1);
}

char* CommandName(char* c) {
    char* p = strrchr(c, '/');
    return p ? p + 1 : c;
}

int main(int argc, char* argv[]) {
    const char* cmd = CommandName(argv[0]);
    bool success = false;

    if (argc == 5) {
        bool init_file = false;
        if (strcmp(argv[1], "--create") == 0)
            init_file = false;
        else if (strcmp(argv[1], "--create-init") == 0)
            init_file = true;
        else
            UsageAndExit(cmd);
        off_t file_size = 0;
        if (!StrToSize(argv[4], &file_size)) {
            PrintError("invalid file size value", argv[4]);
            UsageAndExit(cmd);
        }
        success = CommandCreate(cmd, argv[2], argv[3], file_size, init_file);
    } else if (argc == 4) {
        bool verify_file = false;
        if (strcmp(argv[1], "--ensure") == 0)
            verify_file = false;
        else if (strcmp(argv[1], "--verify") == 0)
            verify_file = true;
        else
            UsageAndExit(cmd);
        success = CommandEnsure(cmd, argv[2], argv[3], verify_file);
    } else if (argc == 3) {
        if (strcmp(argv[1], "--support") == 0) {
            success = CommandSupport(cmd, argv[2]);
        } else {
            UsageAndExit(cmd);
        }
    } else {
        UsageAndExit(cmd);
    }
    if (!success) exit(1);
    exit(0);
}
