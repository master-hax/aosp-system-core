/*
 * Copyright (C) 2013 The Android Open Source Project
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *  * Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *  * Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
 * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
 * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sys/time.h>

#include <algorithm>
#include <vector>

#if !defined(_WIN32)
#include <liblp/liblp.h>
#endif

#include "util.h"

static bool g_verbose = false;

double now() {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (double)tv.tv_sec + (double)tv.tv_usec / 1000000;
}

void die(const char* fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    fprintf(stderr, "fastboot: error: ");
    vfprintf(stderr, fmt, ap);
    fprintf(stderr, "\n");
    va_end(ap);
    exit(EXIT_FAILURE);
}

void set_verbose() {
    g_verbose = true;
}

void verbose(const char* fmt, ...) {
    if (!g_verbose) return;

    if (*fmt != '\n') {
        va_list ap;
        va_start(ap, fmt);
        fprintf(stderr, "fastboot: verbose: ");
        vfprintf(stderr, fmt, ap);
        va_end(ap);
    }
    fprintf(stderr, "\n");
}

std::vector<std::string> GetDynamicPartitionNames(const std::string& super_image) {
#if !defined(_WIN32)
    auto metadata = android::fs_mgr::ReadFromImageFile(super_image);
    if (!metadata) {
        return {};
    }
    std::vector<std::string> partition_names;
    for (const auto& partition : metadata->partitions) {
        auto partition_name = android::fs_mgr::GetPartitionName(partition);
        if (partition.attributes & LP_PARTITION_ATTR_SLOT_SUFFIXED) {
            // On retrofit devices, we don't know if, or whether, the A or B
            // slot has been flashed for dynamic partitions. Instead we add
            // both names to the list as a conservative guess.
            partition_names.emplace_back(partition_name + "_a");
            partition_names.emplace_back(partition_name + "_b");
        } else {
            partition_names.emplace_back(partition_name);
        }
    }
    return partition_names;
#else
    (void)super_image;
    return {};
#endif
}

bool IsPartitionInSuperImage(const std::string& super_image, const std::string& partition_name) {
    auto partition_names = GetDynamicPartitionNames(super_image);
    return std::find(partition_names.begin(), partition_names.end(), partition_name) !=
           partition_names.end();
}
