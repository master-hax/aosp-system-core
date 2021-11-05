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

#include <android-base/file.h>
#include <android-base/properties.h>
#include <gtest/gtest.h>
#include <log/log.h>
#include <sys/mman.h>

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string>

TEST(drop_caches, set_perf_property) {
    size_t filesize = 32000000;
    size_t chunksize = 64000;
    char buf[chunksize];

    android::base::unique_fd fd(open("/data/local/tmp/garbage.data", O_CREAT | O_RDWR, 0666));
    ASSERT_NE(-1, fd);
    for (uint chunk = 0; chunk < filesize / chunksize; chunk++) {
        for (uint c = 0; c < chunksize; c++) {
            buf[c] = (random() % 26) + 'A';
        }
        write(fd, buf, chunksize);
    }
    lseek(fd, 0, SEEK_SET);
    ASSERT_NE(-1, fdatasync(fd.get()));

    // Read the 32MB file in 64K chunks, 3x.
    for (uint times = 3; times > 0; times--) {
        ssize_t n;
        unsigned int counter = 0;
        while ((n = read(fd.get(), buf, sizeof(buf))) > 0) {
            counter++;
        }
        ALOGI("Loops to read file: %u", counter);
        lseek(fd, 0, SEEK_SET);
    }

    void* ptr = mmap(nullptr, filesize, PROT_READ, MAP_PRIVATE, fd, 0);

    struct rusage usage_before_minor, usage_after_minor;
    getrusage(RUSAGE_SELF, &usage_before_minor);

    for (unsigned int i = 0; i < filesize / 4096; i++) {
        volatile int tmp = *((char*)ptr + (i * 4096));
        (void)tmp;  // Bypass the unused error.
    }
    getrusage(RUSAGE_SELF, &usage_after_minor);

    ALOGI("Minor faults before: %ld", usage_before_minor.ru_minflt);
    ALOGI("Minor faults after: %ld", usage_after_minor.ru_minflt);
    ALOGI("Minor faults diff: %ld", usage_after_minor.ru_minflt - usage_before_minor.ru_minflt);
    ALOGI("Major faults before: %ld", usage_before_minor.ru_majflt);
    ALOGI("Major faults after: %ld", usage_after_minor.ru_majflt);
    ALOGI("Major faults diff: %ld", usage_after_minor.ru_majflt - usage_before_minor.ru_majflt);

    munmap(ptr, filesize);

    android::base::SetProperty("perf.drop_caches", "3");
    usleep(1000000);
    ASSERT_EQ("0", android::base::GetProperty("perf.drop_caches", "-1"));

    ptr = mmap(nullptr, filesize, PROT_READ, MAP_PRIVATE, fd, 0);

    struct rusage usage_before_major, usage_after_major;
    getrusage(RUSAGE_SELF, &usage_before_major);

    for (unsigned int i = 0; i < filesize / 4096; i++) {
        volatile int tmp = *((char*)ptr + (i * 4096));
        (void)tmp;  // Bypass the unused error.
    }
    getrusage(RUSAGE_SELF, &usage_after_major);

    ALOGI("(dropped) Minor faults before: %ld", usage_before_major.ru_minflt);
    ALOGI("(dropped) Minor faults after: %ld", usage_after_major.ru_minflt);
    ALOGI("(dropped) Minor faults diff: %ld",
          usage_after_major.ru_minflt - usage_before_major.ru_minflt);
    ALOGI("(dropped) Major faults before: %ld", usage_before_major.ru_majflt);
    ALOGI("(dropped) Major faults after: %ld", usage_after_major.ru_majflt);
    ALOGI("(dropped) Major faults diff: %ld",
          usage_after_major.ru_majflt - usage_before_major.ru_majflt);
}
