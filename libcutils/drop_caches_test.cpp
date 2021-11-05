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
    // Create a 32 MiB file.
    size_t filesize = 33554432;
    // Write 4 KiB sparsely.
    size_t chunksize = 4096;
    char buf[chunksize];
    // Write every 2 MiB.
    size_t blocksize = 2097152;

    // We write in sparse blocks to avoid large, pre-allocated pages from fault_around_bytes.
    ALOGI("Allocating %d byte file with %d chunks every %d bytes.", filesize, chunksize, blocksize);

    android::base::unique_fd fd(open("/data/local/tmp/garbage.data", O_CREAT | O_RDWR, 0666));
    ASSERT_NE(-1, fd);

    for (unsigned int chunk = 0; chunk < filesize / blocksize; chunk++) {
        for (unsigned int c = 0; c < chunksize; c++) {
            buf[c] = (random() % 26) + 'A';
        }
        write(fd, buf, chunksize);
        lseek(fd, chunk * blocksize, SEEK_SET);
    }
    lseek(fd, 0, SEEK_SET);
    ASSERT_NE(-1, fdatasync(fd.get()));

    // Read the file in smaller chunks, 3x.
    for (unsigned int times = 3; times > 0; times--) {
        ssize_t n;
        unsigned int counter = 0;
        while ((n = read(fd.get(), buf, sizeof(buf))) > 0) {
            counter++;
        }
        lseek(fd, 0, SEEK_SET);
    }

    // Read a few bytes from every block while the data is cached.

    void* ptr = mmap(NULL, filesize, PROT_READ, MAP_PRIVATE, fd.get(), 0);
    madvise(ptr, filesize, MADV_RANDOM);

    struct rusage usage_before_minor, usage_after_minor;
    getrusage(RUSAGE_SELF, &usage_before_minor);

    // Why do I need to do -1 here? Is my math off somewhere?
    for (unsigned int i = 0; i < filesize / blocksize - 1; i++) {
        volatile int tmp = *((char*)ptr + (i * blocksize));
        (void)tmp;  // Bypass the unused error.
    }
    getrusage(RUSAGE_SELF, &usage_after_minor);

    ASSERT_NE(-1, munmap(ptr, filesize));

    // TODO: Document what happens below.

    android::base::SetProperty("perf.drop_caches", "3");
    sleep(1);
    ASSERT_EQ("0", android::base::GetProperty("perf.drop_caches", "-1"));

    // Read a few bytes from every block after the cached is cleared.

    ptr = mmap(NULL, filesize, PROT_READ, MAP_PRIVATE, fd.get(), 0);
    madvise(ptr, filesize, MADV_RANDOM);

    struct rusage usage_before_major, usage_after_major;
    getrusage(RUSAGE_SELF, &usage_before_major);

    for (unsigned int i = 0; i < filesize / blocksize - 1; i++) {
        volatile int tmp = *((char*)ptr + (i * blocksize));
        (void)tmp;  // Bypass the unused error.
    }
    getrusage(RUSAGE_SELF, &usage_after_major);

    long with_cache_minor_faults = usage_after_minor.ru_minflt - usage_before_minor.ru_minflt;
    ALOGI("(before) Minor faults diff: %ld", with_cache_minor_faults);
    ALOGI("(before) Major faults diff: %ld",
          usage_after_minor.ru_majflt - usage_before_minor.ru_majflt);
    long without_cache_major_faults = usage_after_major.ru_majflt - usage_before_major.ru_majflt;
    ALOGI("(dropped) Minor faults diff: %ld",
          usage_after_major.ru_minflt - usage_before_major.ru_minflt);
    ALOGI("(dropped) Major faults diff: %ld", without_cache_major_faults);

    bool failure = abs(with_cache_minor_faults - without_cache_major_faults) > 5;
    ASSERT_EQ(failure, false) << "The difference between minor and major faults was too large.";
}
