/*
 * Copyright (C) 2020 The Android Open Source Project
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

#include <libdm/dm.h>

using namespace android::dm;

static int daemon_main(void) {
    int fd = open("/dev/dm-user", O_RDWR);
    if (!fd) {
        perror("Unable to open /dev/dm-user");
        return 1;
    }

    /* Just keeps pumping messages between userspace and the kernel.  We won't
     * actually be doing anything, but the sequence numbers line up so it'll at
     * least make forward progress. */
    while (true) {
        unsigned long buf[1 << 16];

        for (size_t i = 0; i < 1024; ++i) buf[i] = -1UL;

        ssize_t readed = read(fd, &buf, sizeof(buf));
        if (readed < 0) {
            perror("Control read failed");
            return 2;
        }

        printf("read() from dm-user returned %d bytes:\n", readed);
        for (size_t i = 0; i < 4; ++i) printf("%d: 0x%016lu\n", i, buf[i]);
        printf("...\n");

        for (size_t i = 4; i < 1 << 16; ++i) buf[i] = i;

        ssize_t written = write(fd, &buf, sizeof(buf));
        if (written < 0) {
            perror("Control write failed");
            return 3;
        }
    }

    return 0;
}

int main() {
    /* Creates a new block device by just running dmctl, so I don't have to...
     * :) */
    system("dmctl create palmer user 0 1000000");

    /* Backgrounds the daemon.. */
    if (fork() == 0) return daemon_main();

    /* Reads a single */
    int fd = open("/dev/block/mapper/palmer", O_RDWR);
    if (fd < 0) {
        perror("Unable to open block device");
        return 1;
    }

    char buf[4096];
    ssize_t readed = read(fd, &buf[0], 4096);
    if (readed < 0) {
        perror("Unable to read from block device");
        return 2;
    }

    for (ssize_t i = 0; i < readed; ++i) printf("read(): palmer[%d] == 0x%02x\n", i, buf[i]);
    return 0;
}
