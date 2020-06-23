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

#include <linux/types.h>

#define DM_USER_MAP_READ 0
#define DM_USER_MAP_WRITE 1

#define DEBUG 0

struct dm_user_message {
    __u64 seq;
    __u64 type;
    __u64 flags;
    __u64 sector;
    __u64 len;
    __u8 buf[];
};

using namespace android::dm;

static int daemon_main(void) {
    int block_fd = open("/dev/block/mapper/system_a", O_RDWR);
    if (!block_fd) {
        perror("Unable to open /dev/block/mapper/system_a");
        return 1;
    }

    int ctrl_fd = open("/dev/dm-user", O_RDWR);
    if (!ctrl_fd) {
        perror("Unable to open /dev/dm-user");
        return 1;
    }

    size_t buf_size = 1UL << 16;
    char* buf = new char[buf_size];

    /* Just keeps pumping messages between userspace and the kernel.  We won't
     * actually be doing anything, but the sequence numbers line up so it'll at
     * least make forward progress. */
    while (true) {
        struct dm_user_message* msg = (struct dm_user_message*)(&(buf[0]));

        memset(buf, 0, buf_size);

        ssize_t readed = read(ctrl_fd, buf, buf_size);
        if (readed < 0) {
            perror("Control read failed, trying with more space");
            delete[] buf;
            buf_size *= 2;
            fprintf(stderr, "Looking for %x bytes\n", buf_size);
            buf = new char[buf_size];
            if (buf == NULL) {
                perror("Unable to allocate buffer");
                return 2;
            }
            continue;
        }

#if (DEBUG == 1)
        printf("read() from dm-user returned %d bytes:\n", readed);
        printf("    msg->seq:    0x%016llx\n", msg->seq);
        printf("    msg->type:   0x%016llx\n", msg->type);
        printf("    msg->flags:  0x%016llx\n", msg->flags);
        printf("    msg->sector: 0x%016llx\n", msg->sector);
        printf("    msg->len:    0x%016llx\n", msg->len);
#endif

        switch (msg->type) {
            case DM_USER_MAP_READ: {
#if (DEBUG == 1)
                printf("Responding to read of sector %lld with %lld bytes data\n", msg->sector,
                       msg->len);
#endif

                if ((sizeof(*msg) + msg->len) > buf_size) {
                    auto old_buf = buf;
                    buf_size = sizeof(*msg) + msg->len;
                    buf = new char[buf_size];
                    memcpy(buf, old_buf, sizeof(*msg));
                    delete[] old_buf;
                    msg = (struct dm_user_message*)(&(buf[0]));
                }

                ssize_t readed = 0;
                lseek(block_fd, msg->sector * 512, SEEK_SET);
                while (readed < msg->len) {
                    ssize_t r = read(block_fd, msg->buf + readed, msg->len - readed);
                    if (r < 0) {
                        perror("Unable to read from block device");
                        return 7;
                    }
                    readed += r;
                }

                ssize_t written = write(ctrl_fd, buf, sizeof(*msg) + msg->len);
                if (written < 0) {
                    perror("Control write failed");
                    return 3;
                }
                break;
            }

            case DM_USER_MAP_WRITE:
                abort();
                break;
        }

#if (DEBUG == 1)
        printf("read() finished, next message\n");
#endif
    }

    return 0;
}

int main() {
    /* Creates a new block device by just running dmctl, so I don't have to...
     * :) */
    system("dmctl create palmer user 0 1000000");

    /* Backgrounds the daemon... */
    if (fork() == 0) return daemon_main();

    /* That's probably log enough... */
    sleep(5);

#if (DEBUG == 1)
    system("dd if=/dev/block/mapper/system_a bs=4K count=4 of=/mnt/system_a");
    system("dd if=/dev/block/mapper/system_a bs=4K count=4 of=/mnt/system_a");
    system("dd if=/dev/block/mapper/system_a bs=4K count=4 of=/mnt/system_a");
    system("dd if=/dev/block/mapper/palmer bs=4K count=4 of=/mnt/palmer");
    system("dd if=/dev/block/mapper/palmer bs=4K count=4 of=/mnt/palmer");
    system("dd if=/dev/block/mapper/palmer bs=4K count=4 of=/mnt/palmer");
    printf("dd was small, as debug is on\n");
#else
    system("dd if=/dev/block/mapper/system_a bs=4K count=1024 of=/mnt/system_a");
    system("dd if=/dev/block/mapper/system_a bs=4K count=1024 of=/mnt/system_a");
    system("dd if=/dev/block/mapper/system_a bs=4K count=1024 of=/mnt/system_a");
    system("dd if=/dev/block/mapper/palmer bs=4K count=1024 of=/mnt/palmer");
    system("dd if=/dev/block/mapper/palmer bs=4K count=1024 of=/mnt/palmer");
    system("dd if=/dev/block/mapper/palmer bs=4K count=1024 of=/mnt/palmer");
#endif
    return system("diff /mnt/system_a /mnt/palmer");
}
