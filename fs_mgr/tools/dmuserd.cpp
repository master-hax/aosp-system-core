// SPDX-License-Identifier: Apache-2.0

#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <unistd.h>

#define SECTOR_SIZE 512

#define MAX(a, b) ((a) > (b) ? (a) : (b))

/* This should be replaced with linux/dm-user.h. */
#ifndef _LINUX_DM_USER_H
#define _LINUX_DM_USER_H

#include <linux/types.h>

#define DM_USER_MAP_READ 0
#define DM_USER_MAP_WRITE 1

struct dm_user_message {
    __u64 seq;
    __u64 type;
    __u64 flags;
    __u64 sector;
    __u64 len;
    __u8 buf[];
};

#endif

int write_all(int fd, void* buf, size_t len) {
    char* buf_c = (char*)buf;
    ssize_t total = 0;
    ssize_t once;

    while (total < len) {
        once = write(fd, buf_c + total, len - total);
        if (once <= 0) return once;
        total += once;
    }

    return total;
}

int read_all(int fd, void* buf, size_t len) {
    char* buf_c = (char*)buf;
    ssize_t total = 0;
    ssize_t once;

    while (total < len) {
        once = read(fd, buf_c + total, len - total);
        if (once <= 0) return once;
        total += once;
    }

    return total;
}
int simple_daemon(char* control_dev, size_t block_bytes, char* store)

{
    int control_fd = open(control_dev, O_RDWR);
    if (control_fd < 0) {
        fprintf(stderr, "Unable to open control device %s\n", control_dev);
        return -1;
    }

    while (1) {
        struct dm_user_message msg;
        char* base;

        if (read_all(control_fd, &msg, sizeof(msg)) < 0) {
            if (errno == ENOTBLK) return 0;

            perror("unable to read msg");
            return -1;
        }

        base = store + msg.sector * SECTOR_SIZE;
        if (base + msg.len > store + block_bytes) {
            fprintf(stderr, "access out of bounds\n");
            return -1;
        }

        if (msg.type == DM_USER_MAP_WRITE) {
            if (read_all(control_fd, base, msg.len) < 0) {
                if (errno == ENOTBLK) return 0;

                perror("unable to read buf");
                return -1;
            }
        }

        if (write_all(control_fd, &msg, sizeof(msg)) < 0) {
            if (errno == ENOTBLK) return 0;

            perror("unable to write msg");
            return -1;
        }

        if (msg.type == DM_USER_MAP_READ) {
            if (write_all(control_fd, base, msg.len) < 0) {
                if (errno == ENOTBLK) return 0;

                perror("unable to write buf");
                return -1;
            }
        }
    }

    /* The daemon doesn't actully terminate for this test. */
    perror("Unable to read from control device");
    return -1;
}

void usage(char* prog) {
    printf("Usage: %s\n", prog);
    printf("	Handles block requests in userspace, backed by memory\n");
    printf("  -h			Display this help message\n");
    printf("  -c <control dev>		Control device to use for the test\n");
    printf("  -s <sectors>		The number of sectors in the device\n");
    printf("  -b <store path>		The file to use as a backing store, otherwise memory\n");
}

int main(int argc, char* argv[]) {
    char* control_dev = NULL;
    size_t block_bytes = 0;
    char* backing_path = NULL;
    char* store;
    int c;

    prctl(PR_SET_IO_FLUSHER, 0, 0, 0, 0);

    while ((c = getopt(argc, argv, "h:c:s:b:")) != -1) {
        switch (c) {
            case 'h':
                usage(basename(argv[0]));
                exit(0);
            case 'c':
                control_dev = strdup(optarg);
                break;
            case 's':
                block_bytes = atoi(optarg) * SECTOR_SIZE;
                break;
            case 'b':
                backing_path = strdup(optarg);
                break;
            default:
                usage(basename(argv[0]));
                exit(1);
        }
    }

    if (backing_path == NULL) {
        store = (char*)(malloc(block_bytes));
        for (size_t i = 0; i < block_bytes / sizeof(size_t); ++i) ((size_t*)(store))[i] = i;
    } else {
        int backing_fd = open(backing_path, O_RDWR);
        if (backing_fd < 0) {
            perror("Unable to open backing store");
            exit(2);
        }

        store = (char*)(mmap(NULL, block_bytes, PROT_READ | PROT_WRITE, MAP_SHARED, backing_fd, 0));
        if (store == NULL) {
            perror("Unable to mmap() backing store");
            exit(2);
        }
    }

    int r = simple_daemon(control_dev, block_bytes, store);
    if (r) fprintf(stderr, "simple_daemon() errored out\n");
    return r;
}
