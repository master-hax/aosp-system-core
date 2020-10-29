// SPDX-License-Identifier: Apache-2.0

#define _LARGEFILE64_SOURCE

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
#include <iostream>

#define SECTOR_SIZE ((__u64)512)
#define BUFFER_BYTES 4096

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

static bool verbose = false;

size_t write_all(int fd, void* buf, size_t len) {
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

size_t read_all(int fd, void* buf, size_t len) {
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

int not_splice(int from, __u64 from_offset, int to, __u64 to_offset, __u64 count) {
    if (from_offset > 0) lseek64(from, from_offset, SEEK_SET);
    if (to_offset > 0) lseek64(to, to_offset, SEEK_SET);

    while (count > 0) {
        char buf[BUFFER_BYTES];
        __u64 max = count > BUFFER_BYTES ? BUFFER_BYTES : count;

        if (read_all(from, &buf[0], max) < 0) {
            perror("Unable to read");
            return -EIO;
        }

        if (write_all(to, &buf[0], max) < 0) {
            perror("Unable to write");
            return -EIO;
        }

        count -= max;
    }

    return 0;
}

int simple_daemon(char* control_path, char* backing_path) {
    int control_fd = open(control_path, O_RDWR);
    if (control_fd < 0) {
        fprintf(stderr, "Unable to open control device %s\n", control_path);
        return -1;
    }

    int backing_fd = open(backing_path, O_RDWR);
    if (backing_fd < 0) {
        fprintf(stderr, "Unable to open backing device %s\n", backing_path);
        return -1;
    }

    while (1) {
        struct dm_user_message msg;
        char* base;

        if (verbose) std::cerr << "dmuserd: Waiting for message...\n";

        if (read_all(control_fd, &msg, sizeof(msg)) < 0) {
            if (errno == ENOTBLK) return 0;

            perror("unable to read msg");
            return -1;
        }

        if (verbose) {
            switch (msg.type) {
                case DM_USER_MAP_WRITE:
                    std::cerr << "dmuserd: Got write request for sector "
                              << std::to_string(msg.sector) << " with length "
                              << std::to_string(msg.len) << "\n";
                    break;
                case DM_USER_MAP_READ:
                    std::cerr << "dmuserd: Got read request for sector "
                              << std::to_string(msg.sector) << " with length "
                              << std::to_string(msg.len) << "\n";
                    break;
                default:
                    std::cerr << "dmuserd: unknown message type " << std::to_string(msg.type)
                              << "\n";
                    exit(3);
                    break;
            }
        }

        if (msg.type == DM_USER_MAP_WRITE) {
            if (not_splice(control_fd, 0, backing_fd, msg.sector * SECTOR_SIZE, msg.len) < 0) {
                if (errno == ENOTBLK) return 0;
                std::cerr << "unable to handle write data\n";
                return -1;
            }
        }

        if (verbose) std::cerr << "dmuserd: Responding to message\n";

        if (write_all(control_fd, &msg, sizeof(msg)) < 0) {
            if (errno == ENOTBLK) return 0;
            perror("unable to write msg");
            return -1;
        }

        if (msg.type == DM_USER_MAP_READ) {
            if (verbose) std::cerr << "dmuserd: Sending read data\n";
            if (not_splice(backing_fd, msg.sector * SECTOR_SIZE, control_fd, 0, msg.len) < 0) {
                if (errno == ENOTBLK) return 0;
                std::cerr << "unable to handle read data\n";
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
    printf("  -b <store path>		The file to use as a backing store, otherwise memory\n");
    printf("  -v                        Enable verbose mode\n");
}

int main(int argc, char* argv[]) {
    char* control_path = NULL;
    char* backing_path = NULL;
    char* store;
    int c;

    prctl(PR_SET_IO_FLUSHER, 0, 0, 0, 0);

    while ((c = getopt(argc, argv, "h:c:s:b:v")) != -1) {
        switch (c) {
            case 'h':
                usage(basename(argv[0]));
                exit(0);
            case 'c':
                control_path = strdup(optarg);
                break;
            case 'b':
                backing_path = strdup(optarg);
                break;
            case 'v':
                verbose = true;
                break;
            default:
                usage(basename(argv[0]));
                exit(1);
        }
    }

    int r = simple_daemon(control_path, backing_path);
    if (r) fprintf(stderr, "simple_daemon() errored out\n");
    return r;
}
