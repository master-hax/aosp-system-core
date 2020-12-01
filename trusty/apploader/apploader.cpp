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

#define LOG_TAG "TrustyAppLoader"

#include <android-base/logging.h>
#include <fcntl.h>
#include <getopt.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/sendfile.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <trusty/tipc.h>
#include <unistd.h>
#include <algorithm>
#include <string>

#include "apploader_ipc.h"

using std::string;

/*
 * According to man sendfile, the function always transfers at most 0x7fff000
 * bytes per call.
 */
#define SENDFILE_MAX 0x7ffff000L

constexpr const char kTrustyDeviceName[] = "/dev/trusty-ipc-dev0";

static uint32_t load_flags = 0;

static const char* _sopts = "hs";
static const struct option _lopts[] = {
        {"help", no_argument, 0, 'h'},
        {"start", no_argument, 0, 's'},
        {0, 0, 0, 0},
};

static const char* usage =
        "Usage: %s [options] package-file\n"
        "\n"
        "options:\n"
        "  -h, --help            prints this message and exit\n"
        "  -s, --start           start the application after loading it\n"
        "\n";

static void print_usage_and_exit(const char* prog, int code) {
    fprintf(stderr, usage, prog);
    exit(code);
}

static void parse_options(int argc, char** argv) {
    int c;
    int oidx = 0;

    while (1) {
        c = getopt_long(argc, argv, _sopts, _lopts, &oidx);
        if (c == -1) {
            break; /* done */
        }

        switch (c) {
            case 'h':
                print_usage_and_exit(argv[0], EXIT_SUCCESS);
                break;

            case 's':
                load_flags |= APPLOADER_LOAD_APP_START;
                break;

            default:
                print_usage_and_exit(argv[0], EXIT_FAILURE);
        }
    }
}

static int read_file(const char* file_name, off64_t* out_file_size) {
    int rc;
    int fd = -1;
    int memfd = -1;
    long page_size = sysconf(_SC_PAGESIZE);
    off64_t file_size, file_page_offset, file_page_size;
    struct stat64 st;

    fd = open(file_name, O_RDONLY);
    if (fd < 0) {
        fprintf(stderr, "Error opening file '%s': %s\n", file_name, strerror(errno));

        rc = fd;
        goto err_open;
    }

    rc = fstat64(fd, &st);
    if (rc < 0) {
        fprintf(stderr, "Error calling stat on file '%s': %s\n", file_name, strerror(errno));
        goto err_fstat;
    }

    if (st.st_size < 0) {
        fprintf(stderr, "Invalid size for file '%s': %ld\n", file_name, st.st_size);
        goto err_file_size;
    }

    file_size = st.st_size;
    if (out_file_size) *out_file_size = file_size;

    memfd = memfd_create("trusty-app", 0);
    if (memfd < 0) {
        fprintf(stderr, "Error creating memfd: %s\n", strerror(errno));

        rc = memfd;
        goto err_memfd_create;
    }

    /* The memfd size needs to be a multiple of the page size */
    file_page_offset = file_size & (page_size - 1);
    if (file_page_offset) file_page_offset = page_size - file_page_offset;
    if (__builtin_add_overflow(file_size, file_page_offset, &file_page_size)) {
        fprintf(stderr, "Failed to page-align file size\n");
        rc = -1;
        goto err_page_align;
    }

    rc = ftruncate64(memfd, file_page_size);
    if (rc < 0) {
        fprintf(stderr, "Error truncating memfd: %s\n", strerror(errno));
        goto err_ftruncate;
    }

    while (file_size > 0) {
        size_t len = std::min(file_size, SENDFILE_MAX);
        ssize_t num_sent = sendfile(memfd, fd, NULL, len);
        if (num_sent < 0) {
            if (errno == EINTR || errno == EAGAIN) {
                continue;
            }

            fprintf(stderr, "Error copying package file '%s': %s\n", file_name, strerror(errno));

            rc = num_sent;
            goto err_sendfile;
        }

        assert(num_sent <= file_size);
        file_size -= num_sent;
    }

    close(fd);
    return memfd;

err_sendfile:
err_ftruncate:
err_page_align:
    close(memfd);
err_memfd_create:
err_file_size:
err_fstat:
    close(fd);
err_open:
    return rc;
}

static ssize_t send_load_message(int tipc_fd, int package_fd, off64_t package_size) {
    struct apploader_header hdr = {
            .cmd = APPLOADER_CMD_LOAD_APPLICATION,
    };
    struct apploader_load_app_req req = {
            .package_size = static_cast<uint64_t>(package_size),
            .flags = load_flags,
    };
    struct iovec tx[2] = {{&hdr, sizeof(hdr)}, {&req, sizeof(req)}};
    struct trusty_shm shm = {
            .fd = package_fd,
            .transfer = TRUSTY_SHARE,
    };
    return tipc_send(tipc_fd, tx, 2, &shm, 1);
}

static ssize_t read_response(int tipc_fd) {
    struct apploader_resp resp;
    ssize_t rc = read(tipc_fd, &resp, sizeof(resp));
    if (rc < 0) {
        fprintf(stderr, "Failed to read response: %zd\n", rc);
        return rc;
    }

    if (rc < sizeof(resp)) {
        fprintf(stderr, "Not enough data in response: %zd\n", rc);
        return -EIO;
    }

    if (resp.hdr.cmd != (APPLOADER_CMD_LOAD_APPLICATION | APPLOADER_RESP_BIT)) {
        fprintf(stderr, "Invalid command in response: %u\n", resp.hdr.cmd);
        return -EINVAL;
    }

    switch (resp.error) {
        case APPLOADER_NO_ERROR:
            break;
        case APPLOADER_ERR_UNKNOWN_CMD:
            fprintf(stderr, "Error: unknown command\n");
            break;
        case APPLOADER_ERR_INVALID_CMD:
            fprintf(stderr, "Error: invalid command\n");
            break;
        case APPLOADER_ERR_NO_MEMORY:
            fprintf(stderr, "Error: out of Trusty memory\n");
            break;
        case APPLOADER_ERR_BAD_PACKAGE:
            fprintf(stderr, "Error: invalid application package\n");
            break;
        case APPLOADER_ERR_INTERNAL:
            fprintf(stderr, "Error: internal apploader error\n");
            break;
        default:
            fprintf(stderr, "Unrecognized error: %zd\n", rc);
            break;
    }

    return static_cast<ssize_t>(resp.error);
}

static ssize_t send_app_package(const char* package_file_name) {
    ssize_t rc = 0;
    int tipc_fd = -1;
    int package_fd = -1;
    off64_t package_size;

    package_fd = read_file(package_file_name, &package_size);
    if (package_fd < 0) {
        rc = package_fd;
        goto err_read_file;
    }

    tipc_fd = tipc_connect(kTrustyDeviceName, APPLOADER_PORT);
    if (tipc_fd < 0) {
        fprintf(stderr, "Failed to connect to Trusty app loader: %s\n", strerror(-tipc_fd));
        rc = tipc_fd;
        goto err_tipc_connect;
    }

    rc = send_load_message(tipc_fd, package_fd, package_size);
    if (rc < 0) {
        fprintf(stderr, "Failed to send package: %zd\n", rc);
        goto err_send;
    }

    rc = read_response(tipc_fd);

err_send:
    tipc_close(tipc_fd);
err_tipc_connect:
    close(package_fd);
err_read_file:
    return rc;
}

int main(int argc, char** argv) {
    parse_options(argc, argv);
    if (optind + 1 != argc) {
        print_usage_and_exit(argv[0], EXIT_FAILURE);
    }

    int rc = send_app_package(argv[optind]);
    return rc == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
