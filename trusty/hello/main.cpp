/*
 * Copyright (C) 2018 The Android Open Source Project
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

#include <BufferAllocator/BufferAllocator.h>
#include <errno.h>
#include <getopt.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/uio.h>
#include <unistd.h>

#include <trusty/tipc.h>

#include "hello.h"

// Trusty ipc device mapped to linux
#define TRUSTY_IPC_DEVNAME "/dev/trusty-ipc-dev0"

int main(int argc, char* argv[]) {
    if (argc < 2) {
        printf("Usage: %s <cmd>\n", argv[0]);
        return 0;
    }

    int cmd = atoi(argv[1]);

    int rc = 0;

    // This will attempt to connect to the Trusty TA on its port
    // name. The second parameter tells connect() that if no such port exists,
    // it should block and wait until one does.
    int fd = tipc_connect(TRUSTY_IPC_DEVNAME, HELLO_PORT);
    if (fd < 0) {
        fprintf(stderr, "failed to connect to '%s' app: %s\n", HELLO_PORT, strerror(-fd));
        return fd;
    }

    // allocate shared buffer
    BufferAllocator allocator;
    android::base::unique_fd dma_buf(allocator.Alloc("system", HELLO_SHMEM_SIZE));
    if (dma_buf.get() < 0) {
        fprintf(stderr, "failed to allocate shared data buffer: %d\n", dma_buf.get());
        return dma_buf.get();
    }

    // map buffer to user app address space
    void* shm_buffer = mmap(0, HELLO_SHMEM_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, dma_buf, 0);
    if (shm_buffer == MAP_FAILED) {
        fprintf(stderr, "failed to create shared mem\n");
        return -2;
    }

    // fill it with data
    memcpy(shm_buffer, "Hello TA!", sizeof("Hello TA!") + 1);

    // Fill in a request for TA.
    struct hello_req req;
    req.cmd = cmd;

    // create request and shared mem handles
    struct iovec iov = {
            .iov_base = &req,
            .iov_len = sizeof(req),
    };
    struct trusty_shm shm = {
            .fd = dma_buf,
            .transfer = TRUSTY_SHARE,
    };

    // send message to TA
    rc = tipc_send(fd, &iov, 1, &shm, 1);
    if (rc != sizeof(struct hello_req)) {
        fprintf(stderr, "failed to send tipc request: %d\n", rc);
        return rc;
    }

    // receive a response from TA
    struct hello_resp resp;
    int bytes_read = read(fd, &resp, sizeof(struct hello_resp));
    if (bytes_read < 0) {
        fprintf(stderr, "failed to read response from TA: %d\n", rc);
        return rc;
    }

    if (bytes_read != sizeof(struct hello_resp)) {
        fprintf(stderr, "invalid response size: %d\n", rc);
        return rc;
    }

    printf("Received response status: %d\n", resp.status);
    printf("Message in shared mem: %s\n", (const char*)shm_buffer);

    // Close connection to TA
    tipc_close(fd);

    return rc == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
