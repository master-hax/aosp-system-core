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

#define LOG_TAG "libtrusty"

#include <errno.h>
#include <fcntl.h>
#include <linux/vm_sockets.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <unistd.h>

#include <log/log.h>

#include <trusty/ipc.h>

static bool use_vsock_connection = false;
static int tipc_vsock_connect(const char* cid_port_str, const char* srv_name) {
    int ret;
    char* port_str;
    char* end_str;
    long cid = strtol(cid_port_str, &port_str, 0);
    if (port_str[0] != ':') {
        ALOGE("%s: invalid VSOCK str, \"%s\", need cid:port missing : after cid\n", __func__,
              cid_port_str);
        return -EINVAL;
    }
    long port = strtol(port_str + 1, &end_str, 0);
    if (end_str[0] != '\0') {
        ALOGE("%s: invalid VSOCK str, \"%s\", need cid:port got %ld:%ld\n", __func__, cid_port_str,
              cid, port);
        return -EINVAL;
    }
    int fd = socket(AF_VSOCK, SOCK_STREAM, 0); /* TODO: should be seq-packet */
    if (fd < 0) {
        ret = -errno;
        ALOGE("%s: can't get vsock socket for tipc service \"%s\" (err=%d)\n", __func__, srv_name,
              errno);
        return ret < 0 ? ret : -1;
    }
    struct sockaddr_vm sa = {
            .svm_family = AF_VSOCK,
            .svm_port = port,
            .svm_cid = cid,
    };
    ret = TEMP_FAILURE_RETRY(connect(fd, (struct sockaddr*)&sa, sizeof(sa)));
    if (ret) {
        ret = -errno;
        ALOGE("%s: can't connect to vsock for tipc service \"%s\" (err=%d)\n", __func__, srv_name,
              errno);
        close(fd);
        return ret < 0 ? ret : -1;
    }
    /*
     * TODO: Current vsock tipc bridge in trusty expects a port name in the
     * first packet. We need to replace this with a protocol that also does DICE
     * based autentication.
     */
    ret = TEMP_FAILURE_RETRY(write(fd, srv_name, strlen(srv_name)));
    if (ret != strlen(srv_name)) {
        ret = -errno;
        ALOGE("%s: failed to send tipc service name \"%s\" to vsock (err=%d)\n", __func__, srv_name,
              errno);
        close(fd);
        return ret < 0 ? ret : -1;
    }
    use_vsock_connection = true;
    return fd;
}

static size_t tipc_vsock_send(int fd, const struct iovec* iov, int iovcnt, struct trusty_shm* shms,
                              int shmcnt) {
    int ret;

    (void)shms;
    if (shmcnt != 0) {
        ALOGE("%s: vsock does not yet support passing fds\n", __func__);
        return -ENOTSUP;
    }
    ret = TEMP_FAILURE_RETRY(writev(fd, iov, iovcnt));
    if (ret < 0) {
        ret = -errno;
        ALOGE("%s: failed to send message (err=%d)\n", __func__, errno);
        return ret < 0 ? ret : -1;
    }

    return ret;
}

int tipc_connect(const char* dev_name, const char* srv_name) {
    int fd;
    int rc;

    if (strncmp(dev_name, "VSOCK:", 6) == 0) {
        return tipc_vsock_connect(dev_name + 6, srv_name);
    }

    fd = TEMP_FAILURE_RETRY(open(dev_name, O_RDWR));
    if (fd < 0) {
        rc = -errno;
        ALOGE("%s: cannot open tipc device \"%s\": %s\n", __func__, dev_name, strerror(errno));
        return rc < 0 ? rc : -1;
    }

    rc = TEMP_FAILURE_RETRY(ioctl(fd, TIPC_IOC_CONNECT, srv_name));
    if (rc < 0) {
        rc = -errno;
        ALOGE("%s: can't connect to tipc service \"%s\" (err=%d)\n", __func__, srv_name, errno);
        close(fd);
        return rc < 0 ? rc : -1;
    }

    ALOGV("%s: connected to \"%s\" fd %d\n", __func__, srv_name, fd);
    return fd;
}

ssize_t tipc_send(int fd, const struct iovec* iov, int iovcnt, struct trusty_shm* shms,
                  int shmcnt) {
    if (use_vsock_connection) {
        return tipc_vsock_send(fd, iov, iovcnt, shms, shmcnt);
    }
    struct tipc_send_msg_req req;
    req.iov = (__u64)iov;
    req.iov_cnt = (__u64)iovcnt;
    req.shm = (__u64)shms;
    req.shm_cnt = (__u64)shmcnt;

    int rc = TEMP_FAILURE_RETRY(ioctl(fd, TIPC_IOC_SEND_MSG, &req));
    if (rc < 0) {
        ALOGE("%s: failed to send message (err=%d)\n", __func__, rc);
    }

    return rc;
}

void tipc_close(int fd) {
    close(fd);
}
