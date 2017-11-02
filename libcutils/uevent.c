/*
 * Copyright (C) 2011 The Android Open Source Project
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

#include <cutils/uevent.h>

#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include <linux/netlink.h>

#include <private/android_filesystem_config.h>

/**
 * Gets the uid of root in the current user namespace. Returns AID_OVERFLOWUID
 * if the root user is not mapped in the current namespace.
 */
uid_t uevent_root_uid() {
    const uid_t parent_root_uid = 0;
    uid_t current_root_uid = parent_root_uid;
    uid_t current_namespace_uid, parent_namespace_uid, kernel_overflow_uid;
    uint32_t length;
    FILE *uid_map_file = NULL, *overflowuid_file = NULL;

    uid_map_file = fopen("/proc/self/uid_map", "r");
    if (!uid_map_file) {
        /* the kernel does not support user namespaces */
        goto out;
    }

    /* sanity check. verify that the overflow UID is the expected one */
    overflowuid_file = fopen("/proc/sys/kernel/overflowuid", "r");
    if (!overflowuid_file) {
        goto out;
    }
    if (fscanf(overflowuid_file, "%u", &kernel_overflow_uid) != 1 ||
        kernel_overflow_uid != AID_OVERFLOWUID) {
        goto out;
    }

    /* in case root is unmapped, return the kernel "overflow" uid */
    current_root_uid = AID_OVERFLOWUID;
    while (fscanf(uid_map_file, "%u %u %u\n", &current_namespace_uid, &parent_namespace_uid,
                  &length) == 3) {
        if (parent_namespace_uid != parent_root_uid || length < 1) {
            continue;
        }
        current_root_uid = current_namespace_uid;
        break;
    }

out:
    if (uid_map_file) fclose(uid_map_file);
    if (overflowuid_file) fclose(overflowuid_file);
    return current_root_uid;
}

/**
 * Like recv(), but checks that messages actually originate from the kernel.
 */
ssize_t uevent_kernel_multicast_recv(int socket, void* buffer, size_t length, uid_t root_uid) {
    uid_t uid = -1;
    return uevent_kernel_multicast_uid_recv(socket, buffer, length, root_uid, &uid);
}

/**
 * Like the above, but passes a uid_t in by pointer. In the event that this
 * fails due to a bad uid check, the uid_t will be set to the uid of the
 * socket's peer.
 *
 * If this method rejects a netlink message from outside the kernel, it
 * returns -1, sets errno to EIO, and sets "user" to the UID associated with the
 * message. If the peer UID cannot be determined, "user" is set to -1."
 */
ssize_t uevent_kernel_multicast_uid_recv(int socket, void* buffer, size_t length, uid_t root_uid,
                                         uid_t* uid) {
    return uevent_kernel_recv(socket, buffer, length, true, root_uid, uid);
}

ssize_t uevent_kernel_recv(int socket, void* buffer, size_t length, bool require_group,
                           uid_t root_uid, uid_t* uid) {
    struct iovec iov = { buffer, length };
    struct sockaddr_nl addr;
    char control[CMSG_SPACE(sizeof(struct ucred))];
    struct msghdr hdr = {
        &addr,
        sizeof(addr),
        &iov,
        1,
        control,
        sizeof(control),
        0,
    };

    *uid = -1;
    ssize_t n = recvmsg(socket, &hdr, 0);
    if (n <= 0) {
        return n;
    }

    struct cmsghdr *cmsg = CMSG_FIRSTHDR(&hdr);
    if (cmsg == NULL || cmsg->cmsg_type != SCM_CREDENTIALS) {
        /* ignoring netlink message with no sender credentials */
        goto out;
    }

    struct ucred *cred = (struct ucred *)CMSG_DATA(cmsg);
    *uid = cred->uid;
    if (cred->uid != root_uid) {
        /* ignoring netlink message from non-root user */
        goto out;
    }

    if (addr.nl_pid != 0) {
        /* ignore non-kernel */
        goto out;
    }
    if (require_group && addr.nl_groups == 0) {
        /* ignore unicast messages when requested */
        goto out;
    }

    return n;

out:
    /* clear residual potentially malicious data */
    bzero(buffer, length);
    errno = EIO;
    return -1;
}

int uevent_open_socket(int buf_sz, bool passcred)
{
    struct sockaddr_nl addr;
    int on = passcred;
    int s;

    memset(&addr, 0, sizeof(addr));
    addr.nl_family = AF_NETLINK;
    addr.nl_pid = getpid();
    addr.nl_groups = 0xffffffff;

    s = socket(PF_NETLINK, SOCK_DGRAM | SOCK_CLOEXEC, NETLINK_KOBJECT_UEVENT);
    if(s < 0)
        return -1;

    /* buf_sz should be less than net.core.rmem_max for this to succeed */
    if (setsockopt(s, SOL_SOCKET, SO_RCVBUF, &buf_sz, sizeof(buf_sz)) < 0) {
        close(s);
        return -1;
    }

    setsockopt(s, SOL_SOCKET, SO_PASSCRED, &on, sizeof(on));

    if(bind(s, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
        close(s);
        return -1;
    }

    return s;
}
