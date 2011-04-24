/*
 * Copyright (C) 2008 The Android Open Source Project
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
#include <errno.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <string.h>

#include <linux/netlink.h>

#define LOG_TAG "NetlinkListener"
#include <cutils/log.h>

#include <sysutils/NetlinkListener.h>
#include <sysutils/NetlinkEvent.h>

NetlinkListener::NetlinkListener(int socket) :
                            SocketListener(socket, false) {
}

bool NetlinkListener::onDataAvailable(SocketClient *cli)
{
    int socket = cli->getSocket();
    struct sockaddr_nl addr;
    socklen_t addr_len = sizeof(addr);
    int count;

    if ((count = recvfrom(socket, mBuffer, sizeof(mBuffer), 0,
                          (struct sockaddr *)&addr, &addr_len)) < 0) {
        SLOGE("recv failed (%s)", strerror(errno));
        return false;
    }

    if (addr.nl_pid != 0 && addr.nl_groups == 0) {
        SLOGW("forged uevent message from pid %d ignored", addr.nl_pid);
        return false;
    }

    NetlinkEvent *evt = new NetlinkEvent();
    if (!evt->decode(mBuffer, count)) {
        SLOGE("Error decoding NetlinkEvent");
        goto out;
    }

    onEvent(evt);
out:
    delete evt;
    return true;
}
