/*
 * Copyright (C) 2007 The Android Open Source Project
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

#define TRACE_TAG TRANSPORT

#include "sysdeps.h"
#include "transport.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "adb.h"

#if ADB_HOST

static int remote_read(apacket* p, atransport* t) {
    int n = usb_read(t->usb, &p->msg, sizeof(p->msg));
    if (n < 0) {
        D("remote usb: read terminated (message)");
        return -1;
    }
    if (static_cast<size_t>(n) != sizeof(p->msg) || !check_header(p, t)) {
        D("remote usb: check_header failed");
        return -1;
    }
    if (p->msg.data_length) {
        n = usb_read(t->usb, &p->data, p->msg.data_length);
        if (n < 0) {
            D("remote usb: terminated (data)");
            return -1;
        }
        if (static_cast<uint32_t>(n) != p->msg.data_length) {
            D("remote usb: read payload failed (need %u bytes, received %d bytes)",
              p->msg.data_length, n);
            return -1;
        }
    }
    if (!check_data(p)) {
        D("remote usb: check_data failed");
        return -1;
    }
    return 0;
}

// If the device we're connecting to was already connected to adb before we started, there could be
// stale packets in our input queue. Read and throw away until we hit a CNXN packet.
static int initial_read(apacket* p, atransport* t) {
    usb_handle* h = t->usb;
    while (true) {
        // Call usb_read using a buffer having a multiple of usb_get_max_packet_size() bytes
        // to avoid overflow. See http://libusb.sourceforge.net/api-1.0/packetoverflow.html.
        size_t usb_packet_size = usb_get_max_packet_size(h);
        char buffer[4096];

        CHECK_GE(usb_packet_size, sizeof(amessage));
        CHECK_LT(usb_packet_size, 4096UL);

        int n = usb_read(h, buffer, usb_packet_size);
        if (n == -1) {
            return -1;
        } else if (n != sizeof(amessage)) {
            LOG(WARNING) << "skipping " << n << " byte packet";
            continue;
        }

        amessage* msg = reinterpret_cast<amessage*>(buffer);
        p->msg = *msg;
        if (p->msg.command != A_CNXN && p->msg.command != A_AUTH) {
            LOG(WARNING) << "skipping non-CNXN, non-AUTH probable amessage";
            continue;
        }

        if (!check_header(p, t)) {
            LOG(WARNING) << "skipping invalid amessage";
            continue;
        }

        if (n != 0) {
            n = usb_read(h, &p->data, p->msg.data_length);
            if (n == -1) {
                LOG(WARNING) << "failed to read payload for CNXN";
                return -1;
            }

            if (!check_data(p)) {
                LOG(WARNING) << "payload checksum validation failed, skipping";
                continue;
            }
        }

        // Switch over to the regular read function now.
        t->read_from_remote = remote_read;
        return 0;
    }
}

#else

// On Android devices, we rely on the kernel to provide buffered read.
// So we can recover automatically from EOVERFLOW.
static int remote_read(apacket* p, atransport* t) {
    if (usb_read(t->usb, &p->msg, sizeof(amessage))) {
        D("remote usb: read terminated (message)");
        return -1;
    }

    if (!check_header(p, t)) {
        D("remote usb: check_header failed");
        return -1;
    }

    if (p->msg.data_length) {
        if (usb_read(t->usb, p->data, p->msg.data_length)) {
            D("remote usb: terminated (data)");
            return -1;
        }
    }

    if (!check_data(p)) {
        D("remote usb: check_data failed");
        return -1;
    }

    return 0;
}
#endif

static int remote_write(apacket* p, atransport* t) {
    unsigned size = p->msg.data_length;

    if (usb_write(t->usb, &p->msg, sizeof(amessage))) {
        D("remote usb: 1 - write terminated");
        return -1;
    }
    if(p->msg.data_length == 0) return 0;
    if (usb_write(t->usb, &p->data, size)) {
        D("remote usb: 2 - write terminated");
        return -1;
    }

    return 0;
}

static void remote_close(atransport* t) {
    usb_close(t->usb);
    t->usb = 0;
}

static void remote_kick(atransport* t) {
    usb_kick(t->usb);
}

void init_usb_transport(atransport* t, usb_handle* h) {
    D("transport: usb");
    t->close = remote_close;
    t->SetKickFunction(remote_kick);
    t->SetWriteFunction(remote_write);
#if ADB_HOST
    t->read_from_remote = initial_read;
#else
    t->read_from_remote = remote_read;
#endif
    t->sync_token = 1;
    t->type = kTransportUsb;
    t->usb = h;
}

int is_adb_interface(int usb_class, int usb_subclass, int usb_protocol) {
    return (usb_class == ADB_CLASS && usb_subclass == ADB_SUBCLASS && usb_protocol == ADB_PROTOCOL);
}

bool should_use_libusb() {
#if defined(_WIN32) || !ADB_HOST
    return false;
#else
    static bool disable = getenv("ADB_LIBUSB") && strcmp(getenv("ADB_LIBUSB"), "0") == 0;
    return !disable;
#endif
}
