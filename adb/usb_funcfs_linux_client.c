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
 *
 * Copyright (C) 2012 Samsung Electronics Co Ltd.
 * Andrzej Pietrasiewicz <andrzej.p@samsung.com>
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include <sys/ioctl.h>
#include <sys/types.h>
#include <dirent.h>
#include <errno.h>

#include <linux/usb_ch9.h>
#include <linux/usb_functionfs.h>

#include "sysdeps.h"

#define   TRACE_TAG  TRACE_USB
#include "adb.h"

#define MAX_PACKET_SIZE_FS	64
#define MAX_PACKET_SIZE_HS	512

#define cpu_to_le16(x)  htole16(x)
#define cpu_to_le32(x)  htole32(x)

static const char ep0_path[] = USB_ADB_PATH"/ep0";
static const char ep1_path[] = USB_ADB_PATH"/ep1";
static const char ep2_path[] = USB_ADB_PATH"/ep2";

static const struct {
    struct usb_functionfs_descs_head header;
    struct {
        struct usb_interface_descriptor intf;
        struct usb_endpoint_descriptor_no_audio source;
        struct usb_endpoint_descriptor_no_audio sink;
    } __attribute__((packed)) fs_descs, hs_descs;
} __attribute__((packed)) descriptors = {
    .header = {
        .magic = cpu_to_le32(FUNCTIONFS_DESCRIPTORS_MAGIC),
        .length = cpu_to_le32(sizeof descriptors),
        .fs_count = 3,
        .hs_count = 3,
},
    .fs_descs = {
        .intf = {
            .bLength = sizeof descriptors.fs_descs.intf,
            .bDescriptorType = USB_DT_INTERFACE,
            .bInterfaceNumber = 0,
            .bNumEndpoints = 2,
            .bInterfaceClass = ADB_CLASS,
            .bInterfaceSubClass = ADB_SUBCLASS,
            .bInterfaceProtocol = ADB_PROTOCOL,
            .iInterface = 1, /* first string from the provided table */
        },
        .source = {
            .bLength = sizeof descriptors.fs_descs.source,
            .bDescriptorType = USB_DT_ENDPOINT,
            .bEndpointAddress = 1 | USB_DIR_OUT,
            .bmAttributes = USB_ENDPOINT_XFER_BULK,
            .wMaxPacketSize = MAX_PACKET_SIZE_FS,
	},
        .sink = {
            .bLength = sizeof descriptors.fs_descs.sink,
            .bDescriptorType = USB_DT_ENDPOINT,
            .bEndpointAddress = 2 | USB_DIR_IN,
            .bmAttributes = USB_ENDPOINT_XFER_BULK,
            .wMaxPacketSize = MAX_PACKET_SIZE_FS,
        },
    },
    .hs_descs = {
        .intf = {
            .bLength = sizeof descriptors.hs_descs.intf,
            .bDescriptorType = USB_DT_INTERFACE,
            .bInterfaceNumber = 0,
            .bNumEndpoints = 2,
            .bInterfaceClass = ADB_CLASS,
            .bInterfaceSubClass = ADB_SUBCLASS,
            .bInterfaceProtocol = ADB_PROTOCOL,
            .iInterface = 1, /* first string from the provided table */
        },
        .source = {
            .bLength = sizeof descriptors.hs_descs.source,
            .bDescriptorType = USB_DT_ENDPOINT,
            .bEndpointAddress = 1 | USB_DIR_OUT,
            .bmAttributes = USB_ENDPOINT_XFER_BULK,
            .wMaxPacketSize = MAX_PACKET_SIZE_HS,
        },
        .sink = {
            .bLength = sizeof descriptors.hs_descs.sink,
            .bDescriptorType = USB_DT_ENDPOINT,
            .bEndpointAddress = 2 | USB_DIR_IN,
            .bmAttributes = USB_ENDPOINT_XFER_BULK,
            .wMaxPacketSize = MAX_PACKET_SIZE_HS,
        },
    },
};

#define STR_INTERFACE_ "ADB Interface"

static const struct {
    struct usb_functionfs_strings_head header;
    struct {
        __le16 code;
        const char str1[sizeof STR_INTERFACE_];
    } __attribute__((packed)) lang0;
} __attribute__((packed)) strings = {
    .header = {
        .magic = cpu_to_le32(FUNCTIONFS_STRINGS_MAGIC),
        .length = cpu_to_le32(sizeof strings),
        .str_count = cpu_to_le32(1),
        .lang_count = cpu_to_le32(1),
    },
    .lang0 = {
        cpu_to_le16(0x0409), /* en-us */
        STR_INTERFACE_,
    },
};

struct usb_handle
{
    const char *EP0_NAME;
    const char *EP_IN_NAME;
    const char *EP_OUT_NAME;
    int control;
    int bulk_out; /* "out" from the host's perspective => source for adbd */
    int bulk_in;  /* "in" from the host's perspective => sink for adbd */
    adb_cond_t notify;
    adb_mutex_t lock;
};

static void init_functionfs(struct usb_handle *h)
{
    ssize_t ret;

    D("OPENING %s\n", h->EP0_NAME);
    h->control = adb_open(h->EP0_NAME, O_RDWR);
    if (h->control < 0) {
        D("[ %s: cannot open control endpoint ]\n", h->EP0_NAME);
        h->control = -errno;
        return;
    }

    D("[ %s: writing descriptors ]\n", h->EP0_NAME);
    ret = adb_write(h->control, &descriptors, sizeof descriptors);
    if (ret < 0) {
        D("[ %s: write: descriptors ]\n", h->EP0_NAME);
        h->control = -errno;
        return;
    }

    D("[ %s: writing strings ]\n", h->EP0_NAME);
    ret = adb_write(h->control, &strings, sizeof strings);
    if(ret < 0) {
        D("[ %s: write: strings ]\n", h->EP0_NAME);
        h->control = -errno;
        return;
    }

    D("[ %s: opening ]\n", h->EP_OUT_NAME);
    if ((h->bulk_out = adb_open(h->EP_OUT_NAME, O_RDWR)) < 0) {
        D("[ %s: cannot open bulk-out endpoint ]\n", h->EP_OUT_NAME);
        h->bulk_out = -errno;
        return;
    }
	
    D("[ %s: opening ]\n", h->EP_IN_NAME);
    if ((h->bulk_in = adb_open(h->EP_IN_NAME, O_RDWR)) < 0) {
        D("[ %s: cannot open bulk-in endpoint ]\n", h->EP_IN_NAME);
        h->bulk_in = -errno;
        return;
    }

    return;
}

void usb_cleanup()
{
    // nothing to do here
}

static void *usb_open_thread(void *x)
{
    struct usb_handle *usb = (struct usb_handle *)x;

    while (1) {
        // wait until the USB device needs opening
        adb_mutex_lock(&usb->lock);
        while (usb->control != -1)
            adb_cond_wait(&usb->notify, &usb->lock);
        adb_mutex_unlock(&usb->lock);

        init_functionfs(usb);
        D("[ opening device succeeded ]\n");

        D("[ usb_thread - registering device ]\n");
        register_usb_transport(usb, 0, 1);
    }

    // never gets here
    return 0;
}

static int bulk_write(int bulk_in, const void *buf, size_t length)
{
    size_t count = 0;
    int ret;

    do {
        ret = adb_write(bulk_in, buf + count, length - count);
        if (ret < 0) {
            if (errno != EINTR)
                return ret;
            } else
                count += ret;
    } while (count < length);

    D("[ bulk_write done fd=%d ]\n", bulk_in);
    return count;
}

int usb_write(usb_handle *h, const void *data, int len)
{
    int n;

    D("about to write (fd=%d, len=%d)\n", h->bulk_in, len);
    n = bulk_write(h->bulk_in, data, len);
    if(n != len) {
        D("ERROR: fd = %d, n = %d, errno = %d (%s)\n",
            h->bulk_in, n, errno, strerror(errno));
        return -1;
    }
    D("[ done fd=%d ]\n", h->bulk_in);
    return 0;
}

static int bulk_read(int bulk_out, void *buf, size_t length)
{
    size_t count = 0;
    int ret;

    do {
        ret = adb_read(bulk_out, buf + count, length - count);
        if (ret < 0) {
            if (errno != EINTR)
                return ret;
            } else
            count += ret;
    } while (count < length);

    D("[ bulk_read done fd=%d ]\n", bulk_out);
    return count;
}

int usb_read(usb_handle *h, void *data, int len)
{
    int n;

    D("about to read (fd=%d, len=%d)\n", h->bulk_out, len);
    n = bulk_read(h->bulk_out, data, len);
    if(n != len) {
        D("ERROR: fd = %d, n = %d, errno = %d (%s)\n",
            h->bulk_out, n, errno, strerror(errno));
        return -1;
    }
    D("[ done fd=%d ]\n", h->bulk_out);
    return 0;
}

static int autoconfig(struct usb_handle *h)
{
    struct stat statb;

    if (stat(h->EP0_NAME = ep0_path, &statb) == 0) {
        h->EP_OUT_NAME = ep1_path;
        h->EP_IN_NAME = ep2_path;
    } else {
        h->EP0_NAME = 0;
        return -ENODEV;
    }

    return 0;
}

void usb_init()
{
    usb_handle *h;
    adb_thread_t tid;

    D("[ usb_init - using FunctionFS ]\n");

    h = calloc(1, sizeof(usb_handle));
    if (autoconfig(h) < 0) {
	fatal_errno("[ can't recognize usb FunctionFS bulk device ]\n");
	free(h);
        return;
    }

    h->control = h->bulk_out = h->bulk_out = -1;

    adb_cond_init(&h->notify, 0);
    adb_mutex_init(&h->lock, 0);

    D("[ usb_init - starting thread ]\n");
    if(adb_thread_create(&tid, usb_open_thread, h)){
        fatal_errno("[ cannot create usb thread ]\n");
    }
}

void usb_kick(usb_handle *h)
{
    int err;

    err = ioctl(h->bulk_in, FUNCTIONFS_CLEAR_HALT);
    if (err < 0)
	perror("[ reset source fd ]\n");

    err = ioctl(h->bulk_out, FUNCTIONFS_CLEAR_HALT);
    if (err < 0)
	perror("reset sink fd");

    adb_mutex_lock(&h->lock);
    adb_close(h->control);
    adb_close(h->bulk_out);
    adb_close(h->bulk_in);
    h->control = h->bulk_out = h->bulk_out = -1;

    // notify usb_open_thread that we are disconnected
    adb_cond_signal(&h->notify);
    adb_mutex_unlock(&h->lock);
}

int usb_close(usb_handle *h)
{
    return 0;
}
