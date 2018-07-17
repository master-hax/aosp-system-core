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

#include "usb_client.h"

#include <endian.h>
#include <fcntl.h>
#include <linux/usb/ch9.h>
#include <linux/usb/functionfs.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <android-base/logging.h>
#include <android-base/properties.h>

#define MAX_PACKET_SIZE_FS 64
#define MAX_PACKET_SIZE_HS 512
#define MAX_PACKET_SIZE_SS 1024

#define FB_FFS_NUM_BUFS 16
#define FB_FFS_BUF_SIZE 32768

constexpr const char* USB_FFS_FASTBOOT_EP0 = "/dev/usb-ffs/fastboot/ep0";
constexpr const char* USB_FFS_FASTBOOT_OUT = "/dev/usb-ffs/fastboot/ep1";
constexpr const char* USB_FFS_FASTBOOT_IN = "/dev/usb-ffs/fastboot/ep2";

struct func_desc {
    struct usb_interface_descriptor intf;
    struct usb_endpoint_descriptor_no_audio source;
    struct usb_endpoint_descriptor_no_audio sink;
} __attribute__((packed));

struct ss_func_desc {
    struct usb_interface_descriptor intf;
    struct usb_endpoint_descriptor_no_audio source;
    struct usb_ss_ep_comp_descriptor source_comp;
    struct usb_endpoint_descriptor_no_audio sink;
    struct usb_ss_ep_comp_descriptor sink_comp;
} __attribute__((packed));

struct desc_v2 {
    struct usb_functionfs_descs_head_v2 header;
    // The rest of the structure depends on the flags in the header.
    __le32 fs_count;
    __le32 hs_count;
    __le32 ss_count;
    struct func_desc fs_descs, hs_descs;
    struct ss_func_desc ss_descs;
} __attribute__((packed));

struct usb_interface_descriptor fastboot_interface = {
        .bLength = USB_DT_INTERFACE_SIZE,
        .bDescriptorType = USB_DT_INTERFACE,
        .bInterfaceNumber = 0,
        .bNumEndpoints = 2,
        .bInterfaceClass = USB_CLASS_VENDOR_SPEC,
        .bInterfaceSubClass = 66,
        .bInterfaceProtocol = 3,
        .iInterface = 1, /* first string from the provided table */
};

static struct func_desc fs_descriptors = {
        .intf = fastboot_interface,
        .source =
                {
                        .bLength = sizeof(fs_descriptors.source),
                        .bDescriptorType = USB_DT_ENDPOINT,
                        .bEndpointAddress = 1 | USB_DIR_OUT,
                        .bmAttributes = USB_ENDPOINT_XFER_BULK,
                        .wMaxPacketSize = MAX_PACKET_SIZE_FS,
                },
        .sink =
                {
                        .bLength = sizeof(fs_descriptors.sink),
                        .bDescriptorType = USB_DT_ENDPOINT,
                        .bEndpointAddress = 2 | USB_DIR_IN,
                        .bmAttributes = USB_ENDPOINT_XFER_BULK,
                        .wMaxPacketSize = MAX_PACKET_SIZE_FS,
                },
};

static struct func_desc hs_descriptors = {
        .intf = fastboot_interface,
        .source =
                {
                        .bLength = sizeof(hs_descriptors.source),
                        .bDescriptorType = USB_DT_ENDPOINT,
                        .bEndpointAddress = 1 | USB_DIR_OUT,
                        .bmAttributes = USB_ENDPOINT_XFER_BULK,
                        .wMaxPacketSize = MAX_PACKET_SIZE_HS,
                },
        .sink =
                {
                        .bLength = sizeof(hs_descriptors.sink),
                        .bDescriptorType = USB_DT_ENDPOINT,
                        .bEndpointAddress = 2 | USB_DIR_IN,
                        .bmAttributes = USB_ENDPOINT_XFER_BULK,
                        .wMaxPacketSize = MAX_PACKET_SIZE_HS,
                },
};

static struct ss_func_desc ss_descriptors = {
        .intf = fastboot_interface,
        .source =
                {
                        .bLength = sizeof(ss_descriptors.source),
                        .bDescriptorType = USB_DT_ENDPOINT,
                        .bEndpointAddress = 1 | USB_DIR_OUT,
                        .bmAttributes = USB_ENDPOINT_XFER_BULK,
                        .wMaxPacketSize = MAX_PACKET_SIZE_SS,
                },
        .source_comp =
                {
                        .bLength = sizeof(ss_descriptors.source_comp),
                        .bDescriptorType = USB_DT_SS_ENDPOINT_COMP,
                        .bMaxBurst = 15,
                },
        .sink =
                {
                        .bLength = sizeof(ss_descriptors.sink),
                        .bDescriptorType = USB_DT_ENDPOINT,
                        .bEndpointAddress = 2 | USB_DIR_IN,
                        .bmAttributes = USB_ENDPOINT_XFER_BULK,
                        .wMaxPacketSize = MAX_PACKET_SIZE_SS,
                },
        .sink_comp =
                {
                        .bLength = sizeof(ss_descriptors.sink_comp),
                        .bDescriptorType = USB_DT_SS_ENDPOINT_COMP,
                        .bMaxBurst = 15,
                },
};

#define STR_INTERFACE_ "fastboot"

static const struct {
    struct usb_functionfs_strings_head header;
    struct {
        __le16 code;
        const char str1[sizeof(STR_INTERFACE_)];
    } __attribute__((packed)) lang0;
} __attribute__((packed)) strings = {
        .header =
                {
                        .magic = htole32(FUNCTIONFS_STRINGS_MAGIC),
                        .length = htole32(sizeof(strings)),
                        .str_count = htole32(1),
                        .lang_count = htole32(1),
                },
        .lang0 =
                {
                        htole16(0x0409), /* en-us */
                        STR_INTERFACE_,
                },
};

static struct desc_v2 v2_descriptor = {
        .header =
                {
                        .magic = htole32(FUNCTIONFS_DESCRIPTORS_MAGIC_V2),
                        .length = htole32(sizeof(v2_descriptor)),
                        .flags = FUNCTIONFS_HAS_FS_DESC | FUNCTIONFS_HAS_HS_DESC |
                                 FUNCTIONFS_HAS_SS_DESC,
                },
        .fs_count = 3,
        .hs_count = 3,
        .ss_count = 5,
        .fs_descs = fs_descriptors,
        .hs_descs = hs_descriptors,
        .ss_descs = ss_descriptors,
};

static void close_functionfs(usb_handle* h) {
    if (h->bulk_in > 0) {
        close(h->bulk_in);
        h->bulk_in = -1;
    }
    if (h->bulk_out > 0) {
        close(h->bulk_out);
        h->bulk_out = -1;
    }
    if (h->control > 0) {
        close(h->control);
        h->control = -1;
    }
}

static bool init_functionfs(usb_handle* h) {
    ssize_t ret;
    LOG(INFO) << "initializing functionfs";

    if (h->control < 0) {  // might have already done this before
        LOG(INFO) << "opening control endpoint " << USB_FFS_FASTBOOT_EP0;
        h->control = open(USB_FFS_FASTBOOT_EP0, O_RDWR);
        if (h->control < 0) {
            PLOG(ERROR) << "cannot open control endpoint " << USB_FFS_FASTBOOT_EP0;
            goto err;
        }

        ret = write(h->control, &v2_descriptor, sizeof(v2_descriptor));
        if (ret < 0) {
            PLOG(ERROR) << "cannot write descriptors " << USB_FFS_FASTBOOT_EP0;
            goto err;
        }

        ret = write(h->control, &strings, sizeof(strings));
        if (ret < 0) {
            PLOG(ERROR) << "cannot write strings " << USB_FFS_FASTBOOT_EP0;
            goto err;
        }
        // Signal only when writing the descriptors to ffs
        android::base::SetProperty("sys.usb.ffs.ready", "1");
    }

    h->bulk_out = open(USB_FFS_FASTBOOT_OUT, O_RDONLY);
    if (h->bulk_out < 0) {
        PLOG(ERROR) << "cannot open bulk-out endpoint " << USB_FFS_FASTBOOT_OUT;
        goto err;
    }

    h->bulk_in = open(USB_FFS_FASTBOOT_IN, O_WRONLY);
    if (h->bulk_in < 0) {
        PLOG(ERROR) << "cannot open bulk-in endpoint " << USB_FFS_FASTBOOT_IN;
        goto err;
    }

    h->read_aiob.fd = h->bulk_out;
    h->write_aiob.fd = h->bulk_in;
    h->reads_zero_packets = false;
    return true;

err:
    close_functionfs(h);
    return false;
}

ClientUsbTransport::ClientUsbTransport()
    : handle_(std::unique_ptr<usb_handle>(get_usb_handle(FB_FFS_NUM_BUFS, FB_FFS_BUF_SIZE))) {
    if (!init_functionfs(handle_.get())) {
        handle_.reset(nullptr);
    }
}

ssize_t ClientUsbTransport::Read(void* data, size_t len) {
    if (handle_ == nullptr) {
        return -1;
    }
    char* char_data = reinterpret_cast<char*>(data);
    ssize_t ret = 0;
    while (ret < static_cast<ssize_t>(len)) {
        int this_len =
                std::min(len - ret, static_cast<unsigned long>(FB_FFS_NUM_BUFS * FB_FFS_BUF_SIZE));
        int this_ret = handle_->read(handle_.get(), char_data, this_len);
        ret += this_ret;
        char_data += this_len;
        if (this_ret < 0) {
            return this_ret;
        } else if (this_ret < this_len) {
            break;
        }
    }
    return ret;
}

ssize_t ClientUsbTransport::Write(const void* data, size_t len) {
    if (handle_ == nullptr) {
        return -1;
    }
    const char* char_data = reinterpret_cast<const char*>(data);
    ssize_t ret = 0;
    while (ret < static_cast<ssize_t>(len)) {
        int this_len =
                std::min(len - ret, static_cast<unsigned long>(FB_FFS_NUM_BUFS * FB_FFS_BUF_SIZE));
        int this_ret = handle_->write(handle_.get(), data, len);
        ret += this_ret;
        char_data += this_len;
        if (this_ret < 0) {
            return this_ret;
        } else if (this_ret < this_len) {
            break;
        }
    }
    return ret;
}

int ClientUsbTransport::Close() {
    if (handle_ == nullptr) {
        return -1;
    }
    close_functionfs(handle_.get());
    return 0;
};
