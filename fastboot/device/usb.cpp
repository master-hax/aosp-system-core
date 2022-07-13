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

#include "usb.h"

#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <unistd.h>

#include <linux/usb/ch9.h>
#include <linux/usb/functionfs.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <mutex>
#include <thread>
#include "liburing.h"

#include <android-base/logging.h>
#include <android-base/properties.h>

using namespace std::chrono_literals;

#define D(...)
#define MAX_PACKET_SIZE_FS 64
#define MAX_PACKET_SIZE_HS 512
#define MAX_PACKET_SIZE_SS 1024

#define USB_FFS_BULK_SIZE 16384

static constexpr size_t IO_URING_QUEUE_DEPTH = 256;

static void aio_block_exit(aio_block* aiob) {
    io_uring_queue_exit(&aiob->ring);
}

static void aio_block_init(aio_block* aiob, unsigned /*num_bufs*/) {
    aiob->num_submitted = 0;
    const auto ret = io_uring_queue_init(IO_URING_QUEUE_DEPTH, &aiob->ring, 0);
    if (ret < 0) {
        D("Failed to initialize io_uring %d %s", ret, strerror(ret));
    }
}

static int getMaxPacketSize(int ffs_fd) {
    usb_endpoint_descriptor desc;
    if (ioctl(ffs_fd, FUNCTIONFS_ENDPOINT_DESC, reinterpret_cast<unsigned long>(&desc))) {
        D("[ could not get endpoint descriptor! (%d) ]", errno);
        return MAX_PACKET_SIZE_HS;
    } else {
        return desc.wMaxPacketSize;
    }
}

static int usb_ffs_write(usb_handle* h, const void* data, int len) {
    D("about to write (fd=%d, len=%d)", h->bulk_in.get(), len);

    const char* buf = static_cast<const char*>(data);
    int orig_len = len;
    while (len > 0) {
        int write_len = std::min(USB_FFS_BULK_SIZE, len);
        int n = write(h->bulk_in.get(), buf, write_len);
        if (n < 0) {
            D("ERROR: fd = %d, n = %d: %s", h->bulk_in.get(), n, strerror(errno));
            return -1;
        }
        buf += n;
        len -= n;
    }

    D("[ done fd=%d ]", h->bulk_in.get());
    return orig_len;
}

static int usb_ffs_read(usb_handle* h, void* data, int len, bool allow_partial) {
    D("about to read (fd=%d, len=%d)", h->bulk_out.get(), len);

    char* buf = static_cast<char*>(data);
    int orig_len = len;
    unsigned count = 0;
    while (len > 0) {
        int read_len = std::min(USB_FFS_BULK_SIZE, len);
        int n = read(h->bulk_out.get(), buf, read_len);
        if (n < 0) {
            D("ERROR: fd = %d, n = %d: %s", h->bulk_out.get(), n, strerror(errno));
            return -1;
        }
        buf += n;
        len -= n;
        count += n;

        // For fastbootd command such as "getvar all", len parameter is always set 64.
        // But what we read is actually less than 64.
        // For example, length 10 for "getvar all" command.
        // If we get less data than expected, this means there should be no more data.
        if (allow_partial && n < read_len) {
            orig_len = count;
            break;
        }
    }

    D("[ done fd=%d ]", h->bulk_out.get());
    return orig_len;
}

static void prep_async_read(struct io_uring* ring, int fd, void* data, size_t len, int64_t offset) {
    auto sqe = io_uring_get_sqe(ring);
    io_uring_prep_read(sqe, fd, data, len, offset);
}

static void prep_async_write(struct io_uring* ring, int fd, const void* data, size_t len,
                             int64_t offset) {
    auto sqe = io_uring_get_sqe(ring);
    io_uring_prep_write(sqe, fd, data, len, offset);
}

template <bool read, typename T>
void prep_async_io(struct io_uring* ring, int fd, T* data, size_t len, int64_t offset) {
    if constexpr (read) {
        prep_async_read(ring, fd, data, len, offset);
    } else {
        prep_async_write(ring, fd, data, len, offset);
    }
}

template <bool read, typename T>
static int usb_ffs_do_aio(usb_handle* h, T* const data, int len) {
    if (h == nullptr) {
        return -1;
    }
    aio_block* aiob = read ? &h->read_aiob : &h->write_aiob;
    bool zero_packet = false;

    int num_bufs = len / h->io_size + (len % h->io_size == 0 ? 0 : 1);
    const auto packet_size = getMaxPacketSize(aiob->fd);
    auto cur_data = data;

    for (int i = 0; i < num_bufs; i++) {
        const int buf_len = std::min(len, static_cast<int>(h->io_size));
        prep_async_io<read>(&aiob->ring, aiob->fd, cur_data, buf_len, 0);

        len -= buf_len;
        cur_data = reinterpret_cast<T*>(reinterpret_cast<size_t>(cur_data) + buf_len);

        if (len == 0 && buf_len % packet_size == 0 && read) {
            // adb does not expect the device to send a zero packet after data transfer,
            // but the host *does* send a zero packet for the device to read.
            zero_packet = h->reads_zero_packets;
        }
    }
    if (zero_packet) {
        prep_async_io<read>(&aiob->ring, aiob->fd, cur_data, packet_size, 0);

        num_bufs += 1;
    }
    int ret = io_uring_submit(&aiob->ring);
    if (ret <= 0) {
        PLOG(ERROR) << "io_uring: failed to submit SQE entries to kernel";
    }
    int res = 0;
    for (int i = 0; i < num_bufs; ++i) {
        struct io_uring_cqe* cqe{};
        const auto ret = TEMP_FAILURE_RETRY(io_uring_wait_cqe(&aiob->ring, &cqe));
        if (ret < 0 || cqe == nullptr) {
            PLOG(ERROR) << "Failed to get CQE from kernel";
            return -1;
        }
        res += cqe->res;
        io_uring_cqe_seen(&aiob->ring, cqe);
    }
    return res;
}

static int usb_ffs_aio_read(usb_handle* h, void* data, int len, bool /* allow_partial */) {
    return usb_ffs_do_aio<true>(h, data, len);
}

static int usb_ffs_aio_write(usb_handle* h, const void* data, int len) {
    return usb_ffs_do_aio<false>(h, data, len);
}

static void usb_ffs_close(usb_handle* h) {
    LOG(INFO) << "closing functionfs transport";

    h->bulk_out.reset();
    h->bulk_in.reset();

    if (h->write == usb_ffs_aio_write) {
        aio_block_exit(&h->read_aiob);
        aio_block_exit(&h->write_aiob);
    }

    // Notify usb_adb_open_thread to open a new connection.
    h->lock.lock();
    h->open_new_connection = true;
    h->lock.unlock();
    h->notify.notify_one();
}

usb_handle* create_usb_handle(unsigned num_bufs, unsigned io_size) {
    usb_handle* h = new usb_handle();

    if (android::base::GetBoolProperty("sys.usb.ffs.aio_compat", false)) {
        // Devices on older kernels (< 3.18) will not have aio support for ffs
        // unless backported. Fall back on the non-aio functions instead.
        h->write = usb_ffs_write;
        h->read = usb_ffs_read;
    } else {
        h->write = usb_ffs_aio_write;
        h->read = usb_ffs_aio_read;
        aio_block_init(&h->read_aiob, num_bufs);
        aio_block_init(&h->write_aiob, num_bufs);
    }
    h->io_size = io_size;
    h->close = usb_ffs_close;
    return h;
}
