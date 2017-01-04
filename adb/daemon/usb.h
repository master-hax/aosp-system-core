#pragma once

/*
 * Copyright (C) 2017 The Android Open Source Project
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

#include <atomic>
#include <condition_variable>
#include <mutex>

// Kernels before 3.3 have a 16KiB transfer limit  That limit was replaced
// with a 16MiB global limit in 3.3, but each URB submitted required a
// contiguous kernel allocation, so you would get ENOMEM if you tried to
// send something larger than the biggest available contiguous kernel
// memory region. Large contiguous allocations could be unreliable
// on a device kernel that has been running for a while fragmenting its
// memory so we start with a larger allocation, and shrink the amount if
// necessary.
#define USB_FFS_BULK_SIZE 16384

struct usb_handle {
    usb_handle() : kicked(false) {
    }

    std::condition_variable notify;
    std::mutex lock;
    std::atomic<bool> kicked;
    bool open_new_connection = true;

    int (*write)(usb_handle* h, const void* data, int len);
    int (*read)(usb_handle* h, void* data, int len);
    void (*kick)(usb_handle* h);
    void (*close)(usb_handle* h);

    // FunctionFS
    int control = -1;
    int bulk_out = -1; /* "out" from the host's perspective => source for adbd */
    int bulk_in = -1;  /* "in" from the host's perspective => sink for adbd */

    int max_rw;
};

bool init_functionfs(struct usb_handle* h);
