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

#undef NDEBUG
#include <assert.h>
#include <err.h>
#include <stdlib.h>
#include <sys/types.h>

#include <algorithm>
#include <chrono>
#include <memory>

#include <android-base/file.h>
#include <android-base/stringprintf.h>
#include <android-base/logging.h>
#include <libusb/libusb.h>

#include "bench_adb.h"

using android::base::ReadFully;
using android::base::StringPrintf;
using android::base::WriteFully;
using namespace std::chrono_literals;

#define ADB_CLASS              0xff
#define ADB_SUBCLASS           0x42
#define ADB_PROTOCOL           0x1

static int is_adb_interface(int usb_class, int usb_subclass, int usb_protocol) {
    return (usb_class == ADB_CLASS && usb_subclass == ADB_SUBCLASS && usb_protocol == ADB_PROTOCOL);
}

// TODO: Merge the libusb CL and remove all of this copy/pasted code.
// RAII wrappers for libusb.
struct ConfigDescriptorDeleter {
    void operator()(libusb_config_descriptor* desc) {
        libusb_free_config_descriptor(desc);
    }
};

using unique_config_descriptor = std::unique_ptr<libusb_config_descriptor, ConfigDescriptorDeleter>;

struct DeviceHandleDeleter {
    void operator()(libusb_device_handle* h) {
        libusb_close(h);
    }
};

static std::string get_device_address(libusb_device* device) {
    return StringPrintf("usb:%d:%d", libusb_get_bus_number(device),
                        libusb_get_device_address(device));
}

static bool endpoint_is_output(uint8_t endpoint) {
    return (endpoint & LIBUSB_ENDPOINT_DIR_MASK) == LIBUSB_ENDPOINT_OUT;
}

bool find_adb_interface(libusb_device* device, int* iface_num, uint8_t* bulk_in, uint8_t* bulk_out) {
    std::string device_address = get_device_address(device);
    libusb_device_descriptor device_desc;
    int rc = libusb_get_device_descriptor(device, &device_desc);
    if (rc != 0) {
        LOG(WARNING) << "failed to get device descriptor for device at " << device_address << ": "
                     << libusb_error_name(rc);
        return false;
    }

    if (device_desc.bDeviceClass != LIBUSB_CLASS_PER_INTERFACE) {
        // Assume that all Android devices have the device class set to per interface.
        // TODO: Is this assumption valid?
        LOG(VERBOSE) << "skipping device with incorrect class at " << device_address;
        return false;
    }

    libusb_config_descriptor* config_raw;
    rc = libusb_get_active_config_descriptor(device, &config_raw);
    if (rc != 0) {
        LOG(WARNING) << "failed to get active config descriptor for device at " << device_address
                     << ": " << libusb_error_name(rc);
        return false;
    }
    const unique_config_descriptor config(config_raw);

    // Use size_t for interface_num so <iostream>s don't mangle it.
    size_t interface_num;
    uint16_t dummy;
    uint16_t* zero_mask = &dummy;
    bool found_adb = false;

    for (interface_num = 0; interface_num < config->bNumInterfaces; ++interface_num) {
        const libusb_interface& interface = config->interface[interface_num];
        if (interface.num_altsetting != 1) {
            // Assume that interfaces with alternate settings aren't adb interfaces.
            // TODO: Is this assumption valid?
            LOG(VERBOSE) << "skipping interface with incorrect num_altsetting at " << device_address
                         << " (interface " << interface_num << ")";
            continue;
        }

        const libusb_interface_descriptor& interface_desc = interface.altsetting[0];
        if (!is_adb_interface(interface_desc.bInterfaceClass, interface_desc.bInterfaceSubClass,
                              interface_desc.bInterfaceProtocol)) {
            LOG(VERBOSE) << "skipping non-adb interface at " << device_address << " (interface "
                         << interface_num << ")";
            continue;
        }

        LOG(VERBOSE) << "found potential adb interface at " << device_address << " (interface "
                     << interface_num << ")";

        bool found_in = false;
        bool found_out = false;
        for (size_t endpoint_num = 0; endpoint_num < interface_desc.bNumEndpoints; ++endpoint_num) {
            const auto& endpoint_desc = interface_desc.endpoint[endpoint_num];
            const uint8_t endpoint_addr = endpoint_desc.bEndpointAddress;
            const uint8_t endpoint_attr = endpoint_desc.bmAttributes;

            const uint8_t transfer_type = endpoint_attr & LIBUSB_TRANSFER_TYPE_MASK;

            if (transfer_type != LIBUSB_TRANSFER_TYPE_BULK) {
                continue;
            }

            if (endpoint_is_output(endpoint_addr) && !found_out) {
                found_out = true;
                *bulk_out = endpoint_addr;
                *zero_mask = endpoint_desc.wMaxPacketSize - 1;
            } else if (!endpoint_is_output(endpoint_addr) && !found_in) {
                found_in = true;
                *bulk_in = endpoint_addr;
            }
        }

        if (found_in && found_out) {
            found_adb = true;
            break;
        } else {
            LOG(VERBOSE) << "rejecting potential adb interface at " << device_address
                         << "(interface " << interface_num << "): missing bulk endpoints "
                         << "(found_in = " << found_in << ", found_out = " << found_out << ")";
        }
    }

    if (!found_adb) {
        LOG(VERBOSE) << "skipping device with no adb interfaces at " << device_address;
        return false;
    }

    *iface_num = interface_num;
    return true;
}

bool libusb_PerformFully(libusb_device_handle* handle, uint8_t endpoint, void* buf, size_t len) {
    int rc;
    int actual_length;
    unsigned char* c = static_cast<unsigned char*>(buf);

    while (len) {
        rc = libusb_bulk_transfer(handle, endpoint, const_cast<unsigned char*>(c), len,
                                  &actual_length, 0);
        if (rc != 0 || actual_length == 0) {
            errno = EIO;
            return false;
        }

        len -= actual_length;
        c += actual_length;
    }

    return true;
}

bool libusb_ReadFully(libusb_device_handle* handle, uint8_t endpoint, void* buf, size_t len) {
    assert(!endpoint_is_output(endpoint));
    return libusb_PerformFully(handle, endpoint, buf, len);
}

bool libusb_WriteFully(libusb_device_handle* handle, uint8_t endpoint, const void* buf, size_t len) {
    assert(endpoint_is_output(endpoint));
    return libusb_PerformFully(handle, endpoint, const_cast<void*>(buf), len);
}

int main() {
    libusb_init(nullptr);
    libusb_device_handle* handle = libusb_open_device_with_vid_pid(nullptr, 0x18d1, 0x4ee7);
    if (!handle) {
        errx(1, "failed to find adb device");
    }

    assert(handle);
    libusb_device* device = libusb_get_device(handle);

    int interface;
    uint8_t bulk_in, bulk_out;
    if (!find_adb_interface(device, &interface, &bulk_in, &bulk_out)) {
        errx(1, "target device doesn't have an ADB interface");
    }

    int rc = libusb_claim_interface(handle, interface);
    if (rc != 0) {
        LOG(FATAL) << "failed to claim USB interface: " << libusb_error_name(rc);
    }

    Timer timer;

    // Benchmark pulls.
    timer.start();
    BenchmarkCommand cmd = BenchmarkCommand::WRITE;
    uint32_t length = 128 * 1024 * 1024;
    if (!libusb_WriteFully(handle, bulk_out, &cmd, sizeof(cmd))) {
        LOG(FATAL) << "failed to write command to USB interface";
    }
    if (!libusb_WriteFully(handle, bulk_out, &length, sizeof(length))) {
        LOG(FATAL) << "failed to write length to USB interface";
    }
    while (length > 0) {
        char buf[TRANSFER_LENGTH];
        size_t read_len = std::min(size_t(length), sizeof(buf));
        if (!libusb_ReadFully(handle, bulk_in, buf, sizeof(buf))) {
            LOG(FATAL) << "failed to read remote data";
        }
        length -= read_len;
    }

    auto duration = timer.end();
    auto ms = duration / 1ms;

    LOG(INFO) << "pull of 128MiB took " << ms << "ms (" << (128 * 1000.0 / ms) << "MiB/s)";
    cmd = BenchmarkCommand::EXIT;
    if (!libusb_WriteFully(handle, bulk_out, &cmd, sizeof(cmd))) {
        LOG(INFO) << "failed to tell bench_adbd to exit";
    }
}
