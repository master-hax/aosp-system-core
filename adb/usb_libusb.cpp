/*
 * Copyright (C) 2016 The Android Open Source Project
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

#include "sysdeps.h"

#include <stdint.h>

#include <atomic>
#include <chrono>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>

#include <libusb/libusb.h>

#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/quick_exit.h>
#include <android-base/stringprintf.h>
#include <android-base/strings.h>

#include "adb.h"
#include "transport.h"

using namespace std::literals;

using android::base::StringPrintf;

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

using unique_device_handle = std::unique_ptr<libusb_device_handle, DeviceHandleDeleter>;

struct transfer_info {
    transfer_info() {
        transfer = libusb_alloc_transfer(0);
    }

    ~transfer_info() {
        libusb_free_transfer(transfer);
    }

    libusb_transfer* transfer;
    std::condition_variable cv;
    std::mutex mutex;
};

struct usb_handle {
    usb_handle(const std::string& device_address, const std::string& serial,
               unique_device_handle&& device_handle, uint8_t interface, uint8_t bulk_in,
               uint8_t bulk_out, size_t zero_mask)
        : device_address(device_address),
          serial(serial),
          device_handle(device_handle.release()),
          closing(false),
          active_transfers(0),
          interface(interface),
          bulk_in(bulk_in),
          bulk_out(bulk_out),
          zero_mask(zero_mask) {
    }

    ~usb_handle() {
        Close();
    }

    void Close() {
        // Cancelling transfers will trigger more Closes, so make sure this only happens once.
        if (closing) {
            return;
        }
        closing = true;

        // Make sure that no new transfers come in.
        libusb_device_handle* handle = nullptr;
        device_handle.exchange(handle);

        while (active_transfers) {
            // Make sure that new transfers that came in anyway get cancelled.
            libusb_cancel_transfer(read.transfer);
            libusb_cancel_transfer(write.transfer);
            std::this_thread::sleep_for(10ms);
        }

        // Once we know that no transfers are left, finally close the handle.
        if (handle) {
            libusb_release_interface(handle, interface);
            libusb_close(handle);
        }
    }

    std::string device_address;
    std::string serial;

    std::atomic<libusb_device_handle*> device_handle;

    transfer_info read;
    transfer_info write;

    std::atomic<bool> closing;
    std::atomic<int> active_transfers;

    uint8_t interface;
    uint8_t bulk_in;
    uint8_t bulk_out;
    uint16_t zero_mask;
};

class BorrowedDeviceHandle {
  public:
    explicit BorrowedDeviceHandle(usb_handle* handle) : handle(handle) {
        ++handle->active_transfers;
        device_handle = handle->device_handle.load();
    }

    ~BorrowedDeviceHandle() {
        --handle->active_transfers;
    }

    libusb_device_handle* get() {
        return device_handle;
    }

    operator bool() {
        return device_handle;
    }

  private:
    usb_handle* handle;
    libusb_device_handle* device_handle;
};

static auto& usb_handles = *new std::unordered_map<std::string, std::unique_ptr<usb_handle>>();
static auto& usb_handles_mutex = *new std::recursive_mutex();

static std::thread* device_poll_thread = nullptr;

static std::string get_device_address(libusb_device* device) {
    return StringPrintf("usb:%d:%d", libusb_get_bus_number(device),
                        libusb_get_device_address(device));
}

static bool endpoint_is_output(int endpoint) {
    return (endpoint & LIBUSB_ENDPOINT_DIR_MASK) == LIBUSB_ENDPOINT_OUT;
}

static void poll_for_devices() {
    libusb_device** list;
    adb_thread_setname("device poll");
    while (true) {
        const ssize_t device_count = libusb_get_device_list(nullptr, &list);

        LOG(VERBOSE) << "found " << device_count << " attached devices";

        for (ssize_t i = 0; i < device_count; ++i) {
            libusb_device* device = list[i];
            std::string device_address = get_device_address(device);
            std::string device_serial;

            // Figure out if we want to open the device.
            libusb_device_descriptor device_desc;
            int rc = libusb_get_device_descriptor(device, &device_desc);
            if (rc != 0) {
                LOG(WARNING) << "failed to get device descriptor for device at " << device_address
                             << ": " << libusb_error_name(rc);
            }

            if (device_desc.bDeviceClass != LIBUSB_CLASS_PER_INTERFACE) {
                // Assume that all Android devices have the device class set to per interface.
                // TODO: Is this assumption valid?
                LOG(VERBOSE) << "skipping device with incorrect class at " << device_address;
                continue;
            }

            libusb_config_descriptor* config_raw;
            rc = libusb_get_active_config_descriptor(device, &config_raw);
            if (rc != 0) {
                LOG(WARNING) << "failed to get active config descriptor for device at "
                             << device_address << ": " << libusb_error_name(rc);
                continue;
            }
            const unique_config_descriptor config(config_raw);

            // Use size_t for interface_num so <iostream>s don't mangle it.
            size_t interface_num;
            uint16_t zero_mask;
            uint8_t bulk_in = 0, bulk_out = 0;
            bool found_adb = false;

            for (interface_num = 0; interface_num < config->bNumInterfaces; ++interface_num) {
                const libusb_interface& interface = config->interface[interface_num];
                if (interface.num_altsetting != 1) {
                    // Assume that interfaces with alternate settings aren't adb interfaces.
                    // TODO: Is this assumption valid?
                    LOG(VERBOSE) << "skipping interface with incorrect num_altsetting at "
                                 << device_address << " (interface " << interface_num << ")";
                    continue;
                }

                const libusb_interface_descriptor& interface_desc = interface.altsetting[0];
                if (!is_adb_interface(interface_desc.bInterfaceClass,
                                      interface_desc.bInterfaceSubClass,
                                      interface_desc.bInterfaceProtocol)) {
                    LOG(VERBOSE) << "skipping non-adb interface at " << device_address
                                 << " (interface " << interface_num << ")";
                    continue;
                }

                LOG(VERBOSE) << "found potential adb interface at " << device_address
                             << " (interface " << interface_num << ")";

                bool found_in = false;
                bool found_out = false;
                for (size_t endpoint_num = 0; endpoint_num < interface_desc.bNumEndpoints;
                     ++endpoint_num) {
                    const auto& endpoint_desc = interface_desc.endpoint[endpoint_num];
                    const uint8_t endpoint_addr = endpoint_desc.bEndpointAddress;
                    const uint8_t endpoint_attr = endpoint_desc.bmAttributes;

                    const uint8_t transfer_type = endpoint_attr & LIBUSB_TRANSFER_TYPE_MASK;

                    if (transfer_type != LIBUSB_TRANSFER_TYPE_BULK) {
                        continue;
                    }

                    if (endpoint_is_output(endpoint_addr) && !found_out) {
                        found_out = true;
                        bulk_out = endpoint_addr;
                        zero_mask = endpoint_desc.wMaxPacketSize - 1;
                    } else if (!endpoint_is_output(endpoint_addr) && !found_in) {
                        found_in = true;
                        bulk_in = endpoint_addr;
                    }
                }

                if (found_in && found_out) {
                    found_adb = true;
                    break;
                } else {
                    LOG(VERBOSE) << "rejecting potential adb interface at " << device_address
                                 << "(interface " << interface_num << "): missing bulk endpoints "
                                 << "(found_in = " << found_in << ", found_out = " << found_out
                                 << ")";
                }
            }

            if (!found_adb) {
                LOG(VERBOSE) << "skipping device with no adb interfaces at " << device_address;
                continue;
            }

            std::unique_lock<std::recursive_mutex> lock(usb_handles_mutex);
            if (usb_handles.find(device_address) != usb_handles.end()) {
                LOG(VERBOSE) << "device at " << device_address
                             << " has already been registered, skipping";
                continue;
            }

            libusb_device_handle* handle_raw;
            rc = libusb_open(list[i], &handle_raw);
            if (rc != 0) {
                LOG(WARNING) << "failed to open usb device at " << device_address << ": "
                             << libusb_error_name(rc);
                continue;
            }

            unique_device_handle handle(handle_raw);
            LOG(DEBUG) << "successfully opened adb device at " << device_address << ", "
                       << StringPrintf("bulk_in = %#x, bulk_out = %#x", bulk_in, bulk_out);

            device_serial.resize(255);
            rc = libusb_get_string_descriptor_ascii(
                handle_raw, device_desc.iSerialNumber,
                reinterpret_cast<unsigned char*>(&device_serial[0]), device_serial.length());
            if (rc == 0) {
                LOG(WARNING) << "received empty serial from device at " << device_address;
                continue;
            } else if (rc < 0) {
                LOG(WARNING) << "failed to get serial from device at " << device_address
                             << libusb_error_name(rc);
                continue;
            }
            device_serial.resize(rc);

            // Try to reset the device.
            rc = libusb_reset_device(handle_raw);
            if (rc != 0) {
                LOG(WARNING) << "failed to reset opened device '" << device_serial
                             << "': " << libusb_error_name(rc);
                continue;
            }

            // WARNING: this isn't released via RAII.
            rc = libusb_claim_interface(handle.get(), interface_num);
            if (rc != 0) {
                LOG(WARNING) << "failed to claim adb interface for device '" << device_serial << "'"
                             << libusb_error_name(rc);
                continue;
            }

            for (uint8_t endpoint : {bulk_in, bulk_out}) {
                rc = libusb_clear_halt(handle.get(), endpoint);
                if (rc != 0) {
                    LOG(WARNING) << "failed to clear halt on device '" << device_serial
                                 << "' endpoint 0x" << std::hex << endpoint << ": "
                                 << libusb_error_name(rc);
                    libusb_release_interface(handle.get(), interface_num);
                    continue;
                }
            }

            auto result =
                std::make_unique<usb_handle>(device_address, device_serial, std::move(handle),
                                             interface_num, bulk_in, bulk_out, zero_mask);
            usb_handle* usb_handle_raw = result.get();
            usb_handles[device_address] = std::move(result);

            register_usb_transport(usb_handle_raw, device_serial.c_str(), device_address.c_str(), 1);

            LOG(INFO) << "registered new usb device '" << device_serial << "'";
        }
        libusb_free_device_list(list, 1);

        std::this_thread::sleep_for(500ms);
    }
}

void usb_init() {
    LOG(DEBUG) << "initializing libusb...";
    int rc = libusb_init(nullptr);
    if (rc != 0) {
        LOG(FATAL) << "failed to initialize libusb: " << libusb_error_name(rc);
    }

    // Spawn a thread for libusb_handle_events.
    std::thread([]() {
        adb_thread_setname("libusb");
        while (true) {
            libusb_handle_events(nullptr);
        }
    }).detach();

    // Spawn a thread to do device enumeration.
    // TODO: Use libusb_hotplug_* instead?
    device_poll_thread = new std::thread(poll_for_devices);
    android::base::at_quick_exit([]() {
        std::unique_lock<std::recursive_mutex> lock(usb_handles_mutex);
        for (auto& it : usb_handles) {
            it.second->Close();
        }
    });
}

static int perform_usb_transfer(usb_handle* h, transfer_info* info) {
    libusb_transfer* transfer = info->transfer;

    transfer->user_data = info;
    transfer->callback = [](libusb_transfer* transfer) {
        transfer_info* info = static_cast<transfer_info*>(transfer->user_data);

        // Make sure that the original submitter has made it to the condition_variable wait.
        LOG(DEBUG) << "transfer callback entered";
        std::unique_lock<std::mutex> lock(info->mutex);
        lock.unlock();
        LOG(DEBUG) << "callback successfully acquired lock";

        if (transfer->status != LIBUSB_TRANSFER_COMPLETED) {
            LOG(WARNING) << "transfer failed: " << libusb_error_name(transfer->status);
            info->cv.notify_one();
            return;
        }

        if (transfer->actual_length != transfer->length) {
            LOG(DEBUG) << "transfer incomplete, resubmitting";
            transfer->length -= transfer->actual_length;
            transfer->buffer += transfer->actual_length;
            int rc = libusb_submit_transfer(transfer);
            if (rc != 0) {
                LOG(WARNING) << "failed to submit transfer: " << libusb_error_name(rc);
                transfer->status = LIBUSB_TRANSFER_ERROR;
                info->cv.notify_one();
            }
            return;
        }

#if !defined(__linux__)
        if (endpoint_is_output && h->zero_mask && (h->zero_mask & transfer->length) == 0) {
            transfer->length = 0;
            int rc = libusb_submit_transfer(transfer);
            if (rc != 0) {
                LOG(WARNING) << "failed to submit transfer: " << libusb_error_name(rc);
                transfer->status = LIBUSB_TRANSFER_ERROR;
                h->write_cv.notify_one();
            }
            return;
        }
#endif
        LOG(VERBOSE) << "transfer fully complete";
        info->cv.notify_one();
    };

#if defined(__linux__)
    // libusb currently only supports this under Linux.
    if (endpoint_is_output(transfer->endpoint)) {
        if (h->zero_mask && (transfer->length & h->zero_mask) == 0) {
            transfer->flags |= LIBUSB_TRANSFER_ADD_ZERO_PACKET;
        }
    }
#endif

    std::unique_lock<std::mutex> lock(info->mutex);
    int rc = libusb_submit_transfer(transfer);
    if (rc != 0) {
        LOG(WARNING) << "failed to submit transfer: " << libusb_error_name(rc);
        errno = EIO;
        return -1;
    }

    info->cv.wait(lock);
    if (transfer->status != 0) {
        errno = EIO;
        return -1;
    }

    return 0;
}

int usb_write(usb_handle* h, const void* d, int len) {
    LOG(DEBUG) << "usb_write of length " << len;

    BorrowedDeviceHandle handle(h);
    if (!handle) {
        errno = EIO;
        return -1;
    }

    transfer_info* info = &h->write;
    info->transfer->dev_handle = handle.get();
    info->transfer->flags = 0;
    info->transfer->endpoint = h->bulk_out;
    info->transfer->type = LIBUSB_TRANSFER_TYPE_BULK;
    info->transfer->length = len;
    info->transfer->buffer = reinterpret_cast<unsigned char*>(const_cast<void*>(d));
    info->transfer->num_iso_packets = 0;

    int rc = perform_usb_transfer(h, info);
    LOG(DEBUG) << "usb_write(" << len << ") = " << rc;
    return rc;
}

int usb_read(usb_handle* h, void* d, int len) {
    LOG(DEBUG) << "usb_read of length " << len;

    BorrowedDeviceHandle handle(h);
    if (!handle) {
        errno = EIO;
        return -1;
    }

    transfer_info* info = &h->read;
    info->transfer->dev_handle = handle.get();
    info->transfer->flags = 0;
    info->transfer->endpoint = h->bulk_in;
    info->transfer->type = LIBUSB_TRANSFER_TYPE_BULK;
    info->transfer->length = len;
    info->transfer->buffer = reinterpret_cast<unsigned char*>(d);
    info->transfer->num_iso_packets = 0;

    int rc = perform_usb_transfer(h, info);
    LOG(DEBUG) << "usb_read(" << len << ") = " << rc;
    return rc;
}

int usb_close(usb_handle* h) {
    std::unique_lock<std::recursive_mutex> lock(usb_handles_mutex);
    auto it = usb_handles.find(h->device_address);
    if (it == usb_handles.end()) {
        LOG(FATAL) << "attempted to close unregistered usb_handle for '" << h->serial << "'";
    }
    it->second->Close();
    usb_handles.erase(h->device_address);
    return 0;
}

void usb_kick(usb_handle* h) {
    h->Close();
}
