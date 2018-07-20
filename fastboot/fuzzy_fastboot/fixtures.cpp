/*
 * Copyright (C) 2018 The Android Open Source Project
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *  * Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *  * Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
 * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
 * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <termios.h>
#include <unistd.h>
#include <chrono>
#include <cstdlib>
#include <fstream>
#include <map>
#include <random>
#include <regex>
#include <set>
#include <thread>
#include <vector>

#include <android-base/stringprintf.h>
#include <gtest/gtest.h>

#include "fastboot_driver.h"
#include "usb.h"

#include "extensions.h"
#include "fixtures.h"
#include "test_utils.h"
#include "usb_transport_sniffer.h"

namespace fastboot {

int FastBootTest::MatchFastboot(usb_ifc_info* info, const char* local_serial) {
    if (info->ifc_class != 0xff || info->ifc_subclass != 0x42 || info->ifc_protocol != 0x03) {
        return -1;
    }

    cb_scratch = info->device_path;

    // require matching serial number or device path if requested
    // at the command line with the -s option.
    if (local_serial && (strcmp(local_serial, info->serial_number) != 0 &&
                         strcmp(local_serial, info->device_path) != 0))
        return -1;
    return 0;
}

bool FastBootTest::UsbStillAvailible() {
    // For some reason someone decided to prefix the path with "usb:"
    std::string prefix("usb:");
    if (std::equal(prefix.begin(), prefix.end(), device_path.begin())) {
        std::string fname(device_path.begin() + prefix.size(), device_path.end());
        std::string real_path =
                android::base::StringPrintf("/sys/bus/usb/devices/%s/serial", fname.c_str());
        std::ifstream f(real_path.c_str());
        return f.good();
    }
    exit(-1);  // This should never happend
    return true;
}

RetCode FastBootTest::DownloadCommand(uint32_t size, std::string* response,
                                      std::vector<std::string>* info) {
    return fb->DownloadCommand(size, response, info);
}

RetCode FastBootTest::SendBuffer(const std::vector<char>& buf) {
    return fb->SendBuffer(buf);
}

RetCode FastBootTest::HandleResponse(std::string* response, std::vector<std::string>* info,
                                     int* dsize) {
    return fb->HandleResponse(response, info, dsize);
}

void FastBootTest::SetUp() {
    if (device_path != "") {               // make sure the device is still connected
        ASSERT_TRUE(UsbStillAvailible());  // The device disconnected
    }

    const auto matcher = [](usb_ifc_info* info) -> int { return MatchFastboot(info, nullptr); };
    for (int i = 0; i < MAX_USB_TRIES && !transport; i++) {
        std::unique_ptr<UsbTransport> usb(usb_open(matcher, USB_TIMEOUT));
        if (usb)
            transport = std::unique_ptr<UsbTransportSniffer>(
                    new UsbTransportSniffer(std::move(usb), serial_port));
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }

    ASSERT_TRUE(transport);  // no nullptr

    if (device_path == "") {  // We set it the first time, then make sure it never changes
        device_path = cb_scratch;
    } else {
        ASSERT_EQ(device_path, cb_scratch);  // The path can not change
    }
    fb = std::unique_ptr<FastBootDriver>(
            new FastBootDriver(transport.get(), [](std::string&) {}, true));
}

void FastBootTest::TearDown() {
    EXPECT_TRUE(UsbStillAvailible()) << USB_PORT_GONE;

    TearDownSerial();

    fb.reset();

    if (transport) {
        // transport->Reset();
        transport->Close();
        transport.reset();
    }

    ASSERT_TRUE(UsbStillAvailible()) << USB_PORT_GONE;
}

// TODO, this should eventually be piped to a file instead of stdout
void FastBootTest::TearDownSerial() {
    if (!transport) return;
    // One last read from serial
    transport->ProcessSerial();
    if (HasFailure()) {
        // TODO, print commands leading up
        printf("<<<<<<<< TRACE BEGIN >>>>>>>>>\n");
        printf("%s", transport->CreateTrace().c_str());
        printf("<<<<<<<< TRACE END >>>>>>>>>\n");
        // std::vector<std::pair<const TransferType, const std::vector<char>>>  prev =
        // transport->Transfers();
    }
}

void FastBootTest::WaitForDevice() {}

void FastBootTest::ChangeLockState(bool unlock, bool assert_change) {
    if (!fb) {
        return;
    }
    std::string resp;
    EXPECT_EQ(fb->GetVar("unlocked", &resp), SUCCESS) << "getvar:unlocked failed";
    ASSERT_TRUE(resp == "no" || resp == "yes")
            << "getvar:unlocked response was not 'no' or 'yes': " + resp;

    if ((unlock && resp == "no") || (!unlock && resp == "yes")) {
        std::string cmd = unlock ? "unlock" : "lock";
        ASSERT_EQ(fb->RawCommand("flashing " + cmd, &resp), SUCCESS)
                << "Attempting to change locked state, but 'flashing" + cmd + "' command failed";
        fb.reset();
        transport->Close();
        transport.reset();
        printf("PLEASE CONFIRM '%sing' BOOTLOADER ON DEVICE\n", cmd.c_str());
        while (UsbStillAvailible())
            ;  // Wait for disconnect
        printf("WAITING FOR DEVICE");
        // Need to wait for device
        const auto matcher = [](usb_ifc_info* info) -> int { return MatchFastboot(info, nullptr); };
        while (!transport) {
            std::unique_ptr<UsbTransport> usb(usb_open(matcher, USB_TIMEOUT));
            if (usb) {
                transport = std::unique_ptr<UsbTransportSniffer>(
                        new UsbTransportSniffer(std::move(usb), serial_port));
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(1000));
            putchar('.');
        }
        device_path = cb_scratch;
        fb = std::unique_ptr<FastBootDriver>(
                new FastBootDriver(transport.get(), [](std::string&) {}, true));
        if (assert_change) {
            ASSERT_EQ(fb->GetVar("unlocked", &resp), SUCCESS) << "getvar:unlocked failed";
            ASSERT_EQ(resp, unlock ? "yes" : "no")
                    << "getvar:unlocked response was not 'no' or 'yes': " + resp;
        }
        printf("SUCCESS\n");
    }
}

std::string FastBootTest::device_path = "";
std::string FastBootTest::cb_scratch = "";
int FastBootTest::serial_port = 0;

void BasicFunctionality::SetUp() {
    FastBootTest::SetUp();
    ChangeLockState(true);
}

void Conformance::SetUp() {
    FastBootTest::SetUp();
    ChangeLockState(true);
}

void UnlockPermissions::SetUp() {
    FastBootTest::SetUp();
    ChangeLockState(true);
}

void LockPermissions::SetUp() {
    FastBootTest::SetUp();
    ChangeLockState(false);
}

void ExtensionsGetVarConformance::SetUp() {
    FastBootTest::SetUp();
    ChangeLockState(true);
}

void ExtensionsOemConformance::SetUp() {
    FastBootTest::SetUp();
    ChangeLockState(true);
}

void ExtensionsPartition::SetUp() {
    FastBootTest::SetUp();
    ChangeLockState(true);
}

void Fuzz::SetUp() {
    FastBootTest::SetUp();
    ChangeLockState(true);
}

void Fuzz::TearDown() {
    ASSERT_TRUE(UsbStillAvailible()) << USB_PORT_GONE;

    TearDownSerial();

    std::string tmp;
    if (fb->GetVar("product", &tmp) != SUCCESS) {
        printf("DEVICE UNRESPONSE, attempting to recover...");
        transport->Reset();
        printf("issued USB reset...");

        if (fb->GetVar("product", &tmp) != SUCCESS) {
            printf("FAIL\n");
            exit(-1);
        }
        printf("SUCCESS!\n");
    }

    if (transport) {
        transport->Close();
        transport.reset();
    }

    ASSERT_TRUE(UsbStillAvailible()) << USB_PORT_GONE;
}

}  // end namespace fastboot
