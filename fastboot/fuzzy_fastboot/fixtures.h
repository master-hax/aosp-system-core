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
#pragma once
#include <gtest/gtest.h>

#include "fastboot_driver.h"

#include "extensions.h"
#include "usb_transport_sniffer.h"

namespace fastboot {

const int USB_TIMEOUT = 30000;

constexpr char USB_PORT_GONE[] =
        "The USB port has disappeared, this is usually due to the bootloader crashing";

class FastBootTest : public testing::Test {
  public:
    static int serial_port;
    static constexpr int MAX_USB_TRIES = 10;

    static int MatchFastboot(usb_ifc_info* info, const char* local_serial = nullptr);
    bool UsbStillAvailible();

  protected:
    RetCode DownloadCommand(uint32_t size, std::string* response = nullptr,
                            std::vector<std::string>* info = nullptr);

    RetCode SendBuffer(const std::vector<char>& buf);
    RetCode HandleResponse(std::string* response = nullptr,
                           std::vector<std::string>* info = nullptr, int* dsize = nullptr);

    void SetUp() override;
    void TearDown() override;
    void TearDownSerial();
    void ChangeLockState(bool unlock, bool assert_change = true);

    std::unique_ptr<UsbTransportSniffer> transport;
    std::unique_ptr<FastBootDriver> fb;

  private:
    // This is an annoying hack
    static std::string cb_scratch;
    static std::string device_path;
};

class BasicFunctionality : public FastBootTest {
  protected:
    void SetUp() override;
};

class Conformance : public FastBootTest {
  protected:
    void SetUp() override;
};

class UnlockPermissions : public FastBootTest {
  protected:
    void SetUp() override;
};

class LockPermissions : public FastBootTest {
  protected:
    void SetUp() override;
};

// Magic C++ double inheritance
class ExtensionsGetVarConformance
    : public FastBootTest,
      public ::testing::WithParamInterface<
              std::pair<std::string, extension::Configuration::GetVar>> {
  protected:
    void SetUp() override;
};

class ExtensionsOemConformance
    : public FastBootTest,
      public ::testing::WithParamInterface<
              std::tuple<std::string, bool, extension::Configuration::CommandTest>> {
  protected:
    void SetUp() override;
};

class ExtensionsPartition
    : public FastBootTest,
      public ::testing::WithParamInterface<
              std::pair<std::string, extension::Configuration::PartitionInfo>> {
  protected:
    void SetUp() override;
};

class AnyPartition : public ExtensionsPartition {};
class WriteablePartition : public ExtensionsPartition {};
class WriteHashablePartition : public ExtensionsPartition {};
class WriteHashNonParsedPartition : public ExtensionsPartition {};

class Fuzz : public FastBootTest {
  protected:
    void SetUp() override;
    void TearDown() override;
};

}  // end namespace fastboot
