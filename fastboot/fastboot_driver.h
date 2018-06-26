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
#include <cstdlib>
#include <deque>
#include <limits>
#include <string>
#include <vector>

#include <android-base/logging.h>
#include <android-base/stringprintf.h>
#include <bootimg.h>
#include <inttypes.h>
#include <sparse/sparse.h>
#include "fastboot_commands.h"

class Transport;

namespace fastboot {

static constexpr int FB_COMMAND_SZ = 64;
static constexpr int FB_RESPONSE_SZ = 64;

class FastBootDriver {
  public:
    static constexpr int RESP_TIMEOUT = 10;  // 10 seconds
    static constexpr int MAX_RESP_DATA_SIZE = std::numeric_limits<int32_t>::max();

    enum RetCode : int {
        SUCCESS = 0,
        BAD_ARG,
        IO_ERROR,
        BAD_DEV_RESP,
        DEVICE_FAIL,
        TIMEOUT,
        INTERAL_ERROR,
    };

    static const std::string RCString(RetCode rc);

    FastBootDriver(Transport& transport,
                   std::function<void(std::string&)> info = [](std::string& tmp) { (void)tmp; });

    /* HIGHER LEVEL COMMANDS */
    RetCode GetVarAll(std::vector<std::string>& resp);
    RetCode GetVar(const std::string& key, std::string& val);
    RetCode Flash(const std::string& part, std::vector<char>& data);
    RetCode Flash(const std::string& part, int fd, uint32_t sz);
    RetCode Flash(const std::string& part, sparse_file& s);
    RetCode Download(int fd, size_t size);
    RetCode Download(const std::vector<char>& buf);
    RetCode Download(sparse_file& s);
    RetCode Upload(const std::string& outfile);
    RetCode Erase(const std::string& part);
    RetCode SetActive(const std::string& part);
    RetCode Reboot();
    RetCode Partitions(std::vector<std::tuple<std::string, uint32_t>>& parts);
    RetCode Require(const std::string& var, const std::vector<std::string>& allowed, bool& reqmet,
                    bool invert = false);

    /* LOWER LEVEL COMMAND INTERFACE */
    RetCode Command(commands::Command& cmd, bool clear = true, int* dsize = nullptr);
    RetCode Command(commands::Command& cmd, std::string& val, bool clear = true,
                    int* dsize = nullptr);

    std::string Response();
    std::vector<std::string> Info();
    std::string Error();

    void SetInfoCallback(std::function<void(std::string&)> info);
    RetCode WaitForDisconnect();

    // TODO: these will be moved to protected after engine.cpp is updated to use Command()
    RetCode RawCommand(const std::string& cmd, bool clear = true, int* dsize = nullptr);
    RetCode RawCommand(const std::string& cmd, std::string& resp, bool clear = true,
                       int* dsize = nullptr);

  protected:
    Transport& transport;

  private:
    RetCode HandleResponse(bool clear = true, int* dsize = nullptr);
    RetCode SendBuffer(const std::vector<char>& buf);
    RetCode ReadBuffer(std::vector<char>& buf);

    void DisableChecks();
    // Error printing
    std::string ErrnoStr(const std::string& msg);

    std::string g_error;
    std::function<void(std::string&)> info_cb;
    bool disable_checks;

    std::string response;           // Stores the last response
    std::vector<std::string> info;  // Info sent back from device
};

}  // namespace fastboot
