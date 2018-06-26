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
#include "fastboot_driver.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <algorithm>
#include <chrono>
#include <memory>
#include <regex>
#include <vector>

#include <android-base/file.h>
#include <android-base/stringprintf.h>
#include <android-base/unique_fd.h>
#include <utils/FileMap.h>
#include "transport.h"

namespace fastboot {
/*************************** PUBLIC *******************************/
FastBootDriver::FastBootDriver(Transport& transport, std::function<void(std::string&)> info)
    : transport(transport) {
    info_cb = info;
    disable_checks = false;
}

void FastBootDriver::DisableChecks() {
    disable_checks = true;
}

void FastBootDriver::SetInfoCallback(std::function<void(std::string&)> info) {
    info_cb = info;
}

const std::string FastBootDriver::RCString(FastBootDriver::RetCode rc) {
    switch (rc) {
        case SUCCESS:
            return std::string("Success");

        case BAD_ARG:
            return std::string("Invalid Argument");

        case IO_ERROR:
            return std::string("I/O Error");

        case BAD_DEV_RESP:
            return std::string("Invalid Device Response");

        case DEVICE_FAIL:
            return std::string("Device Error");

        case TIMEOUT:
            return std::string("Timeout");

        default:
            return std::string("Unknown Error");
    }
}

std::string FastBootDriver::Error() {
    return g_error;
}

FastBootDriver::RetCode FastBootDriver::WaitForDisconnect() {
    return transport.WaitForDisconnect() ? IO_ERROR : SUCCESS;
}

FastBootDriver::RetCode FastBootDriver::GetVar(const std::string& key, std::string& val) {
    commands::GetVar cmd(key);
    return Command(cmd, val);
}

FastBootDriver::RetCode FastBootDriver::GetVarAll(std::vector<std::string>& resp) {
    commands::GetVar cmd("all");
    RetCode ret = Command(cmd);
    resp = Info();
    return ret;
}

std::string FastBootDriver::Response() {
    return response;
}

std::vector<std::string> FastBootDriver::Info() {
    return info;
}

FastBootDriver::RetCode FastBootDriver::Command(commands::Command& cmd, std::string& resp,
                                                bool clear, int* dsize) {
    RetCode recv = SUCCESS;
    RetCode trans = SUCCESS;
    std::string err;

    if (clear) info.clear();

    std::function<bool(std::vector<char>&)> rcb = [&](std::vector<char>& buf) -> bool {
        if (recv != SUCCESS) {
            return false;
        }
        recv = ReadBuffer(buf);
        return recv == SUCCESS;
    };

    std::function<bool(const std::vector<char>&)> tcb = [&](const std::vector<char>& buf) -> bool {
        if (trans != SUCCESS) {
            return false;
        }
        trans = SendBuffer(buf);
        return trans == SUCCESS;
    };

    bool res = cmd.Execute(rcb, tcb, err);

    if (trans) {  // sending failed
        return trans;
    } else if (recv) {  // recving failed
        return recv;
    } else if (!res) {
        g_error = "Command execute callback reported internal failure: " + err;
        return IO_ERROR;
    }
    RetCode tmp;
    if ((tmp = HandleResponse(false, dsize))) {
        return tmp;
    }
    resp = Response();
    return SUCCESS;
}

FastBootDriver::RetCode FastBootDriver::Command(commands::Command& cmd, bool clear, int* dsize) {
    std::string dummy;
    return Command(cmd, dummy, clear, dsize);
}

FastBootDriver::RetCode FastBootDriver::Flash(const std::string& part, std::vector<char>& data) {
    info.clear();
    RetCode ret;
    commands::BufTransfer cmd1(data);
    if ((ret = Command(cmd1))) {
        return ret;
    }
    commands::Flash cmd2(part);
    return Command(cmd2, false);
}

FastBootDriver::RetCode FastBootDriver::Flash(const std::string& part, int fd, uint32_t sz) {
    info.clear();
    RetCode ret;
    commands::FileTransfer cmd1(fd, sz);
    if ((ret = Command(cmd1))) {
        return ret;
    }
    commands::Flash cmd2(part);
    return Command(cmd2, false);
}

FastBootDriver::RetCode FastBootDriver::Flash(const std::string& part, sparse_file& s) {
    info.clear();
    RetCode ret;
    commands::SparseFileTransfer cmd1(s);
    if ((ret = Command(cmd1))) {
        return ret;
    }
    commands::Flash cmd2(part);
    return Command(cmd2, false);
}

FastBootDriver::RetCode FastBootDriver::Erase(const std::string& part) {
    commands::Flash erase(part);
    return Command(erase);
}

FastBootDriver::RetCode FastBootDriver::SetActive(const std::string& part) {
    commands::SetActive sa(part);
    return Command(sa);
}

FastBootDriver::RetCode FastBootDriver::Reboot() {
    commands::Reboot rbt;
    return Command(rbt);
}

FastBootDriver::RetCode FastBootDriver::Partitions(
        std::vector<std::tuple<std::string, uint32_t>>& parts) {
    std::vector<std::string> all;
    RetCode ret;
    if ((ret = GetVarAll(all))) {
        return ret;
    }

    std::regex reg("partition-size[[:s:]]*:[[:s:]]*([[:w:]]+)[[:s:]]*:[[:s:]]*0x([[:d:]]+)");
    std::smatch sm;

    for (auto s : all) {
        if (std::regex_match(s, sm, reg)) {
            std::string m1(sm[1]);
            std::string m2(sm[2]);
            uint32_t tmp = strtol(m2.c_str(), 0, 16);
            parts.push_back(std::make_tuple(m1, tmp));
        }
    }
    return SUCCESS;
}

FastBootDriver::RetCode FastBootDriver::Require(const std::string& var,
                                                const std::vector<std::string>& allowed,
                                                bool& reqmet, bool invert) {
    reqmet = invert;
    RetCode ret;
    std::string resp;
    if ((ret = GetVar(var, resp))) {
        return ret;
    }

    // Now check if we have a match
    for (const auto s : allowed) {
        // If it ends in *, and starting substring match
        if (resp == s || (s.length() && s.back() == '*' &&
                          !resp.compare(0, s.length() - 1, s, 0, s.length() - 1))) {
            reqmet = !invert;
            break;
        }
    }

    return SUCCESS;
}

FastBootDriver::RetCode FastBootDriver::Download(int fd, size_t size) {
    RetCode ret;
    // Start by sending download command with # of bytes
    commands::Download cmd1(size);
    if ((ret = Command(cmd1))) {
        return ret;
    }
    // Write the buffer
    commands::FileTransfer cmd2(fd, size);
    return Command(cmd2, false);
}

FastBootDriver::RetCode FastBootDriver::Download(const std::vector<char>& buf) {
    RetCode ret;

    // Start by sending download command with # of bytes
    commands::Download cmd(buf.size());
    if ((ret = Command(cmd))) {
        return ret;
    }

    // Write the buffer
    commands::BufTransfer cmd2(buf);
    return Command(cmd2, false);
}

FastBootDriver::RetCode FastBootDriver::Download(sparse_file& s) {
    int64_t size = sparse_file_len(&s, true, false);
    if (size <= 0 || size > std::numeric_limits<uint32_t>::max()) {
        g_error = "Sparse file is too large";
        return BAD_ARG;
    }

    RetCode ret;
    commands::Download cmd(size);
    if ((ret = Command(cmd))) {
        return ret;
    }

    // Write the buffer
    commands::SparseFileTransfer cmd2(s);
    return Command(cmd2, false);
}

FastBootDriver::RetCode FastBootDriver::Upload(const std::string& outfile) {
    RetCode ret;
    int dsize;
    commands::Upload cmd;
    if ((ret = Command(cmd, true, &dsize))) {
        return ret;
    }

    // Read into the file
    commands::Read cmd2(outfile, dsize);
    return Command(cmd2, false);
}

/*************************** PROTECTED *******************************/
FastBootDriver::RetCode FastBootDriver::RawCommand(const std::string& cmd, bool clear, int* dsize) {
    if (transport.Write(cmd.c_str(), cmd.size()) != static_cast<int>(cmd.size())) {
        g_error = ErrnoStr("Write to device failed");
        return IO_ERROR;
    }

    // Read the response
    return HandleResponse(clear, dsize);
}

FastBootDriver::RetCode FastBootDriver::RawCommand(const std::string& cmd, std::string& resp,
                                                   bool clear, int* dsize) {
    if (RetCode ret = RawCommand(cmd, clear, dsize)) {
        return ret;
    }
    resp = Response();
    return SUCCESS;
}

FastBootDriver::RetCode FastBootDriver::HandleResponse(bool clear, int* dsize) {
    char status[FB_RESPONSE_SZ + 1];
    auto start = std::chrono::system_clock::now();
    // erase the response string
    response.erase();
    if (clear) info.clear();
    while ((std::chrono::system_clock::now() - start) < std::chrono::seconds(RESP_TIMEOUT)) {
        int r = transport.Read(status, FB_RESPONSE_SZ);
        if (r < 0) {
            g_error = ErrnoStr("Status read failed");
            return IO_ERROR;
        } else if (r < 4) {
            g_error = android::base::StringPrintf("status malformed (%d bytes)", r);
            return BAD_DEV_RESP;
        }
        status[r] = '\0';  // Need the null terminator
        std::string input(status);
        if (!input.rfind("INFO")) {
            std::string tmp = input.substr(strlen("INFO"));
            info_cb(tmp);
            info.push_back(tmp);
        } else if (!input.rfind("OKAY")) {
            response = input.substr(strlen("OKAY"));
            return SUCCESS;
        } else if (!input.rfind("FAIL")) {
            g_error = android::base::StringPrintf("remote: '%s'", status + 4);
            response = input.substr(strlen("FAIL"));
            return DEVICE_FAIL;
        } else if (!input.rfind("DATA")) {
            std::string tmp = input.substr(strlen("DATA"));
            uint32_t num = strtol(tmp.c_str(), 0, 16);
            if (num > MAX_RESP_DATA_SIZE) {
                g_error = android::base::StringPrintf("Data size too large (%d)", num);
                return BAD_DEV_RESP;
            }
            if (dsize) *dsize = num;
            response = status + 4;
            return SUCCESS;
        } else {
            g_error = android::base::StringPrintf("Device sent unknown status code: %s", status);
            return BAD_DEV_RESP;
        }

    }  // End of while loop

    return TIMEOUT;
}

FastBootDriver::RetCode FastBootDriver::SendBuffer(const std::vector<char>& buf) {
    // Write the buffer
    ssize_t tmp = transport.Write(buf.data(), buf.size());

    if (tmp < 0) {
        g_error = ErrnoStr("Write to device failed in SendBuffer()");
        return IO_ERROR;
    } else if (static_cast<size_t>(tmp) != buf.size()) {
        g_error = android::base::StringPrintf("Failed to write all %zu bytes", buf.size());

        return IO_ERROR;
    }

    return SUCCESS;
}

FastBootDriver::RetCode FastBootDriver::ReadBuffer(std::vector<char>& buf) {
    // Read the buffer
    ssize_t tmp = transport.Read(buf.data(), buf.size());

    if (tmp < 0) {
        g_error = ErrnoStr("Read from device failed in ReadBuffer()");
        return IO_ERROR;
    } else if (static_cast<size_t>(tmp) != buf.size()) {
        g_error = android::base::StringPrintf("Failed to read all %zu bytes", buf.size());
        return IO_ERROR;
    }

    return SUCCESS;
}

std::string FastBootDriver::ErrnoStr(const std::string& msg) {
    return android::base::StringPrintf("%s (%s)", msg.c_str(), strerror(errno));
}

}  // End namespace fastboot
