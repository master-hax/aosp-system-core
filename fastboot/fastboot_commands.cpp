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
#include <string>
#include <vector>

#include <android-base/file.h>
#include <android-base/stringprintf.h>
#include <sparse/sparse.h>
#include <utils/FileMap.h>
#include "fastboot_commands.h"
#include "fastboot_driver.h"

namespace fastboot {
namespace commands {

// StrCommand
bool StrCommand::Execute(const std::function<bool(std::vector<char>&)>&,
                         const std::function<bool(const std::vector<char>&)>& send,
                         std::string& err) {
    // Transfer only accept vector bufs
    auto s = Cmd();
    if (s.size() > FB_COMMAND_SZ) {
        err = "Command '" + s + "' is too long";
        return false;
    }
    std::vector<char> str(s.begin(), s.end());
    return send(str);
}

// GetVar
GetVar::GetVar(std::string key) : key(key) {}

const std::string GetVar::Cmd() {
    return "getvar:" + key;
}

// Download
Download::Download(uint32_t num) : num(num) {}

const std::string Download::Cmd() {
    return android::base::StringPrintf("download:%08x", num);
}

// Upload
const std::string Upload::Cmd() {
    return "upload";
}

// Verify
Verify::Verify(uint32_t num) : num(num) {}

const std::string Verify::Cmd() {
    return android::base::StringPrintf("verify:%08x", num);
}

// Flash
Flash::Flash(std::string part) : part(part) {}

const std::string Flash::Cmd() {
    return "flash:" + part;
}

// SetActive
SetActive::SetActive(std::string slot) : slot(slot) {}

const std::string SetActive::Cmd() {
    return "set_active:" + slot;
}

// Erase
Erase::Erase(std::string part) : part(part) {}

const std::string Erase::Cmd() {
    return "erase:" + part;
}

// Boot
const std::string Boot::Cmd() {
    return std::string("boot");
}

// Continue
const std::string Continue::Cmd() {
    return std::string("continue");
}

// Reboot
const std::string Reboot::Cmd() {
    return std::string("reboot");
}

// Reboot Bootloader
const std::string RebootBootloader::Cmd() {
    return std::string("reboot-bootloader");
}

// Powerdown
// Reboot
const std::string Powerdown::Cmd() {
    return std::string("powerdown");
}

// BufTransfer
BufTransfer::BufTransfer(const std::vector<char> buf) : buf(buf) {}

bool BufTransfer::Execute(const std::function<bool(std::vector<char>&)>&,
                          const std::function<bool(const std::vector<char>&)>& send, std::string&) {
    return send(buf);
}

// FileTransfer
FileTransfer::FileTransfer(int fd, size_t size) : fd(fd), size(size) {}

bool FileTransfer::Execute(const std::function<bool(std::vector<char>&)>&,
                           const std::function<bool(const std::vector<char>&)>& send,
                           std::string& err) {
    static constexpr uint32_t MAX_MAP_SIZE = 512 * 1024 * 1024;
    off64_t offset = 0;
    uint32_t remaining = size;

    while (remaining) {
        // Memory map the file
        android::FileMap filemap;
        size_t len = std::min(remaining, MAX_MAP_SIZE);

        if (!filemap.create(NULL, fd, offset, len, true)) {
            err = "Creating filemap failed";
            return false;
        }

        char* tmp = static_cast<char*>(filemap.getDataPtr());
        const std::vector<char> buf(tmp, tmp + len);
        if (!send(buf)) {
            err = "FileTransfer failed";
            return false;
        }

        remaining -= len;
        offset += len;
    }

    return true;
}

// SparseFileTransfer
SparseFileTransfer::SparseFileTransfer(sparse_file& sf) : sf(sf) {}

bool SparseFileTransfer::Execute(const std::function<bool(std::vector<char>&)>&,
                                 const std::function<bool(const std::vector<char>&)>& send,
                                 std::string& err) {
    SparseCBPrivate priv(this, send, err);
    auto cb = [](void* priv, const void* buf, size_t len) -> int {
        SparseCBPrivate* data = static_cast<SparseCBPrivate*>(priv);
        const char* cbuf = static_cast<const char*>(buf);
        return data->self->SparseWriteCallback(data->send, data->tpbuf, cbuf, len, data->err);
    };

    if (sparse_file_callback(&sf, true, false, cb, &priv) < 0) {
        if (!err.size()) {
            err = "Error reading sparse file";
        }
        return false;
    }

    // Now flush
    if (priv.tpbuf.size()) {
        return send(priv.tpbuf);
    }

    return true;
}

SparseFileTransfer::SparseCBPrivate::SparseCBPrivate(
        SparseFileTransfer* self, const std::function<bool(const std::vector<char>&)>& send,
        std::string& err)
    : self(self), send(send), err(err) {}

int SparseFileTransfer::SparseWriteCallback(const std::function<bool(const std::vector<char>&)>& send,
                                            std::vector<char>& tpbuf, const char* data, size_t len,
                                            std::string& err) {
    size_t total = 0;
    size_t to_write = std::min(TRANSPORT_CHUNK_SIZE - tpbuf.size(), len);

    // Handle the residual
    tpbuf.insert(tpbuf.end(), data, data + to_write);
    if (tpbuf.size() < TRANSPORT_CHUNK_SIZE) {  // Nothing enough to send rn
        return 0;
    }

    if (!send(tpbuf)) {
        err = "Send failed in SparseWriteCallback()";
        return -1;
    }
    tpbuf.clear();
    total += to_write;

    // Now we need to send a multiple of chunk size
    size_t nchunks = (len - total) / TRANSPORT_CHUNK_SIZE;
    size_t nbytes = TRANSPORT_CHUNK_SIZE * nchunks;
    std::vector<char> buf(data + total, data + total + nbytes);
    if (!send(buf)) {
        err = "Send failed in SparseWriteCallback()";
        return -1;
    }
    total += nbytes;

    if (len - total > 0) {  // We have residual data to save for next time
        tpbuf.assign(data + total, data + len);
    }

    return 0;
}

// SparseFileTransfer
Read::Read(const std::string outfile, size_t size) : outfile(outfile), size(size) {}

bool Read::Execute(const std::function<bool(std::vector<char>&)>& recv,
                   const std::function<bool(const std::vector<char>&)>&, std::string& err) {
    std::vector<char> data(size);

    if (!recv(data)) {
        err = "Reading from device failed";
        return false;
    }

    std::string tmp(data.begin(), data.end());
    if (!android::base::WriteStringToFile(tmp, outfile.c_str(), true)) {
        err = android::base::StringPrintf("write to '%s' failed", outfile.c_str());
        return false;
    }
    return true;
}

}  // namespace commands
}  // namespace fastboot
