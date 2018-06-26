#include <android-base/file.h>
#include <android-base/stringprintf.h>
#include <sparse/sparse.h>
#include <utils/FileMap.h>
#include <string>
#include <vector>

#include "fastboot_driver.h"

// StrCommand
bool fastboot::commands::StrCommand::Execute(std::function<bool(std::vector<char>&)>&,
                                             std::function<bool(const std::vector<char>&)>& trans,
                                             std::string& err) {
    // Transfer only accept vector bufs
    auto s = Cmd();
    if (s.size() > FB_COMMAND_SZ) {
        err = "Command '" + s + "' is too long";
        return false;
    }
    std::vector<char> str(s.begin(), s.end());
    return trans(str);
}

// GetVar
fastboot::commands::GetVar::GetVar(std::string key) : key(key) {}

const std::string fastboot::commands::GetVar::Cmd() {
    return "getvar:" + key;
}

// Download
fastboot::commands::Download::Download(uint32_t num) : num(num) {}

const std::string fastboot::commands::Download::Cmd() {
    return android::base::StringPrintf("download:%08x", num);
}

// Upload
const std::string fastboot::commands::Upload::Cmd() {
    return std::string("upload");
}

// Verify
fastboot::commands::Verify::Verify(uint32_t num) : num(num) {}

const std::string fastboot::commands::Verify::Cmd() {
    return android::base::StringPrintf("verify:%08x", num);
}

// Flash
fastboot::commands::Flash::Flash(std::string part) : part(part) {}

const std::string fastboot::commands::Flash::Cmd() {
    return "flash:" + part;
}

// SetActive
fastboot::commands::SetActive::SetActive(std::string slot) : slot(slot) {}

const std::string fastboot::commands::SetActive::Cmd() {
    return "set_active:" + slot;
}

// Erase
fastboot::commands::Erase::Erase(std::string part) : part(part) {}

const std::string fastboot::commands::Erase::Cmd() {
    return "erase:" + part;
}

// Boot
const std::string fastboot::commands::Boot::Cmd() {
    return std::string("boot");
}

// Continue
const std::string fastboot::commands::Continue::Cmd() {
    return std::string("continue");
}

// Reboot
const std::string fastboot::commands::Reboot::Cmd() {
    return std::string("reboot");
}

// Reboot Bootloader
const std::string fastboot::commands::RebootBootloader::Cmd() {
    return std::string("reboot-bootloader");
}

// Powerdown
// Reboot
const std::string fastboot::commands::Powerdown::Cmd() {
    return std::string("powerdown");
}

// Transfer
bool fastboot::commands::Transfer::Execute(std::function<bool(std::vector<char>&)>&,
                                           std::function<bool(const std::vector<char>&)>& trans,
                                           std::string& err) {
    return Buf(trans, err);
}

// BufTransfer
fastboot::commands::BufTransfer::BufTransfer(const std::vector<char> buf) : buf(buf) {}

bool fastboot::commands::BufTransfer::Buf(std::function<bool(const std::vector<char>&)> transfer,
                                          std::string&) {
    return transfer(buf);
}

// FileTransfer
fastboot::commands::FileTransfer::FileTransfer(int fd, size_t size) : fd(fd), size(size) {}

bool fastboot::commands::FileTransfer::Buf(std::function<bool(const std::vector<char>&)> transfer,
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
        if (!transfer(buf)) {
            err = "FileTransfer failed";
            return false;
        }

        remaining -= len;
        offset += len;
    }

    return true;
}

// SparseFileTransfer
fastboot::commands::SparseFileTransfer::SparseFileTransfer(sparse_file& sf) : sf(sf) {}

bool fastboot::commands::SparseFileTransfer::Buf(
        std::function<bool(const std::vector<char>&)> transfer, std::string& err) {
    std::vector<char> tpbuf;
    std::function<int(const char*, size_t)> cb = [this, &tpbuf, &err, &transfer](
                                                         const char* buf, size_t size) -> int {
        return this->SparseWriteCallback(transfer, tpbuf, buf, size, err);
    };

    if (sparse_file_callback(&sf, true, false, SparseWriteCallbackEntry, &cb) < 0) {
        err = "Error reading sparse file";
        return false;
    }

    // Now flush
    if (tpbuf.size()) {
        return transfer(tpbuf);
    }

    return true;
}

int fastboot::commands::SparseFileTransfer::SparseWriteCallbackEntry(void* priv, const void* data,
                                                                     size_t len) {
    auto* cb = static_cast<std::function<int(const char*, size_t)>*>(priv);
    const char* buf = static_cast<const char*>(data);
    return cb->operator()(buf, len);
}

int fastboot::commands::SparseFileTransfer::SparseWriteCallback(
        std::function<bool(const std::vector<char>&)> transfer, std::vector<char>& tpbuf,
        const char* data, size_t len, std::string& err) {
    size_t total = 0;
    size_t to_write = std::min(TRANSPORT_CHUNK_SIZE - tpbuf.size(), len);

    // Handle the residual
    tpbuf.insert(tpbuf.end(), data, data + to_write);
    if (tpbuf.size() < TRANSPORT_CHUNK_SIZE) {  // Nothing enough to send rn
        return 0;
    }

    if (transfer(tpbuf)) {
        err = "Send failed in SparseWriteCallback()";
        return -1;
    }
    tpbuf.clear();
    total += to_write;

    // Now we need to send a multiple of chunk size
    size_t nchunks = (len - total) / TRANSPORT_CHUNK_SIZE;
    size_t nbytes = TRANSPORT_CHUNK_SIZE * nchunks;
    std::vector<char> buf(data + total, data + nbytes);
    if (transfer(buf)) {
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
fastboot::commands::Read::Read(const std::string outfile, size_t size)
    : outfile(outfile), size(size) {}

bool fastboot::commands::Read::Execute(std::function<bool(std::vector<char>&)>& recv,
                                       std::function<bool(const std::vector<char>&)>&,
                                       std::string& err) {
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
