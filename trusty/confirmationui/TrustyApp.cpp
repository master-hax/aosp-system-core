/*
 * Copyright 2020, The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "TrustyApp.h"

#include <android-base/file.h>
#include <android-base/logging.h>
#include <sys/uio.h>
#include <trusty/tipc.h>

namespace android {
namespace trusty {

// 0x1000 is the message buffer size but we need to leave some space for a protocol header.
// This assures that packets can always be read/written in one read/write operation.
static constexpr const uint32_t kPacketSize = 0x1000 - 32;

enum class PacketType : uint32_t {
    SND,
    RCV,
    ACK,
};

struct PacketHeader {
    PacketType type;
    uint32_t remaining;

    std::string toString() {
        return "type = " + std::to_string((uint32_t)type) +
               ", remaining = " + std::to_string(remaining);
    }
};

const char* toString(PacketType t) {
    switch (t) {
    case PacketType::SND:
        return "SND";
    case PacketType::RCV:
        return "RCV";
    case PacketType::ACK:
        return "ACK";
    default:
        return "UNKNOWN";
    }
}

static constexpr const uint32_t kHeaderSize = sizeof(PacketHeader);
static constexpr const uint32_t kPayloadSize = kPacketSize - kHeaderSize;
static uint8_t file_bytes[8192];
static uint8_t input_bytes[1024];

ssize_t TrustyRpc(int handle, const uint8_t* obegin, const uint8_t* oend, uint8_t* ibegin,
                  uint8_t* iend) {
    // get corpus
    bool has_send = false;
    uint32_t file_index = 0;
    TemporaryFile tf;
    tf.DoNotRemove();
    LOG(INFO) << tf.fd;
    LOG(INFO) << tf.path;
    // get corpus

    while (obegin != oend) {
        PacketHeader header = {
            .type = PacketType::SND,
            .remaining = uint32_t(oend - obegin),
        };
        uint32_t body_size = std::min(kPayloadSize, header.remaining);
        iovec iov[] = {
            {
                .iov_base = &header,
                .iov_len = kHeaderSize,
            },
            {
                .iov_base = const_cast<uint8_t*>(obegin),
                .iov_len = body_size,
            },
        };
        int rc = writev(handle, iov, 2);

        // get corpus
        LOG(INFO) << "file_index " << file_index;
        uint16_t* payload_size = (uint16_t*)&file_bytes[file_index];
        *payload_size = kHeaderSize + body_size;
        file_index += 2;

        LOG(INFO) << "file_index " << file_index;

        LOG(INFO) << header.toString();
        const uint8_t* bytes = (uint8_t*)&header;
        for (uint32_t i = 0; i < kHeaderSize; i++) {
            LOG(INFO) << i << " " << bytes[i];
            file_bytes[file_index + i] = bytes[i];
        }
        file_index += kHeaderSize;

        LOG(INFO) << "file_index " << file_index;
        bytes = obegin;
        for (uint32_t i = 0; i < body_size; i++) {
            // LOG(INFO) << i << " " << bytes[i];
            file_bytes[file_index + i] = bytes[i];
        }
        file_index += body_size;
        // get corpus

        if (!rc) {
            PLOG(ERROR) << "Error sending SND message. " << rc;
            return rc;
        }

        obegin += body_size;

        rc = read(handle, &header, kHeaderSize);
        if (!rc) {
            PLOG(ERROR) << "Error reading ACK. " << rc;
            return rc;
        }

        if (header.type != PacketType::ACK || header.remaining != oend - obegin) {
            LOG(ERROR) << "malformed ACK";
            return -1;
        }
    }

    ssize_t remaining = 0;
    auto begin = ibegin;
    do {
        PacketHeader header = {
            .type = PacketType::RCV,
            .remaining = 0,
        };

        iovec iov[] = {
            {
                .iov_base = &header,
                .iov_len = kHeaderSize,
            },
            {
                .iov_base = begin,
                .iov_len = uint32_t(iend - begin),
            },
        };

        ssize_t rc = writev(handle, iov, 1);

        // get corpus
        LOG(INFO) << "file_index " << file_index;
        uint16_t* payload_size = (uint16_t*)&file_bytes[file_index];
        *payload_size = kHeaderSize;
        file_index += 2;
        LOG(INFO) << "file_index " << file_index;

        uint8_t* bytes = (uint8_t*)&header;
        LOG(INFO) << header.toString();
        for (uint32_t i = 0; i < kHeaderSize; i++) {
            LOG(INFO) << i << " " << bytes[i];
            file_bytes[file_index + i] = bytes[i];
        }
        file_index += kHeaderSize;
        LOG(INFO) << "file_index " << file_index;

        //        bytes = begin;
        //        for (uint32_t i = 0; i < uint32_t(iend - begin); i++) {
        //            //LOG(INFO) << i << " " << bytes[i];
        //            file_bytes[file_index + i] = bytes[i];
        //        }
        //        file_index += uint32_t(iend - begin);
        // get corpus

        if (!rc) {
            PLOG(ERROR) << "Error sending RCV message. " << rc;
            return rc;
        }

        rc = readv(handle, iov, 2);
        if (rc < 0) {
            PLOG(ERROR) << "Error reading response. " << rc;
            return rc;
        }

        uint32_t body_size = std::min(kPayloadSize, header.remaining);
        if (body_size != rc - kHeaderSize) {
            LOG(ERROR) << "Unexpected amount of data: " << rc;
            return -1;
        }

        has_send = true;
        LOG(INFO) << tf.path;
        LOG(INFO) << tf.path;
        remaining = header.remaining - body_size;
        begin += body_size;
    } while (remaining);

    // get corpus
    if (has_send) {
        bool rc = base::WriteFully(tf.fd, file_bytes, file_index);
        LOG(INFO) << "WriteFully " << rc;
        LOG(INFO) << "file_index " << file_index;
        if (file_index < 1024) {
            lseek(tf.fd, 0, SEEK_SET);
            rc = base::ReadFully(tf.fd, &input_bytes[0], file_index);
            LOG(INFO) << "ReadFully " << rc;
            for (uint32_t i = 0; i < file_index; i++) {
                LOG(INFO) << +i << " input_bytes " << +input_bytes[i];
                LOG(INFO) << +i << " file_types " << +file_bytes[i];
            }
        }
    }
    // get corpus

    return begin - ibegin;
}

TrustyApp::TrustyApp(const std::string& path, const std::string& appname)
    : handle_(kInvalidHandle) {
    handle_ = tipc_connect(path.c_str(), appname.c_str());
    if (handle_ == kInvalidHandle) {
        LOG(ERROR) << AT << "failed to connect to Trusty TA \"" << appname << "\" using dev:"
                   << "\"" << path << "\"";
    }
    LOG(INFO) << AT << "succeeded to connect to Trusty TA \"" << appname << "\"";
}
TrustyApp::~TrustyApp() {
    if (handle_ != kInvalidHandle) {
        tipc_close(handle_);
    }
    LOG(INFO) << "Done shutting down TrustyApp";
}

}  // namespace trusty
}  // namespace android
