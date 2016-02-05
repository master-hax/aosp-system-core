/*
 * Copyright (C) 2015 The Android Open Source Project
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

// This file implements the fastboot UDP protocol; see fastboot_protocol.txt for documentation.

#include "udp.h"

#include <errno.h>
#include <stdio.h>

#include <list>
#include <memory>
#include <vector>

#include <android-base/macros.h>
#include <android-base/stringprintf.h>

#include "socket.h"

namespace udp {

using namespace internal;

constexpr size_t kMinPacketSize = 512;
constexpr size_t kHeaderSize = 4;

enum Index {
    kIndexId = 0,
    kIndexFlags = 1,
    kIndexSeqH = 2,
    kIndexSeqL = 3,
};

// Extracts a big-endian uint16_t from a byte array.
static uint16_t ExtractUint16(const uint8_t* bytes) {
    return (static_cast<uint16_t>(bytes[0]) << 8) | bytes[1];
}

// Packet header handling.
class Header {
  public:
    Header();
    ~Header() = default;

    uint8_t id() const { return bytes_[kIndexId]; }
    uint16_t sequence_number() const { return ExtractUint16(&bytes_[kIndexSeqH]); }
    bool has_continuation() const { return bytes_[kIndexFlags] & kFlagContinuation; }
    const uint8_t* bytes() const { return bytes_; }

    void Set(uint8_t id, uint16_t sequence, Flag flag);

    // Checks whether |response| is a match for this header.
    bool Matches(const uint8_t* response);

  private:
    uint8_t bytes_[kHeaderSize];
};

Header::Header() {
    Set(kIdError, 0, kFlagNone);
}

void Header::Set(uint8_t id, uint16_t sequence, Flag flag) {
    bytes_[kIndexId] = id;
    bytes_[kIndexFlags] = flag;
    bytes_[kIndexSeqH] = sequence >> 8;
    bytes_[kIndexSeqL] = sequence;
}

bool Header::Matches(const uint8_t* response) {
    // Sequence numbers must be the same to match, but the response ID can either be the same
    // or an error response which is always accepted.
    return bytes_[kIndexSeqH] == response[kIndexSeqH] &&
           bytes_[kIndexSeqL] == response[kIndexSeqL] &&
           (bytes_[kIndexId] == response[kIndexId] || response[kIndexId] == kIdError);
}

// Stores received data. The UDP protocol may receive data before the fastboot engine is ready for
// it, so this helps keep data copying to a minimum.
class RxData {
  public:
    RxData() = default;
    ~RxData() = default;

    // Adds a new message to the storage.
    void SavePacket(const uint8_t* data, size_t size);

    // Moves up to |size| bytes from storage into |data|, returns the number of bytes written.
    size_t Get(uint8_t* data, size_t size);

    // Moves all stored data into a single vector of bytes and returns it.
    std::vector<uint8_t> GetAll();

    bool Empty() const { return buffers_.empty(); }

    // Clears all stored data.
    void Clear() { buffers_.clear(); }

  private:
    // Store as a list of vectors instead of just appending to a single vector to avoid resizing.
    std::list<std::vector<uint8_t>> buffers_;

    DISALLOW_COPY_AND_ASSIGN(RxData);
};

void RxData::SavePacket(const uint8_t* data, size_t size) {
    // We only need to store the data bytes.
    if (size > kHeaderSize) {
        buffers_.emplace_back(data + kHeaderSize, data + size);
    }
}

size_t RxData::Get(uint8_t* data, size_t size) {
    const uint8_t* const data_start = data;

    while (size > 0 && !buffers_.empty()) {
        std::vector<uint8_t>& buffer = buffers_.front();

        if (size >= buffer.size()) {
            // We have enough space to copy out a full buffer.
            memcpy(data, buffer.data(), buffer.size());
            size -= buffer.size();
            data += buffer.size();
            buffers_.pop_front();
        } else {
            // The buffer is too big, just copy out what we can.
            memcpy(data, buffer.data(), size);
            buffer.erase(buffer.begin(), buffer.begin() + size);
            data += size;
            size = 0;
        }
    }

    return data - data_start;
}

std::vector<uint8_t> RxData::GetAll() {
    // In the common case of only one vector, we can just move it out very quickly.
    if (buffers_.size() == 1) {
        std::vector<uint8_t> ret = std::move(buffers_.front());
        buffers_.pop_front();
        return ret;
    }

    // Otherwise, figure out the total size first to avoid having to re-size multiple times.
    std::vector<uint8_t> ret;
    size_t total_bytes = 0;
    for (const auto& buffer : buffers_) {
        total_bytes += buffer.size();
    }
    ret.reserve(total_bytes);

    while (!buffers_.empty()) {
        ret.insert(ret.end(), buffers_.front().begin(), buffers_.front().end());
        buffers_.pop_front();
    }

    return ret;
};

// Implements the Transport interface to work with the fastboot engine.
class UdpTransport : public Transport {
  public:
    // Factory function so we can return nullptr if initialization fails.
    static std::unique_ptr<UdpTransport> NewTransport(std::unique_ptr<Socket> socket,
                                                      std::string* error);
    ~UdpTransport() override = default;

    ssize_t Read(void* data, size_t length) override;
    ssize_t Write(const void* data, size_t length) override;
    int Close() override;

  private:
    UdpTransport(std::unique_ptr<Socket> socket) : socket_(std::move(socket)) {}

    // Performs the UDP initialization procedure. Returns true on success.
    bool InitializeProtocol(std::string* error);

    // Sends |length| bytes from |data| and waits for the response packet up to |attempts| times.
    // Continuation packets are handled automatically and any return data is saved to |rx_data_|.
    // Returns false and fills |error| on failure.
    bool SendData(Id id, const uint8_t* data, size_t length, int attempts, std::string* error);

    // Helper for SendData(); sends a single packet and handles the response. |header| specifies
    // the initial outgoing packet information but may be modified by this function.
    bool SendSinglePacketHelper(Header* header, const uint8_t* data, size_t length, int attempts,
                                std::string* error);

    std::unique_ptr<Socket> socket_;
    int sequence_ = -1;
    RxData rx_data_;
    size_t max_data_length_ = kMinPacketSize - kHeaderSize;
    std::vector<uint8_t> rx_packet_;

    DISALLOW_COPY_AND_ASSIGN(UdpTransport);
};

std::unique_ptr<UdpTransport> UdpTransport::NewTransport(std::unique_ptr<Socket> socket,
                                                         std::string* error) {
    std::unique_ptr<UdpTransport> transport(new UdpTransport(std::move(socket)));

    if (!transport->InitializeProtocol(error)) {
        return nullptr;
    }

    return transport;
}

bool UdpTransport::InitializeProtocol(std::string* error) {
    // First send the query packet to sync with the target. Only attempt this a small number of
    // times so we can fail out quickly if the target isn't available.
    sequence_ = 0;
    rx_packet_.resize(kMinPacketSize);
    if (!SendData(kIdDeviceQuery, nullptr, 0, kMaxConnectAttempts, error)) {
        return false;
    }

    // The first two data bytes contain the next sequence number the target expects.
    std::vector<uint8_t> data = rx_data_.GetAll();
    if (data.size() < 2) {
        *error = "invalid query response from target";
        return false;
    }
    sequence_ = ExtractUint16(data.data());

    // Now send the initialization packet with our version and maximum packet size.
    uint8_t init_data[] = {kProtocolVersion >> 8, kProtocolVersion & 0xFF,
                           kHostMaxPacketSize >> 8, kHostMaxPacketSize & 0xFF};
    if (!SendData(kIdInitialization, init_data, sizeof(init_data), kMaxTransmissionAttempts,
                  error)) {
        return false;
    }

    // The first two data bytes contain the version, the second two bytes contain the target max
    // supported packet size, which must be at least 512 bytes.
    data = rx_data_.GetAll();
    if (data.size() < 4) {
        *error = "invalid initialization response from target";
        return false;
    }

    uint16_t version = ExtractUint16(data.data());
    if (version < kProtocolVersion) {
        *error = android::base::StringPrintf("target reported invalid protocol version %d",
                                             version);
        return false;
    }

    uint16_t packet_size = ExtractUint16(data.data() + 2);
    if (packet_size < kMinPacketSize) {
        *error = android::base::StringPrintf("target reported invalid packet size %d", packet_size);
        return false;
    }
    packet_size = std::min(kHostMaxPacketSize, packet_size);
    max_data_length_ = packet_size - kHeaderSize;
    rx_packet_.resize(packet_size);

    return true;
}

// SendData() is just responsible for chunking |data| into packets until it's all been sent.
// Per-packet timeout/retransmission logic is done in SendSinglePacketHelper().
bool UdpTransport::SendData(Id id, const uint8_t* data, size_t length, int attempts,
                            std::string* error) {
    if (socket_ == nullptr) {
        *error = "socket is closed";
        return false;
    }

    Header header;
    size_t packet_data_length;
    do {
        // Set the continuation flag and truncate packet data if needed.
        if (length > max_data_length_) {
            packet_data_length = max_data_length_;
            header.Set(id, sequence_, kFlagContinuation);
        } else {
            packet_data_length = length;
            header.Set(id, sequence_, kFlagNone);
        }

        if (!SendSinglePacketHelper(&header, data, packet_data_length, attempts, error)) {
            return false;
        }

        length -= packet_data_length;
        data += packet_data_length;
    } while (length > 0);

    return true;
}

bool UdpTransport::SendSinglePacketHelper(Header* header, const uint8_t* data, size_t length,
                                          const int attempts, std::string* error) {
    int attempts_left = attempts;
    while (attempts_left > 0) {
        if (!socket_->Send({{header->bytes(), kHeaderSize}, {data, length}})) {
            *error = Socket::GetErrorMessage();
            return false;
        }

        // Keep listening until we get a matching response or timeout.
        ssize_t bytes = 0;
        do {
            bytes = socket_->Receive(rx_packet_.data(), rx_packet_.size(), kResponseTimeoutMs);
            if (bytes == -1) {
                if (socket_->ReceiveTimedOut()) {
                    break;
                }
                *error = Socket::GetErrorMessage();
                return false;
            } else if (bytes < static_cast<ssize_t>(kHeaderSize)) {
                *error = "protocol error: incomplete header";
                return false;
            }
        } while (!header->Matches(rx_packet_.data()));

        if (socket_->ReceiveTimedOut()) {
            --attempts_left;
            continue;
        }

        // If the device just switched to an error packet, wipe out any data we've gotten up to
        // this point, but don't break the loop in case the error message spans multiple packets.
        if (header->id() != Id::kIdError && rx_packet_[kIndexId] == kIdError) {
            rx_data_.Clear();
        }

        ++sequence_;
        rx_data_.SavePacket(rx_packet_.data(), bytes);

        // If the response has a continuation flag we need to prompt for more data by sending
        // an empty packet.
        if (rx_packet_[kIndexFlags] & kFlagContinuation) {
            // We got a valid response so reset our attempt counter.
            attempts_left = attempts;
            header->Set(rx_packet_[kIndexId], sequence_, kFlagNone);
            data = nullptr;
            length = 0;
            continue;
        }

        break;
    }

    if (attempts_left <= 0) {
        *error = "no response from target";
        return false;
    }

    if (rx_packet_[kIndexId] == kIdError) {
        std::vector<uint8_t> message = rx_data_.GetAll();
        message.push_back('\0');
        *error = android::base::StringPrintf("target reported error: %s", message.data());
        return false;
    }

    return true;
}

ssize_t UdpTransport::Read(void* data, size_t length) {
    // If we don't already have a packet waiting, read from the target by sending an empty packet.
    while (rx_data_.Empty()) {
        std::string error;
        if (!SendData(kIdFastboot, nullptr, 0, kMaxTransmissionAttempts, &error)) {
            fprintf(stderr, "UDP error: %s\n", error.c_str());
            return -1;
        }
    }
    return rx_data_.Get(reinterpret_cast<uint8_t*>(data), length);
}

ssize_t UdpTransport::Write(const void* data, size_t length) {
    std::string error;
    if (!SendData(kIdFastboot, reinterpret_cast<const uint8_t*>(data), length,
                  kMaxTransmissionAttempts, &error)) {
        fprintf(stderr, "UDP error: %s\n", error.c_str());
        return -1;
    }
    return length;
}

int UdpTransport::Close() {
    if (socket_ == nullptr) {
        return 0;
    }

    int result = socket_->Close();
    socket_.reset();
    return result;
}

std::unique_ptr<Transport> Connect(const std::string& hostname, int port, std::string* error) {
    return internal::Connect(Socket::NewClient(Socket::Protocol::kUdp, hostname, port, error),
                             error);
}

namespace internal {

std::unique_ptr<Transport> Connect(std::unique_ptr<Socket> sock, std::string* error) {
    if (sock == nullptr) {
        // If Socket creation failed |error| is already set.
        return nullptr;
    }

    return UdpTransport::NewTransport(std::move(sock), error);
}

}  // namespace internal

}  // namespace udp
