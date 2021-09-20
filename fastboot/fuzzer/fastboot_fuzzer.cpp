/*
 * Copyright (C) 2021 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */
#include <android-base/file.h>
#include "fastboot.h"
#include "socket.h"
#include "socket_mock_fuzz.h"
#include "tcp.h"
#include "udp.h"
#include "vendor_boot_img_utils.h"

#include <fuzzer/FuzzedDataProvider.h>

using namespace std;

const size_t kYearMin = 2000;
const size_t kYearMax = 2127;
const size_t kMonthMin = 1;
const size_t kMonthMax = 12;
const size_t kDayMin = 1;
const size_t kDayMax = 31;
const size_t kVersionMin = 0;
const size_t kVersionMax = 127;
const size_t kMaxStringSize = 100;
const size_t kMinTimeout = 10;
const size_t kMaxTimeout = 3000;
const uint16_t kValidUdpPacketSize = 512;
const uint16_t kMinUdpPackets = 1;
const uint16_t kMaxUdpPackets = 10;

const string kValidTcpHandshakeString = "FB01";
const string kInvalidTcpHandshakeString = "FB00";
const string kValidRamdiskName = "default";
const string kVendorBootFile = "/tmp/vendorBootFile";
const string kRamdiskFile = "/tmp/ramdiskFile";
const char* kFsOptionsArray[] = {"casefold", "projid", "compress"};

class FastbootFuzzer {
  public:
    void process(const uint8_t* data, size_t size);

  private:
    void invokeParseApi();
    void invokeSocket();
    void invokeTcp();
    void invokeUdp();
    void invokeVendorBootImgUtils(const uint8_t* data, size_t size);
    bool makeConnectedSockets(Socket::Protocol protocol, unique_ptr<Socket>* server,
                              unique_ptr<Socket>* client, const string& hostname);
    unique_ptr<FuzzedDataProvider> mFdp = nullptr;
};

void FastbootFuzzer::invokeParseApi() {
    boot_img_hdr_v1 hdr = {};
    FastBootTool fastBoot;

    int32_t year = mFdp->ConsumeIntegralInRange<int32_t>(kYearMin, kYearMax);
    int32_t month = mFdp->ConsumeIntegralInRange<int32_t>(kMonthMin, kMonthMax);
    int32_t day = mFdp->ConsumeIntegralInRange<int32_t>(kDayMin, kDayMax);
    string date = to_string(year) + "-" + to_string(month) + "-" + to_string(day);
    fastBoot.ParseOsPatchLevel(&hdr, date.c_str());

    int32_t major = mFdp->ConsumeIntegralInRange<int32_t>(kVersionMin, kVersionMax);
    int32_t minor = mFdp->ConsumeIntegralInRange<int32_t>(kVersionMin, kVersionMax);
    int32_t patch = mFdp->ConsumeIntegralInRange<int32_t>(kVersionMin, kVersionMax);
    string version = to_string(major) + "." + to_string(minor) + "." + to_string(patch);
    fastBoot.ParseOsVersion(&hdr, version.c_str());

    fastBoot.ParseFsOption(mFdp->PickValueInArray(kFsOptionsArray));
}

bool FastbootFuzzer::makeConnectedSockets(Socket::Protocol protocol, unique_ptr<Socket>* server,
                                          unique_ptr<Socket>* client,
                                          const string& hostname = "localhost") {
    *server = Socket::NewServer(protocol, 0);
    if (*server == nullptr) {
        return false;
    }
    *client = Socket::NewClient(protocol, hostname, (*server)->GetLocalPort(), nullptr);
    if (*client == nullptr) {
        return false;
    }
    if (protocol == Socket::Protocol::kTcp) {
        *server = (*server)->Accept();
        if (*server == nullptr) {
            return false;
        }
    }
    return true;
}

void FastbootFuzzer::invokeSocket() {
    unique_ptr<Socket> server, client;

    for (Socket::Protocol protocol : {Socket::Protocol::kUdp, Socket::Protocol::kTcp}) {
        if (makeConnectedSockets(protocol, &server, &client)) {
            string message = mFdp->ConsumeRandomLengthString(kMaxStringSize);
            client->Send(message.c_str(), message.length());
            string received(message.length(), '\0');
            if (mFdp->ConsumeBool()) {
                client->Close();
            }
            if (mFdp->ConsumeBool()) {
                server->Close();
            }
            server->ReceiveAll(&received[0], received.length(),
                               /* timeout_ms */
                               mFdp->ConsumeIntegralInRange<size_t>(kMinTimeout, kMaxTimeout));
            server->Close();
            client->Close();
        }
    }
}

void FastbootFuzzer::invokeTcp() {
    /* Using a raw SocketMockFuzz* here because ownership shall be passed to the Transport object */
    SocketMockFuzz* tcpMock = new SocketMockFuzz;
    tcpMock->ExpectSend(mFdp->ConsumeBool() ? kValidTcpHandshakeString
                                            : kInvalidTcpHandshakeString);
    tcpMock->AddReceive(mFdp->ConsumeBool() ? kValidTcpHandshakeString
                                            : kInvalidTcpHandshakeString);

    string error;
    unique_ptr<Transport> transport = tcp::internal::Connect(unique_ptr<Socket>(tcpMock), &error);

    if (transport.get()) {
        string writeMessage = mFdp->ConsumeRandomLengthString(kMaxStringSize);
        if (mFdp->ConsumeBool()) {
            tcpMock->ExpectSend(writeMessage);
        } else {
            tcpMock->ExpectSendFailure(writeMessage);
        }
        string readMessage = mFdp->ConsumeRandomLengthString(kMaxStringSize);
        if (mFdp->ConsumeBool()) {
            tcpMock->AddReceive(readMessage);
        } else {
            tcpMock->AddReceiveFailure();
        }

        transport->Write(writeMessage.data(), writeMessage.length());

        string buffer(readMessage.length(), '\0');
        transport->Read(&buffer[0], buffer.length());

        transport->Close();
    }
}

static string PacketValue(uint16_t value) {
    return string{static_cast<char>(value >> 8), static_cast<char>(value)};
}

static string ErrorPacket(uint16_t sequence, const string& message = "",
                          char flags = udp::internal::kFlagNone) {
    return string{udp::internal::kIdError, flags} + PacketValue(sequence) + message;
}

static string InitPacket(uint16_t sequence, uint16_t version, uint16_t max_packet_size) {
    return string{udp::internal::kIdInitialization, udp::internal::kFlagNone} +
           PacketValue(sequence) + PacketValue(version) + PacketValue(max_packet_size);
}

static string QueryPacket(uint16_t sequence, uint16_t new_sequence) {
    return string{udp::internal::kIdDeviceQuery, udp::internal::kFlagNone} + PacketValue(sequence) +
           PacketValue(new_sequence);
}

static string QueryPacket(uint16_t sequence) {
    return string{udp::internal::kIdDeviceQuery, udp::internal::kFlagNone} + PacketValue(sequence);
}

static string FastbootPacket(uint16_t sequence, const string& data = "",
                             char flags = udp::internal::kFlagNone) {
    return string{udp::internal::kIdFastboot, flags} + PacketValue(sequence) + data;
}

void FastbootFuzzer::invokeUdp() {
    /* Using a raw SocketMockFuzz* here because ownership shall be passed to the Transport object */
    SocketMockFuzz* udpMock = new SocketMockFuzz;
    uint16_t startingSequence = mFdp->ConsumeIntegral<uint16_t>();
    int32_t deviceMaxPacketSize = mFdp->ConsumeBool() ? kValidUdpPacketSize
                                                      : mFdp->ConsumeIntegralInRange<uint16_t>(
                                                                0, kValidUdpPacketSize - 1);
    udpMock->ExpectSend(QueryPacket(0));
    udpMock->AddReceive(QueryPacket(0, startingSequence));
    udpMock->ExpectSend(InitPacket(startingSequence, udp::internal::kProtocolVersion,
                                   udp::internal::kHostMaxPacketSize));
    udpMock->AddReceive(
            InitPacket(startingSequence, udp::internal::kProtocolVersion, deviceMaxPacketSize));

    string error;
    unique_ptr<Transport> transport = udp::internal::Connect(unique_ptr<Socket>(udpMock), &error);
    bool isTransportInitialized = transport != nullptr && error.empty();

    if (isTransportInitialized) {
        uint16_t numPackets =
                mFdp->ConsumeIntegralInRange<uint16_t>(kMinUdpPackets, kMaxUdpPackets);

        for (uint16_t i = 0; i < numPackets; ++i) {
            string writeMessage = mFdp->ConsumeRandomLengthString(kMaxStringSize);
            string readMessage = mFdp->ConsumeRandomLengthString(kMaxStringSize);
            if (mFdp->ConsumeBool()) {
                udpMock->ExpectSend(FastbootPacket(i, writeMessage));
            } else {
                udpMock->ExpectSend(ErrorPacket(i, writeMessage));
            }

            if (mFdp->ConsumeBool()) {
                udpMock->AddReceive(FastbootPacket(i, readMessage));
            } else {
                udpMock->AddReceive(ErrorPacket(i, readMessage));
            }
            transport->Write(writeMessage.data(), writeMessage.length());
            string buffer(readMessage.length(), '\0');
            transport->Read(&buffer[0], buffer.length());
        }
        transport->Close();
    }
}

void FastbootFuzzer::invokeVendorBootImgUtils(const uint8_t* data, size_t size) {
    int32_t vendorBootFd = open(kVendorBootFile.c_str(), O_CREAT | O_RDWR, 0644);
    if (vendorBootFd < 0) {
        return;
    }
    int32_t ramdiskFd = open(kRamdiskFile.c_str(), O_CREAT | O_RDWR, 0644);
    if (ramdiskFd < 0) {
        return;
    }
    write(vendorBootFd, data, size);
    write(ramdiskFd, data, size);
    string ramdiskName = mFdp->ConsumeBool() ? kValidRamdiskName
                                             : mFdp->ConsumeRandomLengthString(kMaxStringSize);
    string contentVendorBootFd = {};
    string contentRamdiskFd = {};
    android::base::ReadFdToString(vendorBootFd, &contentVendorBootFd);
    android::base::ReadFdToString(ramdiskFd, &contentRamdiskFd);
    uint64_t vendorBootSize =
            mFdp->ConsumeBool() ? contentVendorBootFd.size() : mFdp->ConsumeIntegral<uint64_t>();
    uint64_t ramDiskSize =
            mFdp->ConsumeBool() ? contentRamdiskFd.size() : mFdp->ConsumeIntegral<uint64_t>();
    (void)replace_vendor_ramdisk(vendorBootFd, vendorBootSize, ramdiskName, ramdiskFd, ramDiskSize);
    close(vendorBootFd);
    close(ramdiskFd);
}

void FastbootFuzzer::process(const uint8_t* data, size_t size) {
    mFdp = make_unique<FuzzedDataProvider>(data, size);
    invokeParseApi();
    invokeSocket();
    invokeTcp();
    invokeUdp();
    invokeVendorBootImgUtils(data, size);
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    FastbootFuzzer fastbootFuzzer;
    fastbootFuzzer.process(data, size);
    return 0;
}
