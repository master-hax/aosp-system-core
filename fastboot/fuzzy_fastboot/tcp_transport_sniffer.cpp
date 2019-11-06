#include "tcp_transport_sniffer.h"
#include <android-base/stringprintf.h>
#include <sys/select.h>
#include <sys/time.h>
#include <sys/types.h>
#include <iomanip>
#include <sstream>

namespace fastboot {

TcpTransportSniffer::TcpTransportSniffer(std::unique_ptr<Transport> transport)
    : transport_(std::move(transport)) {}

TcpTransportSniffer::~TcpTransportSniffer() {
    Close();
}

ssize_t TcpTransportSniffer::Read(void* data, size_t len) {
    return transport_->Read(data, len);
}

ssize_t TcpTransportSniffer::Write(const void* data, size_t len) {
    return transport_->Write(data, len);
}

int TcpTransportSniffer::Close() {
    return transport_->Close();
}

int TcpTransportSniffer::Reset() {
    return 0;
}

}  // namespace fastboot
