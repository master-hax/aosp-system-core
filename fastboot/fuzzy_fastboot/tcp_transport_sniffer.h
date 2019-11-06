#pragma once

#include <sys/types.h>
#include <unistd.h>
#include <chrono>
#include <cstdlib>
#include <fstream>
#include <string>
#include <vector>

#include "tcp.h"

namespace fastboot {

class TcpTransportSniffer : public Transport {
  public:
    TcpTransportSniffer(std::unique_ptr<Transport> transport);
    ~TcpTransportSniffer() override;

    virtual ssize_t Read(void* data, size_t len) override;
    virtual ssize_t Write(const void* data, size_t len) override;
    virtual int Close() override final;  // note usage in destructor
    virtual int Reset();

  private:
    std::unique_ptr<Transport> transport_;
};

}  // End namespace fastboot
