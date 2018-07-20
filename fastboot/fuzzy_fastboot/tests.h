#pragma once
#include <cstdlib>
#include <string>
#include <vector>

#include "fastboot_hli.h"

class FastBootTest {
  public:
    enum TestResult : int {
        PASS = 0,
        FAIL,
        WARNING,
    };

    virtual ~FastBootTest() = default;
    virtual TestResult Run(FastBootHLI& fb) = 0;
    virtual const std::string& Name() = 0;
    virtual const std::string& Descrip() = 0;
};

class AliveTest : public FastBootTest {
  public:
    virtual TestResult Run(FastBootHLI& fb) override;
    virtual const std::string& Name() override;
    virtual const std::string& Descrip() override;
};

class LongCmd : public FastBootTest {
  public:
    virtual TestResult Run(FastBootHLI& fb) override;
    virtual const std::string& Name() override;
    virtual const std::string& Descrip() override;
};

// It is critical that reconnection works for error recovery
class DeviceReconnect : public FastBootTest {
  public:
    virtual TestResult Run(FastBootHLI& fb) override;
    virtual const std::string& Name() override;
    virtual const std::string& Descrip() override;
};

class DownloadSize : public FastBootTest {
  public:
    virtual TestResult Run(FastBootHLI& fb) override;
    virtual const std::string& Name() override;
    virtual const std::string& Descrip() override;
};

class PartionBounds : public FastBootTest {
  public:
    virtual TestResult Run(FastBootHLI& fb) override;
    virtual const std::string& Name() override;
    virtual const std::string& Descrip() override;
};
