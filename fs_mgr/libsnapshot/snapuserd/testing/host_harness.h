// Copyright (C) 2023 The Android Open Source Project
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#pragma once

#include <string>
#include <utility>
#include <vector>

#include "harness.h"

namespace android {
namespace snapshot {

class TestBlockServer final : public IBlockServer {
  public:
    explicit TestBlockServer(const std::string& misc_name);
    bool ProcessRequests() override;
    void* GetResponseBuffer(size_t size, size_t to_write) override;
    bool SendBufferedIo() override;

    std::string&& sent_io() { return std::move(sent_io_); }

  private:
    std::string misc_name_;
    std::string sent_io_;
    std::vector<std::pair<std::string, size_t>> buffered_;
};

class TestBlockServerOpener final : public IBlockServerOpener {
  public:
    explicit TestBlockServerOpener(const std::string& misc_name);
    std::unique_ptr<IBlockServer> Open(IBlockServer::Delegate* delegate,
                                       size_t buffer_size) override;

  private:
    std::string misc_name_;
};

class TestBlockServerFactory final : public IBlockServerFactory {
  public:
    std::shared_ptr<IBlockServerOpener> CreateOpener(const std::string& misc_name) override;
};

class HostUserDevice final : public IUserDevice {
  public:
    const std::string& GetPath() override { return empty_name_; }
    bool Destroy() { return true; }

  private:
    std::string empty_name_;
};

class HostTestHarness final : public ITestHarness {
  public:
    std::unique_ptr<IUserDevice> CreateUserDevice(const std::string& dev_name,
                                                  const std::string& misc_name,
                                                  uint64_t num_sectors) override;
    IBlockServerFactory* GetBlockServerFactory() override;
    bool HasUserDevice() override { return false; }

  private:
    TestBlockServerFactory factory_;
};

}  // namespace snapshot
}  // namespace android
