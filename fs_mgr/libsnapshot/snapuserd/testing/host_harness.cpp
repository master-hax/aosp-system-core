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

#include "host_harness.h"

#include "snapuserd_logging.h"

namespace android {
namespace snapshot {

TestBlockServer::TestBlockServer(const std::string& misc_name) : misc_name_(misc_name) {}

bool TestBlockServer::ProcessRequests() {
    SNAP_LOG(ERROR) << "ProcessRequests not supported in TestBlockServer";
    return false;
}

void* TestBlockServer::GetResponseBuffer(size_t size, size_t to_write) {
    std::string buffer(size, '\0');
    buffered_.emplace_back(std::move(buffer), to_write);
    return buffered_.back().first.data();
}

bool TestBlockServer::SendBufferedIo() {
    for (const auto& [data, to_write] : buffered_) {
        sent_io_ += data.substr(0, to_write);
    }
    buffered_.clear();
    return true;
}

TestBlockServerOpener::TestBlockServerOpener(const std::string& misc_name)
    : misc_name_(misc_name) {}

std::unique_ptr<IBlockServer> TestBlockServerOpener::Open(IBlockServer::Delegate*, size_t) {
    return std::make_unique<TestBlockServer>(misc_name_);
}

std::shared_ptr<IBlockServerOpener> TestBlockServerFactory::CreateOpener(
        const std::string& misc_name) {
    return std::make_shared<TestBlockServerOpener>(misc_name);
}

std::unique_ptr<IUserDevice> HostTestHarness::CreateUserDevice(const std::string&,
                                                               const std::string&, uint64_t) {
    return std::make_unique<HostUserDevice>();
}

IBlockServerFactory* HostTestHarness::GetBlockServerFactory() {
    return &factory_;
}

}  // namespace snapshot
}  // namespace android
