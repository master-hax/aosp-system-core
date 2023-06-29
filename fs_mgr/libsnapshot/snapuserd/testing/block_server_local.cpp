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

#include "block_server_local.h"

#include <chrono>

#include "snapuserd_logging.h"

namespace android {
namespace snapshot {

using namespace std::chrono_literals;

LocalBlockServer::LocalBlockServer(std::shared_ptr<LocalBlockServerQueue> queue, Delegate* delegate)
    : queue_(queue), delegate_(delegate) {}

bool LocalBlockServer::ProcessRequests() {
    while (true) {
        current_request_ = queue_->GetNextRequest();
        if (!current_request_) {
            // No more requests, time to shutdown.
            return false;
        }
        if (current_request_->shutdown) {
            current_request_->completed = true;
            current_request_->cv.notify_one();
            return false;
        }

        // Reset per-request state.
        buffers_.clear();

        bool ok = delegate_->RequestSectors(current_request_->sector, current_request_->len);

        // If ProcessRequest returns false, then SendError() should have been called.
        CHECK_EQ(ok, current_request_->errored);
        if (ok) {
            // The entire request should have been fulfilled.
            CHECK_EQ(current_request_->len, current_request_->fulfilled);
            // There should be no pending buffered data.
            CHECK(buffers_.empty());
        }

        current_request_->completed = true;
        current_request_->cv.notify_one();
        current_request_ = nullptr;
    }
}

void* LocalBlockServer::GetResponseBuffer(size_t size, size_t to_write) {
    CHECK_NE(current_request_, nullptr);
    CHECK_LE(to_write, size);

    std::string buffer(size, '\0');
    buffers_.emplace_back(std::move(buffer), to_write);
    return buffers_.back().first.data();
}

bool LocalBlockServer::SendBufferedIo() {
    CHECK_NE(current_request_, nullptr);
    CHECK_LE(current_request_->fulfilled, current_request_->len);

    while (!buffers_.empty()) {
        std::pair<std::string, size_t> buffer = std::move(buffers_.front());
        buffers_.pop_front();

        // Abort if we're trying to write too much data.
        if (current_request_->len - current_request_->fulfilled < buffer.second) {
            LOG(ERROR) << "Returned too much data to read request";
            return false;
        }

        memcpy(current_request_->out + current_request_->fulfilled, buffer.first.data(),
               buffer.second);
        current_request_->fulfilled += buffer.second;
    }

    return true;
}

void LocalBlockServer::SendError() {
    current_request_->errored = true;
}

LocalBlockServerQueue::LocalBlockServerQueue(const std::string& misc_name, uint64_t num_sectors)
    : misc_name_(misc_name), num_sectors_(num_sectors) {}

std::unique_ptr<IBlockServer> LocalBlockServerQueue::Open(IBlockServer::Delegate* delegate) {
    return std::make_unique<LocalBlockServer>(shared_from_this(), delegate);
}

BlockRequest* LocalBlockServerQueue::GetNextRequest() {
    std::unique_lock<std::mutex> lock(lock_);

    auto stop_waiting = [this]() -> bool { return shutdown_ || !requests_.empty(); };
    cv_.wait(lock, stop_waiting);

    // If no more requests, then we've shutdown.
    if (requests_.empty()) {
        CHECK(shutdown_);
        return nullptr;
    }

    auto request = std::move(requests_.front());
    requests_.pop_front();
    return request;
}

bool LocalBlockServerQueue::Read(uint64_t sector, void* buffer, uint64_t len) {
    if (len > num_sectors_ || sector > num_sectors_ - len) {
        LOG(ERROR) << "Invalid read request (sector " << sector << ", len " << len
                   << ", num_sectors " << num_sectors_ << ")";
        return false;
    }

    BlockRequest request;
    request.sector = sector;
    request.out = reinterpret_cast<uint8_t*>(buffer);
    request.len = len;

    return CompleteRequest(&request);
}

bool LocalBlockServerQueue::CompleteRequest(BlockRequest* request) {
    {
        std::unique_lock<std::mutex> lock(lock_);
        if (shutdown_) {
            LOG(ERROR) << "Attempt to read after block queue shutdown";
            return false;
        }
        if (request->shutdown) {
            shutdown_ = true;
        }
        requests_.emplace_back(request);
        cv_.notify_all();
    }

    std::unique_lock<std::mutex> lock(request->m);
    request->cv.wait(lock, [&]() -> bool { return request->completed; });
    return !request->errored;
}

void LocalBlockServerQueue::Shutdown() {
    std::unique_lock<std::mutex> lock(lock_);

    if (shutdown_) {
        return;
    }

    // Push a bogus request, which allows us to wait for all previous requests
    // to complete.
    BlockRequest request;
    request.shutdown = true;
    CompleteRequest(&request);
}

LocalBlockServerFactory::~LocalBlockServerFactory() {
    auto devices = std::move(devices_);
    for (const auto& entry : devices) {
        entry.second->Shutdown();
    }
}

std::shared_ptr<IBlockServerOpener> LocalBlockServerFactory::CreateOpener(
        const std::string& misc_name) {
    auto iter = devices_.find(misc_name);
    if (iter == devices_.end()) {
        LOG(ERROR) << "Device not found: " << misc_name;
        return nullptr;
    }
    return iter->second;
}

std::shared_ptr<LocalBlockServerQueue> LocalBlockServerFactory::AddDevice(
        const std::string& misc_name, uint64_t num_sectors) {
    if (auto iter = devices_.find(misc_name); iter != devices_.end()) {
        LOG(ERROR) << "Device already exists: " << misc_name;
        return nullptr;
    }

    auto dev = std::shared_ptr<LocalBlockServerQueue>(
            new LocalBlockServerQueue(misc_name, num_sectors));
    devices_[misc_name] = dev;
    return dev;
}

bool LocalBlockServerFactory::DeleteDevice(const std::string& misc_name) {
    auto iter = devices_.find(misc_name);
    if (iter == devices_.end()) {
        LOG(ERROR) << "Device not found: " << misc_name;
        return false;
    }

    iter->second->Shutdown();
    devices_.erase(iter);
    return true;
}

}  // namespace snapshot
}  // namespace android
