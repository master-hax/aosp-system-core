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

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <sys/types.h>

#include <condition_variable>
#include <deque>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>
#include <utility>

#include <snapuserd/block_server.h>

namespace android {
namespace snapshot {

class LocalBlockServerQueue;

// Userspace version of dm_user_header.
struct BlockRequest {
    // Used to handle per-request notifications.
    std::mutex m;
    std::condition_variable cv;

    // In/out from snapuserd.
    uint64_t sector = 0;
    uint64_t len = 0;
    uint8_t* out = nullptr;

    // Request state.
    uint64_t fulfilled = 0;
    bool errored = false;
    bool shutdown = false;
    bool completed = false;
};

// Represents a "connection" to a fake dm-user device.
class LocalBlockServer final : public IBlockServer {
  public:
    LocalBlockServer(std::shared_ptr<LocalBlockServerQueue> queue, Delegate* delegate);
    bool ProcessRequests() override;
    void* GetResponseBuffer(size_t size, size_t to_write) override;
    bool SendBufferedIo() override;
    void SendError() override;

  private:
    std::shared_ptr<LocalBlockServerQueue> queue_;
    Delegate* delegate_;
    BlockRequest* current_request_ = nullptr;

    // Request response state.
    std::deque<std::pair<std::string, size_t>> buffers_;
};

// Represents a fake dm-user driver. This contains a queue of BlockRequests to
// process. Requests are pushed on the writer thread and removed from the queue
// on the reader thread.
class LocalBlockServerQueue final : public IBlockServerOpener,
                                    public std::enable_shared_from_this<LocalBlockServerQueue> {
  public:
    std::unique_ptr<IBlockServer> Open(IBlockServer::Delegate* delegate) override;

    // Pop the next read request from the queue. Called from the reader thread.
    BlockRequest* GetNextRequest();

    // Request a read, which will get processed by a LocalBlockServer. This
    // should be called from a writer thread.
    bool Read(uint64_t sector, void* buffer, uint64_t len);

    void Shutdown();

    const std::string& misc_name() const { return misc_name_; }

  private:
    friend class LocalBlockServerFactory;

    explicit LocalBlockServerQueue(const std::string& misc_name, uint64_t num_sectors);

    bool CompleteRequest(std::unique_lock<std::mutex>* lock, BlockRequest* request);

    std::string misc_name_;
    uint64_t num_sectors_;

    // The API does not actually do multi-threaded reads, but we still use a
    // deque anyway for simplicity.
    std::mutex lock_;
    std::condition_variable cv_;
    std::deque<BlockRequest*> requests_;
    bool shutdown_ = false;
};

class LocalBlockServerFactory final : public IBlockServerFactory {
  public:
    ~LocalBlockServerFactory();

    std::shared_ptr<IBlockServerOpener> CreateOpener(const std::string& misc_name) override;

    std::shared_ptr<LocalBlockServerQueue> AddDevice(const std::string& misc_name,
                                                     uint64_t num_sectors);
    bool DeleteDevice(const std::string& misc_name);

  private:
    std::unordered_map<std::string, std::shared_ptr<LocalBlockServerQueue>> devices_;
};

}  // namespace snapshot
}  // namespace android
