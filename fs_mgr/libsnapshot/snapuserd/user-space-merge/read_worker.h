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

#include <utility>
#include <vector>

#include <snapuserd/block_server.h>
#include "worker.h"

namespace android {
namespace snapshot {

class ReadWorker : public Worker, public IBlockServer::Delegate {
  public:
    ReadWorker(const std::string& cow_device, const std::string& backing_device,
               const std::string& misc_name, const std::string& base_path_merge,
               std::shared_ptr<SnapshotHandler> snapuserd,
               std::shared_ptr<IBlockServerOpener> opener);

    bool Run();
    bool Init() override;
    void CloseFds() override;
    bool RequestSectors(uint64_t sector, uint64_t size) override;

    IBlockServer* block_server() const { return block_server_.get(); }

  private:
    bool SendBufferedIo();

    bool ProcessCowOp(const CowOperationV2* cow_op, void* buffer);
    bool ProcessXorOp(const CowOperationV2* cow_op, void* buffer);
    bool ProcessOrderedOp(const CowOperationV2* cow_op, void* buffer);
    bool ProcessCopyOp(const CowOperationV2* cow_op, void* buffer);
    bool ProcessReplaceOp(const CowOperationV2* cow_op, void* buffer);
    bool ProcessZeroOp(void* buffer);

    bool ReadAlignedSector(sector_t sector, size_t sz);
    bool ReadUnalignedSector(sector_t sector, size_t size);
    int ReadUnalignedSector(sector_t sector, size_t size,
                            std::vector<std::pair<sector_t, const CowOperationV2*>>::iterator& it);
    bool ReadFromSourceDevice(const CowOperationV2* cow_op, void* buffer);
    bool ReadDataFromBaseDevice(sector_t sector, void* buffer, size_t read_size);

    constexpr bool IsBlockAligned(size_t size) { return ((size & (BLOCK_SZ - 1)) == 0); }
    constexpr sector_t ChunkToSector(chunk_t chunk) { return chunk << CHUNK_SHIFT; }

    std::string backing_store_device_;
    unique_fd backing_store_fd_;

    std::shared_ptr<IBlockServerOpener> block_server_opener_;
    std::unique_ptr<IBlockServer> block_server_;

    std::basic_string<uint8_t> xor_buffer_;
};

}  // namespace snapshot
}  // namespace android
