// Copyright (C) 2020 The Android Open Source Project
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

#include <linux/types.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/mman.h>

#include <bitset>
#include <condition_variable>
#include <csignal>
#include <cstring>
#include <future>
#include <iostream>
#include <limits>
#include <map>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/stringprintf.h>
#include <android-base/unique_fd.h>
#include <ext4_utils/ext4_utils.h>
#include <libdm/dm.h>
#include <libsnapshot/cow_reader.h>
#include <libsnapshot/cow_writer.h>
#include <snapuserd/snapuserd_kernel.h>

namespace android {
namespace snapshot {

using android::base::unique_fd;
using namespace std::chrono_literals;

static constexpr size_t PAYLOAD_SIZE = (1UL << 20);
static_assert(PAYLOAD_SIZE >= BLOCK_SZ);

/*
 * With 4 threads, we get optimal performance
 * when update_verifier reads the partition during
 * boot.
 */
static constexpr int NUM_THREADS_PER_PARTITION = 1;

enum class READ_AHEAD_IO_TRANSITION {
    MERGE_READY,
    MERGE_BEGIN,
    MERGE_FAILED,
    MERGE_COMPLETE,
    IO_TERMINATED,
    READ_AHEAD_FAILURE,
};

enum class MERGE_BLOCK_STATE {
    MERGE_PENDING,
    MERGE_IN_PROGRESS,
    MERGE_COMPLETED,
    MERGE_FAILED,
};

struct MergeBlockState {
    MERGE_BLOCK_STATE merge_state_;
    size_t num_ios_in_progress_;

    MergeBlockState(MERGE_BLOCK_STATE state, size_t n_ios) :
      merge_state_(state), num_ios_in_progress_(n_ios) {}
};

class BufferSink : public IByteSink {
  public:
    void Initialize(size_t size);
    void* GetBufPtr() { return buffer_.get(); }
    void Clear() { memset(GetBufPtr(), 0, buffer_size_); }
    void* GetPayloadBuffer(size_t size);
    void* GetBuffer(size_t requested, size_t* actual) override;
    void UpdateBufferOffset(size_t size) { buffer_offset_ += size; }
    struct dm_user_header* GetHeaderPtr();
    bool ReturnData(void*, size_t) override { return true; }
    void ResetBufferOffset() { buffer_offset_ = 0; }
    void* GetPayloadBufPtr();

  private:
    std::unique_ptr<uint8_t[]> buffer_;
    loff_t buffer_offset_;
    size_t buffer_size_;
};

class XorSink : public IByteSink {
  public:
    void Initialize(BufferSink* sink, size_t size);
    void Reset();
    void* GetBuffer(size_t requested, size_t* actual) override;
    bool ReturnData(void* buffer, size_t len) override;

  private:
    BufferSink* bufsink_;
    std::unique_ptr<uint8_t[]> buffer_;
    size_t buffer_size_;
    size_t returned_;
};

class Snapuserd;

class ReadAheadThread {
  public:
    ReadAheadThread(const std::string& cow_device, const std::string& backing_device,
                    const std::string& misc_name, std::shared_ptr<Snapuserd> snapuserd);
    bool RunThread();

  private:
    void InitializeRAIter();
    bool RAIterDone();
    void RAIterNext();
    const CowOperation* GetRAOpIter();

    void InitializeBuffer();
    bool InitReader();
    bool InitializeFds();

    void CloseFds() {
        backing_store_fd_ = {};
    }

    bool ReadAheadIOStart();
    int PrepareReadAhead(uint64_t* source_offset, int* pending_ops,
                         std::vector<uint64_t>& blocks,
                         std::vector<const CowOperation*>& xor_op_vec);
    bool ReconstructDataFromCow();
    void CheckOverlap(const CowOperation* cow_op);

    void* read_ahead_buffer_;
    void* metadata_buffer_;
    std::vector<const CowOperation*>::iterator read_ahead_iter_;
    std::string cow_device_;
    std::string backing_store_device_;
    std::string misc_name_;

    unique_fd cow_fd_;
    unique_fd backing_store_fd_;

    std::shared_ptr<Snapuserd> snapuserd_;
    std::unique_ptr<CowReader> reader_;

    std::unordered_set<uint64_t> dest_blocks_;
    std::unordered_set<uint64_t> source_blocks_;
    bool overlap_;
    BufferSink bufsink_;
};

class WorkerThread {
  public:
    WorkerThread(const std::string& cow_device, const std::string& backing_device,
                 const std::string& control_device, const std::string& misc_name,
                 const std::string& base_path_merge,
                 std::shared_ptr<Snapuserd> snapuserd);
    bool RunThread();
    bool RunMergeThread();

  private:
    // Initialization
    void InitializeBufsink();
    bool InitializeFds();
    bool InitReader();
    void CloseFds() {
        ctrl_fd_ = {};
        backing_store_fd_ = {};
        base_path_merge_fd_ = {};
    }

    // IO Path
    bool ProcessIORequest();
    int ReadData(sector_t sector, size_t size);
    int ReadUnalignedSector(sector_t sector, size_t size,
                            std::vector<std::pair<sector_t, const CowOperation*>>::iterator& it);

    // Processing COW operations
    bool ProcessCowOp(const CowOperation* cow_op);
    bool ProcessReplaceOp(const CowOperation* cow_op);

    // Handles Copy and Xor
    bool ProcessCopyOp(const CowOperation* cow_op);
    bool ProcessXorOp(const CowOperation* cow_op);
    bool ProcessZeroOp();

    // Merge related ops
    bool Merge();
    bool MergeOrderedOps(std::unique_ptr<ICowOpIter>& cowop_iter);
    bool MergeReplaceZeroOps(std::unique_ptr<ICowOpIter>& cowop_iter);
    int PrepareMerge(uint64_t* source_offset, int* pending_ops,
                      std::unique_ptr<ICowOpIter>& cowop_iter,
                      std::vector<const CowOperation*>* replace_zero_vec = nullptr);

    bool ReadFromBaseDevice(const CowOperation* cow_op);

    sector_t ChunkToSector(chunk_t chunk) { return chunk << CHUNK_SHIFT; }
    chunk_t SectorToChunk(sector_t sector) { return sector >> CHUNK_SHIFT; }

    std::unique_ptr<CowReader> reader_;
    BufferSink bufsink_;
    XorSink xorsink_;

    std::string cow_device_;
    std::string backing_store_device_;
    std::string control_device_;
    std::string misc_name_;
    std::string base_path_merge_;

    unique_fd cow_fd_;
    unique_fd backing_store_fd_;
    unique_fd base_path_merge_fd_;
    unique_fd ctrl_fd_;

    std::shared_ptr<Snapuserd> snapuserd_;
};

class Snapuserd : public std::enable_shared_from_this<Snapuserd> {
  public:
    Snapuserd(const std::string& misc_name, const std::string& cow_device,
              const std::string& backing_device,
              const std::string& base_path_merge);
    bool InitCowDevice();
    bool Start();

    const std::string& GetControlDevicePath() { return control_device_; }
    const std::string& GetMiscName() { return misc_name_; }
    uint64_t GetNumSectors() { return num_sectors_; }
    bool IsAttached() const { return attached_; }
    void AttachControlDevice() { attached_ = true; }

    void CheckMergeCompletionStatus();
    bool CommitMerge(int num_merge_ops);

    void CloseFds() {
      cow_fd_ = {};
    }
    void FreeResources() {
        worker_threads_.clear();
        read_ahead_thread_ = nullptr;
        merge_thread_ = nullptr;
    }

    bool InitializeWorkers();
    std::unique_ptr<CowReader> CloneReaderForWorker();
    std::shared_ptr<Snapuserd> GetSharedPtr() { return shared_from_this(); }

    std::vector<std::pair<sector_t, const CowOperation*>>& GetChunkVec() { return chunk_vec_; }

    static bool compare(std::pair<sector_t, const CowOperation*> p1,
                        std::pair<sector_t, const CowOperation*> p2) {
        return p1.first < p2.first;
    }

    void UnmapBufferRegion();
    bool MmapMetadata();

    // Read-ahead related functions
    std::vector<const CowOperation*>& GetReadAheadOpsVec() { return read_ahead_ops_; }
    std::unordered_map<uint64_t, void*>& GetReadAheadMap() { return read_ahead_buffer_map_; }
    void* GetMappedAddr() { return mapped_addr_; }
    bool IsReadAheadFeaturePresent() { return read_ahead_feature_; }

    void PrepareReadAhead();
    void MergeCompleted();
    void MergeFailed();
    void ReadAheadIOFailed();

    //user-space merge transitions
    bool WaitForMergeReady();
    void NotifyRAForMergeReady();
    bool ReadAheadIOCompleted(bool sync);
    bool WaitForMergeBegin();
    void NotifyIOTerminated();
    void InitiateMerge();
    void WaitForMergeComplete();

    bool ReconstructDataFromCow() { return populate_data_from_cow_; }
    void ReconstructDataFromCowFinish() { populate_data_from_cow_ = false; }

    // RA related functions
    uint64_t GetBufferMetadataOffset();
    size_t GetBufferMetadataSize();
    size_t GetBufferDataOffset();
    size_t GetBufferDataSize();

    // Total number of blocks to be merged in a given read-ahead buffer region
    void SetTotalRaBlocksMerged(int x) { total_ra_blocks_merged_ = x; }
    int GetTotalRaBlocksMerged() { return total_ra_blocks_merged_; }
    void SetSocketPresent(bool socket) { is_socket_present_ = socket; }
    bool MergeInitiated() { return merge_initiated_; }
    double GetMergePercentage() { return merge_completion_percentage_; }

    // Merge Block State Transitions
    void SetMergeBlockCompleted(size_t block_index);
    void SetMergeBlockPending(size_t block_index);

  private:
    bool ReadMetadata();
    sector_t ChunkToSector(chunk_t chunk) { return chunk << CHUNK_SHIFT; }
    chunk_t SectorToChunk(sector_t sector) { return sector >> CHUNK_SHIFT; }
    bool IsBlockAligned(int read_size) { return ((read_size & (BLOCK_SZ - 1)) == 0); }
    struct BufferState* GetBufferState();
    void UpdateMergeCompletionPercentage();

    void ReadBlocks(const std::string partition_name, const std::string& dm_block_device);
    void ReadBlocksToCache(const std::string& dm_block_device, const std::string partition_name,
                           off_t offset, size_t size);

    std::string cow_device_;
    std::string backing_store_device_;
    std::string control_device_;
    std::string misc_name_;
    std::string base_path_merge_;

    unique_fd cow_fd_;

    uint64_t num_sectors_;

    std::unique_ptr<CowReader> reader_;

    // chunk_vec stores the pseudo mapping of sector
    // to COW operations.
    std::vector<std::pair<sector_t, const CowOperation*>> chunk_vec_;

    std::mutex lock_;
    std::condition_variable cv;

    void* mapped_addr_;
    size_t total_mapped_addr_length_;

    std::vector<std::unique_ptr<WorkerThread>> worker_threads_;
    // Read-ahead related
    std::unordered_map<uint64_t, void*> read_ahead_buffer_map_;
    std::vector<const CowOperation*> read_ahead_ops_;
    bool populate_data_from_cow_ = false;
    bool read_ahead_feature_;
    int total_ra_blocks_merged_ = 0;
    READ_AHEAD_IO_TRANSITION io_state_;
    std::unique_ptr<ReadAheadThread> read_ahead_thread_;

    // user-space-merging
    std::unordered_map<uint64_t, int> block_to_ra_index_;

    // Merge Block state
    std::vector<std::unique_ptr<MergeBlockState>> merge_blk_state_;
    std::mutex m_lock_;
    std::condition_variable m_cv_;

    std::unique_ptr<WorkerThread> merge_thread_;
    double merge_completion_percentage_;

    bool merge_initiated_ = false;
    bool attached_ = false;
    bool is_socket_present_;
};

}  // namespace snapshot
}  // namespace android
