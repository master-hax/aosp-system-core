/*
 * Copyright (C) 2020 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "snapuserd.h"

#include <dirent.h>
#include <fcntl.h>
#include <linux/fs.h>
#include <unistd.h>
#include <algorithm>

#include <csignal>
#include <optional>
#include <set>

#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/parseint.h>
#include <android-base/properties.h>
#include <android-base/strings.h>
#include <android-base/unique_fd.h>
#include <snapuserd/snapuserd_client.h>

namespace android {
namespace snapshot {

using namespace android;
using namespace android::dm;
using android::base::unique_fd;

#define SNAP_LOG(level) LOG(level) << misc_name_ << ": "
#define SNAP_PLOG(level) PLOG(level) << misc_name_ << ": "

Snapuserd::Snapuserd(const std::string& misc_name, const std::string& cow_device,
                     const std::string& backing_device,
                     const std::string& base_path_merge) {
    misc_name_ = misc_name;
    cow_device_ = cow_device;
    backing_store_device_ = backing_device;
    control_device_ = "/dev/dm-user/" + misc_name;
    base_path_merge_ = base_path_merge;
}

bool Snapuserd::InitializeWorkers() {
    for (int i = 0; i < NUM_THREADS_PER_PARTITION; i++) {
        std::unique_ptr<WorkerThread> wt = std::make_unique<WorkerThread>(
                cow_device_, backing_store_device_, control_device_, misc_name_,
                base_path_merge_, GetSharedPtr());

        worker_threads_.push_back(std::move(wt));
    }

    merge_thread_ = std::make_unique<WorkerThread>(
              cow_device_, backing_store_device_, control_device_, misc_name_,
              base_path_merge_, GetSharedPtr());

    read_ahead_thread_ = std::make_unique<ReadAheadThread>(cow_device_, backing_store_device_,
                                                           misc_name_, GetSharedPtr());
    return true;
}

std::unique_ptr<CowReader> Snapuserd::CloneReaderForWorker() {
    return reader_->CloneCowReader();
}

void Snapuserd::UpdateMergeCompletionPercentage() {
    struct CowHeader* ch = reinterpret_cast<struct CowHeader*>(mapped_addr_);
    merge_completion_percentage_ = (ch->num_merge_ops * 100.0) / reader_->get_num_total_data_ops();

    SNAP_LOG(DEBUG) << "Merge-complete %: " << merge_completion_percentage_
                   << " num_merge_ops: " << ch->num_merge_ops
                   << " total-ops: " << reader_->get_num_total_data_ops();
}

bool Snapuserd::CommitMerge(int num_merge_ops) {
    struct CowHeader* ch = reinterpret_cast<struct CowHeader*>(mapped_addr_);
    ch->num_merge_ops += num_merge_ops;

    if (read_ahead_feature_ && read_ahead_ops_.size() > 0) {
        struct BufferState* ra_state = GetBufferState();
        ra_state->read_ahead_state = kCowReadAheadInProgress;
    }

    int ret = msync(mapped_addr_, BLOCK_SZ, MS_SYNC);
    if (ret < 0) {
        SNAP_PLOG(ERROR) << "msync header failed: " << ret;
        return false;
    }

    // Update the merge completion - this is used by update engine
    // to track the completion. No need to take a lock. It is ok
    // even if there is a miss on reading a latest updated value.
    // Subsequent polling will eventually converge to completion.
    UpdateMergeCompletionPercentage();
    return true;
}

void Snapuserd::PrepareReadAhead() {
    if (!read_ahead_feature_) {
        return;
    }

    struct BufferState* ra_state = GetBufferState();
    // Check if the data has to be re-constructed from COW device
    if (ra_state->read_ahead_state == kCowReadAheadDone) {
        populate_data_from_cow_ = true;
    } else {
        populate_data_from_cow_ = false;
    }

    NotifyRAForMergeReady();
}

void Snapuserd::InitiateMerge() {
    SNAP_LOG(INFO) << "Initiating merge....";
    {
        std::lock_guard<std::mutex> lock(lock_);
        merge_initiated_ = true;
        bool rathread = (read_ahead_feature_ && (read_ahead_ops_.size() > 0));

        // If there are only REPLACE ops to be merged, then we need
        // to explicitly set the state to MERGE_BEGIN as there
        // is no read-ahead thread
        if (!rathread) {
            io_state_ = READ_AHEAD_IO_TRANSITION::MERGE_BEGIN;
        }
    }
    cv.notify_all();
}

// For testing only
void Snapuserd::WaitForMergeComplete() {
    {
        std::unique_lock<std::mutex> lock(lock_);
        while (!(io_state_ == READ_AHEAD_IO_TRANSITION::MERGE_COMPLETE ||
                 io_state_ == READ_AHEAD_IO_TRANSITION::MERGE_FAILED ||
                 io_state_ == READ_AHEAD_IO_TRANSITION::IO_TERMINATED)) {
            cv.wait(lock);
        }
    }
}

bool Snapuserd::WaitForMergeBegin() {
    {
        std::unique_lock<std::mutex> lock(lock_);
        while (!MergeInitiated() ||
                !(io_state_ == READ_AHEAD_IO_TRANSITION::MERGE_BEGIN ||
                  io_state_ == READ_AHEAD_IO_TRANSITION::READ_AHEAD_FAILURE ||
                  io_state_ == READ_AHEAD_IO_TRANSITION::IO_TERMINATED)) {
            cv.wait(lock);
        }

        if (io_state_ == READ_AHEAD_IO_TRANSITION::READ_AHEAD_FAILURE ||
            io_state_ == READ_AHEAD_IO_TRANSITION::IO_TERMINATED) {
            return false;
        }

        return true;
    }
}

void Snapuserd::NotifyRAForMergeReady() {
    {
        std::lock_guard<std::mutex> lock(lock_);
        if (io_state_ != READ_AHEAD_IO_TRANSITION::IO_TERMINATED &&
            io_state_ != READ_AHEAD_IO_TRANSITION::READ_AHEAD_FAILURE) {
            SNAP_LOG(INFO) << "Setting IO state to merge_ready...";
            io_state_ = READ_AHEAD_IO_TRANSITION::MERGE_READY;
        }
    }

    cv.notify_all();
}

bool Snapuserd::WaitForMergeReady() {
    {
        std::unique_lock<std::mutex> lock(lock_);
        while (!(io_state_ == READ_AHEAD_IO_TRANSITION::MERGE_READY ||
                 io_state_ == READ_AHEAD_IO_TRANSITION::MERGE_FAILED ||
                 io_state_ == READ_AHEAD_IO_TRANSITION::MERGE_COMPLETE ||
                 io_state_ == READ_AHEAD_IO_TRANSITION::IO_TERMINATED)) {
            cv.wait(lock);
        }

        if (io_state_ == READ_AHEAD_IO_TRANSITION::MERGE_FAILED ||
            io_state_ == READ_AHEAD_IO_TRANSITION::MERGE_COMPLETE ||
            io_state_ == READ_AHEAD_IO_TRANSITION::IO_TERMINATED) {
            return false;
        }
        return true;
    }
}

void Snapuserd::MergeFailed() {
    {
        std::lock_guard<std::mutex> lock(lock_);
        io_state_ = READ_AHEAD_IO_TRANSITION::MERGE_FAILED;
    }

    cv.notify_all();
}

void Snapuserd::MergeCompleted() {
    {
        std::lock_guard<std::mutex> lock(lock_);
        io_state_ = READ_AHEAD_IO_TRANSITION::MERGE_COMPLETE;
    }

    cv.notify_all();
}

void Snapuserd::NotifyIOTerminated() {
    {
        std::lock_guard<std::mutex> lock(lock_);
        io_state_ = READ_AHEAD_IO_TRANSITION::IO_TERMINATED;
    }

    SNAP_LOG(INFO) << "io-terminated - requesting merge to fail...";
    cv.notify_all();
}

bool Snapuserd::ReadAheadIOCompleted(bool sync) {
    if (sync) {
        // Flush the entire buffer region
        int ret = msync(mapped_addr_, total_mapped_addr_length_, MS_SYNC);
        if (ret < 0) {
            PLOG(ERROR) << "msync failed after ReadAheadIOCompleted: " << ret;
            return false;
        }

        // Metadata and data are synced. Now, update the state.
        // We need to update the state after flushing data; if there is a crash
        // when read-ahead IO is in progress, the state of data in the COW file
        // is unknown. kCowReadAheadDone acts as a checkpoint wherein the data
        // in the scratch space is good and during next reboot, read-ahead thread
        // can safely re-construct the data.
        struct BufferState* ra_state = GetBufferState();
        ra_state->read_ahead_state = kCowReadAheadDone;

        ret = msync(mapped_addr_, BLOCK_SZ, MS_SYNC);
        if (ret < 0) {
            PLOG(ERROR) << "msync failed to flush Readahead completion state...";
            return false;
        }

        SNAP_LOG(INFO) << "msync done for overlapping blocks.....";
    }

    // Notify the merge thread
    {
        std::lock_guard<std::mutex> lock(lock_);
        if (io_state_ != READ_AHEAD_IO_TRANSITION::IO_TERMINATED &&
            io_state_ != READ_AHEAD_IO_TRANSITION::MERGE_FAILED) {
            SNAP_LOG(INFO) << "Setting IO state to merge_begin";
            io_state_ = READ_AHEAD_IO_TRANSITION::MERGE_BEGIN;
        }
    }

    cv.notify_all();
    return true;
}

void Snapuserd::ReadAheadIOFailed() {
    {
        std::lock_guard<std::mutex> lock(lock_);
        io_state_ = READ_AHEAD_IO_TRANSITION::READ_AHEAD_FAILURE;
    }

    cv.notify_all();
}

//========== End of state transition functions ====================

void Snapuserd::CheckMergeCompletionStatus() {
    if (!merge_initiated_) {
        SNAP_LOG(INFO) << "Merge was not initiated. Total-data-ops: "
                       << reader_->get_num_total_data_ops();
        return;
    }

    struct CowHeader* ch = reinterpret_cast<struct CowHeader*>(mapped_addr_);

    SNAP_LOG(INFO) << "Merge-status: Total-Merged-ops: " << ch->num_merge_ops
                   << " Total-data-ops: " << reader_->get_num_total_data_ops();
}

bool Snapuserd::ReadMetadata() {
    reader_ = std::make_unique<CowReader>();
    CowHeader header;
    CowOptions options;

    SNAP_LOG(DEBUG) << "ReadMetadata: Parsing cow file";

    if (!reader_->Parse(cow_fd_)) {
        SNAP_LOG(ERROR) << "Failed to parse";
        return false;
    }

    if (!reader_->GetHeader(&header)) {
        SNAP_LOG(ERROR) << "Failed to get header";
        return false;
    }

    if (!(header.block_size == BLOCK_SZ)) {
        SNAP_LOG(ERROR) << "Invalid header block size found: " << header.block_size;
        return false;
    }

    SNAP_LOG(INFO) << "Merge-ops: " << header.num_merge_ops;

    if (!MmapMetadata()) {
        SNAP_LOG(ERROR) << "mmap failed";
        return false;
    }

    UpdateMergeCompletionPercentage();

    // Initialize the iterator for reading metadata
    std::unique_ptr<ICowOpIter> cowop_iter = reader_->GetMergeOpIter();

    int num_ra_ops_per_iter = ((GetBufferDataSize()) / BLOCK_SZ);
    int ra_index = 0;

    while (!cowop_iter->Done()) {
        const CowOperation* cow_op = &cowop_iter->Get();

        chunk_vec_.push_back(std::make_pair(ChunkToSector(cow_op->new_block), cow_op));
        cowop_iter->Next();

        if (IsOrderedOp(*cow_op)) {
            read_ahead_ops_.push_back(cow_op);
            block_to_ra_index_[cow_op->new_block] = ra_index;
            num_ra_ops_per_iter -= 1;

            if ((ra_index + 1) - merge_blk_state_.size() == 1) {
                std::unique_ptr<MergeBlockState> blk_state =
                    std::make_unique<MergeBlockState>(MERGE_BLOCK_STATE::MERGE_PENDING, 0);

                merge_blk_state_.push_back(std::move(blk_state));
            }

            // Move to next RA block
            if (num_ra_ops_per_iter == 0) {
                num_ra_ops_per_iter = ((GetBufferDataSize()) / BLOCK_SZ);
                ra_index += 1;
            }
        }
    }

    chunk_vec_.shrink_to_fit();
    read_ahead_ops_.shrink_to_fit();

    // Sort the vector based on sectors as we need this during un-aligned access
    std::sort(chunk_vec_.begin(), chunk_vec_.end(), compare);

    PrepareReadAhead();

    return true;
}

bool Snapuserd::MmapMetadata() {
    CowHeader header;
    reader_->GetHeader(&header);

    if (header.major_version >= 2 && header.buffer_size > 0) {
        total_mapped_addr_length_ = header.header_size + BUFFER_REGION_DEFAULT_SIZE;
        read_ahead_feature_ = true;
    } else {
        // mmap the first 4k page - older COW format
        total_mapped_addr_length_ = BLOCK_SZ;
        read_ahead_feature_ = false;
    }

    mapped_addr_ = mmap(NULL, total_mapped_addr_length_, PROT_READ | PROT_WRITE, MAP_SHARED,
                        cow_fd_.get(), 0);
    if (mapped_addr_ == MAP_FAILED) {
        SNAP_LOG(ERROR) << "mmap metadata failed";
        return false;
    }

    return true;
}

void Snapuserd::UnmapBufferRegion() {
    int ret = munmap(mapped_addr_, total_mapped_addr_length_);
    if (ret < 0) {
        SNAP_PLOG(ERROR) << "munmap failed";
    }
}

void MyLogger(android::base::LogId, android::base::LogSeverity severity, const char*, const char*,
              unsigned int, const char* message) {
    if (severity == android::base::ERROR) {
        fprintf(stderr, "%s\n", message);
    } else {
        fprintf(stdout, "%s\n", message);
    }
}

bool Snapuserd::InitCowDevice() {
    cow_fd_.reset(open(cow_device_.c_str(), O_RDWR));
    if (cow_fd_ < 0) {
        SNAP_PLOG(ERROR) << "Open Failed: " << cow_device_;
        return false;
    }

    unique_fd fd(TEMP_FAILURE_RETRY(open(base_path_merge_.c_str(), O_RDONLY | O_CLOEXEC)));
    if (fd < 0) {
        SNAP_LOG(ERROR) << "Cannot open block device";
        return false;
    }

    uint64_t dev_sz = get_block_device_size(fd.get());
    if (!dev_sz) {
        SNAP_LOG(ERROR) << "Failed to find block device size: " << base_path_merge_;
        return false;
    }

    num_sectors_ = dev_sz >> SECTOR_SHIFT;

    return ReadMetadata();
}

void Snapuserd::ReadBlocksToCache(const std::string& dm_block_device,
                                  const std::string partition_name, off_t offset, size_t size) {
    android::base::unique_fd fd(TEMP_FAILURE_RETRY(open(dm_block_device.c_str(), O_RDONLY)));
    if (fd.get() == -1) {
        SNAP_PLOG(ERROR) << "Error reading " << dm_block_device
                         << " partition-name: " << partition_name;
        return;
    }

    size_t remain = size;
    off_t file_offset = offset;
    // We pick 4M I/O size based on the fact that the current
    // update_verifier has a similar I/O size.
    size_t read_sz = 1024 * BLOCK_SZ;
    std::vector<uint8_t> buf(read_sz);

    while (remain > 0) {
        size_t to_read = std::min(remain, read_sz);

        if (!android::base::ReadFullyAtOffset(fd.get(), buf.data(), to_read, file_offset)) {
            SNAP_PLOG(ERROR) << "Failed to read block from block device: " << dm_block_device
                             << " at offset: " << file_offset
                             << " partition-name: " << partition_name << " total-size: " << size
                             << " remain_size: " << remain;
            return;
        }

        file_offset += to_read;
        remain -= to_read;
    }

    SNAP_LOG(INFO) << "Finished reading block-device: " << dm_block_device
                   << " partition: " << partition_name << " size: " << size
                   << " offset: " << offset;
}

void Snapuserd::ReadBlocks(const std::string partition_name, const std::string& dm_block_device) {
    SNAP_LOG(DEBUG) << "Reading partition: " << partition_name
                    << " Block-Device: " << dm_block_device;

    uint64_t dev_sz = 0;

    unique_fd fd(TEMP_FAILURE_RETRY(open(dm_block_device.c_str(), O_RDONLY | O_CLOEXEC)));
    if (fd < 0) {
        SNAP_LOG(ERROR) << "Cannot open block device";
        return;
    }

    dev_sz = get_block_device_size(fd.get());
    if (!dev_sz) {
        SNAP_PLOG(ERROR) << "Could not determine block device size: " << dm_block_device;
        return;
    }

    int num_threads = 2;
    size_t num_blocks = dev_sz >> BLOCK_SHIFT;
    size_t num_blocks_per_thread = num_blocks / num_threads;
    size_t read_sz_per_thread = num_blocks_per_thread << BLOCK_SHIFT;
    off_t offset = 0;

    for (int i = 0; i < num_threads; i++) {
        std::async(std::launch::async, &Snapuserd::ReadBlocksToCache, this, dm_block_device,
                   partition_name, offset, read_sz_per_thread);

        offset += read_sz_per_thread;
    }
}


/*
 * Entry point to launch threads
 */
bool Snapuserd::Start() {
    std::vector<std::future<bool>> threads;
    std::future<bool> ra_thread;
    bool rathread = (read_ahead_feature_ && (read_ahead_ops_.size() > 0));

    if (rathread) {
        ra_thread = std::async(std::launch::async, &ReadAheadThread::RunThread,
                               read_ahead_thread_.get());

        // TODO: Check if we need to wait
        SNAP_LOG(INFO) << "Read-ahead thread started...";
    }

    // Launch worker threads
    for (int i = 0; i < worker_threads_.size(); i++) {
        threads.emplace_back(
                std::async(std::launch::async, &WorkerThread::RunThread, worker_threads_[i].get()));
    }

    bool second_stage_init = true;

    // We don't want to read the blocks during first stage init.
    if (android::base::EndsWith(misc_name_, "-init") || is_socket_present_) {
        second_stage_init = false;
    }

    if (second_stage_init) {
        SNAP_LOG(INFO) << "Reading blocks to cache....";
        auto& dm = DeviceMapper::Instance();
        auto dm_block_devices = dm.FindDmPartitions();
        if (dm_block_devices.empty()) {
            SNAP_LOG(ERROR) << "No dm-enabled block device is found.";
        } else {
            auto parts = android::base::Split(misc_name_, "-");
            std::string partition_name = parts[0];

            const char* suffix_b = "_b";
            const char* suffix_a = "_a";

            partition_name.erase(partition_name.find_last_not_of(suffix_b) + 1);
            partition_name.erase(partition_name.find_last_not_of(suffix_a) + 1);

            if (dm_block_devices.find(partition_name) == dm_block_devices.end()) {
                SNAP_LOG(ERROR) << "Failed to find dm block device for " << partition_name;
            } else {
                ReadBlocks(partition_name, dm_block_devices.at(partition_name));
            }
        }
    } else {
        SNAP_LOG(INFO) << "Not reading block device into cache";
    }

    std::future<bool> merge_thread;

    merge_thread = std::async(std::launch::async, &WorkerThread::RunMergeThread, merge_thread_.get());

    bool ret = true;
    for (auto& t : threads) {
        ret = t.get() && ret;
    }

    SNAP_LOG(INFO) << "Waiting for merge complete....";

    // For testing only - remove after implementing worker threads
    WaitForMergeComplete();

    NotifyIOTerminated();

    // Worker threads are terminated by this point - this can only happen:
    //
    // 1: If dm-user device is destroyed
    // 2: We had an I/O failure when reading root partitions
    //
    // In case (1), this would be a graceful shutdown. In this case, merge
    // thread and RA thread should have already terminated by this point. We will be
    // destroying the dm-user device only _after_ merge is completed.
    //
    // In case (2), if merge thread had started, then it will be
    // continuing to merge. We can either wait for the merge to finish
    // or stop the merging as we had an I/O failure.
    //
    bool merge_thread_status;
    bool ra_thread_status;

    merge_thread_status = merge_thread.get();

    if (rathread) {
        ra_thread_status = ra_thread.get();
    }

    SNAP_LOG(INFO) << "Worker threads terminated with ret: " << ret
                   << " Merge-thread with ret: " << merge_thread_status
                   << " RA-thread with ret: " << ra_thread_status;
    return ret;
}

// Merge Block State Transitions
void Snapuserd::SetMergeBlockCompleted(size_t block_index) {
    {
        std::lock_guard<std::mutex> lock(m_lock_);
        MergeBlockState* blk_state = merge_blk_state_[block_index].get();

        CHECK(blk_state->merge_state_ == MERGE_BLOCK_STATE::MERGE_IN_PROGRESS);
        CHECK(blk_state->num_ios_in_progress_ == 0);

        blk_state->merge_state_ = MERGE_BLOCK_STATE::MERGE_COMPLETED;
    }

    // Wake all I/O threads waiting on this block
    m_cv_.notify_all();
}

void Snapuserd::SetMergeBlockPending(size_t block_index) {
    {
        std::unique_lock<std::mutex> lock(m_lock_);
        MergeBlockState* blk_state = merge_blk_state_[block_index].get();
        // Wait if there are any in-flight I/O's - we cannot merge at this point
        while (!(blk_state->num_ios_in_progress_ == 0)) {
            m_cv_.wait(lock);
        }

        CHECK(blk_state->merge_state_ == MERGE_BLOCK_STATE::MERGE_PENDING);

        blk_state->merge_state_ = MERGE_BLOCK_STATE::MERGE_IN_PROGRESS;
    }
}

void Snapuserd::CheckMergeBlockState(size_t block_index) {

    do
    {
        bool merge_complete = false;
        bool merge_pending = false;
        bool merge_failed = false;

        std::unique_lock<std::mutex> lock(m_lock_);
        MergeBlockState* blk_state = merge_blk_state_[block_index].get();

        if (blk_state->merge_state_ == MERGE_BLOCK_STATE::MERGE_COMPLETED) {
            merge_complete = true;
            break;
        }

        if (blk_state->merge_state_ == MERGE_BLOCK_STATE::MERGE_PENDING) {
            merge_pending = true;
            blk_state->num_ios_in_progress_ += 1;
            break;
        }

        // Merge is in-progress - wait for it to complete
        while (!(blk_state->merge_state_ == MERGE_BLOCK_STATE::MERGE_COMPLETED ||
                 blk_state->merge_state_ == MERGE_FAILED)) {
            m_cv_.wait(lock);
        }

        if (blk_state->merge_state_ == MERGE_BLOCK_STATE::MERGE_COMPLETED) {
            merge_complete = true;
        } else {
            merge_failed = true;
        }

        break;

    } while(0);

    if (merge_complete) {

        // Read from base device
    }

    if (merge_pending) {
        // Read from source deviec
        // Decrement the num_ios_in_progress
        // Wake up merge thread
    }

    if (merge_failed) {
        // fail the I/O
    }
}

uint64_t Snapuserd::GetBufferMetadataOffset() {
    CowHeader header;
    reader_->GetHeader(&header);

    size_t size = header.header_size + sizeof(BufferState);
    return size;
}

/*
 * Metadata for read-ahead is 16 bytes. For a 2 MB region, we will
 * end up with 8k (2 PAGE) worth of metadata. Thus, a 2MB buffer
 * region is split into:
 *
 * 1: 8k metadata
 *
 */
size_t Snapuserd::GetBufferMetadataSize() {
    CowHeader header;
    reader_->GetHeader(&header);

    size_t metadata_bytes = (header.buffer_size * sizeof(struct ScratchMetadata)) / BLOCK_SZ;
    return metadata_bytes;
}

size_t Snapuserd::GetBufferDataOffset() {
    CowHeader header;
    reader_->GetHeader(&header);

    return (header.header_size + GetBufferMetadataSize());
}

/*
 * (2MB - 8K = 2088960 bytes) will be the buffer region to hold the data.
 */
size_t Snapuserd::GetBufferDataSize() {
    CowHeader header;
    reader_->GetHeader(&header);

    size_t size = header.buffer_size - GetBufferMetadataSize();
    return size;
}

struct BufferState* Snapuserd::GetBufferState() {
    CowHeader header;
    reader_->GetHeader(&header);

    struct BufferState* ra_state =
            reinterpret_cast<struct BufferState*>((char*)mapped_addr_ + header.header_size);
    return ra_state;
}

}  // namespace snapshot
}  // namespace android
