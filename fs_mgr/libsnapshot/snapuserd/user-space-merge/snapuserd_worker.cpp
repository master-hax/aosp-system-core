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

#include <csignal>
#include <optional>
#include <set>

#include <snapuserd/snapuserd_client.h>

namespace android {
namespace snapshot {

using namespace android;
using namespace android::dm;
using android::base::unique_fd;

#define SNAP_LOG(level) LOG(level) << misc_name_ << ": "
#define SNAP_PLOG(level) PLOG(level) << misc_name_ << ": "

void BufferSink::Initialize(size_t size) {
    buffer_size_ = size;
    buffer_offset_ = 0;
    buffer_ = std::make_unique<uint8_t[]>(size);
}

void* BufferSink::GetPayloadBuffer(size_t size) {
    if ((buffer_size_ - buffer_offset_) < size) return nullptr;

    char* buffer = reinterpret_cast<char*>(GetBufPtr());
    struct dm_user_message* msg = (struct dm_user_message*)(&(buffer[0]));
    return (char*)msg->payload.buf + buffer_offset_;
}

void* BufferSink::GetBuffer(size_t requested, size_t* actual) {
    void* buf = GetPayloadBuffer(requested);
    if (!buf) {
        *actual = 0;
        return nullptr;
    }
    *actual = requested;
    return buf;
}

struct dm_user_header* BufferSink::GetHeaderPtr() {
    if (!(sizeof(struct dm_user_header) <= buffer_size_)) {
        return nullptr;
    }
    char* buf = reinterpret_cast<char*>(GetBufPtr());
    struct dm_user_header* header = (struct dm_user_header*)(&(buf[0]));
    return header;
}

void* BufferSink::GetPayloadBufPtr() {
    char* buffer = reinterpret_cast<char*>(GetBufPtr());
    struct dm_user_message* msg = reinterpret_cast<struct dm_user_message*>(&(buffer[0]));
    return msg->payload.buf;
}

void XorSink::Initialize(BufferSink* sink, size_t size) {
    bufsink_ = sink;
    buffer_size_ = size;
    returned_ = 0;
    buffer_ = std::make_unique<uint8_t[]>(size);
}

void XorSink::Reset() {
    returned_ = 0;
}

void* XorSink::GetBuffer(size_t requested, size_t* actual) {
    if (requested > buffer_size_) {
        *actual = buffer_size_;
    } else {
        *actual = requested;
    }
    return buffer_.get();
}

bool XorSink::ReturnData(void* buffer, size_t len) {
    uint8_t* xor_data = reinterpret_cast<uint8_t*>(buffer);
    uint8_t* buff = reinterpret_cast<uint8_t*>(bufsink_->GetPayloadBuffer(len + returned_));
    if (buff == nullptr) {
        return false;
    }
    for (size_t i = 0; i < len; i++) {
        buff[returned_ + i] ^= xor_data[i];
    }
    returned_ += len;
    return true;
}

WorkerThread::WorkerThread(const std::string& cow_device, const std::string& backing_device,
                           const std::string& control_device, const std::string& misc_name,
                           const std::string& base_path_merge,
                           std::shared_ptr<Snapuserd> snapuserd) {
    cow_device_ = cow_device;
    backing_store_device_ = backing_device;
    control_device_ = control_device;
    misc_name_ = misc_name;
    base_path_merge_ = base_path_merge;
    snapuserd_ = snapuserd;
}

bool WorkerThread::InitializeFds() {
    backing_store_fd_.reset(open(backing_store_device_.c_str(), O_RDONLY));
    if (backing_store_fd_ < 0) {
        SNAP_PLOG(ERROR) << "Open Failed: " << backing_store_device_;
        return false;
    }

    cow_fd_.reset(open(cow_device_.c_str(), O_RDWR));
    if (cow_fd_ < 0) {
        SNAP_PLOG(ERROR) << "Open Failed: " << cow_device_;
        return false;
    }

    ctrl_fd_.reset(open(control_device_.c_str(), O_RDWR));
    if (ctrl_fd_ < 0) {
        SNAP_PLOG(ERROR) << "Unable to open " << control_device_;
        return false;
    }

    // Base devie used by merge thread
    base_path_merge_fd_.reset(open(base_path_merge_.c_str(), O_RDWR));
    if (base_path_merge_fd_ < 0) {
        SNAP_PLOG(ERROR) << "Open Failed: " << base_path_merge_;
        return false;
    }

    return true;
}

bool WorkerThread::InitReader() {
    reader_ = snapuserd_->CloneReaderForWorker();

    if (!reader_->InitForMerge(std::move(cow_fd_))) {
        return false;
    }
    return true;
}

// Start the replace operation. This will read the
// internal COW format and if the block is compressed,
// it will be de-compressed.
bool WorkerThread::ProcessReplaceOp(const CowOperation* cow_op) {
    if (!reader_->ReadData(*cow_op, &bufsink_)) {
        SNAP_LOG(ERROR) << "ProcessReplaceOp failed for block " << cow_op->new_block;
        return false;
    }

    return true;
}

bool WorkerThread::ReadFromBaseDevice(const CowOperation* cow_op) {
    void* buffer = bufsink_.GetPayloadBuffer(BLOCK_SZ);
    if (buffer == nullptr) {
        SNAP_LOG(ERROR) << "ReadFromBaseDevice: Failed to get payload buffer";
        return false;
    }
    SNAP_LOG(DEBUG) << " ReadFromBaseDevice...: new-block: " << cow_op->new_block
                    << " Source: " << cow_op->source;
    uint64_t offset = cow_op->source;
    if (cow_op->type == kCowCopyOp) {
        offset *= BLOCK_SZ;
    }
    if (!android::base::ReadFullyAtOffset(backing_store_fd_, buffer, BLOCK_SZ, offset)) {
        std::string op;
        if (cow_op->type == kCowCopyOp)
            op = "Copy-op";
        else {
            op = "Xor-op";
        }
        SNAP_PLOG(ERROR) << op << " failed. Read from backing store: " << backing_store_device_
                         << "at block :" << offset / BLOCK_SZ << " offset:" << offset % BLOCK_SZ;
        return false;
    }

    return true;
}

// Start the copy operation. This will read the backing
// block device which is represented by cow_op->source.
bool WorkerThread::ProcessCopyOp(const CowOperation* cow_op) {
    SNAP_LOG(DEBUG) << " GetReadAheadPopulatedBuffer failed..."
                  << " new_block: " << cow_op->new_block;
    // TODO: Check for merge completion
    if (!ReadFromBaseDevice(cow_op)) {
        return false;
    }

    return true;
}

bool WorkerThread::ProcessXorOp(const CowOperation* cow_op) {
    // TODO: Check for merge completion
    if (!ReadFromBaseDevice(cow_op)) {
        return false;
    }
    xorsink_.Reset();
    if (!reader_->ReadData(*cow_op, &xorsink_)) {
        SNAP_LOG(ERROR) << "ProcessXorOp failed for block " << cow_op->new_block;
        return false;
    }

    return true;
}

bool WorkerThread::ProcessZeroOp() {
    // Zero out the entire block
    void* buffer = bufsink_.GetPayloadBuffer(BLOCK_SZ);
    if (buffer == nullptr) {
        SNAP_LOG(ERROR) << "ProcessZeroOp: Failed to get payload buffer";
        return false;
    }

    memset(buffer, 0, BLOCK_SZ);
    return true;
}

bool WorkerThread::ProcessCowOp(const CowOperation* cow_op) {
    if (cow_op == nullptr) {
        SNAP_LOG(ERROR) << "ProcessCowOp: Invalid cow_op";
        return false;
    }

    switch (cow_op->type) {
        case kCowReplaceOp: {
            return ProcessReplaceOp(cow_op);
        }

        case kCowZeroOp: {
            return ProcessZeroOp();
        }

        case kCowCopyOp: {
            return ProcessCopyOp(cow_op);
        }

        case kCowXorOp: {
            return ProcessXorOp(cow_op);
        }

        default: {
            SNAP_LOG(ERROR) << "Unknown operation-type found: " << cow_op->type;
        }
    }
    return false;
}

int WorkerThread::ReadUnalignedSector(
        sector_t sector, size_t size,
        std::vector<std::pair<sector_t, const CowOperation*>>::iterator& it) {
    size_t skip_sector_size = 0;

    SNAP_LOG(DEBUG) << "ReadUnalignedSector: sector " << sector << " size: " << size
                    << " Aligned sector: " << it->first;

    if (!ProcessCowOp(it->second)) {
        SNAP_LOG(ERROR) << "ReadUnalignedSector: " << sector << " failed of size: " << size
                        << " Aligned sector: " << it->first;
        return -1;
    }

    int num_sectors_skip = sector - it->first;

    if (num_sectors_skip > 0) {
        skip_sector_size = num_sectors_skip << SECTOR_SHIFT;
        char* buffer = reinterpret_cast<char*>(bufsink_.GetBufPtr());
        struct dm_user_message* msg = (struct dm_user_message*)(&(buffer[0]));

        if (skip_sector_size == BLOCK_SZ) {
            SNAP_LOG(ERROR) << "Invalid un-aligned IO request at sector: " << sector
                            << " Base-sector: " << it->first;
            return -1;
        }

        memmove(msg->payload.buf, (char*)msg->payload.buf + skip_sector_size,
                (BLOCK_SZ - skip_sector_size));
    }

    bufsink_.ResetBufferOffset();
    return std::min(size, (BLOCK_SZ - skip_sector_size));
}

/*
 * Read the data for a given COW Operation.
 *
 * Kernel can issue IO at a sector granularity.
 * Hence, an IO may end up with reading partial
 * data from a COW operation or we may also
 * end up with interspersed request between
 * two COW operations.
 *
 */
int WorkerThread::ReadData(sector_t sector, size_t size) {
    std::vector<std::pair<sector_t, const CowOperation*>>& chunk_vec = snapuserd_->GetChunkVec();
    std::vector<std::pair<sector_t, const CowOperation*>>::iterator it;
    /*
     * chunk_map stores COW operation at 4k granularity.
     * If the requested IO with the sector falls on the 4k
     * boundary, then we can read the COW op directly without
     * any issue.
     *
     * However, if the requested sector is not 4K aligned,
     * then we will have the find the nearest COW operation
     * and chop the 4K block to fetch the requested sector.
     */
    it = std::lower_bound(chunk_vec.begin(), chunk_vec.end(), std::make_pair(sector, nullptr),
                          Snapuserd::compare);

    if (!(it != chunk_vec.end())) {
        SNAP_LOG(ERROR) << "ReadData: Sector " << sector << " not found in chunk_vec";
        return -1;
    }

    // We didn't find the required sector; hence find the previous sector
    // as lower_bound will gives us the value greater than
    // the requested sector
    if (it->first != sector) {
        if (it != chunk_vec.begin()) {
            --it;
        }

        /*
         * If the IO is spanned between two COW operations,
         * split the IO into two parts:
         *
         * 1: Read the first part from the single COW op
         * 2: Read the second part from the next COW op.
         *
         * Ex: Let's say we have a 1024 Bytes IO request.
         *
         * 0       COW OP-1  4096     COW OP-2  8192
         * |******************|*******************|
         *              |*****|*****|
         *           3584           4608
         *              <- 1024B - >
         *
         * We have two COW operations which are 4k blocks.
         * The IO is requested for 1024 Bytes which are spanned
         * between two COW operations. We will split this IO
         * into two parts:
         *
         * 1: IO of size 512B from offset 3584 bytes (COW OP-1)
         * 2: IO of size 512B from offset 4096 bytes (COW OP-2)
         */
        return ReadUnalignedSector(sector, size, it);
    }

    int num_ops = DIV_ROUND_UP(size, BLOCK_SZ);
    sector_t read_sector = sector;
    while (num_ops) {
        // We have to make sure that the reads are
        // sequential; there shouldn't be a data
        // request merged with a metadata IO.
        if (it->first != read_sector) {
            SNAP_LOG(ERROR) << "Invalid IO request: read_sector: " << read_sector
                            << " cow-op sector: " << it->first;
            return -1;
        } else if (!ProcessCowOp(it->second)) {
            return -1;
        }
        num_ops -= 1;
        read_sector += (BLOCK_SZ >> SECTOR_SHIFT);

        it++;

        if (it == chunk_vec.end() && num_ops) {
            SNAP_LOG(ERROR) << "Invalid IO request at sector " << sector
                            << " COW ops completed; pending read-request: " << num_ops;
            return -1;
        }
        // Update the buffer offset
        bufsink_.UpdateBufferOffset(BLOCK_SZ);
    }

    // Reset the buffer offset
    bufsink_.ResetBufferOffset();
    return size;
}

void WorkerThread::InitializeBufsink() {
    // Allocate the buffer which is used to communicate between
    // daemon and dm-user. The buffer comprises of header and a fixed payload.
    // If the dm-user requests a big IO, the IO will be broken into chunks
    // of PAYLOAD_SIZE.
    size_t buf_size = sizeof(struct dm_user_header) + PAYLOAD_SIZE;
    bufsink_.Initialize(buf_size);
}

bool WorkerThread::RunThread() {
    InitializeBufsink();
    xorsink_.Initialize(&bufsink_, BLOCK_SZ);

    if (!InitializeFds()) {
        return false;
    }

    if (!InitReader()) {
        return false;
    }

    // Start serving IO
    while (true) {
        if (!ProcessIORequest()) {
            break;
        }
    }

    CloseFds();
    reader_->CloseCowFd();

    return true;
}

bool WorkerThread::ProcessIORequest() {
    return false;
}

}  // namespace snapshot
}  // namespace android
