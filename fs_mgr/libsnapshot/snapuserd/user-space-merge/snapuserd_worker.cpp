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

    // Base device used by merge thread
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

bool WorkerThread::ReadFromSourceDevice(const CowOperation* cow_op) {
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
    if (!ReadFromSourceDevice(cow_op)) {
        return false;
    }

    return true;
}

bool WorkerThread::ProcessXorOp(const CowOperation* cow_op) {
    if (!ReadFromSourceDevice(cow_op)) {
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

bool WorkerThread::ProcessOrderedOp(const CowOperation* cow_op) {
    MERGE_BLOCK_STATE state = snapuserd_->GetMergeBlockState(cow_op->new_block);

    CHECK(state != MERGE_BLOCK_STATE::MERGE_IN_PROGRESS);

    if (state == MERGE_BLOCK_STATE::MERGE_COMPLETED) {
        // Merge is completed for this COW op; just read directly from
        // the base device
        SNAP_LOG(DEBUG) << "Merge-completed: Reading from base device sector: "
                       << (cow_op->new_block >> SECTOR_SHIFT)
                       << " Block-number: "
                       << cow_op->new_block;
        if (!ReadDataFromBaseDevice(ChunkToSector(cow_op->new_block), BLOCK_SZ)) {
            SNAP_LOG(ERROR) << "ReadDataFromBaseDevice at sector: "
                            << (cow_op->new_block >> SECTOR_SHIFT)
                            << " after merge-complete.";
            return false;
        }
        return true;
    } else if (state == MERGE_BLOCK_STATE::MERGE_PENDING) {
          bool ret;
          if (cow_op->type == kCowCopyOp) {
              ret = ProcessCopyOp(cow_op);
          } else {
              ret = ProcessXorOp(cow_op);
          }

          snapuserd_->NotifyIOCompletion(cow_op->new_block);
          return ret;
    }

    // All other states, fail the I/O viz (MERGE_FAILED and INVALID)
    return false;
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

        case kCowCopyOp:
          [[fallthrough]];
        case kCowXorOp: {
            return ProcessOrderedOp(cow_op);
        }

        default: {
            SNAP_LOG(ERROR) << "Unknown operation-type found: " << cow_op->type;
        }
    }
    return false;
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

// Read Header from dm-user misc device. This gives
// us the sector number for which IO is issued by dm-snapshot device
bool WorkerThread::ReadDmUserHeader() {
    if (!android::base::ReadFully(ctrl_fd_, bufsink_.GetBufPtr(), sizeof(struct dm_user_header))) {
        if (errno != ENOTBLK) {
            SNAP_PLOG(ERROR) << "Control-read failed";
        }

        return false;
    }

    return true;
}

// Send the payload/data back to dm-user misc device.
bool WorkerThread::WriteDmUserPayload(size_t size, bool header_response) {
    size_t payload_size = size;
    void* buf = bufsink_.GetPayloadBufPtr();
    if (header_response) {
        payload_size += sizeof(struct dm_user_header);
        buf = bufsink_.GetBufPtr();
    }

    if (!android::base::WriteFully(ctrl_fd_, buf, payload_size)) {
        SNAP_PLOG(ERROR) << "Write to dm-user failed size: " << payload_size;
        return false;
    }

    return true;
}

bool WorkerThread::ReadDataFromBaseDevice(sector_t sector, size_t read_size)
{
    CHECK(read_size <= BLOCK_SZ);

    void* buffer = bufsink_.GetPayloadBuffer(BLOCK_SZ);
    if (buffer == nullptr) {
        SNAP_LOG(ERROR) << "ReadFromBaseDevice: Failed to get payload buffer";
        return false;
    }

    loff_t offset = sector << SECTOR_SHIFT;
    if (!android::base::ReadFullyAtOffset(base_path_merge_fd_, buffer, read_size, offset)) {
        SNAP_PLOG(ERROR) << "ReadDataFromBaseDevice failed. fd: " << base_path_merge_fd_
                         << "at sector :" << sector << " size: " << read_size;
        return false;
    }

    return true;
}

bool WorkerThread::DmuserReadRequest() {
    struct dm_user_header* header = bufsink_.GetHeaderPtr();
    size_t remaining_size = header->len;
    sector_t sector = header->sector;
    std::vector<std::pair<sector_t, const CowOperation*>>& chunk_vec = snapuserd_->GetChunkVec();
    bool header_response = true;
    bool io_error = false;
    int ret;

    if (!IsBlockAligned((header->sector << SECTOR_SHIFT)) ||
        !IsBlockAligned(header->len)) {
        // TODO: We need to handle un-aligned I/O requests. There are
        // few corner cases which has to be addressed. For now, just return
        // I/O error.
        SNAP_LOG(INFO) << "I/O error - not block aligned....";
        header->type = DM_USER_RESP_ERROR;
        if (!WriteDmUserPayload(0, header_response)) {
            return false;
        }

        return true;
    }

    do {
        // Process 1MB payload at a time
        size_t read_size = std::min(PAYLOAD_SIZE, remaining_size);

        header->type = DM_USER_RESP_SUCCESS;
        size_t total_bytes_read = 0;
        io_error = false;
        bufsink_.ResetBufferOffset();

        while (read_size) {
            // We need to check every 4k block to verify if it is
            // present in the mapping.
            size_t size = std::min(BLOCK_SZ, read_size);

            auto it = std::lower_bound(chunk_vec.begin(), chunk_vec.end(),
                                   std::make_pair(sector, nullptr), Snapuserd::compare);
            bool not_found = (it == chunk_vec.end() || it->first != sector);

            if (not_found) {
                // Block not found in map - which means this block was not
                // changed as per the OTA. Just route the I/O to the base
                // device.
                if (!ReadDataFromBaseDevice(sector, size)) {
                    SNAP_LOG(ERROR) << "ReadDataFromBaseDevice failed";
                    header->type = DM_USER_RESP_ERROR;
                }

                ret = size;
            } else {
                // We found the sector in mapping. Check the type of COW OP and
                // process it.
                if (!ProcessCowOp(it->second)) {
                    SNAP_LOG(ERROR) << "ProcessCowOp failed";
                    header->type = DM_USER_RESP_ERROR;
                }

                ret = BLOCK_SZ;
            }

            // Just return the header if it is an error
            if (header->type == DM_USER_RESP_ERROR) {
                SNAP_LOG(ERROR) << "IO read request failed...";
                ret = 0;

                // This is an issue with the dm-user interface. There
                // is no way to propagate the I/O error back to dm-user
                // if we have already communicated the header back. Header
                // is responded once at the beginning; however I/O can
                // be processed in chunks. If we encounter an I/O error
                // somewhere in the middle of the processing, we can't communicate
                // this back to dm-user.
                //
                // TODO: Fix the interface
                CHECK(header_response);

                if (!WriteDmUserPayload(ret, header_response)) {
                    return false;
                }

                io_error = true;
                break;
            }


            read_size -= ret;
            total_bytes_read += ret;
            sector += (ret >> SECTOR_SHIFT);
            bufsink_.UpdateBufferOffset(ret);
        }

        if (!io_error) {
            if (!WriteDmUserPayload(total_bytes_read, header_response)) {
                return false;
            }

            SNAP_LOG(DEBUG) << "WriteDmUserPayload success total_bytes_read: " << total_bytes_read
                           << " header-response: " << header_response
                           << " remaining_size: " << remaining_size;
            header_response = false;
            remaining_size -= total_bytes_read;
        }
    } while (remaining_size > 0 && !io_error);

    return true;
}

bool WorkerThread::ProcessIORequest() {
    struct dm_user_header* header = bufsink_.GetHeaderPtr();

    if (!ReadDmUserHeader()) {
        return false;
    }

    SNAP_LOG(DEBUG) << "Daemon: msg->seq: " << std::dec << header->seq;
    SNAP_LOG(DEBUG) << "Daemon: msg->len: " << std::dec << header->len;
    SNAP_LOG(DEBUG) << "Daemon: msg->sector: " << std::dec << header->sector;
    SNAP_LOG(DEBUG) << "Daemon: msg->type: " << std::dec << header->type;
    SNAP_LOG(DEBUG) << "Daemon: msg->flags: " << std::dec << header->flags;

    switch (header->type) {
        case DM_USER_REQ_MAP_READ: {
            if (!DmuserReadRequest()) {
                return false;
            }
            break;
        }

        case DM_USER_REQ_MAP_WRITE: {
            // TODO: We should not get any write request
            // to dm-user as we mount all partitions
            // as read-only
            return false;
        }
    }

    return true;
}

}  // namespace snapshot
}  // namespace android
