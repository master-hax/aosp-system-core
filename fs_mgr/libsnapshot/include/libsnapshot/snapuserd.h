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

#include <stdint.h>

#include <linux/types.h>
#include <stdlib.h>

#include <csignal>
#include <cstring>
#include <iostream>
#include <limits>
#include <string>
#include <thread>
#include <vector>

#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/stringprintf.h>
#include <android-base/unique_fd.h>

#include <libdm/dm.h>
#include <libsnapshot/cow_reader.h>
#include <libsnapshot/cow_writer.h>

namespace android {
namespace snapshot {

using android::base::unique_fd;

// Kernel COW header fields
static constexpr uint32_t SNAP_MAGIC = 0x70416e53;

static constexpr uint32_t SNAPSHOT_DISK_VERSION = 1;

static constexpr uint32_t NUM_SNAPSHOT_HDR_CHUNKS = 1;

static constexpr uint32_t SNAPSHOT_VALID = 1;

/*
 * The basic unit of block I/O is a sector. It is used in a number of contexts
 * in Linux (blk, bio, genhd). The size of one sector is 512 = 2**9
 * bytes. Variables of type sector_t represent an offset or size that is a
 * multiple of 512 bytes. Hence these two constants.
 */
static constexpr uint32_t SECTOR_SHIFT = 9;

typedef __u64 sector_t;
typedef sector_t chunk_t;

static constexpr uint32_t CHUNK_SIZE = 8;
static constexpr uint32_t CHUNK_SHIFT = (__builtin_ffs(CHUNK_SIZE) - 1);

static constexpr uint32_t BLOCK_SIZE = 4096;
static constexpr uint32_t BLOCK_SHIFT = (__builtin_ffs(BLOCK_SIZE) - 1);

// This structure represents the kernel COW header.
// All the below fields should be in Little Endian format.
struct disk_header {
    uint32_t magic;

    /*
     * Is this snapshot valid.  There is no way of recovering
     * an invalid snapshot.
     */
    uint32_t valid;

    /*
     * Simple, incrementing version. no backward
     * compatibility.
     */
    uint32_t version;

    /* In sectors */
    uint32_t chunk_size;
} __packed;

// A disk exception is a mapping of old_chunk to new_chunk
// old_chunk is the chunk ID of a dm-snapshot device.
// new_chunk is the chunk ID of the COW device.
struct disk_exception {
    uint64_t old_chunk;
    uint64_t new_chunk;
} __packed;

// Control structures to communicate with dm-user
// It comprises of header and a payload
struct dm_user_header {
    __u64 seq;
    __u64 type;
    __u64 flags;
    __u64 sector;
    __u64 len;
    __u64 io_in_progress;
} __attribute__((packed));

struct dm_user_payload {
    __u8 buf[];
};

// Message comprising both header and payload
struct dm_user_message {
    struct dm_user_header header;
    struct dm_user_payload payload;
};

class BufferSink : public IByteSink {
  public:
    void Initialize(size_t size) {
        buffer_size_ = size;
        buffer_offset_ = 0;
        buffer_ = std::make_unique<uint8_t[]>(size);
    }

    void* GetBufPtr() { return buffer_.get(); }

    void Clear() { memset(GetBufPtr(), 0, buffer_size_); }

    void* GetPayloadBuffer(size_t size) {
        if ((buffer_size_ - buffer_offset_) < size) return nullptr;

        char* buffer = reinterpret_cast<char*>(GetBufPtr());
        struct dm_user_message* msg = (struct dm_user_message*)(&(buffer[0]));
        return (char*)msg->payload.buf + buffer_offset_;
    }

    void* GetBuffer(size_t requested, size_t* actual) override {
        void* buf = GetPayloadBuffer(requested);
        if (!buf) {
            *actual = 0;
            return nullptr;
        }
        *actual = requested;
        return buf;
    }

    void UpdateBufferOffset(size_t size) { buffer_offset_ += size; }

    struct dm_user_header* GetHeaderPtr() {
        CHECK(sizeof(struct dm_user_header) <= buffer_size_);
        char* buf = reinterpret_cast<char*>(GetBufPtr());
        struct dm_user_header* header = (struct dm_user_header*)(&(buf[0]));
        return header;
    }

    bool ReturnData(void*, size_t) override { return true; }
    void ResetBufferOffset() { buffer_offset_ = 0; }

  private:
    std::unique_ptr<uint8_t[]> buffer_;
    loff_t buffer_offset_;
    size_t buffer_size_;
};

class Snapuserd final {
  public:
    Snapuserd(const std::string& in_cow_device, const std::string& in_backing_store_device)
        : in_cow_device_(in_cow_device),
          in_backing_store_device_(in_backing_store_device),
          metadata_read_done_(false) {}

    int Init();
    int Run();
    int ReadDmUserHeader();
    int WriteDmUserPayload(size_t size);
    int ConstructKernelCowHeader();
    int ReadMetadata();
    int ZerofillDiskExceptions(size_t read_size);
    int ReadDiskExceptions(chunk_t chunk, size_t size);
    int ReadData(chunk_t chunk, size_t size);

  private:
    int ProcessReplaceOp(const CowOperation* cow_op);
    int ProcessCopyOp(const CowOperation* cow_op);
    int ProcessZeroOp();

    std::string in_cow_device_;
    std::string in_backing_store_device_;

    unique_fd cow_fd_;
    unique_fd backing_store_fd_;
    unique_fd ctrl_fd_;

    uint32_t exceptions_per_area_;

    std::unique_ptr<ICowOpIter> cowop_iter_;
    std::unique_ptr<CowReader> reader_;

    // Vector of disk exception which is a
    // mapping of old-chunk to new-chunk
    std::vector<std::unique_ptr<uint8_t[]>> vec_;

    // Index - Chunk ID
    // Value - cow operation
    std::vector<const CowOperation*> chunk_vec_;

    bool metadata_read_done_;
    BufferSink bufsink_;
};

}  // namespace snapshot
}  // namespace android
