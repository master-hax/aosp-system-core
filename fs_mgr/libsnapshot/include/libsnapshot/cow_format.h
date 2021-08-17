// Copyright (C) 2019 The Android Open Source Project
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
#include <string>
#include <vector>

namespace android {
namespace snapshot {

static constexpr uint64_t kCowMagicNumber = 0x436f77634f572121ULL;
static constexpr uint32_t kCowVersionMajor = 2;
static constexpr uint32_t kCowVersionMinor = 0;

static constexpr uint32_t kCowVersionManifest = 2;

static constexpr uint32_t BLOCK_SZ = 4096;
static constexpr uint32_t BLOCK_SHIFT = (__builtin_ffs(BLOCK_SZ) - 1);

// This header appears as the first sequence of bytes in the COW. All fields
// in the layout are little-endian encoded. The on-disk layout is:
//
//      +-----------------------+
//      |     Header (fixed)    |
//      +-----------------------+
//      |     Scratch space     |
//      +-----------------------+
//      | Operation  (variable) |
//      | Data       (variable) |
//      +-----------------------+
//      |    Footer (fixed)     |
//      +-----------------------+
//
// The operations begin immediately after the header, and the "raw data"
// immediately follows the operation which refers to it. While streaming
// an OTA, we can immediately write the op and data, syncing after each pair,
// while storing operation metadata in memory. At the end, we compute data and
// hashes for the footer, which is placed at the tail end of the file.
//
// A missing or corrupt footer likely indicates that writing was cut off
// between writing the last operation/data pair, or the footer itself. In this
// case, the safest way to proceed is to assume the last operation is faulty.

struct CowHeader {
    uint64_t magic;
    uint16_t major_version;
    uint16_t minor_version;

    // Size of this struct.
    uint16_t header_size;

    // Size of footer struct
    uint16_t footer_size;

    // Size of op struct
    uint16_t op_size;

    // The size of block operations, in bytes.
    uint32_t block_size;

    // The number of ops to cluster together. 0 For no clustering. Cannot be 1.
    uint32_t cluster_ops;

    // Tracks merge operations completed
    uint64_t num_merge_ops;

    // Scratch space used during merge
    uint32_t buffer_size;
} __attribute__((packed));

// This structure is the same size of a normal Operation, but is repurposed for the footer.
struct CowFooterOperation {
    // The operation code (always kCowFooterOp).
    uint8_t type;

    // If this operation reads from the data section of the COW, this contains
    // the compression type of that data (see constants below).
    uint8_t compression;

    // Length of Footer Data. Currently 64 for both checksums
    uint16_t data_length;

    // The amount of file space used by Cow operations
    uint64_t ops_size;

    // The number of cow operations in the file
    uint64_t num_ops;
} __attribute__((packed));

struct CowFooterData {
    // SHA256 checksums of Footer op
    uint8_t footer_checksum[32];

    // SHA256 of the operation sequence.
    uint8_t ops_checksum[32];
} __attribute__((packed));

// Cow operations are currently fixed-size entries, but this may change if
// needed.
struct CowOperation {
    // The operation code (see the constants and structures below).
    uint8_t type;

    // If this operation reads from the data section of the COW, this contains
    // the compression type of that data (see constants below).
    uint8_t compression;

    // If this operation reads from the data section of the COW, this contains
    // the length.
    uint16_t data_length;

    // The block of data in the new image that this operation modifies.
    uint64_t new_block;

    // The value of |source| depends on the operation code.
    //
    // For copy operations, this is a block location in the source image.
    //
    // For replace operations, this is a byte offset within the COW's data
    // sections (eg, not landing within the header or metadata). It is an
    // absolute position within the image.
    //
    // For zero operations (replace with all zeroes), this is unused and must
    // be zero.
    //
    // For Label operations, this is the value of the applied label.
    //
    // For Cluster operations, this is the length of the following data region
    //
    // For Xor operations, this is the byte location in the source image.
    uint64_t source;
} __attribute__((packed));

static_assert(sizeof(CowOperation) == sizeof(CowFooterOperation));

static constexpr uint8_t kCowCopyOp = 1;
static constexpr uint8_t kCowReplaceOp = 2;
static constexpr uint8_t kCowZeroOp = 3;
static constexpr uint8_t kCowLabelOp = 4;
static constexpr uint8_t kCowClusterOp = 5;
static constexpr uint8_t kCowXorOp = 6;
static constexpr uint8_t kCowSequenceOp = 7;
static constexpr uint8_t kCowFooterOp = -1;

static constexpr uint8_t kCowCompressNone = 0;
static constexpr uint8_t kCowCompressGz = 1;
static constexpr uint8_t kCowCompressBrotli = 2;

static constexpr uint8_t kCowReadAheadNotStarted = 0;
static constexpr uint8_t kCowReadAheadInProgress = 1;
static constexpr uint8_t kCowReadAheadDone = 2;

struct CowFooter {
    CowFooterOperation op;
    CowFooterData data;
} __attribute__((packed));

class CowOp {
  public:
    virtual ~CowOp(){};
    virtual uint8_t getType() const = 0;
    virtual uint64_t getOpLength() const = 0;
    virtual uint64_t getDataLength() const = 0;
    virtual uint32_t getNewBlock() const = 0;
    virtual uint32_t getNumNewBlock() const = 0;
    virtual bool importOp(uint8_t*, size_t) = 0;
    virtual std::vector<uint8_t> exportOp() const = 0;
    virtual bool isMetaDataOp() const = 0;
    virtual bool isOrderedOp() const = 0;
};

class CowCopyOp : public CowOp {
  public:
    bool isMetaDataOp() const override { return false; }
    bool isOrderedOp() const override { return true; }
    uint64_t getDataLength() const override { return 0; };
    uint32_t getNewBlock() const override { return new_block_; }
    void setNewBlock(uint32_t block) { new_block_ = block; }
    uint32_t getSourceBlock() const { return source_block_; }
    void setSourceBlock(uint32_t block) { source_block_ = block; }

  protected:
    uint32_t new_block_;
    uint32_t source_block_;
};

class LegacyCowCopyOp : public CowCopyOp {
  public:
    uint8_t getType() const override { return kCowCopyOp; }
    uint64_t getOpLength() const override { return sizeof(CowOperation); }
    uint32_t getNumNewBlock() const override { return 1; }

    bool importOp(uint8_t* data, size_t len) override;
    std::vector<uint8_t> exportOp() const override;
};

class CowBlockOp : public CowOp {
  public:
    bool isMetaDataOp() const override { return false; }
    uint64_t getDataLoc() const { return data_loc_; };
    void setDataLoc(uint64_t len) { data_loc_ = len; };
    uint64_t getDataLength() const override { return data_length_; };
    void setDataLength(uint16_t len) { data_length_ = len; };
    uint32_t getNewBlock() const override { return new_block_; }
    void setNewBlock(uint32_t block) { new_block_ = block; }
    uint8_t getCompression() const { return compression_; }
    void setCompression(uint8_t compression) { compression_ = compression; }

  protected:
    uint32_t new_block_;
    uint64_t data_loc_;
    uint16_t data_length_;
    uint8_t compression_;
};

class CowReplaceOp : public CowBlockOp {
  public:
    bool isOrderedOp() const override { return false; }
};

class LegacyCowReplaceOp : public CowReplaceOp {
  public:
    uint8_t getType() const override { return kCowReplaceOp; }
    uint64_t getOpLength() const override { return sizeof(CowOperation); }
    uint32_t getNumNewBlock() const override { return 1; }

    bool importOp(uint8_t* data, size_t len) override;
    std::vector<uint8_t> exportOp() const override;
};

class CowZeroOp : public CowOp {
  public:
    bool isMetaDataOp() const override { return false; }
    bool isOrderedOp() const override { return false; }
    uint64_t getDataLength() const override { return 0; };
    uint32_t getNewBlock() const override { return new_block_; }
    void setNewBlock(uint32_t block) { new_block_ = block; }

    bool importOp(uint8_t*, size_t) override;
    std::vector<uint8_t> exportOp() const override;

  protected:
    uint32_t new_block_;
};

class LegacyCowZeroOp : public CowZeroOp {
  public:
    uint8_t getType() const override { return kCowZeroOp; }
    uint64_t getOpLength() const override { return sizeof(CowOperation); }
    uint32_t getNumNewBlock() const override { return 1; }

    bool importOp(uint8_t* data, size_t len) override;
    std::vector<uint8_t> exportOp() const override;
};

class CowLabelOp : public CowOp {
  public:
    bool isMetaDataOp() const override { return true; }
    bool isOrderedOp() const override { return false; }
    uint64_t getDataLength() const override { return 0; };
    int64_t getLabel() const { return label_; }
    void setLabel(uint64_t label) { label_ = label; }
    uint32_t getNewBlock() const override { return 0; }
    uint32_t getNumNewBlock() const override { return 0; }

    bool importOp(uint8_t*, size_t) override;
    std::vector<uint8_t> exportOp() const override;

  protected:
    uint64_t label_;
};

class LegacyCowLabelOp : public CowLabelOp {
  public:
    uint8_t getType() const override { return kCowClusterOp; }
    uint64_t getOpLength() const override { return sizeof(CowOperation); }

    bool importOp(uint8_t* data, size_t len) override;
    std::vector<uint8_t> exportOp() const override;
};

class CowClusterOp : public CowOp {
  public:
    bool isMetaDataOp() const override { return true; }
    bool isOrderedOp() const override { return false; }
    uint64_t getDataLength() const override { return 0; };
    int64_t getNextClusterStart() const { return next_cluster_; }
    void setNextClusterStart(uint64_t offset) { next_cluster_ = offset; }
    uint32_t getNewBlock() const override { return 0; }
    uint32_t getNumNewBlock() const { return 0; }

    bool importOp(uint8_t*, size_t) override;
    std::vector<uint8_t> exportOp() const override;

  protected:
    uint64_t next_cluster_;
};

class LegacyCowClusterOp : public CowClusterOp {
  public:
    uint8_t getType() const { return kCowClusterOp; }
    uint64_t getOpLength() const { return sizeof(CowOperation); }
    uint32_t getNumNewBlock() const { return 0; }

    bool importOp(uint8_t* data, size_t len) override;
    std::vector<uint8_t> exportOp() const override;
};

class CowXorOp : public CowBlockOp {
  public:
    bool isOrderedOp() const override { return true; }
    uint32_t getOffset() const { return offset_; }
    void setOffset(uint32_t block) { offset_ = block; }

  protected:
    uint64_t offset_;
};

class LegacyCowXorOp : public CowXorOp {
  public:
    uint8_t getType() const { return kCowXorOp; }
    uint64_t getOpLength() const { return sizeof(CowOperation); }
    uint32_t getNumNewBlock() const { return 1; }

    bool importOp(uint8_t* data, size_t len) override;
    std::vector<uint8_t> exportOp() const override;
};

class CowSequenceOp : public CowOp {
  public:
    bool isMetaDataOp() const override { return true; }
    bool isOrderedOp() const override { return false; }
    uint64_t getDataLength() const override { return data_length_; }
    void setDataLength(uint16_t len) { data_length_ = len; }
    uint64_t getDataLoc() const { return data_loc_; };
    void setDataLoc(uint64_t len) { data_loc_ = len; };
    uint32_t getNewBlock() const override { return 0; }

    bool importOp(uint8_t* data, size_t len) override;
    std::vector<uint8_t> exportOp() const override;

  protected:
    uint64_t data_loc_;
    uint16_t data_length_;
};

class LegacyCowSequenceOp : public CowSequenceOp {
  public:
    uint8_t getType() const override { return kCowSequenceOp; }
    uint64_t getOpLength() const override { return sizeof(CowOperation); }
    uint32_t getNumNewBlock() const override { return 0; }

    bool importOp(uint8_t* data, size_t len) override;
    std::vector<uint8_t> exportOp() const override;
};

struct ScratchMetadata {
    // Block of data in the image that operation modifies
    // and read-ahead thread stores the modified data
    // in the scratch space
    uint64_t new_block;
    // Offset within the file to read the data
    uint64_t file_offset;
} __attribute__((packed));

struct BufferState {
    uint8_t read_ahead_state;
} __attribute__((packed));

// 2MB Scratch space used for read-ahead
static constexpr uint64_t BUFFER_REGION_DEFAULT_SIZE = (1ULL << 21);

std::ostream& operator<<(std::ostream& os, CowOperation const& arg);

int64_t GetNextOpOffset(const CowOperation& op, uint32_t cluster_size);
int64_t GetNextDataOffset(const CowOperation& op, uint32_t cluster_size);
int64_t GetNextOpOffsetC(const CowOp& op, uint32_t cluster_ops);
int64_t GetNextDataOffsetC(const CowOp& op, uint32_t cluster_ops);

// Ops that are internal to the Cow Format and not OTA data
bool IsMetadataOp(const CowOperation& op);
// Ops that have dependencies on old blocks, and must take care in their merge order
bool IsOrderedOp(const CowOperation& op);

}  // namespace snapshot
}  // namespace android
