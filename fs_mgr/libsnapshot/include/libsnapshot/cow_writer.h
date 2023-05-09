// copyright (c) 2019 the android open source project
//
// licensed under the apache license, version 2.0 (the "license");
// you may not use this file except in compliance with the license.
// you may obtain a copy of the license at
//
//      http://www.apache.org/licenses/license-2.0
//
// unless required by applicable law or agreed to in writing, software
// distributed under the license is distributed on an "as is" basis,
// without warranties or conditions of any kind, either express or implied.
// see the license for the specific language governing permissions and
// limitations under the license.

#pragma once

#include <stdint.h>

#include <condition_variable>
#include <cstdint>
#include <future>
#include <memory>
#include <mutex>
#include <optional>
#include <queue>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#include <android-base/unique_fd.h>
#include <libsnapshot/cow_format.h>
#include <libsnapshot/cow_reader.h>

namespace android {
namespace snapshot {

struct CowOptions {
    uint32_t block_size = 4096;
    std::string compression;

    // Maximum number of blocks that can be written.
    std::optional<uint64_t> max_blocks;

    // Number of CowOperations in a cluster. 0 for no clustering. Cannot be 1.
    uint32_t cluster_ops = 200;

    bool scratch_space = true;

    // Preset the number of merged ops. Only useful for testing.
    uint64_t num_merge_ops = 0;

    // Number of threads for compression
    int num_compress_threads = 0;

    // Batch write cluster ops
    bool batch_write = false;
};

// Interface for writing to a snapuserd COW. All operations are ordered; merges
// will occur in the sequence they were added to the COW.
class ICowWriter {
  public:
    virtual ~ICowWriter() {}

    // Encode an operation that copies the contents of |old_block| to the
    // location of |new_block|. 'num_blocks' is the number of contiguous
    // COPY operations from |old_block| to |new_block|.
    virtual bool AddCopy(uint64_t new_block, uint64_t old_block, uint64_t num_blocks = 1) = 0;

    // Encode a sequence of raw blocks. |size| must be a multiple of the block size.
    virtual bool AddRawBlocks(uint64_t new_block_start, const void* data, size_t size) = 0;

    // Add a sequence of xor'd blocks. |size| must be a multiple of the block size.
    virtual bool AddXorBlocks(uint32_t new_block_start, const void* data, size_t size,
                              uint32_t old_block, uint16_t offset) = 0;

    // Encode a sequence of zeroed blocks. |size| must be a multiple of the block size.
    virtual bool AddZeroBlocks(uint64_t new_block_start, uint64_t num_blocks) = 0;

    // Add a label to the op sequence.
    virtual bool AddLabel(uint64_t label) = 0;

    // Add sequence data for op merging. Data is a list of the destination block numbers.
    virtual bool AddSequenceData(size_t num_ops, const uint32_t* data) = 0;

    // Flush all pending writes. This must be called before closing the writer
    // to ensure that the correct headers and footers are written.
    virtual bool Finalize() = 0;

    // Return number of bytes the cow image occupies on disk.
    virtual uint64_t GetCowSize() = 0;

    virtual const CowOptions& options() const = 0;
};

class CompressWorker {
  public:
    CompressWorker(CowCompressionAlgorithm compression, uint32_t block_size);
    bool RunThread();
    void EnqueueCompressBlocks(const void* buffer, size_t num_blocks);
    bool GetCompressedBuffers(std::vector<std::basic_string<uint8_t>>* compressed_buf);
    void Finalize();
    static std::basic_string<uint8_t> Compress(CowCompressionAlgorithm compression,
                                               const void* data, size_t length);

    static bool CompressBlocks(CowCompressionAlgorithm compression, size_t block_size,
                               const void* buffer, size_t num_blocks,
                               std::vector<std::basic_string<uint8_t>>* compressed_data);

  private:
    struct CompressWork {
        const void* buffer;
        size_t num_blocks;
        bool compression_status = false;
        std::vector<std::basic_string<uint8_t>> compressed_data;
    };

    CowCompressionAlgorithm compression_;
    uint32_t block_size_;

    std::queue<CompressWork> work_queue_;
    std::queue<CompressWork> compressed_queue_;
    std::mutex lock_;
    std::condition_variable cv_;
    bool stopped_ = false;

    std::basic_string<uint8_t> Compress(const void* data, size_t length);
    bool CompressBlocks(const void* buffer, size_t num_blocks,
                        std::vector<std::basic_string<uint8_t>>* compressed_data);
};

class CowWriterBase : public ICowWriter {
  public:
    CowWriterBase(const CowOptions& options) : options_(options) {}
    virtual ~CowWriterBase() {}

    bool AddCopy(uint64_t new_block, uint64_t old_block, uint64_t num_blocks = 1) override;
    bool AddRawBlocks(uint64_t new_block_start, const void* data, size_t size) override;
    bool AddXorBlocks(uint32_t new_block_start, const void* data, size_t size, uint32_t old_block,
                      uint16_t offset) override;
    bool AddZeroBlocks(uint64_t new_block_start, uint64_t num_blocks) override;
    bool AddLabel(uint64_t label) override;
    bool AddSequenceData(size_t num_ops, const uint32_t* data) override;

    const CowOptions& options() const override { return options_; }

  protected:
    virtual bool EmitCopy(uint64_t new_block, uint64_t old_block, uint64_t num_blocks = 1) = 0;
    virtual bool EmitRawBlocks(uint64_t new_block_start, const void* data, size_t size) = 0;
    virtual bool EmitXorBlocks(uint32_t new_block_start, const void* data, size_t size,
                               uint32_t old_block, uint16_t offset) = 0;
    virtual bool EmitZeroBlocks(uint64_t new_block_start, uint64_t num_blocks) = 0;
    virtual bool EmitLabel(uint64_t label) = 0;
    virtual bool EmitSequenceData(size_t num_ops, const uint32_t* data) = 0;

    bool ValidateNewBlock(uint64_t new_block);

    CowOptions options_;
};

}  // namespace snapshot
}  // namespace android
