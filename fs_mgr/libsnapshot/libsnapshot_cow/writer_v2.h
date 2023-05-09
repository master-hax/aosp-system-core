// copyright (c) 2023 the android open source project
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

#include <libsnapshot/cow_writer.h>

namespace android {
namespace snapshot {

class CowWriterV2 : public CowWriterBase {
  public:
    explicit CowWriterV2(const CowOptions& options);
    ~CowWriterV2() override;

    // Set up the writer.
    // The file starts from the beginning.
    //
    // If fd is < 0, the CowWriter will be opened against /dev/null. This is for
    // computing COW sizes without using storage space.
    //
    // If a label is given, open the writer in append mode and drop any data/ops after the given
    // label. If the label is not found, Initialize will fail.
    bool Initialize(android::base::unique_fd&& fd, std::optional<uint64_t> label);
    bool Initialize(android::base::borrowed_fd fd, std::optional<uint64_t> label);

    bool Finalize() override;

    uint64_t GetCowSize() override;

  protected:
    virtual bool EmitCopy(uint64_t new_block, uint64_t old_block, uint64_t num_blocks = 1) override;
    virtual bool EmitRawBlocks(uint64_t new_block_start, const void* data, size_t size) override;
    virtual bool EmitXorBlocks(uint32_t new_block_start, const void* data, size_t size,
                               uint32_t old_block, uint16_t offset) override;
    virtual bool EmitZeroBlocks(uint64_t new_block_start, uint64_t num_blocks) override;
    virtual bool EmitLabel(uint64_t label) override;
    virtual bool EmitSequenceData(size_t num_ops, const uint32_t* data) override;

  private:
    bool EmitCluster();
    bool EmitClusterIfNeeded();
    bool EmitBlocks(uint64_t new_block_start, const void* data, size_t size, uint64_t old_block,
                    uint16_t offset, uint8_t type);
    void SetupHeaders();
    void SetupWriteOptions();
    bool ParseOptions();
    bool OpenForWrite();
    bool OpenForAppend(uint64_t label);
    bool GetDataPos(uint64_t* pos);
    bool WriteRawData(const void* data, size_t size);
    bool WriteOperation(const CowOperation& op, const void* data = nullptr, size_t size = 0);
    void AddOperation(const CowOperation& op);
    void InitPos();
    void InitBatchWrites();
    void InitWorkers();
    bool FlushCluster();

    bool CompressBlocks(size_t num_blocks, const void* data);
    bool SetFd(android::base::borrowed_fd fd);
    bool Sync();
    bool Truncate(off_t length);
    bool EnsureSpaceAvailable(const uint64_t bytes_needed) const;

  private:
    android::base::unique_fd owned_fd_;
    android::base::borrowed_fd fd_;
    CowHeader header_{};
    CowFooter footer_{};
    CowCompressionAlgorithm compression_ = kCowCompressNone;
    uint64_t current_op_pos_ = 0;
    uint64_t next_op_pos_ = 0;
    uint64_t next_data_pos_ = 0;
    uint64_t current_data_pos_ = 0;
    ssize_t total_data_written_ = 0;
    uint32_t cluster_size_ = 0;
    uint32_t current_cluster_size_ = 0;
    uint64_t current_data_size_ = 0;
    bool is_dev_null_ = false;
    bool merge_in_progress_ = false;
    bool is_block_device_ = false;
    uint64_t cow_image_size_ = INT64_MAX;

    int num_compress_threads_ = 1;
    std::vector<std::unique_ptr<CompressWorker>> compress_threads_;
    std::vector<std::future<bool>> threads_;
    std::vector<std::basic_string<uint8_t>> compressed_buf_;
    std::vector<std::basic_string<uint8_t>>::iterator buf_iter_;

    std::vector<std::unique_ptr<CowOperation>> opbuffer_vec_;
    std::vector<std::unique_ptr<uint8_t[]>> databuffer_vec_;
    std::unique_ptr<struct iovec[]> cowop_vec_;
    int op_vec_index_ = 0;

    std::unique_ptr<struct iovec[]> data_vec_;
    int data_vec_index_ = 0;
    bool batch_write_ = false;
};

}  // namespace snapshot
}  // namespace android
