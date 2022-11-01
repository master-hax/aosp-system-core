#include <sys/types.h>
#include <sys/utsname.h>
#include <unistd.h>

#include <climits>
#include <limits>
#include <queue>
#include <string>

#include <android-base/chrono_utils.h>
#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/properties.h>
#include <android-base/scopeguard.h>
#include <android-base/unique_fd.h>
#include <brotli/encode.h>
#include <libsnapshot/cow_format.h>
#include <libsnapshot/cow_reader.h>
#include <libsnapshot/cow_writer.h>
#include <lz4.h>
#include <zlib.h>

#include <sys/uio.h>

#include <stdlib.h>
#include <time.h>

/*
 * We use Async writes to speed up the OTA
 * installation. Here is the high level flow:
 *
 * Based on the tracing information, during OTA install,
 * we observe that about 60-70% times is spent
 * during block compression and about 5% is spent during
 * COW block device writes. The rest 25-30% time
 * is spent by update-engine to stream the data over network
 * and de-compress it. With this information, the primary
 * design goal is to free up the update-engine thread
 * as soon as possible by queueing up the COW block device
 * writes.
 *
 * This would mean that the buffers for REPLACE and XOR operations
 * have to be cached before freeing up the thread as the I/O operations
 * are done asynchronously.
 *
 * libsnapshot_cow library uses scratch-buffers wherein each buffer is
 * of size 1MB. We use 8 such buffers and can be changed by constant
 * `kNumScratchBuffers`. We pick 1MB as during REPLACE operations,
 * we can get a maximum of 2MB contiguous blocks. kNumScratchBuffers
 * is set to 8 based on the perf analysis. However, this should
 * be a configurable parameter.
 *
 * When update-engine thread invokes libsnapshot_cow API's, we
 * will capture the metadata information related to the I/O using
 * "WriteEntry" structure. This is done by `EmitBlocksAsync` function.
 *
 * =========================================================================
 *
 * Tracking I/O metadata:
 *
 * When update-engine invokes libsnapshot API's, we need
 * to store the metadata anb buffers so that the I/O's
 * can be issues asynchronously. We use "WriteEntry"
 * to capture this metadata.
 *
 * "WriteEntry" structure captures two types of information:
 *
 * 1: Scratch buffers of 1MB with `kNumScratchBuffers` buffers.
 *
 *       +-----------------------+
 *      |     1MB Buffer         |  <-- Write Entry
 *      +------------------------+
 *      |     1MB Buffer         |  <-- Write Entry
 *      +------------------------+
 *             ........
 *      +------------------------+
 *      |     1MB Buffer         | <--- Write Entry
 *      +------------------------+
 *
 *  Thus, we have `kNumScratchBuffers` Write Entry. These buffers
 *  are queued up in `queue_scratch_buffers_` queue.
 *  "WriteEntry->scratch_buffer" will point to these 1MB buffers.
 *
 *  We will use these scratch buffers only when blocks are contiguous
 *  and perfectly fit in one API call i.e. If update-engine invokes
 *  AddRawBlocks(10, buffer, 2097152) for a REPLACE operation;
 *  this means, we have 2MB of contiguous blocks. Thus, we will use two scratch buffers.
 *
 * 2: Not all requests from update-engine are contiguous. For instance,
 * label ops, copy ops can just be a single op operation. Thus for these
 * ops, we will not use scratch buffers.
 *
 * Ex: If update-engine invokes
 *
 * AddRawBlocks(10, buffer, 4096) or
 * AddCopy(10, 30, 1)
 *
 * Both these operation point to changes to one 4k blocks. In this case,
 * we don't use the scratch buffers as mentioned above. Instead,
 * we will allocate the "Writer Entry" for one 4k block.
 * "WriterEntry->buffer_vec_" will hold these buffers.
 *
 * ===========================================================================
 *
 * Flow of I/O:
 *
 * We maintain 3 queues which tracks the I/O flow:
 *
 * 1: Scratch buffer queue
 *
 * 2: Processing I/O queue
 *
 * 3: I/O in progress queue
 *
 * Scratch-buffer-queue            Processing queue    I/O in progress queue
 * +------------------------+     +-------------+     +-------------+
 * |Write-Entry| Write-Entry| --> |Write Entry  | --> | Write Entry |---+
 * +------------------------+     +-------------+     +-------------+   |
 * ^                                                                    |
 * ^                                                                    |
 * |                                                                    |
 * ----<--------<----------<------------<----------------<-------------<+
 *
 * These queues work in a simple producer-consumer mechanism.
 *
 * Update-engine thread submission of I/O requests:
 *
 * 1: Update-engine invokes `EmitBlocksAsync()` function. "WriteEntry" from
 *    "Scratch-buffer-queue" is populated with by copying the buffer and
 *    en-queued to Processing queue.
 *
 * 2: Note that for REPLACE and XOR operation, the submitting thread
 * will not be doing the compression. Update-engine thread will en-queue
 * the "WriteEntry" buffer to processing-queue and will be done with
 * the API call. From this point onwards, update-engine thread is free
 * to work on other tasks viz. streaming new data and de-comperssing them.
 *
 * Background I/O thread:
 *
 * 3: The I/O thread in the background will pick up the "WriteEntry"
 * from processing queue and will work on it based on the COW operation.
 * If the COW operation is a REPLACE or XOR op, compression will be done
 * by this thread.
 *
 * ==========================================================================
 *
 * Flow control of I/O requests:
 *
 * Update-engine thread will block on 3 scenarios when submitting the I/O:
 *
 * 1: Non-availability of scratch-buffers - This can happen if the background
 *    I/O thread is slow.
 *
 * 2: Number of in-flight requests in "Processing-queue" exceeds
 * `kMaxQueueProcessingSize`. We do not want "Processing-queue" to overflow
 * since, some of the buffers are allocated on the fly in the I/O path. Thus,
 * if the queue exceeds `kMaxQueueProcessingSize` size, update-engine
 * thread will block until "Processing-queue" is 50% empty.
 *
 * 3: Forcefully draining I/O requests: This is an explicit call to flush
 * all the in-flight I/O requests primarily used just before writing COW
 * footer.
 *
 * Theoretically, update-engine thread should never block. The background
 * I/O thread should be in lock-step with the update-engine thread. However,
 * we can have scenario where I/O thread can lag sometimes if every single
 * operation is a REPLACE operation. This can happen for a full OTA. Compressing
 * every 4k block can be slow resulting in I/O thread lagging. However,
 * we have 8MB buffers which is more than sufficient to avoid the lag based
 * on perf testing.
 *
 */

namespace android {
namespace snapshot {

ICowBlockWriter::ICowBlockWriter() {}

class CowWriterAsync : public ICowBlockWriter {
  public:
    explicit CowWriterAsync();

    ~CowWriterAsync();

    bool Initialize(android::base::borrowed_fd fd) override;
    bool WriteOperation(CowOperation& op, const void* data = nullptr, size_t size = 0,
                        uint64_t user_data = 0) override;
    bool Sync() override;
    bool DrainIORequests() override;

  private:
    bool WriteRawData(const void* buffer, off_t offset, size_t length, uint64_t user_data,
                      bool is_fixed = false, unsigned int index = 0);
    bool SubmitSqeEntries();
    bool ReapCqeEntries();
    bool ReapAndSubmitIO(bool force_submit = false);
};

CowWriterAsync::CowWriterAsync() {}

CowWriterAsync::~CowWriterAsync() {}

bool CowWriterAsync::WriteOperation(CowOperation&, const void*, size_t, uint64_t) {
    return true;
}

bool CowWriterAsync::WriteRawData(const void*, off_t, size_t, uint64_t, bool, unsigned int) {
    return true;
}

bool CowWriterAsync::ReapCqeEntries() {
    return true;
}

bool CowWriterAsync::SubmitSqeEntries() {
    return true;
}

bool CowWriterAsync::ReapAndSubmitIO(bool) {
    return true;
}

bool CowWriterAsync::Sync() {
    return true;
}

bool CowWriterAsync::DrainIORequests() {
    return true;
}

bool CowWriterAsync::Initialize(android::base::borrowed_fd) {
    return true;
}

//====================================================================================
// The following functions are related to processing I/O requests from
// background I/O thread

bool CowWriter::ProcessWriteEntryNonScratchBuffer(std::unique_ptr<WriteEntry> we) {
    CHECK(!we->scratch_buffer);

    CowOperation op = {};
    op.type = we->op_type;

    if (we->op_type == kCowCopyOp) {
        op.new_block = we->new_block;
        op.source = we->source;
        return block_writer_->WriteOperation(op);
    } else if (we->op_type == kCowZeroOp) {
        op.new_block = we->new_block;
        op.source = 0;
        return block_writer_->WriteOperation(op);
    } else {
        op.new_block = we->new_block;
        CHECK(we->op_type == kCowReplaceOp || we->op_type == kCowXorOp);

        void* buffer = we->buffer_vec_[0].get();
        if (compression_) {
            auto data = Compress(buffer, header_.block_size);
            if (data.empty()) {
                PLOG(ERROR) << "Async - compress failed";
                return false;
            }

            if (data.size() > std::numeric_limits<uint16_t>::max()) {
                LOG(ERROR) << "Compressed block is too large: " << data.size() << " bytes";
                return false;
            }

            std::memcpy(buffer, data.data(), data.size());
            op.compression = compression_;
            op.data_length = static_cast<uint16_t>(data.size());
        } else {
            op.compression = kCowCompressNone;
            op.data_length = static_cast<uint16_t>(header_.block_size);
        }

        if (we->op_type == kCowXorOp) {
            op.source = we->source;
        }

        // Store the "WriteEntry" as we have to track the buffer until
        // I/O is completed.
        queue_io_in_progress_.push(std::move(we));
        return block_writer_->WriteOperation(op, buffer, op.data_length, op.type);
    }

    return true;
}

bool CowWriter::ProcessWriteEntryFromScratchQueue(std::unique_ptr<WriteEntry> we) {
    const int num_scratch_buffers = kScratchBufferSize / header_.block_size;
    off_t offset = 0;
    bool scratch_buffer_used = !(we->op_type == kCowCopyOp || we->op_type == kCowZeroOp);

    for (size_t i = 0; i < num_scratch_buffers; i++) {
        CowOperation op = {};
        op.type = we->op_type;
        op.new_block = we->new_block + i;

        if (we->op_type == kCowCopyOp) {
            op.source = we->source + i;
            if (!block_writer_->WriteOperation(op)) {
                LOG(ERROR) << "WriteOperation - COPY op failed. source: " << op.source
                           << " Processing entry: " << i;
                return false;
            }
        } else if (we->op_type == kCowZeroOp) {
            op.source = 0;
            if (!block_writer_->WriteOperation(op)) {
                LOG(ERROR) << "WriteOperation - ZERO op failed. "
                           << " Processing entry: " << i;
                return false;
            }
        } else {
            void* write_buffer;

            if (compression_) {
                auto data = Compress(reinterpret_cast<char*>(we->scratch_buffer) + offset,
                                     header_.block_size);
                if (data.empty()) {
                    PLOG(ERROR) << "Async - compress failed";
                    return false;
                }

                if (data.size() > std::numeric_limits<uint16_t>::max()) {
                    LOG(ERROR) << "Compressed block is too large: " << data.size() << " bytes";
                    return false;
                }

                if (data.size() > header_.block_size) {
                    // This is little subtle; sometimes compressed data can be more
                    // than block size i.e. 4k. In that case, we cannot store that
                    // back in scratch buffer as we may end up corrupting other buffers.
                    //
                    // Hence, allocate the buffer on the fly and store them until I/O is
                    // completed. Once I/O is done, we will clear this vector.
                    auto buffer = std::make_unique<uint8_t[]>(data.size());
                    write_buffer = buffer.get();
                    std::memcpy(write_buffer, data.data(), data.size());
                    we->buffer_vec_.push_back(std::move(buffer));
                } else {
                    // Copy the compressed data back to scratch queue buffer itself.
                    std::memcpy(reinterpret_cast<char*>(we->scratch_buffer) + offset, data.data(),
                                data.size());
                    write_buffer = reinterpret_cast<char*>(we->scratch_buffer) + offset;
                }
                op.compression = compression_;
                op.data_length = static_cast<uint16_t>(data.size());
            } else {
                op.compression = kCowCompressNone;
                op.data_length = static_cast<uint16_t>(header_.block_size);
                write_buffer = reinterpret_cast<char*>(we->scratch_buffer) + offset;
            }

            if (we->op_type == kCowXorOp) {
                op.source = we->source + (i * header_.block_size);
            }

            uint64_t user_data = 0;
            // Once we are done processing all the 4k buffers in scratch-buffer, we
            // will push this "WriteEntry" to "I/O in progress queue". When all
            // the buffers in this "WriteEntry" have the I/O completed, we can then
            // safely push them back to "Scratch queue".
            if (i == num_scratch_buffers - 1) {
                queue_io_in_progress_.push(std::move(we));
                user_data = op.type;
            }
            if (!block_writer_->WriteOperation(op, write_buffer, op.data_length, user_data)) {
                LOG(ERROR) << "WriteOperation: op.type: " << op.type << " failed"
                           << " Processing entry: " << i;
                return false;
            }
            offset += header_.block_size;
        }
    }

    // Since COPY and XOR blocks don't use scratch-buffers, we can safely push
    // them back to "Scratch queue" immediately.
    if (!scratch_buffer_used) {
        PushWriteEntryToScratchQueue(std::move(we));
    }

    return true;
}

void CowWriter::PushWriteEntryToScratchQueue(std::unique_ptr<WriteEntry> we) {
    {
        std::lock_guard<std::mutex> lock(scratch_buffers_lock_);
        we->buffer_vec_.clear();
        queue_scratch_buffers_.push(std::move(we));
    }
    scratch_buffers_cv_.notify_all();
}

std::unique_ptr<WriteEntry> CowWriter::GetWriteEntryFromProcessQueue() {
    std::unique_ptr<WriteEntry> we;
    bool thread_waiting = false, queue_size;
    {
        std::unique_lock<std::mutex> lock(processing_lock_);
        // Wait until we have some I/O requests or if we are
        // in the process of termination most likely because
        // of cancelling an OTA.
        while (queue_processing_.size() == 0 && !stopped_) {
            auto now = std::chrono::system_clock::now();
            auto deadline = now + 10s;
            auto status = processing_cv_.wait_until(lock, deadline);
            if (status == std::cv_status::timeout) {
                LOG(INFO) << "Waiting for write-entry from process queue"
                          << " scratch queue-size: " << queue_scratch_buffers_.size()
                          << " queue-io-in-progress: " << queue_io_in_progress_.size()
                          << " queue-process-size: " << queue_processing_.size();
                continue;
            }
        }

        // If there are still pending I/O requests, we should continue
        // to process those until queue is empty.
        if (stopped_ && queue_processing_.size() == 0) {
            return std::unique_ptr<WriteEntry>{};
        }
        we = std::move(queue_processing_.front());
        queue_processing_.pop();
        if (queue_processing_waiting_) {
            queue_size = queue_processing_.size();
            thread_waiting = queue_processing_waiting_;
        }
    }

    // Notify if submission thread is waiting and queue is 50% empty
    if (thread_waiting && (queue_size <= (kMaxQueueProcessingSize >> 1))) {
        processing_cv_.notify_all();
    }

    return we;
}

void CowWriter::InitializeBuffers(android::base::borrowed_fd&& fd_in) {
    android::base::borrowed_fd fd = std::move(fd_in);

    block_writer_ = std::make_unique<CowWriterAsync>();

    CHECK(block_writer_->Initialize(fd));

    for (size_t i = 0; i < kNumScratchBuffers; i++) {
        std::unique_ptr<uint8_t[]> buffer = std::make_unique<uint8_t[]>(kScratchBufferSize);
        std::unique_ptr<WriteEntry> writeEntry = std::make_unique<WriteEntry>();
        writeEntry->scratch_buffer = buffer.get();
        queue_scratch_buffers_.push(std::move(writeEntry));
        scratch_buffer_.push_back(std::move(buffer));
    }
}

void CowWriter::DrainComplete() {
    {
        std::unique_lock<std::mutex> lock(processing_lock_);
        CHECK(drain_io_in_progress_);
        drain_io_in_progress_ = false;
        CHECK(queue_processing_.size() == 0);
    }
    processing_cv_.notify_all();
    LOG(INFO) << "Drain-complete: scratch queue-size: " << queue_scratch_buffers_.size();
}

// Background thread to process I/O requests from update-engine asynchronously.
bool CowWriter::RunThread(android::base::borrowed_fd fd) {
    // Just initialize the buffers for now.
    InitializeBuffers(std::move(fd));
    bool succeeded = false;
    auto scope_guard = android::base::make_scope_guard([this, &succeeded]() -> void {
        if (!succeeded) {
            CHECK(!io_error_.exchange(true));
            processing_cv_.notify_all();
        }
    });

    while (true) {
        std::unique_ptr<WriteEntry> we = GetWriteEntryFromProcessQueue();

        if (!we) {
            LOG(INFO) << "I/O Thread Terminating...";
            break;
        }

        CowOperation op = {};
        op.type = we->op_type;

        if (we->op_type == kDrainQueue) {
            if (block_writer_->Sync() && block_writer_->DrainIORequests()) {
                DrainComplete();
            } else {
                LOG(ERROR) << "Failed to drain I/O requests";
                return false;
            }
        } else if (we->op_type == kCowLabelOp) {
            op.source = we->source;

            if (!(block_writer_->WriteOperation(op) && block_writer_->Sync())) {
                LOG(ERROR) << "Labelop failed";
                return false;
            }
        } else if (we->op_type == kCowSequenceOp) {
            op.data_length = we->source;
            void* buffer = we->buffer_vec_[0].get();
            queue_io_in_progress_.push(std::move(we));

            if (!block_writer_->WriteOperation(op, buffer, op.data_length, op.type)) {
                LOG(ERROR) << "kCowSequenceOp failed";
                return false;
            }
        } else if (!we->scratch_buffer) {
            if (!ProcessWriteEntryNonScratchBuffer(std::move(we))) {
                LOG(ERROR) << "ProcessWriteEntryNonScratchBuffer failed";
                return false;
            }
        } else {
            if (!ProcessWriteEntryFromScratchQueue(std::move(we))) {
                LOG(ERROR) << "ProcessWriteEntryFromScratchQueue failed";
                return false;
            }
        }
    }

    succeeded = true;
    return true;
}

// ===================================================================================

// Following functions are related to update-engine thread wherein
// the primary focus is to queue the I/O requests and free up the
// update-engine thread.
std::unique_ptr<WriteEntry> CowWriter::GetWriteEntryFromScratchQueue() {
    std::unique_ptr<WriteEntry> we;
    {
        std::unique_lock<std::mutex> lock(scratch_buffers_lock_);
        while (queue_scratch_buffers_.size() == 0) {
            auto now = std::chrono::system_clock::now();
            auto deadline = now + 3s;
            auto status = scratch_buffers_cv_.wait_until(lock, deadline);
            if (status == std::cv_status::timeout) {
                LOG(INFO) << "Failed to get write entry from scratch queue."
                          << " scratch queue-size: " << queue_scratch_buffers_.size()
                          << " queue-process-size: " << queue_processing_.size();
                continue;
            }
        }
        we = std::move(queue_scratch_buffers_.front());
        queue_scratch_buffers_.pop();
    }
    return we;
}

bool CowWriter::PushWriteEntryToProcessQueue(std::unique_ptr<WriteEntry> we) {
    {
        std::unique_lock<std::mutex> lock(processing_lock_);
        queue_processing_.push(std::move(we));

        if (queue_processing_.size() > kMaxQueueProcessingSize) {
            // Wait until 50% of the queue is empty or if there is an io_error
            // observed during async I/O
            while (queue_processing_.size() > (kMaxQueueProcessingSize >> 1) && !io_error_) {
                auto now = std::chrono::system_clock::now();
                auto deadline = now + 10s;
                queue_processing_waiting_ = true;
                auto status = processing_cv_.wait_until(lock, deadline);
                if (status == std::cv_status::timeout) {
                    LOG(INFO) << "Processing queue size exceeds threshold of: "
                              << (kMaxQueueProcessingSize >> 1)
                              << " scratch queue-size: " << queue_scratch_buffers_.size()
                              << " queue-process-size: " << queue_processing_.size();
                    continue;
                }
            }
        }

        queue_processing_waiting_ = false;
    }

    processing_cv_.notify_all();
    if (io_error_) {
        LOG(ERROR) << "Async I/O thread terminated. I/O requests cannot be processed. Terminating "
                      "update.";
        return false;
    }

    return true;
}

// Entry point to queue up I/O requests from update-engine
bool CowWriter::EmitBlocksAsync(uint64_t new_block_start, const void* data, size_t num_ops,
                                uint64_t old_block, uint16_t offset, uint8_t type) {
    const uint8_t* iter = reinterpret_cast<const uint8_t*>(data);
    CHECK(!merge_in_progress_);

    const int num_scratch_buffers = kScratchBufferSize / header_.block_size;
    size_t i = 0, num_pending_ops = num_ops;

    // Get write-entry from scratch queue. This is primarily used
    // by replace, copy and zero ops. If the blocks are contiguous,
    // copy them in one shot.
    while (i < num_ops && num_pending_ops >= num_scratch_buffers) {
        std::unique_ptr<WriteEntry> we = GetWriteEntryFromScratchQueue();

        we->op_type = type;
        we->new_block = new_block_start + i;

        if (type == kCowXorOp) {
            we->source = (old_block + i) * header_.block_size + offset;
        } else if (type == kCowCopyOp) {
            we->source = (old_block + i);
        }

        if (type == kCowXorOp || type == kCowReplaceOp) {
            // Copy entire buffer in one shot
            std::memcpy(we->scratch_buffer, iter, kScratchBufferSize);
            iter += kScratchBufferSize;
        }

        num_pending_ops -= num_scratch_buffers;
        i += num_scratch_buffers;
        if (!PushWriteEntryToProcessQueue(std::move(we))) {
            return false;
        }
    }

    // We have some ops which doesn't fit in scratch buffers. We don't want to
    // deal with fragmentation of scratch buffers.
    while (num_pending_ops) {
        std::unique_ptr<WriteEntry> we = std::make_unique<WriteEntry>();
        we->op_type = type;
        we->new_block = new_block_start + i;

        if (type == kCowLabelOp) {
            we->source = old_block;
        } else if (type == kCowCopyOp) {
            we->source = old_block + i;
        } else if (type == kCowSequenceOp) {
            we->source = offset;
            auto buffer = std::make_unique<uint8_t[]>(offset);
            std::memcpy(buffer.get(), iter, offset);
            we->buffer_vec_.push_back(std::move(buffer));
            CHECK(num_pending_ops == 1);
        } else if (type == kCowXorOp || type == kCowReplaceOp) {
            // Sometimes, compression size can be greater than
            // then actual data size. Hence, allocate twice the
            // block size. Although, this doesn't seem appealing but
            // we only cache at most 512 blocks at a time and do a
            // flow control of the processing queue. Hence, at any point in time, the maximum
            // memory usage would be 512 * 8192 = 4mb.
            auto buffer = std::make_unique<uint8_t[]>(header_.block_size * 2);
            if (type == kCowXorOp) {
                we->source = (old_block + i) * header_.block_size + offset;
            }

            std::memcpy(buffer.get(), iter, header_.block_size);
            we->buffer_vec_.push_back(std::move(buffer));
            iter += header_.block_size;
        }
        num_pending_ops -= 1;
        i += 1;
        if (!PushWriteEntryToProcessQueue(std::move(we))) {
            return false;
        }
    }

    return true;
}

bool CowWriter::DrainIORequests() {
    // This is a blocking operation wherein update-engine
    // thread will wait until all in-flight I/O requests
    // are completed.
    if (EmitBlocksAsync(0, nullptr, 1, 0, 0, kDrainQueue)) {
        std::unique_lock<std::mutex> lock(processing_lock_);
        drain_io_in_progress_ = true;
        while (drain_io_in_progress_ && !io_error_) {
            auto now = std::chrono::system_clock::now();
            auto deadline = now + 10s;
            auto status = processing_cv_.wait_until(lock, deadline);
            if (status == std::cv_status::timeout) {
                LOG(INFO) << " scratch queue-size: " << queue_scratch_buffers_.size()
                          << " queue-process-size: " << queue_processing_.size();
                continue;
            }
        }
    } else {
        LOG(ERROR) << "Draining I/O requests failed";
        return false;
    }

    if (io_error_) {
        LOG(ERROR) << "Async I/O thread terminated. I/O requests cannot be processed. Terminating "
                      "update.";
        return false;
    }

    return true;
}

void CowWriter::TerminateIOThread() {
    {
        std::unique_lock<std::mutex> lock(processing_lock_);
        stopped_ = true;
    }

    processing_cv_.notify_all();
    if (thread_.joinable()) {
        thread_.join();
    }

    write_async_ = false;
}

void CowWriter::SetupAsyncWriter(android::base::borrowed_fd fd) {
    if (android::base::GetBoolProperty("ro.virtual_ab.cow_write.async.enabled", false)) {
        LOG(INFO) << "ro.virtual_ab.cow_write.async.enabled disabled - Not using async writes";
        return;
    }

    if (fd.get() < 0) {
        return;
    }

    struct stat stat;
    if (fstat(fd_.get(), &stat) < 0) {
        return;
    }

    if (!S_ISBLK(stat.st_mode)) {
        return;
    }

    // Spin up the background thread for processing I/O requests
    thread_ = std::thread(std::bind(&CowWriter::RunThread, this, fd));
    write_async_ = true;
}

}  // namespace snapshot
}  // namespace android
