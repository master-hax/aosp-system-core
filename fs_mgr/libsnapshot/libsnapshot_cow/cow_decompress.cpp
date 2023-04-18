//
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
//

#include "cow_decompress.h"

#include <utility>

#include <android-base/logging.h>
#include <brotli/decode.h>
#include <lz4.h>
#include <zlib.h>

namespace android {
namespace snapshot {

bool IByteStream::ReadFully(void* buffer, size_t buffer_size) {
    size_t stream_remaining = Size();

    char* buffer_pos = reinterpret_cast<char*>(buffer);
    size_t buffer_remaining = buffer_size;
    while (stream_remaining) {
        size_t to_read = std::min(buffer_remaining, stream_remaining);
        size_t actual_read = 0;
        if (!Read(buffer_pos, to_read, &actual_read)) {
            return false;
        }
        if (!actual_read) {
            LOG(ERROR) << "Stream ended prematurely";
            return false;
        }
        CHECK(actual_read <= to_read);

        stream_remaining -= actual_read;
        buffer_pos += actual_read;
        buffer_remaining -= actual_read;
    }
    return true;
}

std::unique_ptr<IDecompressor> IDecompressor::FromString(const std::string& compressor) {
    if (compressor == "lz4") {
        return IDecompressor::Lz4();
    } else if (compressor == "brotli") {
        return IDecompressor::Brotli();
    } else if (compressor == "gz") {
        return IDecompressor::Gz();
    } else {
        return nullptr;
    }
}

class NoDecompressor final : public IDecompressor {
  public:
    bool Decompress(size_t) override;
    bool Decompress(void*, size_t) override {
        LOG(ERROR) << "Not supported";
        return false;
    }
};

bool NoDecompressor::Decompress(size_t) {
    size_t stream_remaining = stream_->Size();
    while (stream_remaining) {
        size_t buffer_size = stream_remaining;
        uint8_t* buffer = reinterpret_cast<uint8_t*>(sink_->GetBuffer(buffer_size, &buffer_size));
        if (!buffer) {
            LOG(ERROR) << "Could not acquire buffer from sink";
            return false;
        }

        // Read until we can fill the buffer.
        uint8_t* buffer_pos = buffer;
        size_t bytes_to_read = std::min(buffer_size, stream_remaining);
        while (bytes_to_read) {
            size_t read;
            if (!stream_->Read(buffer_pos, bytes_to_read, &read)) {
                return false;
            }
            if (!read) {
                LOG(ERROR) << "Stream ended prematurely";
                return false;
            }
            if (!sink_->ReturnData(buffer_pos, read)) {
                LOG(ERROR) << "Could not return buffer to sink";
                return false;
            }
            buffer_pos += read;
            bytes_to_read -= read;
            stream_remaining -= read;
        }
    }
    return true;
}

std::unique_ptr<IDecompressor> IDecompressor::Uncompressed() {
    return std::unique_ptr<IDecompressor>(new NoDecompressor());
}

// Read chunks of the COW and incrementally stream them to the decoder.
class StreamDecompressor : public IDecompressor {
  public:
    bool Decompress(size_t output_bytes) override;
    bool Decompress(void* buffer, size_t buffer_size) override;

    virtual bool Init() = 0;
    virtual bool DecompressInput(const uint8_t* data, size_t length) = 0;
    virtual bool PartialDecompress(const uint8_t* data, size_t length) = 0;
    virtual bool Done() = 0;

  protected:
    bool GetFreshBuffer();

    size_t output_bytes_;
    size_t stream_remaining_;
    uint8_t* output_buffer_ = nullptr;
    size_t output_buffer_remaining_ = 0;
};

static constexpr size_t kChunkSize = 4096;

bool StreamDecompressor::Decompress(size_t output_bytes) {
    if (!Init()) {
        return false;
    }

    stream_remaining_ = stream_->Size();
    output_bytes_ = output_bytes;

    uint8_t chunk[kChunkSize];
    while (stream_remaining_) {
        size_t read = std::min(stream_remaining_, sizeof(chunk));
        if (!stream_->Read(chunk, read, &read)) {
            return false;
        }
        if (!read) {
            LOG(ERROR) << "Stream ended prematurely";
            return false;
        }
        if (!DecompressInput(chunk, read)) {
            return false;
        }

        stream_remaining_ -= read;

        if (stream_remaining_ && Done()) {
            LOG(ERROR) << "Decompressor terminated early";
            return false;
        }
    }
    if (!Done()) {
        LOG(ERROR) << "Decompressor expected more bytes";
        return false;
    }
    return true;
}

bool StreamDecompressor::Decompress(void* buffer, size_t buffer_size) {
    if (!Init()) {
        return false;
    }

    stream_remaining_ = stream_->Size();
    output_buffer_ = reinterpret_cast<uint8_t*>(buffer);
    output_buffer_remaining_ = buffer_size;

    uint8_t chunk[kChunkSize];
    while (stream_remaining_) {
        size_t read = std::min(stream_remaining_, sizeof(chunk));
        if (!stream_->Read(chunk, read, &read)) {
            return false;
        }
        if (!read) {
            LOG(ERROR) << "Stream ended prematurely";
            return false;
        }
        if (!PartialDecompress(chunk, read)) {
            return false;
        }

        stream_remaining_ -= read;

        if (stream_remaining_ && Done()) {
            LOG(ERROR) << "Decompressor terminated early";
            return false;
        }
    }
    if (!Done()) {
        LOG(ERROR) << "Decompressor expected more bytes";
        return false;
    }
    return true;
}

bool StreamDecompressor::GetFreshBuffer() {
    size_t request_size = std::min(output_bytes_, kChunkSize);
    output_buffer_ =
            reinterpret_cast<uint8_t*>(sink_->GetBuffer(request_size, &output_buffer_remaining_));
    if (!output_buffer_) {
        LOG(ERROR) << "Could not acquire buffer from sink";
        return false;
    }
    return true;
}

class GzDecompressor final : public StreamDecompressor {
  public:
    ~GzDecompressor();

    bool Init() override;
    bool DecompressInput(const uint8_t* data, size_t length) override;
    bool PartialDecompress(const uint8_t* data, size_t length) override;
    bool Done() override { return ended_; }

  private:
    z_stream z_ = {};
    bool ended_ = false;
};

bool GzDecompressor::Init() {
    if (int rv = inflateInit(&z_); rv != Z_OK) {
        LOG(ERROR) << "inflateInit returned error code " << rv;
        return false;
    }
    return true;
}

GzDecompressor::~GzDecompressor() {
    inflateEnd(&z_);
}

bool GzDecompressor::DecompressInput(const uint8_t* data, size_t length) {
    z_.next_in = reinterpret_cast<Bytef*>(const_cast<uint8_t*>(data));
    z_.avail_in = length;

    while (z_.avail_in) {
        // If no more output buffer, grab a new buffer.
        if (z_.avail_out == 0) {
            if (!GetFreshBuffer()) {
                return false;
            }
            z_.next_out = reinterpret_cast<Bytef*>(output_buffer_);
            z_.avail_out = output_buffer_remaining_;
        }

        // Remember the position of the output buffer so we can call ReturnData.
        auto avail_out = z_.avail_out;

        // Decompress.
        int rv = inflate(&z_, Z_NO_FLUSH);
        if (rv != Z_OK && rv != Z_STREAM_END) {
            LOG(ERROR) << "inflate returned error code " << rv;
            return false;
        }

        size_t returned = avail_out - z_.avail_out;
        if (!sink_->ReturnData(output_buffer_, returned)) {
            LOG(ERROR) << "Could not return buffer to sink";
            return false;
        }
        output_buffer_ += returned;
        output_buffer_remaining_ -= returned;

        if (rv == Z_STREAM_END) {
            if (z_.avail_in) {
                LOG(ERROR) << "Gz stream ended prematurely";
                return false;
            }
            ended_ = true;
            return true;
        }
    }
    return true;
}

bool GzDecompressor::PartialDecompress(const uint8_t* data, size_t length) {
    z_.next_in = reinterpret_cast<Bytef*>(const_cast<uint8_t*>(data));
    z_.avail_in = length;
    z_.next_out = reinterpret_cast<Bytef*>(output_buffer_);
    z_.avail_out = output_buffer_remaining_;

    while (z_.avail_in) {
        // Decompress.
        int rv = inflate(&z_, Z_NO_FLUSH);
        if (rv != Z_OK && rv != Z_STREAM_END) {
            LOG(ERROR) << "inflate returned error code " << rv;
            return false;
        }

        size_t returned = output_buffer_remaining_ - z_.avail_out;
        CHECK(returned <= output_buffer_remaining_);

        output_buffer_ += returned;
        output_buffer_remaining_ -= returned;

        if (rv == Z_STREAM_END) {
            if (z_.avail_in) {
                LOG(ERROR) << "Gz stream ended prematurely";
                return false;
            }
            ended_ = true;
            return true;
        }
    }
    return true;
}

std::unique_ptr<IDecompressor> IDecompressor::Gz() {
    return std::unique_ptr<IDecompressor>(new GzDecompressor());
}

class BrotliDecompressor final : public StreamDecompressor {
  public:
    ~BrotliDecompressor();

    bool Init() override;
    bool DecompressInput(const uint8_t* data, size_t length) override;
    bool PartialDecompress(const uint8_t* data, size_t length) override;
    bool Done() override { return BrotliDecoderIsFinished(decoder_); }

  private:
    BrotliDecoderState* decoder_ = nullptr;
};

bool BrotliDecompressor::Init() {
    decoder_ = BrotliDecoderCreateInstance(nullptr, nullptr, nullptr);
    return true;
}

BrotliDecompressor::~BrotliDecompressor() {
    if (decoder_) {
        BrotliDecoderDestroyInstance(decoder_);
    }
}

bool BrotliDecompressor::DecompressInput(const uint8_t* data, size_t length) {
    size_t available_in = length;
    const uint8_t* next_in = data;

    bool needs_more_output = false;
    while (available_in || needs_more_output) {
        if (!output_buffer_remaining_ && !GetFreshBuffer()) {
            return false;
        }

        auto output_buffer = output_buffer_;
        auto r = BrotliDecoderDecompressStream(decoder_, &available_in, &next_in,
                                               &output_buffer_remaining_, &output_buffer_, nullptr);
        if (r == BROTLI_DECODER_RESULT_ERROR) {
            LOG(ERROR) << "brotli decode failed";
            return false;
        }
        if (!sink_->ReturnData(output_buffer, output_buffer_ - output_buffer)) {
            return false;
        }
        needs_more_output = (r == BROTLI_DECODER_RESULT_NEEDS_MORE_OUTPUT);
    }
    return true;
}

bool BrotliDecompressor::PartialDecompress(const uint8_t* data, size_t length) {
    size_t available_in = length;
    const uint8_t* next_in = data;

    while (available_in) {
        auto r = BrotliDecoderDecompressStream(decoder_, &available_in, &next_in,
                                               &output_buffer_remaining_, &output_buffer_, nullptr);
        if (r == BROTLI_DECODER_RESULT_ERROR) {
            LOG(ERROR) << "brotli decode failed";
            return false;
        } else if (r == BROTLI_DECODER_RESULT_NEEDS_MORE_OUTPUT) {
            LOG(ERROR) << "output buffer not big enough";
            return false;
        }
    }
    return true;
}

std::unique_ptr<IDecompressor> IDecompressor::Brotli() {
    return std::unique_ptr<IDecompressor>(new BrotliDecompressor());
}

class Lz4Decompressor final : public IDecompressor {
  public:
    ~Lz4Decompressor() override = default;

    bool Decompress(const size_t output_size) override {
        size_t actual_buffer_size = 0;
        auto&& output_buffer = sink_->GetBuffer(output_size, &actual_buffer_size);
        if (actual_buffer_size != output_size) {
            LOG(ERROR) << "Failed to allocate buffer of size " << output_size << " only got "
                       << actual_buffer_size << " bytes";
            return false;
        }
        // If input size is same as output size, then input is uncompressed.
        if (stream_->Size() == output_size) {
            size_t bytes_read = 0;
            stream_->Read(output_buffer, output_size, &bytes_read);
            if (bytes_read != output_size) {
                LOG(ERROR) << "Failed to read all input at once. Expected: " << output_size
                           << " actual: " << bytes_read;
                return false;
            }
            sink_->ReturnData(output_buffer, output_size);
            return true;
        }
        std::string input_buffer;
        input_buffer.resize(stream_->Size());
        size_t bytes_read = 0;
        stream_->Read(input_buffer.data(), input_buffer.size(), &bytes_read);
        if (bytes_read != input_buffer.size()) {
            LOG(ERROR) << "Failed to read all input at once. Expected: " << input_buffer.size()
                       << " actual: " << bytes_read;
            return false;
        }
        const int bytes_decompressed =
                LZ4_decompress_safe(input_buffer.data(), static_cast<char*>(output_buffer),
                                    input_buffer.size(), output_size);
        if (bytes_decompressed != output_size) {
            LOG(ERROR) << "Failed to decompress LZ4 block, expected output size: " << output_size
                       << ", actual: " << bytes_decompressed;
            return false;
        }
        sink_->ReturnData(output_buffer, output_size);
        return true;
    }

    bool Decompress(void* buffer, size_t buffer_size) override {
        std::string input_buffer(stream_->Size(), '\0');
        if (!stream_->ReadFully(input_buffer.data(), input_buffer.size())) {
            return false;
        }

        const int rv = LZ4_decompress_safe(input_buffer.data(), static_cast<char*>(buffer),
                                           input_buffer.size(), buffer_size);
        if (rv < 0) {
            LOG(ERROR) << "Failed to decompress LZ4 block, code: " << rv;
            return false;
        }
        return true;
    }
};

std::unique_ptr<IDecompressor> IDecompressor::Lz4() {
    return std::make_unique<Lz4Decompressor>();
}

}  // namespace snapshot
}  // namespace android
