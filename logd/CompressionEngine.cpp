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

#include "CompressionEngine.h"

#include <android-base/logging.h>
#include <zlib.h>

CompressionEngine& CompressionEngine::GetInstance() {
    CompressionEngine* engine = new ZlibCompressionEngine();
    return *engine;
}

bool ZlibCompressionEngine::Compress(const std::vector<uint8_t>& in, size_t in_size,
                                     std::vector<uint8_t>& out) {
    z_stream strm;
    strm.zalloc = Z_NULL;
    strm.zfree = Z_NULL;
    strm.opaque = Z_NULL;
    int ret = deflateInit(&strm, Z_DEFAULT_COMPRESSION);
    if (ret != Z_OK) {
        LOG(ERROR) << "deflateInit() failed";
        return false;
    }

    uint32_t out_size = deflateBound(&strm, in_size);

    out.resize(out_size);
    strm.avail_in = in_size;
    strm.next_in = const_cast<uint8_t*>(in.data());
    strm.avail_out = out_size;
    strm.next_out = out.data();
    ret = deflate(&strm, Z_FINISH);
    if (ret == Z_STREAM_ERROR) {
        LOG(ERROR) << "delate() failed";
        return false;
    }
    uint32_t compressed_data_size = out_size - strm.avail_out;
    deflateEnd(&strm);
    out.resize(compressed_data_size);

    LOG(INFO) << "Compressed Log, old size: " << in.size() << " compressed size: " << out.size();
    return true;
}

bool ZlibCompressionEngine::Decompress(const std::vector<uint8_t>& in, std::vector<uint8_t>& out) {
    z_stream strm;

    strm.zalloc = Z_NULL;
    strm.zfree = Z_NULL;
    strm.opaque = Z_NULL;
    strm.avail_in = in.size();
    strm.next_in = const_cast<uint8_t*>(in.data());
    strm.avail_out = out.size();
    strm.next_out = out.data();

    int ret;
    inflateInit(&strm);
    ret = inflate(&strm, Z_NO_FLUSH);

    if (strm.avail_in != 0 || strm.avail_out != 0) {
        LOG(ERROR) << "inflate() failed";
        return false;
    }
    inflateEnd(&strm);

    return true;
}