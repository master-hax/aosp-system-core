/*
 * Copyright (C) 2018 The Android Open Source Project
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

#include <libfiemap_writer/fiemap_writer.h>

namespace android {
namespace fiemap_writer {

FiemapWriter::FiemapWriter(const std::string& file, const std::string& bdev, uint64_t size) {}

uint64_t FiemapWriter::BlockSize() const {
    return 0;
}

void FiemapWriter::Flush() const {}

const std::vector<struct fiemap_extent>& FiemapWriter::Fiemap() {
    return fiemap_;
}

bool FiemapWriter::Write(off64_t off, uint8_t* buffer, uint64_t size) {
    return false;
}

bool FiemapWriter::Append(uint8_t* buffer, uint64_t size) {
    return false;
}

bool FiemapWriter::Read(off64_t off, uint8_t* buffer, uint64_t size) {
    return false;
}

}  // namespace fiemap_writer
}  // namespace android
