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

#ifndef LIBLP_READER_H_
#define LIBLP_READER_H_

#include <stddef.h>

#include <memory>

#include "metadata_format.h"

namespace android {
namespace fs_mgr {

// Read logical partition metadata from its predetermined location on a block
// device. If readback fails, we also attempt to load from a backup copy.
std::unique_ptr<LpMetadata> ReadMetadata(const char* block_device);

// Read metadata from a raw byte stream. This function is provided for unit
// testing.
std::unique_ptr<LpMetadata> ParseMetadata(const void* buffer, size_t buffer_size);

}  // namespace fs_mgr
}  // namespace android

#endif /* LIBLP_READER_H_ */
