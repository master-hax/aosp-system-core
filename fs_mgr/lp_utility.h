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

#ifndef LIBLP_UTILITY_H
#define LIBLP_UTILITY_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#include <android-base/logging.h>

#define LP_TAG "[liblp]"
#define LERROR LOG(ERROR) << LP_TAG
#define PERROR PLOG(ERROR) << LP_TAG

namespace android {
namespace fs_mgr {

// Determine the size of a block device (or file). Logs and returns false on
// error. After calling this, the position of |fd| may have changed.
bool GetDescriptorSize(int fd, uint64_t* size);

// Wrapper around lseek64() that performs error checks and logging.
bool SeekFile(int fd, off64_t offset, int whence);

// Call read() until all bytes have been successfully read into the buffer.
// If an error occurs, this will log and return false.
bool ReadFully(int fd, void* buffer, size_t bytes);

// Call write() until all bytes have been successfully written to the
// descriptor. If an error occurs, this will log and return false.
bool WriteFully(int fd, const void* buffer, size_t bytes);

}  // namespace fs_mgr
}  // namespace android

#endif  // LIBLP_UTILITY_H
