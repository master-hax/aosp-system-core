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

#ifndef LIBVBMETA_READER_H_
#define LIBVBMETA_READER_H_

#include <stddef.h>

#include <memory>

#include "footer_format.h"

namespace android {
namespace fs_mgr {

bool ParseSuperAvbFooter(const void *buffer, SuperAVBFooter *footer);
bool ReadSuperAvbFooter(int fd, uint64_t offset, SuperAVBFooter *footer);
bool ParseSuperFooter(const void *buffer, SuperFooter *footer);
bool ReadSuperFooter(int fd, uint64_t super_size, SuperFooter *footer);
uint8_t ReadDataFromSuper(int fd, uint64_t offset);

} // namespace fs_mgr
} // namespace android

#endif /* LIBVBMETA_READER_H_ */
