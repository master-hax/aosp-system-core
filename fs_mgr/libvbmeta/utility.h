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

#ifndef LIBVBMETA_UTILITY_H
#define LIBVBMETA_UTILITY_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#include <android-base/logging.h>
#include <android-base/unique_fd.h>

#define VBMETA_TAG "[libvbmeta]"
#define LWARN LOG(WARNING) << VBMETA_TAG
#define LINFO LOG(INFO) << VBMETA_TAG
#define LERROR LOG(ERROR) << VBMETA_TAG
#define PWARNING PLOG(WARNING) << VBMETA_TAG
#define PERROR PLOG(ERROR) << VBMETA_TAG

namespace android {
namespace fs_mgr {} // namespace fs_mgr
} // namespace android

#endif // LIBVBMETA_UTILITY_H
