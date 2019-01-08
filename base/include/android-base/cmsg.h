/*
 * Copyright (C) 2019 The Android Open Source Project
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

#pragma once

#include <sys/stat.h>
#include <sys/types.h>

#include <type_traits>
#include <vector>

#include <android-base/macros.h>
#include <android-base/unique_fd.h>

namespace android {
namespace base {

#if !defined(_WIN32)

template <typename CollectionType, typename T>
void Append(CollectionType& collection, T&& arg) {
  collection.emplace_back(std::forward<T>(arg));
}

template <typename CollectionType, typename T, typename... Args>
void Append(CollectionType& collection, T&& arg, Args&&... args) {
  collection.emplace_back(std::forward<T>(arg));
  return Append(collection, std::forward<Args>(args)...);
}

ssize_t SendFileDescriptors(int sock, const void* data, size_t data_len,
                            std::vector<android::base::unique_fd> fds);
ssize_t ReceiveFileDescriptors(int sock, void* data, size_t data_len,
                               std::vector<android::base::unique_fd*>* fds);

template <typename... Args>
ssize_t SendFileDescriptors(int sock, const void* data, size_t data_len, Args&&... sent_fds) {
  std::vector<unique_fd> fds;
  Append(fds, std::forward<Args>(sent_fds)...);
  return SendFileDescriptors(sock, data, data_len, std::move(fds));
}

template <typename... Args>
ssize_t ReceiveFileDescriptors(int sock, void* data, size_t data_len, Args&&... received_fds) {
  std::vector<unique_fd*> fds;
  Append(fds, std::forward<Args>(received_fds)...);
  return ReceiveFileDescriptors(sock, data, data_len, &fds);
}

#endif

}  // namespace base
}  // namespace android
