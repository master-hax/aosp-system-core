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

#include <stdint.h>

#include <memory>
#include <string>

#include <android-base/logging.h>

#include <unwindstack/DexFileHooks.h>

namespace unwindstack {
namespace hooks {

// Default null implementation that trivially fails.

__attribute__((weak)) int64_t DexFileFromMemory(const DexFileImpl**, const uint8_t*, size_t) {
  return -1;
}

__attribute__((weak)) bool DexFileFromFile(const DexFileImpl**, uint64_t, const std::string&) {
  return false;
}

__attribute__((weak)) bool GetMethodInformation(const DexFileImpl*, uint64_t, std::string*,
                                                uint64_t*, uint64_t*) {
  return false;
}

__attribute__((weak)) void FreeDexFile(const DexFileImpl*) {}

}  // namespace hooks
}  // namespace unwindstack
