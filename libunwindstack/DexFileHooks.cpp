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
namespace {

// Default null implementation that trivially fails.

int64_t DexFileFromMemory(DexFileImpl**, const uint8_t*, size_t) {
  return -1;
}

bool DexFileFromFile(DexFileImpl**, uint64_t, const char*) {
  return false;
}

bool GetMethodInformation(DexFileImpl*, uint64_t, const char**, uint64_t*) {
  return false;
}

void FreeDexFile(DexFileImpl*) {}

DexFileHooks g_dex_file_hooks = {
    DexFileFromMemory,
    DexFileFromFile,
    GetMethodInformation,
    FreeDexFile,
};

}  // namespace

void SetDexFileHooks(const DexFileHooks* dex_file_hooks) {
  // The null implementation is safe to replace because it doesn't allocate any
  // DexFileImpl objects.
  CHECK_EQ(g_dex_file_hooks.DexFileFromMemory, DexFileFromMemory);
  CHECK_EQ(g_dex_file_hooks.DexFileFromFile, DexFileFromFile);
  CHECK_EQ(g_dex_file_hooks.GetMethodInformation, GetMethodInformation);
  CHECK_EQ(g_dex_file_hooks.FreeDexFile, FreeDexFile);
  g_dex_file_hooks = *dex_file_hooks;
}

const DexFileHooks* GetDexFileHooks() {
  return &g_dex_file_hooks;
}

}  // namespace unwindstack
