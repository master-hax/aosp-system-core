/*
 * Copyright 2020 The Android Open Source Project
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

#ifndef _LIBUNWINDSTACK_UNWINDCOMPONENTCREATOR_H
#define _LIBUNWINDSTACK_UNWINDCOMPONENTCREATOR_H
#include <fuzzer/FuzzedDataProvider.h>
#include <unwindstack/DexFiles.h>
#include <unwindstack/Maps.h>
#include <unwindstack/Regs.h>
#include <unwindstack/RegsArm.h>
#include <unwindstack/RegsArm64.h>
#include <unwindstack/RegsMips.h>
#include <unwindstack/RegsMips64.h>
#include <unwindstack/RegsX86.h>
#include <unwindstack/RegsX86_64.h>
#include <memory>

static constexpr uint8_t kArchCount = 6;
std::unique_ptr<unwindstack::Regs> GetRegisters(unwindstack::ArchEnum arch);
std::unique_ptr<unwindstack::Maps> GetMaps(const char* buffer);
std::unique_ptr<unwindstack::DexFiles> GetDexFiles(FuzzedDataProvider* dataProvider,
                                                   std::shared_ptr<unwindstack::Memory> memory,
                                                   uint maxLibraries, uint maxLibLength);
#endif  // _LIBUNWINDSTACK_UNWINDCOMPONENTCREATOR_H
