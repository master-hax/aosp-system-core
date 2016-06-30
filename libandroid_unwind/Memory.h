/*
 * Copyright (C) 2016 The Android Open Source Project
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

#ifndef _LIBANDROID_UNWIND_MEMORY_H
#define _LIBANDROID_UNWIND_MEMORY_H

#include <stdint.h>

class Memory {
 public:
  Memory() = default;
  virtual ~Memory() = default;

  virtual bool Read32(uint64_t addr, uint32_t* data) = 0;
  virtual bool Read64(uint64_t addr, uint64_t* data) = 0;
  virtual bool Read(uint64_t addr, uint8_t* buffer, size_t size) = 0;
};

#endif  // _LIBANDROID_UNWIND_MEMORY_H
