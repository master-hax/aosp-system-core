/*
 * Copyright (C) 2015 The Android Open Source Project
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

#ifndef _DEBUGGERD_ELF_H
#define _DEBUGGERD_ELF_H

#include <stdint.h>
#include <string>

class Backtrace;

class Elf {
public:
  Elf(Backtrace* backtrace, uintptr_t base_addr) : backtrace_(backtrace), base_addr_(base_addr) {}
  Elf(const Elf& elf) : backtrace_(elf.backtrace_), base_addr_(elf.base_addr_) {}
  virtual ~Elf() {}

  bool Read(uintptr_t, unsigned char*, size_t);

  virtual bool GetBuildId(std::string*) { return false; }

protected:
  Backtrace* backtrace_;
  uintptr_t base_addr_;
};

template <typename HdrType, typename PhdrType, typename NhdrType>
class ElfT : public Elf {
public:
  ElfT(const Elf&, uint8_t*);
  virtual ~ElfT() {}

  bool GetBuildId(std::string*) override;

private:
  HdrType hdr_;
};

bool ElfGetBuildId(Backtrace*, uintptr_t, std::string*);

#endif // _DEBUGGERD_ELF_H
