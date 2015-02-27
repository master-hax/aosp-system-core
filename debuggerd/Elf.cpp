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

#define LOG_TAG "DEBUG"

#include <elf.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <string>

#include <backtrace/Backtrace.h>
#include <log/log.h>
#include <utils/stringprintf.h>

#include "Elf.h"

#if !defined(NT_GNU_BUILD_ID)
#define NT_GNU_BUILD_ID 3
#endif

bool Elf::Read(uintptr_t rel_addr, uint8_t* buffer, size_t bytes) {
  word_t data_word;

  uintptr_t addr = base_addr_ + rel_addr;
  size_t align_bytes = addr & (sizeof(word_t) - 1);
  if (align_bytes != 0) {
    if (!backtrace_->ReadWord(addr & ~(sizeof(word_t)-1), &data_word)) {
      return false;
    }
    align_bytes = sizeof(word_t) - align_bytes;
    memcpy(buffer, reinterpret_cast<uint8_t*>(&data_word) + align_bytes, align_bytes);
    addr += align_bytes;
    buffer += align_bytes;
    bytes -= align_bytes;
  }

  size_t num_words = bytes / sizeof(word_t);
  for (size_t i = 0; i < num_words; i++) {
    if (!backtrace_->ReadWord(addr, &data_word)) {
      return false;
    }
    memcpy(buffer, &data_word, sizeof(word_t));
    buffer += sizeof(word_t);
    addr += sizeof(word_t);
  }

  size_t left_over = bytes & (sizeof(word_t) - 1);
  if (left_over) {
    if (!backtrace_->ReadWord(addr, &data_word)) {
      return false;
    }
    memcpy(buffer, &data_word, left_over);
  }
  return true;
}

template <typename HdrType, typename PhdrType, typename NhdrType>
ElfT<HdrType, PhdrType, NhdrType>::ElfT(const Elf& elf, uint8_t* hdr) : Elf(elf) {
  memcpy(&hdr_.e_ident[0], hdr, EI_NIDENT);
}

template <typename HdrType, typename PhdrType, typename NhdrType>
bool ElfT<HdrType, PhdrType, NhdrType>::GetBuildId(std::string* build_id) {
  // First read the rest of the header.
  if (!Read(EI_NIDENT, reinterpret_cast<uint8_t*>(&hdr_) + EI_NIDENT,
            sizeof(HdrType) - EI_NIDENT)) {
    return false;
  }

  for (size_t i = 0; i < hdr_.e_phnum; i++) {
    PhdrType phdr;
    if (!Read(hdr_.e_phoff + i * hdr_.e_phentsize,
              reinterpret_cast<uint8_t*>(&phdr), sizeof(phdr))) {
      return false;
    }
    // Looking for the .note.gnu.build-id note.
    if (phdr.p_type == PT_NOTE) {
      uintptr_t hdr_size = phdr.p_filesz;
      uintptr_t addr = phdr.p_offset;
      while (hdr_size >= sizeof(NhdrType)) {
        NhdrType nhdr;
        if (!Read(addr, reinterpret_cast<uint8_t*>(&nhdr), sizeof(nhdr))) {
          return false;
        }
        addr += sizeof(nhdr);
        if (nhdr.n_type == NT_GNU_BUILD_ID) {
          // Skip the name (which is the owner and should be "GNU").
          addr += nhdr.n_namesz;
          uint8_t build_id_data[128];
          if (nhdr.n_namesz > sizeof(build_id_data)) {
            ALOGE("Possible corrupted note name size, value is too large: %u",
                  nhdr.n_namesz);
            return false;
          }
          if (!Read(addr, build_id_data, nhdr.n_descsz)) {
            return false;
          }

          build_id->clear();
          for (size_t bytes = 0; bytes < nhdr.n_descsz; bytes++) {
            *build_id += android::StringPrintf("%02x", build_id_data[bytes]);
          }

          return true;
        } else {
          // Move past the extra note data.
          hdr_size -= sizeof(nhdr);
          uintptr_t skip_bytes = nhdr.n_namesz + nhdr.n_descsz;
          addr += skip_bytes;
          if (hdr_size < skip_bytes) {
            break;
          }
          hdr_size -= skip_bytes;
        }
      }
    }
  }
  return false;
}

bool ElfGetBuildId(Backtrace* backtrace, uintptr_t base_addr, std::string* build_id) {
  Elf elf(backtrace, base_addr);

  // Read and verify the elf magic number first.
  uint8_t hdr[EI_NIDENT];
  if (!elf.Read(0, hdr, SELFMAG)) {
    return false;
  }

  if (memcmp(hdr, ELFMAG, SELFMAG) != 0) {
    return false;
  }

  // Read the rest of EI_NIDENT.
  if (!elf.Read(SELFMAG, hdr + SELFMAG, EI_NIDENT - SELFMAG)) {
    return false;
  }

  if (hdr[EI_CLASS] == ELFCLASS32) {
    return ElfT<Elf32_Ehdr, Elf32_Phdr, Elf32_Nhdr>(elf, hdr).GetBuildId(build_id);
  }
#if defined(__LP64__)
  else if (hdr[EI_CLASS] == ELFCLASS64) {
    return ElfT<Elf64_Ehdr, Elf64_Phdr, Elf64_Nhdr>(elf, hdr).GetBuildId(build_id);
  }
#endif

  return false;
}
