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

#ifndef ANDROID_ELF_READER_H
#define ANDROID_ELF_READER_H

#include <stdio.h>

#include <map>
#include <memory>
#include <string>
#include <vector>

#include <android-base/macros.h>
#include <android-base/stringprintf.h>

#include <elf_reader/elf.h>

namespace android {
namespace libelf_reader {

struct ElfTypes32 {
  using Ehdr = Elf32_Ehdr;
  using Shdr = Elf32_Shdr;
  using Phdr = Elf32_Phdr;
  using Sym = Elf32_Sym;
};

struct ElfTypes64 {
  using Ehdr = Elf64_Ehdr;
  using Shdr = Elf64_Shdr;
  using Phdr = Elf64_Phdr;
  using Sym = Elf64_Sym;
};

struct SectionData {
  const char* data;
  size_t size;
  bool own_data;

  SectionData() : data(nullptr), size(0), own_data(false) {}

  SectionData(const char* data, size_t size, bool own_data)
    : data(data), size(size), own_data(own_data) {}

  SectionData(SectionData&& other) {
    *this = std::move(other);
  }

  void operator=(SectionData&& other) {
    data = other.data;
    size = other.size;
    own_data = other.own_data;
    other.data = nullptr;
    other.size = 0;
    other.own_data = false;
  }

  ~SectionData() {
    if (own_data && data != nullptr) {
      delete[] data;
    }
  }

  bool Valid() const {
    return data != nullptr;
  }

  DISALLOW_COPY_AND_ASSIGN(SectionData);
};

template <typename ElfTypes>
class ElfReaderImpl {
 public:
  using Elf_Ehdr = typename ElfTypes::Ehdr;
  using Elf_Shdr = typename ElfTypes::Shdr;
  using Elf_Phdr = typename ElfTypes::Phdr;

  ElfReaderImpl(const char* filename, FILE* fp, size_t file_offset)
      : name_(filename), fp_(fp), file_offset_(file_offset),
        data_(nullptr), data_size_(0), read_flag_(0) {}

  ElfReaderImpl(const char* data, size_t size, const char* mem_name)
      : name_(mem_name), fp_(nullptr), file_offset_(0),
        data_(data), data_size_(size), read_flag_(0) {}

  ~ElfReaderImpl() {
    if (fp_ != nullptr) {
      fclose(fp_);
    }
  }

  bool Is64() {
    return sizeof(Elf_Ehdr) == sizeof(Elf64_Ehdr);
  }

  Elf_Ehdr* ReadHeader() {
    if (read_flag_ & READ_HEADER) {
      return &header_;
    }
    if (!ReadAtOffset(&header_, sizeof(header_), 0)) {
      return nullptr;
    }
    if (memcmp(header_.e_ident, ELFMAG, 4) != 0) {
      return nullptr;
    }
    if (header_.e_ident[EI_CLASS] == ELFCLASS32) {
      if (Is64()) {
        return nullptr;
      }
    } else if (header_.e_ident[EI_CLASS] == ELFCLASS64) {
      if (!Is64()) {
        return nullptr;
      }
    } else {
      return nullptr;
    }
    read_flag_ |= READ_HEADER;
    return &header_;
  }

  const std::vector<Elf_Shdr>* ReadSectionHeaders() {
    if (read_flag_ & READ_SECTION_HEADERS) {
      return &section_headers_;
    }
    Elf_Ehdr* header = ReadHeader();
    if (header == nullptr) {
      return nullptr;
    }
    if (header->e_shentsize != sizeof(Elf_Shdr)) {
      return nullptr;
    }
    section_headers_.resize(header->e_shnum);
    if (!ReadAtOffset(section_headers_.data(),
                      sizeof(Elf_Shdr) * section_headers_.size(), header->e_shoff)) {
      return nullptr;
    }
    read_flag_ |= READ_SECTION_HEADERS;
    return &section_headers_;
  }

  const std::vector<Elf_Phdr>* ReadProgramHeaders() {
    if (read_flag_ & READ_PROGRAM_HEADERS) {
      return &program_headers_;
    }
    Elf_Ehdr* header = ReadHeader();
    if (header == nullptr) {
      return nullptr;
    }
    if (header->e_phentsize != sizeof(Elf_Phdr)) {
      return nullptr;
    }
    program_headers_.resize(header->e_phnum);
    if (!ReadAtOffset(program_headers_.data(),
                      sizeof(Elf_Phdr) * program_headers_.size(), header->e_phoff)) {
      return nullptr;
    }
    read_flag_ |= READ_PROGRAM_HEADERS;
    return &program_headers_;
  }

  const char* GetSectionName(const Elf_Shdr& sec_header) {
    if (!(read_flag_ & READ_SECTION_NAMES)) {
      Elf_Ehdr* header = ReadHeader();
      const std::vector<Elf_Shdr>* sec_headers = ReadSectionHeaders();
      if (header == nullptr || sec_headers == nullptr) {
        return "";
      }
      if (header->e_shstrndx == SHN_UNDEF || header->e_shstrndx >= sec_headers->size()) {
        return "";
      }
      const Elf_Shdr& strsec = (*sec_headers)[header->e_shstrndx];
      section_name_data_.resize(strsec.sh_size);
      if (!ReadAtOffset(section_name_data_.data(), section_name_data_.size(), strsec.sh_offset)) {
        return "";
      }
      read_flag_ |= READ_SECTION_NAMES;
    }
    if (sec_header.sh_name < section_name_data_.size()) {
      return &section_name_data_[sec_header.sh_name];
    }
    return "";
  }

  // Read section data for the section specified by the section header.
  SectionData ReadSectionData(const Elf_Shdr& sec_header) {
    if (fp_ != nullptr) {
      char* data = new char[sec_header.sh_size];
      if (!ReadAtOffset(data, sec_header.sh_size, sec_header.sh_offset)) {
        delete[] data;
        return SectionData(nullptr, 0, false);
      }
      return SectionData(data, sec_header.sh_size, true);
    } else {
      if (sec_header.sh_offset >= data_size_ ||
          sec_header.sh_offset + sec_header.sh_size > data_size_) {
        return SectionData(nullptr, 0, false);
      }
      return SectionData(data_ + sec_header.sh_offset, sec_header.sh_size, false);
    }
  }

  // Read section data into the given buffer.
  bool ReadSectionData(const Elf_Shdr& sec_header, void* buf, size_t buf_size) {
    if (buf_size < sec_header.sh_size) {
      return false;
    }
    if (fp_ != nullptr) {
      if (!ReadAtOffset(buf, sec_header.sh_size, sec_header.sh_offset)) {
        return false;
      }
    } else {
      if (sec_header.sh_offset >= data_size_ ||
          sec_header.sh_offset + sec_header.sh_size > data_size_) {
        return false;
      }
      memcpy(buf, data_ + sec_header.sh_offset, sec_header.sh_size);
    }
    return true;
  }

  // Read section data into the given collection.
  template <typename Collection>
  bool ReadSectionData(const Elf_Shdr& sec_header, Collection* buf) {
    static_assert(sizeof(typename Collection::value_type) == 1, "wrong collection");
    buf->resize(sec_header.sh_size);
    return ReadSectionData(sec_header, &(*buf)[0], sec_header.sh_size);
  }

  // Find section header with section name.
  const Elf_Shdr* FindSection(const char* sec_name) {
    const std::vector<Elf_Shdr>* sec_headers = ReadSectionHeaders();
    if (sec_headers != nullptr) {
      for (const auto& sec : *sec_headers) {
        if (strcmp(GetSectionName(sec), sec_name) == 0) {
          return &sec;
        }
      }
    }
    return nullptr;
  }

  // Read section data for the section specified by the section name.
  SectionData ReadSectionData(const char* sec_name) {
    const Elf_Shdr* sec = FindSection(sec_name);
    if (sec != nullptr) {
      return ReadSectionData(*sec);
    }
    return SectionData(nullptr, 0, false);
  }

  // Read section data to the specified buffer.
  template <typename Collection>
  bool ReadSectionData(const char* sec_name, Collection* buf) {
    const Elf_Shdr* sec = FindSection(sec_name);
    if (sec != nullptr) {
      return ReadSectionData(*sec, buf);
    }
    return false;
  }

  bool GetMinExecutableVaddr(uint64_t* min_vaddr) {
    const std::vector<Elf_Phdr>* program_headers = ReadProgramHeaders();
    if (program_headers == nullptr) {
      return false;
    }
    *min_vaddr = UINT64_MAX;
    for (auto& header : *program_headers) {
      if ((header.p_type == PT_LOAD && (header.p_flags & PF_X))) {
        if (header.p_vaddr < *min_vaddr) {
          *min_vaddr = header.p_vaddr;
        }
      }
    }
    return (*min_vaddr != UINT64_MAX);
  }

 private:
  bool ReadAtOffset(void* buf, size_t size, size_t offset) {
    if (fp_ != nullptr) {
      if (fseek(fp_, file_offset_ + offset, SEEK_SET) != 0) {
        return false;
      }
      if (fread(buf, size, 1, fp_) != 1) {
        return false;
      }
    } else {
      if (offset >= data_size_ || offset + size > data_size_) {
        return false;
      }
      memcpy(buf, data_ + offset, size);
    }
    return true;
  }

  const std::string name_;
  FILE* fp_;
  size_t file_offset_;
  const char* data_;
  size_t data_size_;

  // Indicate which parts have been read.
  static const int READ_HEADER = 1;
  static const int READ_PROGRAM_HEADERS = 2;
  static const int READ_SECTION_HEADERS = 4;
  static const int READ_SECTION_NAMES = 8;
  int read_flag_;

  Elf_Ehdr header_;
  std::vector<Elf_Shdr> section_headers_;
  std::vector<Elf_Phdr> program_headers_;
  std::vector<char> section_name_data_;


  DISALLOW_COPY_AND_ASSIGN(ElfReaderImpl);
};

typedef ElfReaderImpl<ElfTypes32> ElfReader32;
typedef ElfReaderImpl<ElfTypes64> ElfReader64;

// ElfReader can open both 32-bit and 64-bit elf files. It exports some
// general operations like reading sections in elf file.
class ElfReader {
 public:
  static std::unique_ptr<ElfReader> OpenFile(const char* filename, size_t file_offset,
                                             std::string* error_msg);

  static std::unique_ptr<ElfReader> OpenMem(const char* data, size_t size,
                                            const char* mem_name, std::string* error_msg);

  virtual ~ElfReader() {}

  ElfReader(ElfReader32* elf32) : elf32_(elf32), elf64_(nullptr) {}
  ElfReader(ElfReader64* elf64) : elf32_(nullptr), elf64_(elf64) {}

  ElfReader32* GetImpl32() {
    return elf32_.get();
  }

  ElfReader64* GetImpl64() {
    return elf64_.get();
  }

  bool GetMinExecutableVaddr(uint64_t* min_vaddr) {
    if (GetImpl32()) {
      return GetImpl32()->GetMinExecutableVaddr(min_vaddr);
    }
    if (GetImpl64()) {
      return GetImpl64()->GetMinExecutableVaddr(min_vaddr);
    }
    return false;
  }

  SectionData ReadSectionData(const char* sec_name) {
    if (GetImpl32()) {
      return GetImpl32()->ReadSectionData(sec_name);
    }
    if (GetImpl64()) {
      return GetImpl64()->ReadSectionData(sec_name);
    }
    return SectionData();
  }

  template <typename Collection>
  bool ReadSectionData(const char* sec_name, Collection* buf) {
    if (GetImpl32()) {
      return GetImpl32()->ReadSectionData(sec_name, buf);
    }
    if (GetImpl64()) {
      return GetImpl64()->ReadSectionData(sec_name, buf);
    }
    return false;
  }

 private:
  std::unique_ptr<ElfReader32> elf32_;
  std::unique_ptr<ElfReader64> elf64_;

  DISALLOW_COPY_AND_ASSIGN(ElfReader);
};

}  // namespace libelf_reader
}  // namespace android

#endif  // ANDROID_ELF_READER_H_
