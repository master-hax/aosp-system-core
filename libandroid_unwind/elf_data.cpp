Elf64

Elf32


template<type Elf_Phdr, Elf_Ehdr, Elf_Addr> class Elf {
 public:
  Elf(const Memory* memory) : memory_(memory) {}

 private:
  Memory* memory_;
};

class HeaderLoad {
 public:
 private:
};

class HeaderArmExidx {
 public:
 private:
};

class HeaderGnuEhFrame {
 public:
 private:
};

enum {
  ELF_PROGRAM_HEADER_LOAD = 1,
  ELF_PROGRAM_HEADER_DYNAMIC = 2,
  ELF_PROGRAM_HEADER_GNU_EH_FRAME = 0x6474e550,
  ELF_PROGRAM_HEADER_ARM_EXIDX = 0x70000001,
};

bool ProcessProgramHeaders() {
  ElfEhdr ehdr;
  GET_EHDR_FIELD(ei, &ehdr, e_phoff);
  GET_EHDR_FIELD(ei, &ehdr, e_phnum);

  ElfOffset offset = ehdr.e_phoff;
  ElfOff

  for (size_t i = 0; i < ehdr.e_phnum; i++) {
    ElfPhdr phdr;
    GET_PHDR_FIELD(ei, offset, &phdr, p_type);
    switch (phdr.p_type) {
    case PT_LOAD:
      GET_PHDR_FIELD(ei, offset, &phdr, p_vaddr);

      GET_PHDR_FIELD(ei, offset, &phdr, p_offset);
      if (phdr.p_offset == mapoff) {
      }
      break;

    case PT_ARM_EXIDX:
      break;
    }
  }
}

bool ProcessSectionHeaders(bool ignore_compressed) {
  for (size_t i = 1; i < ehdr.e_shnum; i++) {
    if (strcmp(".debug_frame") == 0) {
    } else (strcmp(".gnu_debuglink") == 0) {
    } else (strcmp(".gnu_debugdata") == 0) {
    }
  }
}
