#include <stdio.h>
#include <sys/mman.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <inttypes.h>

#include "Elf.h"
#include "DwarfMemory.h"

template <typename AddressType>
int Process(Elf* elf, Memory* memory) {
  AddressType eh_frame_ptr_offset = elf->GetInterface()->eh_frame_offset();
  if (eh_frame_ptr_offset == 0) {
    printf("No dwarf information found\n");
    return 1;
  }

  DwarfMemory<AddressType> dwarf_memory(memory, eh_frame_ptr_offset);

  uint8_t version;
  if (!dwarf_memory.ReadBytes(&version, 1)) {
    printf("Failed to read version.\n");
    return 1;
  }
  printf("Version %d\n", version);

  uint8_t eh_frame_ptr_encoding;
  if (!dwarf_memory.ReadBytes(&eh_frame_ptr_encoding, 1)) {
    printf("Failed to read eh_frame_ptr_encoding.\n");
    return 1;
  }
  printf("eh_frame_ptr_encoding 0x%x\n", eh_frame_ptr_encoding);

  uint8_t fde_count_encoding;
  if (!dwarf_memory.ReadBytes(&fde_count_encoding, 1)) {
    printf("Failed to read fde_count_encoding.\n");
    return 1;
  }
  printf("fde_count_encoding 0x%x\n", fde_count_encoding);

  uint8_t table_encoding;
  if (!dwarf_memory.ReadBytes(&table_encoding, 1)) {
    printf("Failed to read table_encoding.\n");
    return 1;
  }
  printf("table_encoding 0x%x\n", table_encoding);

  AddressType eh_frame_ptr;
  if (!dwarf_memory.ReadEncodedValue(eh_frame_ptr_encoding, &eh_frame_ptr, dwarf_memory.cur_offset(), eh_frame_ptr_offset, 0xffffffff, 0xffffffff)) {
    printf("Reading encoded frame pointer failed.\n");
    return 1;
  }
  printf("eh_frame_ptr 0x%" PRIx64 "\n", static_cast<uint64_t>(eh_frame_ptr));

  AddressType fde_count;
  if (!dwarf_memory.ReadEncodedValue(fde_count_encoding, &fde_count, dwarf_memory.cur_offset(), eh_frame_ptr_offset, 0xffffffff, 0xfffffff)) {
    printf("Reading encoded fde_count failed.\n");
    return 1;
  }
  printf("fde_count %" PRId64 "\n\n", static_cast<uint64_t>(fde_count));

  // Read all of the entries.
  AddressType initial;
  AddressType address;
  for (size_t i = 0; i < fde_count; i++) {
    if (!dwarf_memory.ReadEncodedValue(table_encoding, &initial, dwarf_memory.cur_offset(), eh_frame_ptr_offset, 0xffffffff, 0xffffffff)) {
      printf("At %zu: failed to read initial\n", i);
      return false;
    }
    if (!dwarf_memory.ReadEncodedValue(table_encoding, &address, dwarf_memory.cur_offset(), eh_frame_ptr_offset, 0xffffffff, 0xffffffff)) {
      printf("At %zu: failed to read address\n", i);
      return false;
    }
    if (sizeof(AddressType) == 4) {
      printf("Initial: 0x%08" PRIx64 "\n", static_cast<uint64_t>(initial));
      printf("Address: 0x%08" PRIx64 "\n", static_cast<uint64_t>(address));
    } else {
      printf("Initial: 0x%016" PRIx64 "\n", static_cast<uint64_t>(initial));
      printf("Address: 0x%016" PRIx64 "\n", static_cast<uint64_t>(address));
    }
  }

  return 0;
}
int main(int argc, char** argv) {
  if (argc != 2) {
    printf("Need a parameter\n");
    return 1;
  }

  MemoryFileAtOffset memory;
  if (!memory.Init(argv[1], 0)) {
    // Initializatation failed.
    printf("Failed to init\n");
    return 1;
  }

  Elf elf(&memory);

  if (!elf.Init()) {
    printf("Failed to init the elf.\n");
    return 1;
  }

  if (!elf.valid()) {
    printf("elf is invalid.\n");
    return 1;
  }

  if (elf.GetType() == ELF_TYPE32) {
    return Process<uint32_t>(&elf, &memory);
  } else {
    return Process<uint64_t>(&elf, &memory);
  }
}
