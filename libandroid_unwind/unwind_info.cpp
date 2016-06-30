#include <elf.h>
#include <stdio.h>
#include <sys/mman.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <inttypes.h>

#include <vector>
#include <unordered_map>

#include "Elf.h"
#include "ElfInterface.h"
#include "ElfArmInterface.h"
#include "DwarfMemory.h"
#include "Dwarf.h"
#include "ArmUnwind.h"

void DumpArm(Elf* elf, Memory* memory) {
  ElfInterface32* elf_interface = reinterpret_cast<ElfInterface32*>(elf->GetInterface());

  ElfArmInterface* arm = elf_interface->arm();
  if (arm == nullptr) {
    printf("No ARM Unwind Information.\n");
    return;
  }

  g_LoggingIndentLevel = 2;
  printf("ARM Unwind Information:\n");
  for (const auto& entry : elf_interface->pt_loads()) {
    printf("  offset 0x%x\n", static_cast<uint32_t>(entry.second.offset));
    printf("  table_offset 0x%x\n", static_cast<uint32_t>(entry.second.table_offset));
    printf("  table_size %zu\n", entry.second.table_size);
    for (auto addr : *arm) {
      printf("  IP 0x%x\n", addr);
      uint64_t entry;
      if (!arm->FindEntry(addr, &entry)) {
        printf("    Unable to find entry data.\n");
        continue;
      }
      ArmUnwind arm(memory);
      if (!arm.ExtractEntry(entry)) {
        printf("     Unable to extract data.\n");
        continue;
      }
      while (arm.Decode());
    }
  }
}

template <typename AddressType>
int Process(Elf* elf, Memory* memory) {
  if (elf->GetMachineType() == EM_ARM) {
    DumpArm(elf, memory);
  }

  g_LoggingIndentLevel = 3;
  AddressType eh_frame_ptr_offset = elf->GetInterface()->eh_frame_offset();
  if (eh_frame_ptr_offset == 0) {
    printf("eh_frame not found\n");
    return 1;
  }
  AddressType eh_frame_ptr_size = elf->GetInterface()->eh_frame_size();
  if (eh_frame_ptr_size == 0) {
    printf("eh_frame zero sized\n");
    return 1;
  }
  DwarfMemory<AddressType> dwarf_memory(memory, eh_frame_ptr_offset, eh_frame_ptr_size);
  Dwarf<AddressType> dwarf(&dwarf_memory, nullptr);

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

  uint64_t eh_frame_ptr;
  if (!dwarf_memory.ReadEncodedValue(eh_frame_ptr_encoding, &eh_frame_ptr, dwarf_memory.cur_offset(), eh_frame_ptr_offset, 0xffffffff, 0xffffffff)) {
    printf("Reading encoded frame pointer failed.\n");
    return 1;
  }
  printf("eh_frame_ptr 0x%" PRIx64 "\n", static_cast<uint64_t>(eh_frame_ptr));

  uint64_t fde_count;
  if (!dwarf_memory.ReadEncodedValue(fde_count_encoding, &fde_count, dwarf_memory.cur_offset(), eh_frame_ptr_offset, 0xffffffff, 0xfffffff)) {
    printf("Reading encoded fde_count failed.\n");
    return 1;
  }
  printf("fde_count %" PRId64 "\n\n", static_cast<uint64_t>(fde_count));

  // Read all of the entries.
  uint64_t initial;
  uint64_t address;
  for (size_t i = 0; i < fde_count; i++) {
    if (!dwarf_memory.ReadEncodedValue(table_encoding, &initial, dwarf_memory.cur_offset(), eh_frame_ptr_offset, static_cast<uint64_t>(-1), static_cast<uint64_t>(-1))) {
      printf("At %zu: failed to read initial\n", i);
      return false;
    }
    if (!dwarf_memory.ReadEncodedValue(table_encoding, &address, dwarf_memory.cur_offset(), eh_frame_ptr_offset, static_cast<uint64_t>(-1), static_cast<uint64_t>(-1))) {
      printf("At %zu: failed to read address\n", i);
      return false;
    }
    if (sizeof(AddressType) == 4) {
      printf("Initial: 0x%08" PRIx64 "\n", initial);
      printf("Address: 0x%08" PRIx64 "\n", address);
    } else {
      printf("Initial: 0x%016" PRIx64 "\n", initial);
      printf("Address: 0x%016" PRIx64 "\n", address);
    }

    uint64_t offset = dwarf_memory.cur_offset();
    DwarfFDE fde_entry;
    DwarfCIE cie_entry;
    if (!dwarf.GetEntryData(address, &fde_entry, &cie_entry)) {
      printf("Failed to read CIE/FDE information\n");
      return false;
    }
    printf("  CIE:\n");
    printf("    version %d\n", cie_entry.version);
    printf("    segment_size %d\n", cie_entry.segment_size);
    printf("    augmentation_string %s\n", cie_entry.augmentation_string.data());
    printf("    code_alignment_factor 0x%" PRIx64 "\n", cie_entry.code_alignment_factor);
    printf("    data_alignment_factor 0x%" PRIx64 "\n", cie_entry.data_alignment_factor);
    printf("    return_address_register %" PRId64 "\n", cie_entry.return_address_register);
    printf("    fde_address_encoding 0x%x\n", cie_entry.fde_address_encoding);
    printf("    lsda_encoding 0x%x\n", cie_entry.lsda_encoding);
    printf("    personality_handler 0x%" PRIx64 "\n", cie_entry.personality_handler);
    printf("    cfa_instructions_offset 0x%" PRIx64 "\n", cie_entry.cfa_instructions_offset);
    printf("    cfa_instructions_end 0x%" PRIx64 "\n", cie_entry.cfa_instructions_end);
    // Evaluate the cfa data.
    if (!dwarf.EvalCfa(cie_entry.cfa_instructions_offset, cie_entry.cfa_instructions_end)) {
      printf("      Failed to eval cie cfa data.\n");
    }

    printf("  FDE:\n");
    printf("    cie_offset 0x%" PRIx64 "\n", fde_entry.cie_offset);
    printf("    cfa_instructions_offset 0x%" PRIx64 "\n", fde_entry.cfa_instructions_offset);
    printf("    cfa_instructions_end 0x%" PRIx64 "\n", fde_entry.cfa_instructions_end);
    printf("    start_ip 0x%" PRIx64 "\n", fde_entry.start_ip);
    printf("    ip_length 0x%" PRIx64 "\n", fde_entry.ip_length);
    printf("    lsda_address 0x%" PRIx64 "\n", fde_entry.lsda_address);
    if (!dwarf.EvalCfa(fde_entry.cfa_instructions_offset, fde_entry.cfa_instructions_end)) {
      printf("      Failed to eval fde cfa data.\n");
    }
    dwarf_memory.set_cur_offset(offset);
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
