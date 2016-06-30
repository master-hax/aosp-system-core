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

#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include "Elf.h"
#include "ElfInterface.h"
#include "ElfInterfaceArm.h"
#include "Dwarf.h"
#include "DwarfStructs.h"
#include "ArmExidx.h"

void DumpArm(Elf* elf) {
  ElfInterfaceArm* interface = reinterpret_cast<ElfInterfaceArm*>(elf->GetInterface());
  if (interface == nullptr) {
    printf("No ARM Unwind Information.\n\n");
    return;
  }

  printf("ARM Unwind Information:\n");
  for (const auto& entry : interface->pt_loads()) {
    uint64_t load_bias = entry.second.table_offset;
    printf(" PC Range 0x%" PRIx64 " - 0x%" PRIx64 "\n", entry.second.offset + load_bias,
           entry.second.table_size + load_bias);
    for (auto addr : *interface) {
      printf("  PC 0x%" PRIx64 "\n", addr + load_bias);
      uint64_t entry;
      if (!interface->FindEntry(addr, &entry)) {
        printf("    Cannot find entry for address.\n");
        continue;
      }
      printf("     Entry %" PRIx64 "\n", entry);
      ArmExidx arm(nullptr, elf->memory(), nullptr);
      if (!arm.ExtractEntry(entry)) {
        if (arm.status() != ARM_STATUS_NO_UNWIND) {
          printf("    Error trying to extract data.\n");
        }
        continue;
      }
      // Dump the raw data bytes.
      if (arm.data()->size() > 0) {
        size_t total  = 0;
        for (const uint8_t data : *arm.data()) {
          if ((total++ % 10) == 0) {
            if (total != 1) {
              printf("\n");
            }
            printf("    Raw Data:");
          }
          printf(" 0x%02x", data);
        }
        printf("\n");
        if (!arm.Eval()) {
          printf("      Error trying to evaluate dwarf data.\n");
        }
      }
    }
  }
  printf("\n");
}

template <typename AddressType>
void DumpEhFrame(Elf* elf) {
  ElfInterfaceBase* elf_interface = elf->GetInterface();
  if (elf_interface->GetDwarfEhFrame() == nullptr) {
    printf("No eh frame found\n");
    return;
  }

  printf("eh frame information:\n");

  uint64_t load_bias;
  for (const auto& entry : elf_interface->pt_loads()) {
    load_bias = entry.second.table_offset;
  }
  DwarfEhFrame<AddressType>* eh_frame = reinterpret_cast<DwarfEhFrame<AddressType>*>(elf_interface->GetDwarfEhFrame());
  for (auto info : *eh_frame) {
    DwarfCIE cie;
    DwarfFDE fde;
    if (!eh_frame->GetEntryData(info.offset, &cie, &fde)) {
      printf("Error trying to read data for entry at 0x%" PRIx64 "\n", info.offset);
      return;
    }
    printf("  PC 0x%" PRIx64 "\n", info.pc + load_bias);
    if (!eh_frame->GetCfaLocationInfo(fde.start_pc + fde.pc_length - 1, &cie, &fde, nullptr)) {
      printf("Failed to process cfa information for entry at 0x%" PRIx64 "\n", info.offset);
    }
  }
}

int main(int argc, char** argv) {
  if (argc != 2) {
    printf("Need to pass the name of an elf to the program.\n");
    return 1;
  }

  struct stat st;
  if (stat(argv[1], &st) == -1) {
    printf("Cannot stat %s: %s\n", argv[1], strerror(errno));
    return 1;
  }
  if (!S_ISREG(st.st_mode)) {
    printf("%s is not a regular file.\n", argv[1]);
    return 1;
  }
  if (S_ISDIR(st.st_mode)) {
    printf("%s is a directory.\n", argv[1]);
    return 1;
  }

  MemoryFileAtOffset* memory = new MemoryFileAtOffset;
  if (!memory->Init(argv[1], 0)) {
    // Initializatation failed.
    printf("Failed to init\n");
    return 1;
  }

  g_LoggingIndentLevel = 2;

  Elf elf(memory);
  if (!elf.Init() || !elf.valid()) {
    printf("%s is not a valid elf file.\n", argv[1]);
    return 1;
  }

  switch (elf.machine_type()) {
  case EM_ARM:
    DumpArm(&elf);
  case EM_386:
    DumpEhFrame<uint32_t>(&elf);
    break;
  case EM_AARCH64:
  case EM_X86_64:
    DumpEhFrame<uint64_t>(&elf);
    break;
  }
  return 0;
}
