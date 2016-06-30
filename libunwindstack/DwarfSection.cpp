/*
 * Copyright (C) 2017 The Android Open Source Project
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

#include "DwarfCfa.h"
#include "DwarfError.h"
#include "DwarfLocation.h"
#include "DwarfMemory.h"
#include "DwarfOp.h"
#include "DwarfSection.h"
#include "DwarfStructs.h"
#include "Memory.h"
#include "Regs.h"

const DwarfFDE* DwarfSection::GetFDEFromPc(uint64_t pc) {
  uint64_t fde_offset;
  if (!GetFDEOffsetFromPc(pc, &fde_offset)) {
    return nullptr;
  }
  const DwarfFDE* fde = GetFDEFromOffset(fde_offset);
  // Guaranteed pc >= pc_start, need to check pc in the fde range.
  if (pc < fde->pc_end) {
    return fde;
  }
  return nullptr;
}

bool DwarfSection::Step(uint64_t pc, Regs* regs, Memory* process_memory) {
  const DwarfFDE* fde = GetFDEFromPc(pc);
  if (fde == nullptr || fde->cie == nullptr) {
    return false;
  }

  // Now get the location information for this pc.
  dwarf_loc_regs_t loc_regs;
  if (!GetCfaLocationInfo(pc, fde, &loc_regs)) {
    return false;
  }

  // Now eval the actual registers.
  return Eval(fde->cie, process_memory, loc_regs, regs);
}

template <typename AddressType>
bool DwarfSectionTmpl<AddressType>::EvalExpression(
    const DwarfLocation& loc, uint8_t version, Memory* regular_memory, AddressType* value) {
  DwarfOp<AddressType> op(&memory_, regular_memory);

  // Need to evaluate the op data.
  uint64_t start = loc.values[1];
  uint64_t end = start + loc.values[0];
  if (!op.Eval(start, end, version)) {
    return false;
  }
  if (op.StackSize() == 0) {
    return false;
  }
  // We don't support an expression that evaluates to a register number.
  if (op.is_register()) {
    return false;
  }
  *value = op.StackAt(0);
  return true;
}

template <typename AddressType>
bool DwarfSectionTmpl<AddressType>::Eval(
    const DwarfCIE* cie, Memory* regular_memory, const dwarf_loc_regs_t& loc_regs, Regs* regs) {
  RegsTmpl<AddressType>* cur_regs = reinterpret_cast<RegsTmpl<AddressType>*>(regs);

  if (cie->return_address_register >= cur_regs->total_regs()) {
    return false;
  }

  // Get the cfa value;
  auto cfa_entry = loc_regs.find(CFA_REG);
  if (cfa_entry == loc_regs.end()) {
    return false;
  }

  AddressType prev_pc = regs->pc();
  AddressType prev_cfa = regs->sp();

  AddressType cfa;
  const DwarfLocation* loc = &cfa_entry->second;
  // Only a few location types are valid for the cfa.
  switch (loc->type) {
  case DWARF_LOCATION_REGISTER:
    if (loc->values[0] >= cur_regs->total_regs()) {
      return false;
    }
    // If the stack pointer regiser is the CFA, and the stack
    // pointer register does not have any associated location
    // information, use the current cfa value.
    if (regs->sp_reg() == loc->values[0] && loc_regs.count(regs->sp_reg()) == 0) {
      cfa = prev_cfa;
    } else {
      cfa = (*cur_regs)[loc->values[0]];
    }
    cfa += loc->values[1];
    break;
  case DWARF_LOCATION_EXPRESSION:
  case DWARF_LOCATION_VAL_EXPRESSION:
  {
    AddressType value;
    if (!EvalExpression(*loc, cie->version, regular_memory, &value)) {
      return false;
    }
    if (loc->type == DWARF_LOCATION_EXPRESSION) {
      if (!regular_memory->Read(value, &cfa, sizeof(AddressType))) {
        return false;
      }
    } else {
      cfa = value;
    }
    break;
  }
  default:
    return false;
  }

  // This code does not guarantee to work properly in cases where a location
  // references a register, and that register is also set to a different
  // location. It might work depending on order, but this seems like
  // a very rare case, so it's not worth supporting.
  bool return_address_register_undefined = false;
  for (const auto& entry : loc_regs) {
    uint16_t reg = entry.first;
    // Already handled the CFA register.
    if (reg == CFA_REG) continue;

    if (reg >= cur_regs->total_regs()) {
      // Skip this unknown register.
      continue;
    }

    const DwarfLocation* loc = &entry.second;
    switch (loc->type) {
    case DWARF_LOCATION_OFFSET:
      if (!regular_memory->Read(cfa + loc->values[0], &(*cur_regs)[reg], sizeof(AddressType))) {
        return false;
      }
      break;
    case DWARF_LOCATION_VAL_OFFSET:
      (*cur_regs)[reg] = cfa + loc->values[0];
      break;
    case DWARF_LOCATION_REGISTER:
      if (loc->values[0] >= cur_regs->total_regs()) {
        return false;
      }
      (*cur_regs)[reg] = (*cur_regs)[loc->values[0]] + loc->values[1];
      break;
    case DWARF_LOCATION_EXPRESSION:
    case DWARF_LOCATION_VAL_EXPRESSION:
    {
      AddressType value;
      if (!EvalExpression(*loc, cie->version, regular_memory, &value)) {
        return false;
      }
      if (loc->type == DWARF_LOCATION_EXPRESSION) {
        if (!regular_memory->Read(value, &(*cur_regs)[reg], sizeof(AddressType))) {
          return false;
        }
      } else {
        (*cur_regs)[reg] = value;
      }
      break;
    }
    case DWARF_LOCATION_UNDEFINED:
      if (reg == cie->return_address_register) {
        return_address_register_undefined = true;
      }
    default:
      break;
    }
  }

  // Find the return address location.
  if (return_address_register_undefined) {
    cur_regs->set_pc(0);
  } else {
    cur_regs->set_pc((*cur_regs)[cie->return_address_register]);
  }
  cur_regs->set_sp(cfa);
  // Stop if the cfa and pc are the same.
  return prev_cfa != cfa || prev_pc != cur_regs->pc();
}

template <typename AddressType>
const DwarfCIE* DwarfSectionTmpl<AddressType>::GetCIE(uint64_t offset) {
  auto cie_entry = cie_entries_.find(offset);
  if (cie_entry != cie_entries_.end()) {
    return &cie_entry->second;
  }
  DwarfCIE* cie = &cie_entries_[offset];

  memory_.set_cur_offset(offset);
  uint32_t length32;
  if (!memory_.ReadBytes(&length32, sizeof(length32))) {
    return nullptr;
  }
  if (length32 == static_cast<uint32_t>(-1)) {
    // 64 bit CIE
    uint64_t length64;
    if (!memory_.ReadBytes(&length64, sizeof(length64))) {
      return nullptr;
    }

    cie->cfa_instructions_end = memory_.cur_offset() + length64;
    cie->fde_address_encoding = DW_EH_PE_sdata8;

    uint64_t cie_id;
    if (!memory_.ReadBytes(&cie_id, sizeof(cie_id))) {
      return nullptr;
    }
    if (!IsCIE64(cie_id)) {
      // This is not a CIE, something has gone horribly wrong.
      return nullptr;
    }
  } else {
    // 32 bit CIE
    cie->cfa_instructions_end = memory_.cur_offset() + length32;
    cie->fde_address_encoding = DW_EH_PE_sdata4;

    uint32_t cie_id;
    if (!memory_.ReadBytes(&cie_id, sizeof(cie_id))) {
      return nullptr;
    }
    if (!IsCIE32(cie_id)) {
      // This is not a CIE, something has gone horribly wrong.
      return nullptr;
    }
  }

  if (!memory_.ReadBytes(&cie->version, sizeof(cie->version))) {
    return nullptr;
  }

  if (cie->version != 1 && cie->version != 3 && cie->version != 4) {
    // Unrecognized version.
    return nullptr;
  }

  // Read the augmentation string.
  char aug_value;
  do {
    if (!memory_.ReadBytes(&aug_value, 1)) {
      return nullptr;
    }
    cie->augmentation_string.push_back(aug_value);
  } while (aug_value != '\0');

  if (cie->version == 4) {
    // Skip the Address Size field since we only use it for validation.
    memory_.set_cur_offset(memory_.cur_offset() + 1);

    // Segment Size
    if (!memory_.ReadBytes(&cie->segment_size, 1)) {
      return nullptr;
    }
  }

  // Code Alignment Factor
  if (!memory_.ReadULEB128(&cie->code_alignment_factor)) {
    return nullptr;
  }

  // Data Alignment Factor
  if (!memory_.ReadSLEB128(&cie->data_alignment_factor)) {
    return nullptr;
  }

  if (cie->version == 1) {
    // Return Address is a single byte.
    uint8_t return_address_register;
    if (!memory_.ReadBytes(&return_address_register, 1)) {
      return nullptr;
    }
    cie->return_address_register = return_address_register;
  } else if (!memory_.ReadULEB128(&cie->return_address_register)) {
    return nullptr;
  }

  if (cie->augmentation_string.size() > 0 && cie->augmentation_string[0] == 'z') {
    uint64_t aug_length;
    if (!memory_.ReadULEB128(&aug_length)) {
      return nullptr;
    }
    cie->cfa_instructions_offset = memory_.cur_offset() + aug_length;

    for (size_t i = 1; i < cie->augmentation_string.size(); i++) {
      switch (cie->augmentation_string[i]) {
      case 'L':
        if (!memory_.ReadBytes(&cie->lsda_encoding, 1)) {
          return nullptr;
        }
        break;
      case 'P':
        {
          uint8_t encoding;
          if (!memory_.ReadBytes(&encoding, 1)) {
            return nullptr;
          }
          if (!memory_.ReadEncodedValue<AddressType>(encoding, &cie->personality_handler)) {
            return nullptr;
          }
        }
        break;
      case 'R':
        if (!memory_.ReadBytes(&cie->fde_address_encoding, 1)) {
          return nullptr;
        }
        break;
      }
    }
  } else {
    cie->cfa_instructions_offset = memory_.cur_offset();
  }
  return cie;
}

template <typename AddressType>
DwarfFDE* DwarfSectionTmpl<AddressType>::GetFDEFromOffset(uint64_t offset) {
  auto fde_entry = fde_entries_.find(offset);
  if (fde_entry != fde_entries_.end()) {
    return &fde_entry->second;
  }
  DwarfFDE* fde = &fde_entries_[offset];

  memory_.set_cur_offset(offset);
  uint32_t length32;
  if (!memory_.ReadBytes(&length32, sizeof(length32))) {
    return nullptr;
  }

  if (length32 == static_cast<uint32_t>(-1)) {
    // 64 bit FDE.
    uint64_t length64;
    if (!memory_.ReadBytes(&length64, sizeof(length64))) {
      return nullptr;
    }
    fde->cfa_instructions_end = memory_.cur_offset() + length64;

    uint64_t value64;
    if (!memory_.ReadBytes(&value64, sizeof(value64))) {
      return nullptr;
    }
    if (IsCIE64(value64)) {
      // This is a CIE, this means something has gone wrong.
      return nullptr;
    }

    // Get the CIE pointer, which is necessary to properly read the rest of
    // of the FDE information.
    fde->cie_offset = GetCIEOffsetFromFDE64(value64);
  } else {
    // 32 bit FDE.
    fde->cfa_instructions_end = memory_.cur_offset() + length32;

    uint32_t value32;
    if (!memory_.ReadBytes(&value32, sizeof(value32))) {
      return nullptr;
    }
    if (IsCIE32(value32)) {
      // This is a CIE, this means something has gone wrong.
      return nullptr;
    }

    // Get the CIE pointer, which is necessary to properly read the rest of
    // of the FDE information.
    fde->cie_offset = GetCIEOffsetFromFDE32(value32);
  }
  uint64_t cur_offset = memory_.cur_offset();

  const DwarfCIE* cie = GetCIE(fde->cie_offset);
  if (cie == nullptr) {
    return nullptr;
  }
  fde->cie = cie;

  if (cie->segment_size != 0) {
    // Skip over the segment selector for now.
    cur_offset += cie->segment_size;
  }
  memory_.set_cur_offset(cur_offset);

  if (!memory_.ReadEncodedValue<AddressType>(cie->fde_address_encoding & 0xf, &fde->pc_start)) {
    return nullptr;
  }
  fde->pc_start = AdjustPcFromFDE(fde->pc_start);

  if (!memory_.ReadEncodedValue<AddressType>(cie->fde_address_encoding & 0xf, &fde->pc_end)) {
    return nullptr;
  }
  fde->pc_end += fde->pc_start;
  if (cie->augmentation_string.size() > 0 && cie->augmentation_string[0] == 'z') {
    // Augmentation Size
    uint64_t aug_length;
    if (!memory_.ReadULEB128(&aug_length)) {
      return nullptr;
    }
    uint64_t cur_offset = memory_.cur_offset();

    if (!memory_.ReadEncodedValue<AddressType>(cie->lsda_encoding, &fde->lsda_address)) {
      return nullptr;
    }

    // Set our position to after all of the augmentation data.
    memory_.set_cur_offset(cur_offset + aug_length);
  }
  fde->cfa_instructions_offset = memory_.cur_offset();

  return fde;
}

template <typename AddressType>
bool DwarfSectionTmpl<AddressType>::GetCfaLocationInfo(
    uint64_t pc, const DwarfFDE* fde, dwarf_loc_regs_t* loc_regs) {
  DwarfCfa<AddressType> cfa(&memory_, fde);

  // Look for the cached copy of the cie data.
  auto reg_entry = cie_loc_regs_.find(fde->cie_offset);
  if (reg_entry == cie_loc_regs_.end()) {
    if (!cfa.GetLocationInfo(pc, fde->cie->cfa_instructions_offset,
                             fde->cie->cfa_instructions_end, loc_regs)) {
      return false;
    }
    cie_loc_regs_[fde->cie_offset] = *loc_regs;
  }
  cfa.set_cie_loc_regs(&cie_loc_regs_[fde->cie_offset]);
  return cfa.GetLocationInfo(pc, fde->cfa_instructions_offset,
                             fde->cfa_instructions_end, loc_regs);
}

template <typename AddressType>
bool DwarfSectionTmpl<AddressType>::Log(
    uint8_t indent, uint64_t pc, uint64_t load_bias, const DwarfFDE* fde) {
  DwarfCfa<AddressType> cfa(&memory_, fde);

  // Always print the cie information.
  const DwarfCIE* cie = fde->cie;
  if (!cfa.Log(indent, pc, load_bias, cie->cfa_instructions_offset, cie->cfa_instructions_end)) {
    return false;
  }
  return cfa.Log(indent, pc, load_bias, fde->cfa_instructions_offset, fde->cfa_instructions_end);
}

// Explicitly instantiate DwarfSectionTmpl
template class DwarfSectionTmpl<uint32_t>;
template class DwarfSectionTmpl<uint64_t>;
