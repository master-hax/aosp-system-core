

class DwarfCie {
};

class DwarfFde {
};

struct DwarfCie32 {
  uint32_t length;
  uint32_t id;
  uint8_t version;
  uint8_t* augmentation_string;
};

struct DwarfCie64 {
  uint64_t length;
  uint64_t id;
  uint8_t version;
  uint8_t* augmentation_string;
};

// The pointer format is described in the Linux Base Spec
// found here http://www.linuxbase.org/spec/.
// Specifically, the pointer format is described in LBS Core - Generic 5.0.
// Section 10.5 Dwarf Extensions.
template <typename AddressType>
bool ReadEncodedPointer(uint64_t offset, uint8_t encoding, AddressType* value) {
  if (encoding == DW_EH_PE_omit) {
    *value = 0;
    return true;
  } else if (encoding == DW_EH_PE_aligned) {
    offset = ALIGN_TO_SOMETHING();
    return memory->Read(offset, &value, sizeof(AddressSize));
  }

  switch (encoding & DW_EH_PE_FORMAT_MASK) {
  case DW_EH_PE_ptr:
  case DW_EH_PE_uleb128:
  case DW_EH_PE_sleb128:
  case DW_EH_PE_udata2:
  case DW_EH_PE_sdata2:
  case DW_EH_PE_udata4:
  case DW_EH_PE_sdata4:
  case DW_EH_PE_udata8:
  case DW_EH_PE_sdata8:
  default:
    return false;
  }

  if (value == 0) {
    return true;
  }

  switch(encoding & DW_EH_PE_APPL_MASK) {
  case DW_EH_PE_absptr:
    break;
  case DW_EH_PE_pcrel:
    break;
  case DW_EH_PE_datarel:
    break;
  case DW_EH_PE_funcrel:
    break;
  case DW_EH_PE_textrel:
    break;
  default:
    return false;
  }

  if (encoding & DW_EH_PE_indirect) {
  }

  return true;
}

class DwarfCie {
 public:
  DwarfCie(DwarfMemory* memory) : memory_(memory) { }
  virtual ~DwarfCie() = default;

 private:
  uint8_t version_;
  umaxptr_t instructions_;
  size_t instructions_length_;
  umaxptr_t code_alignment_factor_;
  umaxptr_t data_alignment_factor_;
  umaxptr_t return_address_register_;
};

struct DwarfEhFrameHdr {
  uint8_t version;
  uint8_t eh_frame_ptr_encoding;
  uint8_t fde_count_encoding;
  uint8_t table_encoding;

  umaxptr_t eh_frame_ptr;
  umaxptr_t fde_count;
};

template <typename AddressType>
bool ParseCie(uint64_t offset) {
  uint32_t value;

  // Length
  if (!memory->Read(offset, &value, sizeof(value))) {
    return false;
  }
  offset += sizeof(value);

  if (value == 0) {
    return true;
  }

  uint64_t entry_length;
  if (value == 0xffffffff) {
    // Extended Length
    if (!memory->Read(offset, &entry_length, sizeof(entry_length))) {
      return false;
    }
  } else {
    entry_length = value;
  }

  // CIE ID
  if (!memory->Read(offset, &value, sizeof(value))) {
    return false;
  }
  if (value != 0) {
    // Illegal value for CIE ID
    return false;
  }
  offset += sizeof(value);

  // Read the version.
  uint8_t version;
  if (!memory->Read(offset++, &version, 1)) {
    return false;
  }
  if (version != 1 && version != 3 && version != 4) {
    // The only versions supported are 1, 3, and 4.
    return false;
  }

  // Augmentation String
  std::vector<uint8_t> augment_string;
  for (size_t i = 0; i < length; i++) {
    uint8_t byte;
    if (!memory->Read(offset++, &byte, 1)) {
      return false;
    }
    augment_string[i] = byte;
    if (byte == 0) {
      break;
    }
  }

  if (version == 4) {
    uint8_t byte;
    // Address Size
    if (!memory->Read(offset++, &byte, 1)) {
      return false;
    }

    // Segment Size
    if (!memory->Read(offset++, &byte, 1)) {
      return false;
    }
  }

#if 0
    if (sizeof(AddressType)) {
      fde_encoding = DW_EH_PE_update4;
    } else {
      fde_encoding = DW_EH_PE_update8;
    }
    lsda_encoding = DW_EH_PE_omit;
    handler = nullptr;
    switch (value) {
    case 'z':
      // Read the size of the augmentation data.
      if (memory->ReadULEB128(&augmentation_size)) {
        return false;
      }
      break;
    case 'L':
      if (!memory->Read(offset, &lsda_encoding, 1)) {
        return false;
      }
      break;
    case 'R':
      if (!memory->Read(offset, &fde_encoding, 1)) {
        return false;
      }
      break;
    case 'S':
      // Set a special flag to indicate that this is a signal frame.
      break;
    case 'P':
      if (!memory->Read(offset, &handler_encoding, 1)) {
        return false;
      }
      // Read encoded pointer.
      if (!memory->ReadEncodedPointer(offset, handler_encoding, &personality_addr)) {
        return false;
      }
      break;
    default:
      // Unknown augmentation, should we log an error.
    }
  }
#endif

  AddressType code_alignment_factor;
  if (!memory->ReadULEB128(&code_alignment_factor)) {
    return false;
  }

  AddressType data_alignment_factor;
  if (!memory->ReadSLEB128(&data_alignment_factor)) {
    return false;
  }

  AddressType return_address_register;
  if (version == 1) {
    uint8_t value;
    if (!memory->Read(offset, &value, 1)) {
      return false;
    }
    return_address_register = value;
  } else {
    if (!memory->ReadULEB128(&return_address_register)) {
      return false;
    }
  }

  std::vector<uint8_t> initial_instructions;
  if (!memory->Read(offset, cfa.data(), length)) {
    return false;
  }
}


bool Parse(DwarfMemory* memory) {
}


struct DwarfFde32 {
  uint32_t length;
  uint32_t pointer;
};

struct DwarfFde64 {
  uint64_t length;
  uint64_t pointer;
};


CIE
---
length (size of the entry)

id (4 or 8 bytes)

version (ubyte)
augmentation (UTF-8 string) (null terminated string) (can be zero byte)
  if (unknown augmentation)
     CIE: length, CIE_id, version, augmentation
     FDE: length, CIE_pointer, initial_location, address_range

address_size (ubyte)
segment_size (ubyte)
code_alignment_factor (unsigned LEB128)
data_alignment_factor (signed LEB128)
return_address_register (unsigned LEB128)
initial_instructions (array of ubyte)
padding up to the initial length


FDE
---
length (initial length) (must be an integral multiple of the address size)
CIE_pointer (4 or 8 bytes) (pointer to the CIE from the start of the .debug_frame)
initial_location (segment selector and target address)
address_range (target address)
  number of bytes of program instructions describe by this entry
instructions (array of ubyte)
padding
