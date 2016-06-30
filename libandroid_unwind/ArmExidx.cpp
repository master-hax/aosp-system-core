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

#include <stdint.h>

#include <deque>
#include <string>

#include <android-base/stringprintf.h>

#define LOG_TAG "unwind"
#include <log/log.h>

#include "ArmExidx.h"

bool Step() {
  return true;
}

bool Extract(arm_ptr_t*) {
#if 0
  // Look for the information.
  // Get the 32 bit value:

  // An ARM unwind entry consists of a prel31 offset to the start of a
  // function followed by 31 bits of data.
  //  If data is 0x1: IP points in a CANT UNWIND section.
  //  If bit 31 is set: This is the table entry.
  //  If bit 31 is zero: This is a prel31 offset of the start of the table
  //  entry for this function.
  if (addr != nullptr) {
    uint32_t value;
    if (!memory_->read32(entry, addr)) {
      return false;
    }
  }

  data_.clear();
  if (data == 1) {
    // Cant Unwind
    return false;
  }

  if (data & (1UL << 31)) {
    // Compact mode.
    data_.push_back((data >> 16) & 0xff);
    data_.push_back((data >> 8) & 0xff);
    data_.push_back(data & 0xff);
  } else {
    arm_addr extbl_data = entry + 4;
    extbl_data += data & 0x7fffffff;

    uint32_t data;
    if (read32(extbl_data, &data)) {
      return false;
    }

    size_t n_table_words = 0;

    if (data & (1UL << 31)) {
      uint8_t pers = (data >> 24) & 0xf;
      if (pers == 1 || pers == 2) {
        n_table_words = (data >> 16) & 0xff;
        extbl_data += 4;
      } else {
        data_.push_back((data >> 16) & 0xff);
      }
      data_.push_back((data >> 8) & 0xff);
      data_.push_back(data & 0xff);
    } else {
      // Ignore the personality routine value.
      extbl_data += 4;
      if (!read32(extbl_data, &data)) {
        return false;
      }
      n_table_words = (data >> 24) & 0xff;
      data_.push_back((data >> 16) & 0xff);
      data_.push_back((data >> 8) & 0xff);
      data_.push_back(data & 0xff);
      extbl_data += 4;
    }
    if (n_table_words > 5) {
      return false;
    }

    for (size_t i = 0; i < n_table_words; i++) {
      if (!read32(extbl_data, &data)) {
        return false;
      }
      extbl_data += 4;
      data_.push_back((data >> 24) & 0xff);
      data_.push_back((data >> 16) & 0xff);
      data_.push_back((data >> 8) & 0xff);
      data_.push_back(data & 0xff);
    }
  }

  if (data_.back() != ARM_EXTBL_OP_FINISH) {
    data_.push_back(ARM_EXTBL_OP_FINISH);
  }

#endif
  return true;
}

inline bool ArmExidx::GetByte(uint8_t* byte) {
  if (data_.empty()) {
    status_ = ARM_STATUS_TRUNCATED;
    return false;
  }
  *byte = data_.front();
  data_.pop_front();
  return true;
}

inline bool ArmExidx::DecodePrefix2_0(uint8_t byte) {
  uint16_t registers = (byte & 0xf) << 8;
  if (!GetByte(&byte)) {
    return false;
  }

  registers |= byte;
  if (registers == 0) {
    // 10000000 00000000: Refuse to unwind
    if (debug_) {
      ALOGI("Refuse to unwind");
    }
    status_ = ARM_STATUS_NO_UNWIND;
    return false;
  }
  // 1000iiii iiiiiiii: Pop up to 12 integer registers under masks {r15-r12}, {r11-r4}
  if (debug_) {
    bool add_comma = false;
    std::string msg = "pop {";
    for (size_t i = 0; i < 12; i++) {
      if (registers & (1 << i)) {
        if (add_comma) {
          msg += ", ";
        }
        msg += android::base::StringPrintf("r%zu", i + 4);
        add_comma = true;
      }
    }
    ALOGI("%s}", msg.c_str());
  }

  uint8_t reg = 0;
  while (registers) {
    uint8_t bit = __builtin_ctz(byte) + 1;
    reg += bit;
    state_.regs[reg+3] = 0;
#if 0
    if (!memory_.read32(state_.cfa, &state_.regs[reg])) {
      return false;
    }
#endif
    state_.cfa += 4;
    registers >>= bit;
  }
  return true;
}

inline bool ArmExidx::DecodePrefix2_1(uint8_t byte) {
  uint8_t bits = byte & 0xf;
  if (bits == 13 || bits == 15) {
    // 10011101: Reserved as prefix for ARM register to register moves
    // 10011111: Reserved as prefix for Intel Wireless MMX register to register moves
    if (debug_) {
      ALOGI("[Reserved]");
    }
    status_ = ARM_STATUS_RESERVED;
    return false;
  }
  // 1001nnnn: Set vsp = r[nnnn] (nnnn != 13, 15)
  if (debug_) {
    ALOGI("vsp = r%d", bits);
  }
  state_.cfa = state_.regs[bits];
  return true;
}

inline bool ArmExidx::DecodePrefix2_2(uint8_t byte) {
  // 10100nnn: Pop r4-r[4+nnn]
  // 10101nnn: Pop r4-r[4+nnn], r14
  if (debug_) {
    std::string msg = "pop {r4";
    uint8_t end_reg = byte & 0x7;
    if (end_reg) {
      msg += android::base::StringPrintf("-r%d", 4 + end_reg);
    }
    if (byte & 0x8) {
      ALOGI("%s, r14}", msg.c_str());
    } else {
      ALOGI("%s}", msg.c_str());
    }
  }

  for (size_t i = 4; i <= 4 + (byte & 0x7); i++) {
    state_.regs[i] = 0;
#if 0
    if (!memory_.read32(state_.cfa, &state_.regs[i]) {
      return false;
    }
#endif
    state_.cfa += 4;
  }
  if (byte & 0x8) {
    state_.regs[14] = 0;
#if 0
    if (!memory_.read32(state_.cfa, &state_.regs[i]) {
      return false;
    }
#endif
    state_.cfa += 4;
  }
  return true;
}

inline bool ArmExidx::DecodePrefix2_3(uint8_t byte) {
  uint8_t bits = byte & 0xf;
  if (bits == 0) {
    // 10110000: Finish
    if (debug_) {
      ALOGI("Finish");
    }
    if (!state_.regs[ARM_PC]) {
      state_.regs[ARM_PC] = state_.regs[ARM_LR];
    }
    status_ = ARM_STATUS_FINISH;
    return false;
  } else if (bits == 1) {
    if (!GetByte(&byte)) {
      return false;
    }

    if (byte == 0) {
      // 10110001 00000000: Spare
      if (debug_) {
        ALOGI("Spare");
      }
      status_ = ARM_STATUS_SPARE;
      return false;
    }
    if (byte >> 4) {
      // 10110001 xxxxyyyy: Spare (xxxx != 0000)
      if (debug_) {
        ALOGI("Spare");
      }
      status_ = ARM_STATUS_SPARE;
      return false;
    }
    // 10110001 0000iiii: Pop integer registers under mask {r3, r2, r1, r0}
    if (debug_) {
      bool add_comma = false;
      std::string msg = "pop {";
      for (size_t i = 0; i < 4; i++) {
        if (byte & (1 << i)) {
          if (add_comma) {
            msg += ", ";
          }
          msg += android::base::StringPrintf("r%zu", i);
          add_comma = true;
        }
      }
      ALOGI("%s}", msg.c_str());
    }
    uint8_t reg = 0;
    while (byte) {
      uint8_t bit = __builtin_ctz(byte) + 1;
      reg += bit;
      state_.regs[reg] = 0;
#if 0
      if (!memory_.read32(state_.cfa, &state_.regs[reg])) {
        return false;
      }
#endif
      state_.cfa += 4;
      byte >>= bit;
    }
  } else if (bits == 2) {
    // 10110010 uleb128: vsp = vsp + 0x204 + (uleb128 << 2)
    uint32_t result = 0;
    uint32_t shift = 0;
    while (true) {
      if (!GetByte(&byte)) {
        return false;
      }

      result += (byte & 0x7f) << shift;
      if ((byte & 0x80) == 0) {
        break;
      }
      shift += 7;
    }
    result <<= 2;
    if (debug_) {
      ALOGI("vsp = vsp + %d", 0x204 + result);
    }
    state_.cfa += 0x204 + result;
  } else if (bits == 3) {
    // 10110011 sssscccc: Pop VFP double precision registers D[ssss]-D[ssss+cccc] by FSTMFDX
    if (!GetByte(&byte)) {
      return false;
    }

    if (debug_) {
      uint8_t start_reg = byte >> 4;
      std::string msg = android::base::StringPrintf("pop {D%d", start_reg);
      uint8_t end_reg = start_reg + (byte & 0xf);
      if (end_reg) {
        msg += android::base::StringPrintf("-D%d", end_reg);
      }
      ALOGI("%s}", msg.c_str());
    }
    state_.cfa += (byte & 0xf) * 8 + 12;
  } else if ((bits >> 2) == 1) {
    // 101101nn: Spare
    if (debug_) {
      ALOGI("Spare");
    }
    status_ = ARM_STATUS_SPARE;
    return false;
  } else {
    // 10111nnn: Pop VFP double-precision registers D[8]-D[8+nnn] by FSTMFDX
    if (debug_) {
      std::string msg = "pop {D8";
      uint8_t last_reg = (byte & 0x7);
      if (last_reg) {
        msg += android::base::StringPrintf("-D%d", last_reg + 8);
      }
      ALOGI("%s}", msg.c_str());
    }
    // Only update the cfa.
    state_.cfa += (byte & 0x7) * 8 + 12;
  }
  return true;
}

inline bool ArmExidx::DecodePrefix2(uint8_t byte) {
  uint8_t bits = (byte >> 4) & 0x3;
  if (bits == 0) {
    return DecodePrefix2_0(byte);
  } else if (bits == 1) {
    return DecodePrefix2_1(byte);
  } else if (bits == 2) {
    return DecodePrefix2_2(byte);
  } else {
    return DecodePrefix2_3(byte);
  }
}

inline bool ArmExidx::DecodePrefix3_0(uint8_t byte) {
  uint8_t bits = byte & 0x7;
  if (bits == 6) {
    if (!GetByte(&byte)) {
      return false;
    }

    // 11000110 sssscccc: Intel Wireless MMX pop wR[ssss]-wR[ssss+cccc]
    if (debug_) {
      uint8_t start_reg = byte >> 4;
      std::string msg = android::base::StringPrintf("pop {wR%d", start_reg);
      uint8_t end_reg = byte & 0xf;
      if (end_reg) {
        msg += android::base::StringPrintf("-wR%d", start_reg + end_reg);
      }
      ALOGI("%s}", msg.c_str());
    }
    // Only update the cfa.
    state_.cfa += (byte & 0xf) * 8 + 8;
  } else if (bits == 7) {
    if (!GetByte(&byte)) {
      return false;
    }

    if (byte == 0) {
      // 11000111 00000000: Spare
      if (debug_) {
        ALOGI("Spare");
      }
      status_ = ARM_STATUS_SPARE;
      return false;
    } else if ((byte >> 4) == 0) {
      // 11000111 0000iiii: Intel Wireless MMX pop wCGR registers {wCGR0,1,2,3}
      if (debug_) {
        bool add_comma = false;
        std::string msg = "pop {";
        for (size_t i = 0; i < 4; i++) {
          if (byte & (1 << i)) {
            if (add_comma) {
              msg += ", ";
            }
            msg += android::base::StringPrintf("wCGR%zu", i);
            add_comma = true;
          }
        }
        ALOGI("%s}", msg.c_str());
      }
      // Only update the cfa.
      state_.cfa += __builtin_popcount(byte) * 4;
    } else {
      // 11000111 xxxxyyyy: Spare (xxxx != 0000)
      if (debug_) {
        ALOGI("Spare");
      }
      status_ = ARM_STATUS_SPARE;
      return false;
    }
  } else {
    // 11000nnn: Intel Wireless MMX pop wR[10]-wR[10+nnn] (nnn != 6, 7)
    if (debug_) {
      std::string msg = "pop {wR10";
      uint8_t nnn = byte & 0x7;
      if (nnn) {
        msg += android::base::StringPrintf("-wR%d", 10 + nnn);
      }
      ALOGI("%s}", msg.c_str());
    }
    // Only update the cfa.
    state_.cfa += (byte & 0x7) * 8 + 8;
  }
  return true;
}

inline bool ArmExidx::DecodePrefix3_1(uint8_t byte) {
  uint8_t bits = byte & 0x7;
  if (bits == 0) {
    // 11001000 sssscccc: Pop VFP double precision registers D[16+ssss]-D[16+ssss+cccc] by VPUSH
    if (!GetByte(&byte)) {
      return false;
    }

    if (debug_) {
      uint8_t start_reg = byte >> 4;
      std::string msg = android::base::StringPrintf("pop {D%d", 16 + start_reg);
      uint8_t end_reg = byte & 0xf;
      if (end_reg) {
        msg += android::base::StringPrintf("-D%d", 16 + start_reg + end_reg);
      }
      ALOGI("%s}", msg.c_str());
    }
    // Only update the cfa.
    state_.cfa += (byte & 0xf) * 8 + 8;
  } else if (bits == 1) {
    // 11001001 sssscccc: Pop VFP double precision registers D[ssss]-D[ssss+cccc] by VPUSH
    if (!GetByte(&byte)) {
      return false;
    }

    if (debug_) {
      uint8_t start_reg = byte >> 4;
      std::string msg = android::base::StringPrintf("pop {D%d", start_reg);
      uint8_t end_reg = byte & 0xf;
      if (end_reg) {
        msg += android::base::StringPrintf("-D%d", start_reg + end_reg);
      }
      ALOGI("%s}", msg.c_str());
    }
    // Only update the cfa.
    state_.cfa += (byte & 0xf) * 8 + 8;
  } else {
    // 11001yyy: Spare (yyy != 000, 001)
    if (debug_) {
      ALOGI("Spare");
    }
    status_ = ARM_STATUS_SPARE;
    return false;
  }
  return true;
}

inline bool ArmExidx::DecodePrefix3_2(uint8_t byte) {
  // 11010nnn: Pop VFP double precision registers D[8]-D[8+nnn] by VPUSH
  if (debug_) {
    std::string msg = "pop {D8";
    uint8_t end_reg = byte & 0x7;
    if (end_reg) {
      msg += android::base::StringPrintf("-D%d", 8 + end_reg);
    }
    ALOGI("%s}", msg.c_str());
  }
  state_.cfa += (byte & 0x7) * 8 + 8;
  return true;
}

inline bool ArmExidx::DecodePrefix3(uint8_t byte) {
  uint8_t bits = (byte >> 3) & 0x7;
  if (bits == 0) {
    return DecodePrefix3_0(byte);
  } else if (bits == 1) {
    return DecodePrefix3_1(byte);
  } else if (bits == 2) {
    return DecodePrefix3_2(byte);
  } else {
    // 11xxxyyy: Spare (xxx != 000, 001, 010)
    if (debug_) {
      ALOGI("Spare");
    }
    status_ = ARM_STATUS_SPARE;
    return false;
  }
}

bool ArmExidx::Decode() {
  uint8_t byte;
  if (!GetByte(&byte)) {
    return false;
  }

  uint8_t bits = byte >> 6;
  if (bits == 0) {
    // 00xxxxxx: vsp = vsp + (xxxxxxx << 2) + 4
    if (debug_) {
      ALOGI("vsp = vsp + %d", ((byte & 0x3f) << 2) + 4);
    }
    state_.cfa += ((byte & 0x3f) << 2) + 4;
  } else if (bits == 1) {
    // 01xxxxxx: vsp = vsp - (xxxxxxx << 2) + 4
    if (debug_) {
      ALOGI("vsp = vsp - %d", ((byte & 0x3f) << 2) + 4);
    }
    state_.cfa -= ((byte & 0x3f) << 2) + 4;
  } else if (bits == 2) {
    return DecodePrefix2(byte);
  } else if (bits == 3) {
    return DecodePrefix3(byte);
  }
  return true;
}

bool ArmExidx::Step() {
#if 0
  if (!extract(ip)) {
    return false;
  }

  uint8_t cmd;
  uint32_t data;
  while (decode(&cmd, &data)) {
    if (!apply(cmd, data)) {
      return false;
    }
  }
#endif
  return true;
}
