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

#include "DwarfCfa.h"
#include "DwarfError.h"
#include "DwarfEncoding.h"

const DwarfCfaLogInfo g_cfa_info[64] = {
  {                           // 0x00 DW_CFA_nop
    "DW_CFA_nop",
    { },
  },
  {
    "DW_CFA_set_loc",                       // 0x01 DW_CFA_set_loc
    { DWARF_DISPLAY_ADDRESS },
  },
  {
    "DW_CFA_advance_loc1",                  // 0x02 DW_CFA_advance_loc1
    { DWARF_DISPLAY_NUMBER },
  },
  {
    "DW_CFA_advance_loc2",                  // 0x03 DW_CFA_advance_loc2
    { DWARF_DISPLAY_NUMBER },
  },
  {
    "DW_CFA_advance_loc4",                  // 0x04 DW_CFA_advance_loc4
    { DWARF_DISPLAY_NUMBER },
  },
  {
    "DW_CFA_offset_extended",               // 0x05 DW_CFA_offset_extended
    { DWARF_DISPLAY_REGISTER, DWARF_DISPLAY_NUMBER },
  },
  {
    "DW_CFA_restore_extended",              // 0x06 DW_CFA_restore_extended
    { DWARF_DISPLAY_REGISTER },
  },
  {
    "DW_CFA_undefined",                     // 0x07 DW_CFA_undefined
    { DWARF_DISPLAY_REGISTER },
  },
  {
    "DW_CFA_same_value",                    // 0x08 DW_CFA_same_value
    { DWARF_DISPLAY_REGISTER },
  },
  {
    "DW_CFA_register",                      // 0x09 DW_CFA_register
    { DWARF_DISPLAY_REGISTER, DWARF_DISPLAY_REGISTER },
  },
  {
    "DW_CFA_remember_state",                // 0x0a DW_CFA_remember_state
    { },
  },
  {
    "DW_CFA_restore_state",                 // 0x0b DW_CFA_restore_state
    { },
  },
  {
    "DW_CFA_def_cfa",                       // 0x0c DW_CFA_def_cfa
    { DWARF_DISPLAY_REGISTER, DWARF_DISPLAY_NUMBER },
  },
  {
    "DW_CFA_def_cfa_register",              // 0x0d DW_CFA_def_cfa_register
    { DWARF_DISPLAY_REGISTER },
  },
  {
    "DW_CFA_def_cfa_offset",                // 0x0e DW_CFA_def_cfa_offset
    { DWARF_DISPLAY_NUMBER },
  },
  {
    "DW_CFA_def_cfa_expression",            // 0x0f DW_CFA_def_cfa_expression
    { DWARF_DISPLAY_EVAL_BLOCK },
  },
  {
    "DW_CFA_expression",                    // 0x10 DW_CFA_expression
    { DWARF_DISPLAY_REGISTER, DWARF_DISPLAY_EVAL_BLOCK },
  },
  {
    "DW_CFA_offset_extended_sf",            // 0x11 DW_CFA_offset_extend_sf
    { DWARF_DISPLAY_REGISTER, DWARF_DISPLAY_SIGNED_NUMBER },
  },
  {
    "DW_CFA_def_cfa_sf",                    // 0x12 DW_CFA_def_cfa_sf
    { DWARF_DISPLAY_REGISTER, DWARF_DISPLAY_SIGNED_NUMBER },
  },
  {
    "DW_CFA_def_cfa_offset_sf",             // 0x13 DW_CFA_def_cfa_offset_sf
    { DWARF_DISPLAY_SIGNED_NUMBER },
  },
  {
    "DW_CFA_val_offset",                    // 0x14 DW_CFA_val_offset
    { DWARF_DISPLAY_REGISTER, DWARF_DISPLAY_NUMBER },
  },
  {
    "DW_CFA_val_offset_sf",                 // 0x15 DW_CFA_val_offset_sf
    { DWARF_DISPLAY_REGISTER, DWARF_DISPLAY_SIGNED_NUMBER },
  },
  {
    "DW_CFA_val_expression",                // 0x16 DW_CFA_val_expression
    { DWARF_DISPLAY_REGISTER, DWARF_DISPLAY_EVAL_BLOCK },
  },
  { nullptr, {} },                               // 0x17 illegal cfa
  { nullptr, {} },                       // 0x18 illegal cfa
  { nullptr, {} },                       // 0x19 illegal cfa
  { nullptr, {} },                       // 0x1a illegal cfa
  { nullptr, {} },                       // 0x1b illegal cfa
  { nullptr, {} },                       // 0x1c DW_CFA_lo_user (Treat as illegal)
  { nullptr, {} },                       // 0x1d illegal cfa
  { nullptr, {} },                       // 0x1e illegal cfa
  { nullptr, {} },                       // 0x1f illegal cfa
  { nullptr, {} },                       // 0x20 illegal cfa
  { nullptr, {} },                       // 0x21 illegal cfa
  { nullptr, {} },                       // 0x22 illegal cfa
  { nullptr, {} },                       // 0x23 illegal cfa
  { nullptr, {} },                       // 0x24 illegal cfa
  { nullptr, {} },                       // 0x25 illegal cfa
  { nullptr, {} },                       // 0x26 illegal cfa
  { nullptr, {} },                       // 0x27 illegal cfa
  { nullptr, {} },                       // 0x28 illegal cfa
  { nullptr, {} },                       // 0x29 illegal cfa
  { nullptr, {} },                       // 0x2a illegal cfa
  { nullptr, {} },                       // 0x2b illegal cfa
  { nullptr, {} },                       // 0x2c illegal cfa
  { nullptr, {} },                       // 0x2d DW_CFA_GNU_window_save (Treat as illegal)
  {
    "DW_CFA_GNU_args_size",                 // 0x2e DW_CFA_GNU_args_size
    { DWARF_DISPLAY_NUMBER },
  },
  {
    "DW_CFA_GNU_negative_offset_extended",  // 0x2f DW_CFA_GNU_negative_offset_extended
    { DWARF_DISPLAY_REGISTER, DWARF_DISPLAY_NUMBER },
  },
  { nullptr, {} },                       // 0x31 illegal cfa
  { nullptr, {} },                       // 0x32 illegal cfa
  { nullptr, {} },                       // 0x33 illegal cfa
  { nullptr, {} },                       // 0x34 illegal cfa
  { nullptr, {} },                       // 0x35 illegal cfa
  { nullptr, {} },                       // 0x36 illegal cfa
  { nullptr, {} },                       // 0x37 illegal cfa
  { nullptr, {} },                       // 0x38 illegal cfa
  { nullptr, {} },                       // 0x39 illegal cfa
  { nullptr, {} },                       // 0x3a illegal cfa
  { nullptr, {} },                       // 0x3b illegal cfa
  { nullptr, {} },                       // 0x3c illegal cfa
  { nullptr, {} },                       // 0x3d illegal cfa
  { nullptr, {} },                       // 0x3e illegal cfa
  { nullptr, {} },                       // 0xef DW_CFA_hi_user (Treat as illegal)
};
