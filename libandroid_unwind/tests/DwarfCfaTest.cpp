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

#include <gtest/gtest.h>

#include "Dwarf.h"
#include "DwarfCfa.h"
#include "Log.h"

#include "LogFake.h"
#include "MemoryFake.h"

class DwarfCfaTest : public ::testing::Test {
 protected:
  virtual void SetUp() {
    ResetLogs();
    cfa_memory_.Clear();
    regular_memory_.Clear();

    g_LoggingEnabled = true;
    g_LoggingIndentLevel = 0;
    g_LoggingOnly = true;
  }

  MemoryFake cfa_memory_;
  MemoryFake regular_memory_;
};

TEST_F(DwarfCfaTest, illegal_opcode) {
  Dwarf<AddressType> dwarf_memory(&cfa_memory_);
  DwarfCfa<AddressType> dwarf_cfa(&dwarf_memory, &regular_memory_);
}
