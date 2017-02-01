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

#include <gtest/gtest.h>

#include "Elf.h"
#include "ElfInterface.h"
#include "MapInfo.h"
#include "Regs.h"

#include "MemoryFake.h"

class ElfFake : public Elf {
 public:
  ElfFake(Memory* memory) : Elf(memory) {}
  virtual ~ElfFake() = default;

  void set_elf_interface(ElfInterface* interface) { interface_.reset(interface); }
};

class ElfInterfaceFake : public ElfInterface {
 public:
  ElfInterfaceFake(Memory* memory) : ElfInterface(memory) {}
  virtual ~ElfInterfaceFake() = default;

  void set_load_bias(uint64_t load_bias) { load_bias_ = load_bias; }

  bool Init() override { return false; }
  bool GetSoname(std::string*) override { return false; }
  bool GetFunctionName(uint64_t, std::string*, uint64_t*) override { return false; }
  bool Step(uint64_t, Regs*, Memory*) override { return false; }
};

template <typename TypeParam>
class RegsTestTmpl : public RegsTmpl<TypeParam> {
 public:
  RegsTestTmpl(uint16_t total_regs, uint16_t regs_sp) : RegsTmpl<TypeParam>(total_regs, regs_sp) {}
  virtual ~RegsTestTmpl() = default;

  uint64_t GetRelPc(size_t, Elf*, const MapInfo*) override { return 0; }
};

class RegsTest : public ::testing::Test {
  void SetUp() override {
    memory_ = new MemoryFake;
    elf_.reset(new ElfFake(memory_));
    elf_interface_ = new ElfInterfaceFake(elf_->memory());
    elf_->set_elf_interface(elf_interface_);
  }

 protected:
  ElfInterfaceFake* elf_interface_;
  MemoryFake* memory_;
  std::unique_ptr<ElfFake> elf_;
};

TEST_F(RegsTest, regs32) {
  RegsTestTmpl<uint32_t> regs32(50, 10);
  ASSERT_EQ(50U, regs32.total_regs());
  ASSERT_EQ(10U, regs32.sp_reg());

  uint32_t* raw = reinterpret_cast<uint32_t*>(regs32.RawData());
  for (size_t i = 0; i < 50; i++) {
    raw[i] = 0xf0000000 + i;
  }
  regs32.set_pc(0xf0120340);
  regs32.set_sp(0xa0ab0cd0);

  for (size_t i = 0; i < 50; i++) {
    ASSERT_EQ(0xf0000000U + i, regs32[i]) << "Failed comparing register " << i;
  }

  ASSERT_EQ(0xf0120340U, regs32.pc());
  ASSERT_EQ(0xa0ab0cd0U, regs32.sp());

  regs32[32] = 10;
  ASSERT_EQ(10U, regs32[32]);
}

TEST_F(RegsTest, regs64) {
  RegsTestTmpl<uint64_t> regs64(30, 12);
  ASSERT_EQ(30U, regs64.total_regs());
  ASSERT_EQ(12U, regs64.sp_reg());

  uint64_t* raw = reinterpret_cast<uint64_t*>(regs64.RawData());
  for (size_t i = 0; i < 30; i++) {
    raw[i] = 0xf123456780000000UL + i;
  }
  regs64.set_pc(0xf123456780102030UL);
  regs64.set_sp(0xa123456780a0b0c0UL);

  for (size_t i = 0; i < 30; i++) {
    ASSERT_EQ(0xf123456780000000U + i, regs64[i]) << "Failed reading register " << i;
  }

  ASSERT_EQ(0xf123456780102030UL, regs64.pc());
  ASSERT_EQ(0xa123456780a0b0c0UL, regs64.sp());

  regs64[8] = 10;
  ASSERT_EQ(10U, regs64[8]);
}

TEST_F(RegsTest, rel_pc) {
  MapInfo info{.start = 0x1000, .end = 0x2000};

  RegsArm64 arm64;
  elf_interface_->set_load_bias(0);
  arm64.set_pc(0x1010);
  ASSERT_EQ(0x10U,  arm64.GetRelPc(0, elf_.get(), &info));
  ASSERT_EQ(0xcU,  arm64.GetRelPc(1, elf_.get(), &info));
  elf_interface_->set_load_bias(0x100);
  ASSERT_EQ(0x110U, arm64.GetRelPc(0, elf_.get(), &info));
  ASSERT_EQ(0x10cU, arm64.GetRelPc(1, elf_.get(), &info));
  arm64.set_pc(0x1000);
  elf_interface_->set_load_bias(0);
  ASSERT_EQ(0x0U, arm64.GetRelPc(1, elf_.get(), &info));

  RegsX86 x86;
  elf_interface_->set_load_bias(0);
  x86.set_pc(0x1010);
  ASSERT_EQ(0x10U,  x86.GetRelPc(0, elf_.get(), &info));
  ASSERT_EQ(0xfU,  x86.GetRelPc(1, elf_.get(), &info));
  elf_interface_->set_load_bias(0x100);
  ASSERT_EQ(0x110U, x86.GetRelPc(0, elf_.get(), &info));
  ASSERT_EQ(0x10fU, x86.GetRelPc(1, elf_.get(), &info));
  x86.set_pc(0x1000);
  elf_interface_->set_load_bias(0);
  ASSERT_EQ(0x0U, x86.GetRelPc(1, elf_.get(), &info));

  RegsX86_64 x86_64;
  elf_interface_->set_load_bias(0);
  x86_64.set_pc(0x1010);
  ASSERT_EQ(0x10U,  x86_64.GetRelPc(0, elf_.get(), &info));
  ASSERT_EQ(0xfU,  x86_64.GetRelPc(1, elf_.get(), &info));
  elf_interface_->set_load_bias(0x100);
  ASSERT_EQ(0x110U, x86_64.GetRelPc(0, elf_.get(), &info));
  ASSERT_EQ(0x10fU, x86_64.GetRelPc(1, elf_.get(), &info));
  x86_64.set_pc(0x1000);
  elf_interface_->set_load_bias(0);
  ASSERT_EQ(0x0U, x86_64.GetRelPc(1, elf_.get(), &info));
}

TEST_F(RegsTest, rel_pc_arm) {
  MapInfo info{.start = 0x1000, .end = 0x2000};

  RegsArm arm;

  // Check fence posts.
  elf_interface_->set_load_bias(0);
  arm.set_pc(0x1004);
  ASSERT_EQ(4U,  arm.GetRelPc(1, elf_.get(), &info));
  arm.set_pc(0x1003);
  ASSERT_EQ(3U,  arm.GetRelPc(1, elf_.get(), &info));
  arm.set_pc(0x1002);
  ASSERT_EQ(2U,  arm.GetRelPc(1, elf_.get(), &info));
  arm.set_pc(0x1001);
  ASSERT_EQ(1U,  arm.GetRelPc(1, elf_.get(), &info));
  arm.set_pc(0x1000);
  ASSERT_EQ(0U,  arm.GetRelPc(1, elf_.get(), &info));

  elf_interface_->set_load_bias(0x100);
  arm.set_pc(0x1004);
  ASSERT_EQ(0x104U,  arm.GetRelPc(1, elf_.get(), &info));
  arm.set_pc(0x1003);
  ASSERT_EQ(0x103U,  arm.GetRelPc(1, elf_.get(), &info));
  arm.set_pc(0x1002);
  ASSERT_EQ(0x102U,  arm.GetRelPc(1, elf_.get(), &info));
  arm.set_pc(0x1001);
  ASSERT_EQ(0x101U,  arm.GetRelPc(1, elf_.get(), &info));
  arm.set_pc(0x1000);
  ASSERT_EQ(0x100U,  arm.GetRelPc(1, elf_.get(), &info));

  elf_interface_->set_load_bias(0);
  arm.set_pc(0x2084);
  ASSERT_EQ(0x1084U,  arm.GetRelPc(0, elf_.get(), &info));
  ASSERT_EQ(0x1080U,  arm.GetRelPc(1, elf_.get(), &info));
  elf_interface_->set_load_bias(0x300);
  arm.set_pc(0x2086);
  ASSERT_EQ(0x1386U,  arm.GetRelPc(0, elf_.get(), &info));
  ASSERT_EQ(0x1382U,  arm.GetRelPc(1, elf_.get(), &info));

  // Check thumb instructions handling.
  memory_->SetData(0x2000, 0);
  elf_interface_->set_load_bias(0);
  arm.set_pc(0x3005);
  ASSERT_EQ(0x2005U,  arm.GetRelPc(0, elf_.get(), &info));
  ASSERT_EQ(0x2003U,  arm.GetRelPc(1, elf_.get(), &info));
  memory_->SetData(0x2000, 0xe000f000);
  ASSERT_EQ(0x2005U,  arm.GetRelPc(0, elf_.get(), &info));
  ASSERT_EQ(0x2001U,  arm.GetRelPc(1, elf_.get(), &info));

  elf_interface_->set_load_bias(0x400);
  memory_->SetData(0x2000, 0);
  arm.set_pc(0x3005);
  ASSERT_EQ(0x2405U,  arm.GetRelPc(0, elf_.get(), &info));
  ASSERT_EQ(0x2403U,  arm.GetRelPc(1, elf_.get(), &info));
  memory_->SetData(0x2000, 0xf111f111);
  ASSERT_EQ(0x2405U,  arm.GetRelPc(0, elf_.get(), &info));
  ASSERT_EQ(0x2401U,  arm.GetRelPc(1, elf_.get(), &info));
}
