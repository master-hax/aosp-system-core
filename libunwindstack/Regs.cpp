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
#include <stdint.h>
#include <sys/ptrace.h>
#include <sys/uio.h>

#include <vector>

#include <unwindstack/Elf.h>
#include <unwindstack/MapInfo.h>
#include <unwindstack/Memory.h>
#include <unwindstack/Regs.h>

#include "Check.h"
#include "Machine.h"
#include "Ucontext.h"
#include "User.h"

namespace unwindstack {

RegsArm::RegsArm()
    : RegsImpl<uint32_t>(ARM_REG_LAST, ARM_REG_SP, Location(LOCATION_REGISTER, ARM_REG_LR)) {}

uint32_t RegsArm::MachineType() {
  return EM_ARM;
}

uint64_t RegsArm::GetAdjustedPc(uint64_t rel_pc, Elf* elf) {
  if (!elf->valid()) {
    return rel_pc;
  }

  uint64_t load_bias = elf->GetLoadBias();
  if (rel_pc < load_bias) {
    return rel_pc;
  }
  uint64_t adjusted_rel_pc = rel_pc - load_bias;

  if (adjusted_rel_pc < 5) {
    return rel_pc;
  }

  if (adjusted_rel_pc & 1) {
    // This is a thumb instruction, it could be 2 or 4 bytes.
    uint32_t value;
    if (rel_pc < 5 || !elf->memory()->Read(adjusted_rel_pc - 5, &value, sizeof(value)) ||
        (value & 0xe000f000) != 0xe000f000) {
      return rel_pc - 2;
    }
  }
  return rel_pc - 4;
}

void RegsArm::SetFromRaw() {
  set_pc(regs_[ARM_REG_PC]);
  set_sp(regs_[ARM_REG_SP]);
}

bool RegsArm::SetPcFromReturnAddress(Memory*) {
  if (pc() == regs_[ARM_REG_LR]) {
    return false;
  }

  set_pc(regs_[ARM_REG_LR]);
  return true;
}

void RegsArm::IterateRegisters(std::function<void(const char*, uint64_t)> fn) {
  fn("r0", regs_[ARM_REG_R0]);
  fn("r1", regs_[ARM_REG_R1]);
  fn("r2", regs_[ARM_REG_R2]);
  fn("r3", regs_[ARM_REG_R3]);
  fn("r4", regs_[ARM_REG_R4]);
  fn("r5", regs_[ARM_REG_R5]);
  fn("r6", regs_[ARM_REG_R6]);
  fn("r7", regs_[ARM_REG_R7]);
  fn("r8", regs_[ARM_REG_R8]);
  fn("r9", regs_[ARM_REG_R9]);
  fn("r10", regs_[ARM_REG_R10]);
  fn("r11", regs_[ARM_REG_R11]);
  fn("ip", regs_[ARM_REG_R12]);
  fn("sp", regs_[ARM_REG_SP]);
  fn("lr", regs_[ARM_REG_LR]);
  fn("pc", regs_[ARM_REG_PC]);
}

RegsArm64::RegsArm64()
    : RegsImpl<uint64_t>(ARM64_REG_LAST, ARM64_REG_SP, Location(LOCATION_REGISTER, ARM64_REG_LR)) {}

uint32_t RegsArm64::MachineType() {
  return EM_AARCH64;
}

uint64_t RegsArm64::GetAdjustedPc(uint64_t rel_pc, Elf* elf) {
  if (!elf->valid()) {
    return rel_pc;
  }

  if (rel_pc < 4) {
    return rel_pc;
  }
  return rel_pc - 4;
}

void RegsArm64::SetFromRaw() {
  set_pc(regs_[ARM64_REG_PC]);
  set_sp(regs_[ARM64_REG_SP]);
}

bool RegsArm64::SetPcFromReturnAddress(Memory*) {
  if (pc() == regs_[ARM64_REG_LR]) {
    return false;
  }

  set_pc(regs_[ARM64_REG_LR]);
  return true;
}

void RegsArm64::IterateRegisters(std::function<void(const char*, uint64_t)> fn) {
  fn("x0", regs_[ARM64_REG_R0]);
  fn("x1", regs_[ARM64_REG_R1]);
  fn("x2", regs_[ARM64_REG_R2]);
  fn("x3", regs_[ARM64_REG_R3]);
  fn("x4", regs_[ARM64_REG_R4]);
  fn("x5", regs_[ARM64_REG_R5]);
  fn("x6", regs_[ARM64_REG_R6]);
  fn("x7", regs_[ARM64_REG_R7]);
  fn("x8", regs_[ARM64_REG_R8]);
  fn("x9", regs_[ARM64_REG_R9]);
  fn("x10", regs_[ARM64_REG_R10]);
  fn("x11", regs_[ARM64_REG_R11]);
  fn("x12", regs_[ARM64_REG_R12]);
  fn("x13", regs_[ARM64_REG_R13]);
  fn("x14", regs_[ARM64_REG_R14]);
  fn("x15", regs_[ARM64_REG_R15]);
  fn("x16", regs_[ARM64_REG_R16]);
  fn("x17", regs_[ARM64_REG_R17]);
  fn("x18", regs_[ARM64_REG_R18]);
  fn("x19", regs_[ARM64_REG_R19]);
  fn("x20", regs_[ARM64_REG_R20]);
  fn("x21", regs_[ARM64_REG_R21]);
  fn("x22", regs_[ARM64_REG_R22]);
  fn("x23", regs_[ARM64_REG_R23]);
  fn("x24", regs_[ARM64_REG_R24]);
  fn("x25", regs_[ARM64_REG_R25]);
  fn("x26", regs_[ARM64_REG_R26]);
  fn("x27", regs_[ARM64_REG_R27]);
  fn("x28", regs_[ARM64_REG_R28]);
  fn("x29", regs_[ARM64_REG_R29]);
  fn("sp", regs_[ARM64_REG_SP]);
  fn("lr", regs_[ARM64_REG_LR]);
  fn("pc", regs_[ARM64_REG_PC]);
}

RegsX86::RegsX86()
    : RegsImpl<uint32_t>(X86_REG_LAST, X86_REG_SP, Location(LOCATION_SP_OFFSET, -4)) {}

uint32_t RegsX86::MachineType() {
  return EM_386;
}

uint64_t RegsX86::GetAdjustedPc(uint64_t rel_pc, Elf* elf) {
  if (!elf->valid()) {
    return rel_pc;
  }

  if (rel_pc == 0) {
    return 0;
  }
  return rel_pc - 1;
}

void RegsX86::SetFromRaw() {
  set_pc(regs_[X86_REG_PC]);
  set_sp(regs_[X86_REG_SP]);
}

bool RegsX86::SetPcFromReturnAddress(Memory* process_memory) {
  // Attempt to get the return address from the top of the stack.
  uint32_t new_pc;
  if (!process_memory->Read(sp_, &new_pc, sizeof(new_pc)) || new_pc == pc()) {
    return false;
  }

  set_pc(new_pc);
  return true;
}

void RegsX86::IterateRegisters(std::function<void(const char*, uint64_t)> fn) {
  fn("eax", regs_[X86_REG_EAX]);
  fn("ebx", regs_[X86_REG_EBX]);
  fn("ecx", regs_[X86_REG_ECX]);
  fn("edx", regs_[X86_REG_EDX]);
  fn("ebp", regs_[X86_REG_EBP]);
  fn("edi", regs_[X86_REG_EDI]);
  fn("esi", regs_[X86_REG_ESI]);
  fn("esp", regs_[X86_REG_ESP]);
  fn("eip", regs_[X86_REG_EIP]);
}

RegsX86_64::RegsX86_64()
    : RegsImpl<uint64_t>(X86_64_REG_LAST, X86_64_REG_SP, Location(LOCATION_SP_OFFSET, -8)) {}

uint32_t RegsX86_64::MachineType() {
  return EM_X86_64;
}

uint64_t RegsX86_64::GetAdjustedPc(uint64_t rel_pc, Elf* elf) {
  if (!elf->valid()) {
    return rel_pc;
  }

  if (rel_pc == 0) {
    return 0;
  }

  return rel_pc - 1;
}

void RegsX86_64::SetFromRaw() {
  set_pc(regs_[X86_64_REG_PC]);
  set_sp(regs_[X86_64_REG_SP]);
}

bool RegsX86_64::SetPcFromReturnAddress(Memory* process_memory) {
  // Attempt to get the return address from the top of the stack.
  uint64_t new_pc;
  if (!process_memory->Read(sp_, &new_pc, sizeof(new_pc)) || new_pc == pc()) {
    return false;
  }

  set_pc(new_pc);
  return true;
}

void RegsX86_64::IterateRegisters(std::function<void(const char*, uint64_t)> fn) {
  fn("rax", regs_[X86_64_REG_RAX]);
  fn("rbx", regs_[X86_64_REG_RBX]);
  fn("rcx", regs_[X86_64_REG_RCX]);
  fn("rdx", regs_[X86_64_REG_RDX]);
  fn("r8", regs_[X86_64_REG_R8]);
  fn("r9", regs_[X86_64_REG_R9]);
  fn("r10", regs_[X86_64_REG_R10]);
  fn("r11", regs_[X86_64_REG_R11]);
  fn("r12", regs_[X86_64_REG_R12]);
  fn("r13", regs_[X86_64_REG_R13]);
  fn("r14", regs_[X86_64_REG_R14]);
  fn("r15", regs_[X86_64_REG_R15]);
  fn("rdi", regs_[X86_64_REG_RDI]);
  fn("rsi", regs_[X86_64_REG_RSI]);
  fn("rbp", regs_[X86_64_REG_RBP]);
  fn("rsp", regs_[X86_64_REG_RSP]);
  fn("rip", regs_[X86_64_REG_RIP]);
}

RegsMips::RegsMips()
    : RegsImpl<uint32_t>(MIPS_REG_LAST, MIPS_REG_SP, Location(LOCATION_REGISTER, MIPS_REG_RA)) {}

uint32_t RegsMips::MachineType() {
  return EM_MIPS;
}

uint64_t RegsMips::GetAdjustedPc(uint64_t rel_pc, Elf* elf) {
  if (!elf->valid()) {
    return rel_pc;
  }

  // For now, just assuming no compact branches
  if (rel_pc < 8) {
    return rel_pc;
  }
  return rel_pc - 8;
}

void RegsMips::SetFromRaw() {
  set_pc(regs_[MIPS_REG_PC]);
  set_sp(regs_[MIPS_REG_SP]);
}

bool RegsMips::SetPcFromReturnAddress(Memory*) {
  if (pc() == regs_[MIPS_REG_RA]) {
    return false;
  }

  set_pc(regs_[MIPS_REG_RA]);
  return true;
}

void RegsMips::IterateRegisters(std::function<void(const char*, uint64_t)> fn) {
  fn("r0", regs_[MIPS_REG_R0]);
  fn("r1", regs_[MIPS_REG_R1]);
  fn("r2", regs_[MIPS_REG_R2]);
  fn("r3", regs_[MIPS_REG_R3]);
  fn("r4", regs_[MIPS_REG_R4]);
  fn("r5", regs_[MIPS_REG_R5]);
  fn("r6", regs_[MIPS_REG_R6]);
  fn("r7", regs_[MIPS_REG_R7]);
  fn("r8", regs_[MIPS_REG_R8]);
  fn("r9", regs_[MIPS_REG_R9]);
  fn("r10", regs_[MIPS_REG_R10]);
  fn("r11", regs_[MIPS_REG_R11]);
  fn("r12", regs_[MIPS_REG_R12]);
  fn("r13", regs_[MIPS_REG_R13]);
  fn("r14", regs_[MIPS_REG_R14]);
  fn("r15", regs_[MIPS_REG_R15]);
  fn("r16", regs_[MIPS_REG_R16]);
  fn("r17", regs_[MIPS_REG_R17]);
  fn("r18", regs_[MIPS_REG_R18]);
  fn("r19", regs_[MIPS_REG_R19]);
  fn("r20", regs_[MIPS_REG_R20]);
  fn("r21", regs_[MIPS_REG_R21]);
  fn("r22", regs_[MIPS_REG_R22]);
  fn("r23", regs_[MIPS_REG_R23]);
  fn("r24", regs_[MIPS_REG_R24]);
  fn("r25", regs_[MIPS_REG_R25]);
  fn("r26", regs_[MIPS_REG_R26]);
  fn("r27", regs_[MIPS_REG_R27]);
  fn("r28", regs_[MIPS_REG_R28]);
  fn("sp", regs_[MIPS_REG_SP]);
  fn("r30", regs_[MIPS_REG_R30]);
  fn("ra", regs_[MIPS_REG_RA]);
  fn("pc", regs_[MIPS_REG_PC]);
}

RegsMips64::RegsMips64()
    : RegsImpl<uint64_t>(MIPS64_REG_LAST, MIPS64_REG_SP,
                         Location(LOCATION_REGISTER, MIPS64_REG_RA)) {}

uint32_t RegsMips64::MachineType() {
  return EM_MIPS;
}

uint64_t RegsMips64::GetAdjustedPc(uint64_t rel_pc, Elf* elf) {
  if (!elf->valid()) {
    return rel_pc;
  }

  // For now, just assuming no compact branches
  if (rel_pc < 8) {
    return rel_pc;
  }
  return rel_pc - 8;
}

void RegsMips64::SetFromRaw() {
  set_pc(regs_[MIPS64_REG_PC]);
  set_sp(regs_[MIPS64_REG_SP]);
}

bool RegsMips64::SetPcFromReturnAddress(Memory*) {
  if (pc() == regs_[MIPS64_REG_RA]) {
    return false;
  }

  set_pc(regs_[MIPS64_REG_RA]);
  return true;
}

void RegsMips64::IterateRegisters(std::function<void(const char*, uint64_t)> fn) {
  fn("r0", regs_[MIPS64_REG_R0]);
  fn("r1", regs_[MIPS64_REG_R1]);
  fn("r2", regs_[MIPS64_REG_R2]);
  fn("r3", regs_[MIPS64_REG_R3]);
  fn("r4", regs_[MIPS64_REG_R4]);
  fn("r5", regs_[MIPS64_REG_R5]);
  fn("r6", regs_[MIPS64_REG_R6]);
  fn("r7", regs_[MIPS64_REG_R7]);
  fn("r8", regs_[MIPS64_REG_R8]);
  fn("r9", regs_[MIPS64_REG_R9]);
  fn("r10", regs_[MIPS64_REG_R10]);
  fn("r11", regs_[MIPS64_REG_R11]);
  fn("r12", regs_[MIPS64_REG_R12]);
  fn("r13", regs_[MIPS64_REG_R13]);
  fn("r14", regs_[MIPS64_REG_R14]);
  fn("r15", regs_[MIPS64_REG_R15]);
  fn("r16", regs_[MIPS64_REG_R16]);
  fn("r17", regs_[MIPS64_REG_R17]);
  fn("r18", regs_[MIPS64_REG_R18]);
  fn("r19", regs_[MIPS64_REG_R19]);
  fn("r20", regs_[MIPS64_REG_R20]);
  fn("r21", regs_[MIPS64_REG_R21]);
  fn("r22", regs_[MIPS64_REG_R22]);
  fn("r23", regs_[MIPS64_REG_R23]);
  fn("r24", regs_[MIPS64_REG_R24]);
  fn("r25", regs_[MIPS64_REG_R25]);
  fn("r26", regs_[MIPS64_REG_R26]);
  fn("r27", regs_[MIPS64_REG_R27]);
  fn("r28", regs_[MIPS64_REG_R28]);
  fn("sp", regs_[MIPS64_REG_SP]);
  fn("r30", regs_[MIPS64_REG_R30]);
  fn("ra", regs_[MIPS64_REG_RA]);
  fn("pc", regs_[MIPS64_REG_PC]);
}

static Regs* ReadArm(void* remote_data) {
  arm_user_regs* user = reinterpret_cast<arm_user_regs*>(remote_data);

  RegsArm* regs = new RegsArm();
  memcpy(regs->RawData(), &user->regs[0], ARM_REG_LAST * sizeof(uint32_t));
  regs->SetFromRaw();
  return regs;
}

static Regs* ReadArm64(void* remote_data) {
  arm64_user_regs* user = reinterpret_cast<arm64_user_regs*>(remote_data);

  RegsArm64* regs = new RegsArm64();
  memcpy(regs->RawData(), &user->regs[0], (ARM64_REG_R31 + 1) * sizeof(uint64_t));
  uint64_t* reg_data = reinterpret_cast<uint64_t*>(regs->RawData());
  reg_data[ARM64_REG_PC] = user->pc;
  reg_data[ARM64_REG_SP] = user->sp;
  regs->SetFromRaw();
  return regs;
}

static Regs* ReadX86(void* remote_data) {
  x86_user_regs* user = reinterpret_cast<x86_user_regs*>(remote_data);

  RegsX86* regs = new RegsX86();
  (*regs)[X86_REG_EAX] = user->eax;
  (*regs)[X86_REG_EBX] = user->ebx;
  (*regs)[X86_REG_ECX] = user->ecx;
  (*regs)[X86_REG_EDX] = user->edx;
  (*regs)[X86_REG_EBP] = user->ebp;
  (*regs)[X86_REG_EDI] = user->edi;
  (*regs)[X86_REG_ESI] = user->esi;
  (*regs)[X86_REG_ESP] = user->esp;
  (*regs)[X86_REG_EIP] = user->eip;

  regs->SetFromRaw();
  return regs;
}

static Regs* ReadX86_64(void* remote_data) {
  x86_64_user_regs* user = reinterpret_cast<x86_64_user_regs*>(remote_data);

  RegsX86_64* regs = new RegsX86_64();
  (*regs)[X86_64_REG_RAX] = user->rax;
  (*regs)[X86_64_REG_RBX] = user->rbx;
  (*regs)[X86_64_REG_RCX] = user->rcx;
  (*regs)[X86_64_REG_RDX] = user->rdx;
  (*regs)[X86_64_REG_R8] = user->r8;
  (*regs)[X86_64_REG_R9] = user->r9;
  (*regs)[X86_64_REG_R10] = user->r10;
  (*regs)[X86_64_REG_R11] = user->r11;
  (*regs)[X86_64_REG_R12] = user->r12;
  (*regs)[X86_64_REG_R13] = user->r13;
  (*regs)[X86_64_REG_R14] = user->r14;
  (*regs)[X86_64_REG_R15] = user->r15;
  (*regs)[X86_64_REG_RDI] = user->rdi;
  (*regs)[X86_64_REG_RSI] = user->rsi;
  (*regs)[X86_64_REG_RBP] = user->rbp;
  (*regs)[X86_64_REG_RSP] = user->rsp;
  (*regs)[X86_64_REG_RIP] = user->rip;

  regs->SetFromRaw();
  return regs;
}

static Regs* ReadMips(void* remote_data) {
  mips_user_regs* user = reinterpret_cast<mips_user_regs*>(remote_data);
  RegsMips* regs = new RegsMips();
  uint32_t* reg_data = reinterpret_cast<uint32_t*>(regs->RawData());

  memcpy(regs->RawData(), &user->regs[MIPS32_EF_R0], (MIPS_REG_R31 + 1) * sizeof(uint32_t));

  reg_data[MIPS_REG_PC] = user->regs[MIPS32_EF_CP0_EPC];
  regs->SetFromRaw();
  return regs;
}

static Regs* ReadMips64(void* remote_data) {
  mips64_user_regs* user = reinterpret_cast<mips64_user_regs*>(remote_data);
  RegsMips64* regs = new RegsMips64();
  uint64_t* reg_data = reinterpret_cast<uint64_t*>(regs->RawData());

  memcpy(regs->RawData(), &user->regs[MIPS64_EF_R0], (MIPS64_REG_R31 + 1) * sizeof(uint64_t));

  reg_data[MIPS64_REG_PC] = user->regs[MIPS64_EF_CP0_EPC];
  regs->SetFromRaw();
  return regs;
}

// This function assumes that reg_data is already aligned to a 64 bit value.
// If not this could crash with an unaligned access.
Regs* Regs::RemoteGet(pid_t pid) {
  // Make the buffer large enough to contain the largest registers type.
  std::vector<uint64_t> buffer(MAX_USER_REGS_SIZE / sizeof(uint64_t));
  struct iovec io;
  io.iov_base = buffer.data();
  io.iov_len = buffer.size() * sizeof(uint64_t);

  if (ptrace(PTRACE_GETREGSET, pid, NT_PRSTATUS, reinterpret_cast<void*>(&io)) == -1) {
    return nullptr;
  }

  switch (io.iov_len) {
  case sizeof(x86_user_regs):
    return ReadX86(buffer.data());
  case sizeof(x86_64_user_regs):
    return ReadX86_64(buffer.data());
  case sizeof(arm_user_regs):
    return ReadArm(buffer.data());
  case sizeof(arm64_user_regs):
    return ReadArm64(buffer.data());
  case sizeof(mips_user_regs):
    return ReadMips(buffer.data());
  case sizeof(mips64_user_regs):
    return ReadMips64(buffer.data());
  }
  return nullptr;
}

static Regs* CreateFromArmUcontext(void* ucontext) {
  arm_ucontext_t* arm_ucontext = reinterpret_cast<arm_ucontext_t*>(ucontext);

  RegsArm* regs = new RegsArm();
  memcpy(regs->RawData(), &arm_ucontext->uc_mcontext.regs[0], ARM_REG_LAST * sizeof(uint32_t));
  regs->SetFromRaw();
  return regs;
}

static Regs* CreateFromArm64Ucontext(void* ucontext) {
  arm64_ucontext_t* arm64_ucontext = reinterpret_cast<arm64_ucontext_t*>(ucontext);

  RegsArm64* regs = new RegsArm64();
  memcpy(regs->RawData(), &arm64_ucontext->uc_mcontext.regs[0], ARM64_REG_LAST * sizeof(uint64_t));
  regs->SetFromRaw();
  return regs;
}

void RegsX86::SetFromUcontext(x86_ucontext_t* ucontext) {
  // Put the registers in the expected order.
  regs_[X86_REG_EDI] = ucontext->uc_mcontext.edi;
  regs_[X86_REG_ESI] = ucontext->uc_mcontext.esi;
  regs_[X86_REG_EBP] = ucontext->uc_mcontext.ebp;
  regs_[X86_REG_ESP] = ucontext->uc_mcontext.esp;
  regs_[X86_REG_EBX] = ucontext->uc_mcontext.ebx;
  regs_[X86_REG_EDX] = ucontext->uc_mcontext.edx;
  regs_[X86_REG_ECX] = ucontext->uc_mcontext.ecx;
  regs_[X86_REG_EAX] = ucontext->uc_mcontext.eax;
  regs_[X86_REG_EIP] = ucontext->uc_mcontext.eip;
  SetFromRaw();
}

static Regs* CreateFromX86Ucontext(void* ucontext) {
  x86_ucontext_t* x86_ucontext = reinterpret_cast<x86_ucontext_t*>(ucontext);

  RegsX86* regs = new RegsX86();
  regs->SetFromUcontext(x86_ucontext);
  return regs;
}

void RegsX86_64::SetFromUcontext(x86_64_ucontext_t* ucontext) {
  // R8-R15
  memcpy(&regs_[X86_64_REG_R8], &ucontext->uc_mcontext.r8, 8 * sizeof(uint64_t));

  // Rest of the registers.
  regs_[X86_64_REG_RDI] = ucontext->uc_mcontext.rdi;
  regs_[X86_64_REG_RSI] = ucontext->uc_mcontext.rsi;
  regs_[X86_64_REG_RBP] = ucontext->uc_mcontext.rbp;
  regs_[X86_64_REG_RBX] = ucontext->uc_mcontext.rbx;
  regs_[X86_64_REG_RDX] = ucontext->uc_mcontext.rdx;
  regs_[X86_64_REG_RAX] = ucontext->uc_mcontext.rax;
  regs_[X86_64_REG_RCX] = ucontext->uc_mcontext.rcx;
  regs_[X86_64_REG_RSP] = ucontext->uc_mcontext.rsp;
  regs_[X86_64_REG_RIP] = ucontext->uc_mcontext.rip;

  SetFromRaw();
}

static Regs* CreateFromX86_64Ucontext(void* ucontext) {
  x86_64_ucontext_t* x86_64_ucontext = reinterpret_cast<x86_64_ucontext_t*>(ucontext);

  RegsX86_64* regs = new RegsX86_64();
  regs->SetFromUcontext(x86_64_ucontext);
  return regs;
}

static Regs* CreateFromMipsUcontext(void* ucontext) {
  mips_ucontext_t* mips_ucontext = reinterpret_cast<mips_ucontext_t*>(ucontext);

  RegsMips* regs = new RegsMips();
  // Copy 64 bit sc_regs over to 32 bit regs
  for (int i = 0; i < 32; i++) {
      (*regs)[MIPS_REG_R0 + i] = mips_ucontext->uc_mcontext.sc_regs[i];
  }
  (*regs)[MIPS_REG_PC] = mips_ucontext->uc_mcontext.sc_pc;
  regs->SetFromRaw();
  return regs;
}

static Regs* CreateFromMips64Ucontext(void* ucontext) {
  mips64_ucontext_t* mips64_ucontext = reinterpret_cast<mips64_ucontext_t*>(ucontext);

  RegsMips64* regs = new RegsMips64();
  // Copy 64 bit sc_regs over to 64 bit regs
  memcpy(regs->RawData(), &mips64_ucontext->uc_mcontext.sc_regs[0], 32 * sizeof(uint64_t));
  (*regs)[MIPS64_REG_PC] = mips64_ucontext->uc_mcontext.sc_pc;
  regs->SetFromRaw();
  return regs;
}

Regs* Regs::CreateFromUcontext(uint32_t machine_type,
                               uint32_t machine_width, void* ucontext) {
  switch (machine_type) {
    case EM_386:
      return CreateFromX86Ucontext(ucontext);
    case EM_X86_64:
      return CreateFromX86_64Ucontext(ucontext);
    case EM_ARM:
      return CreateFromArmUcontext(ucontext);
    case EM_AARCH64:
      return CreateFromArm64Ucontext(ucontext);
    case EM_MIPS:
      if (machine_width == 32)
          return CreateFromMipsUcontext(ucontext);
      else
          return CreateFromMips64Ucontext(ucontext);
  }
  return nullptr;
}

uint32_t Regs::CurrentMachineType() {
#if defined(__arm__)
  return EM_ARM;
#elif defined(__aarch64__)
  return EM_AARCH64;
#elif defined(__i386__)
  return EM_386;
#elif defined(__x86_64__)
  return EM_X86_64;
#elif defined(__mips__)
  return EM_MIPS;
#else
  abort();
#endif
}

uint32_t Regs::GetMachineWidth() {
#if defined(__arm__)
  return 32;
#elif defined(__aarch64__)
  return 64;
#elif defined(__i386__)
  return 32;
#elif defined(__x86_64__)
  return 64;
#elif defined(__mips__) && !defined(__LP64__)
  return 32;
#elif defined(__mips__) && defined(__LP64__)
  return 64;
#else
  abort();
#endif
}

Regs* Regs::CreateFromLocal() {
  Regs* regs;
#if defined(__arm__)
  regs = new RegsArm();
#elif defined(__aarch64__)
  regs = new RegsArm64();
#elif defined(__i386__)
  regs = new RegsX86();
#elif defined(__x86_64__)
  regs = new RegsX86_64();
#elif defined(__mips__) && !defined(__LP64__)
  regs = new RegsMips();
#elif defined(__mips__) && defined(__LP64__)
  regs = new RegsMips64();
#else
  abort();
#endif
  return regs;
}

bool RegsArm::StepIfSignalHandler(uint64_t rel_pc, Elf* elf, Memory* process_memory) {
  uint32_t data;
  Memory* elf_memory = elf->memory();
  // Read from elf memory since it is usually more expensive to read from
  // process memory.
  if (!elf_memory->Read(rel_pc, &data, sizeof(data))) {
    return false;
  }

  uint64_t offset = 0;
  if (data == 0xe3a07077 || data == 0xef900077 || data == 0xdf002777) {
    // non-RT sigreturn call.
    // __restore:
    //
    // Form 1 (arm):
    // 0x77 0x70              mov r7, #0x77
    // 0xa0 0xe3              svc 0x00000000
    //
    // Form 2 (arm):
    // 0x77 0x00 0x90 0xef    svc 0x00900077
    //
    // Form 3 (thumb):
    // 0x77 0x27              movs r7, #77
    // 0x00 0xdf              svc 0
    if (!process_memory->Read(sp(), &data, sizeof(data))) {
      return false;
    }
    if (data == 0x5ac3c35a) {
      // SP + uc_mcontext offset + r0 offset.
      offset = sp() + 0x14 + 0xc;
    } else {
      // SP + r0 offset
      offset = sp() + 0xc;
    }
  } else if (data == 0xe3a070ad || data == 0xef9000ad || data == 0xdf0027ad) {
    // RT sigreturn call.
    // __restore_rt:
    //
    // Form 1 (arm):
    // 0xad 0x70      mov r7, #0xad
    // 0xa0 0xe3      svc 0x00000000
    //
    // Form 2 (arm):
    // 0xad 0x00 0x90 0xef    svc 0x009000ad
    //
    // Form 3 (thumb):
    // 0xad 0x27              movs r7, #ad
    // 0x00 0xdf              svc 0
    if (!process_memory->Read(sp(), &data, sizeof(data))) {
      return false;
    }
    if (data == sp() + 8) {
      // SP + 8 + sizeof(siginfo_t) + uc_mcontext_offset + r0 offset
      offset = sp() + 8 + 0x80 + 0x14 + 0xc;
    } else {
      // SP + sizeof(siginfo_t) + uc_mcontext_offset + r0 offset
      offset = sp() + 0x80 + 0x14 + 0xc;
    }
  }
  if (offset == 0) {
    return false;
  }

  if (!process_memory->Read(offset, regs_.data(), sizeof(uint32_t) * ARM_REG_LAST)) {
    return false;
  }
  SetFromRaw();
  return true;
}

bool RegsArm64::StepIfSignalHandler(uint64_t rel_pc, Elf* elf, Memory* process_memory) {
  uint64_t data;
  Memory* elf_memory = elf->memory();
  // Read from elf memory since it is usually more expensive to read from
  // process memory.
  if (!elf_memory->Read(rel_pc, &data, sizeof(data))) {
    return false;
  }

  // Look for the kernel sigreturn function.
  // __kernel_rt_sigreturn:
  // 0xd2801168     mov x8, #0x8b
  // 0xd4000001     svc #0x0
  if (data != 0xd4000001d2801168ULL) {
    return false;
  }

  // SP + sizeof(siginfo_t) + uc_mcontext offset + X0 offset.
  if (!process_memory->Read(sp() + 0x80 + 0xb0 + 0x08, regs_.data(),
                            sizeof(uint64_t) * ARM64_REG_LAST)) {
    return false;
  }

  SetFromRaw();
  return true;
}

bool RegsX86::StepIfSignalHandler(uint64_t rel_pc, Elf* elf, Memory* process_memory) {
  uint64_t data;
  Memory* elf_memory = elf->memory();
  // Read from elf memory since it is usually more expensive to read from
  // process memory.
  if (!elf_memory->Read(rel_pc, &data, sizeof(data))) {
    return false;
  }

  if (data == 0x80cd00000077b858ULL) {
    // Without SA_SIGINFO set, the return sequence is:
    //
    //   __restore:
    //   0x58                            pop %eax
    //   0xb8 0x77 0x00 0x00 0x00        movl 0x77,%eax
    //   0xcd 0x80                       int 0x80
    //
    // SP points at arguments:
    //   int signum
    //   struct sigcontext (same format as mcontext)
    struct x86_mcontext_t context;
    if (!process_memory->Read(sp() + 4, &context, sizeof(context))) {
      return false;
    }
    regs_[X86_REG_EBP] = context.ebp;
    regs_[X86_REG_ESP] = context.esp;
    regs_[X86_REG_EBX] = context.ebx;
    regs_[X86_REG_EDX] = context.edx;
    regs_[X86_REG_ECX] = context.ecx;
    regs_[X86_REG_EAX] = context.eax;
    regs_[X86_REG_EIP] = context.eip;
    SetFromRaw();
    return true;
  } else if ((data & 0x00ffffffffffffffULL) == 0x0080cd000000adb8ULL) {
    // With SA_SIGINFO set, the return sequence is:
    //
    //   __restore_rt:
    //   0xb8 0xad 0x00 0x00 0x00        movl 0xad,%eax
    //   0xcd 0x80                       int 0x80
    //
    // SP points at arguments:
    //   int signum
    //   siginfo*
    //   ucontext*

    // Get the location of the sigcontext data.
    uint32_t ptr;
    if (!process_memory->Read(sp() + 8, &ptr, sizeof(ptr))) {
      return false;
    }
    // Only read the portion of the data structure we care about.
    x86_ucontext_t x86_ucontext;
    if (!process_memory->Read(ptr + 0x14, &x86_ucontext.uc_mcontext, sizeof(x86_mcontext_t))) {
      return false;
    }
    SetFromUcontext(&x86_ucontext);
    return true;
  }
  return false;
}

bool RegsX86_64::StepIfSignalHandler(uint64_t rel_pc, Elf* elf, Memory* process_memory) {
  uint64_t data;
  Memory* elf_memory = elf->memory();
  // Read from elf memory since it is usually more expensive to read from
  // process memory.
  if (!elf_memory->Read(rel_pc, &data, sizeof(data)) || data != 0x0f0000000fc0c748) {
    return false;
  }

  uint16_t data2;
  if (!elf_memory->Read(rel_pc + 8, &data2, sizeof(data2)) || data2 != 0x0f05) {
    return false;
  }

  // __restore_rt:
  // 0x48 0xc7 0xc0 0x0f 0x00 0x00 0x00   mov $0xf,%rax
  // 0x0f 0x05                            syscall
  // 0x0f                                 nopl 0x0($rax)

  // Read the mcontext data from the stack.
  // sp points to the ucontext data structure, read only the mcontext part.
  x86_64_ucontext_t x86_64_ucontext;
  if (!process_memory->Read(sp() + 0x28, &x86_64_ucontext.uc_mcontext, sizeof(x86_64_mcontext_t))) {
    return false;
  }
  SetFromUcontext(&x86_64_ucontext);
  return true;
}

bool RegsMips::StepIfSignalHandler(uint64_t rel_pc, Elf* elf, Memory* process_memory) {
  uint64_t data;
  uint64_t offset = 0;
  Memory* elf_memory = elf->memory();
  // Read from elf memory since it is usually more expensive to read from
  // process memory.
  if (!elf_memory->Read(rel_pc, &data, sizeof(data))) {
    return false;
  }

  // Look for the kernel sigreturn functions.
  // __vdso_rt_sigreturn:
  // 0x24021061     li  v0, 0x1061
  // 0x0000000c     syscall
  // __vdso_sigreturn:
  // 0x24021017     li  v0, 0x1017
  // 0x0000000c     syscall
  if (data == 0x0000000c24021061ULL) {
    // vdso_rt_sigreturn => read rt_sigframe
    // offset = siginfo offset + sizeof(siginfo) + uc_mcontext offset + sc_pc offset
    offset = 24 + 128 + 24 + 8;
  } else if (data == 0x0000000c24021017LL) {
    // vdso_sigreturn => read sigframe
    // offset = sigcontext offset + sc_pc offset
    offset = 24 + 8;
  } else {
    return false;
  }

  // read sc_pc and sc_regs[32] from stack
  uint64_t values[MIPS_REG_LAST];
  if (!process_memory->Read(sp() + offset, values, sizeof(values))) {
    return false;
  }

  // Copy 64 bit sc_pc over to 32 bit regs_[MIPS_REG_PC]
  regs_[MIPS_REG_PC] = values[0];

  // Copy 64 bit sc_regs over to 32 bit regs
  for (int i = 0; i < 32; i++) {
      regs_[MIPS_REG_R0 + i] = values[1 + i];
  }

  SetFromRaw();
  return true;
}

bool RegsMips64::StepIfSignalHandler(uint64_t rel_pc, Elf* elf, Memory* process_memory) {
  uint64_t data;
  Memory* elf_memory = elf->memory();
  // Read from elf memory since it is usually more expensive to read from
  // process memory.
  if (!elf_memory->Read(rel_pc, &data, sizeof(data))) {
    return false;
  }

  // Look for the kernel sigreturn function.
  // __vdso_rt_sigreturn:
  // 0x2402145b     li  v0, 0x145b
  // 0x0000000c     syscall
  if (data != 0x0000000c2402145bULL) {
    return false;
  }

  // vdso_rt_sigreturn => read rt_sigframe
  // offset = siginfo offset + sizeof(siginfo) + uc_mcontext offset
  // read 64 bit sc_regs[32] from stack into 64 bit regs_
  if (!process_memory->Read(sp() + 24 + 128 + 40, regs_.data(),
                            sizeof(uint64_t) * (MIPS64_REG_LAST - 1))) {
    return false;
  }

  // offset = siginfo offset + sizeof(siginfo) + uc_mcontext offset + sc_pc offset
  // read 64 bit sc_pc from stack into 64 bit regs_[MIPS64_REG_PC]
  if (!process_memory->Read(sp() + 24 + 128 + 40 + 576, &regs_[MIPS64_REG_PC],
                            sizeof(uint64_t))) {
    return false;
  }

  SetFromRaw();
  return true;
}

}  // namespace unwindstack
