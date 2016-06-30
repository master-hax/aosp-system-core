/*
 * Copyright (C) 2016 The Android Open Source Project
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *  * Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *  * Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
 * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
 * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <elf.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/uio.h>

#include <vector>

#include "Elf.h"
#include "Regs.h"
#include "User.h"

Regs* ReadX86(void* remote_data) {
  x86_user_regs* user = reinterpret_cast<x86_user_regs*>(remote_data);

  Regs32* regs = new Regs32(X86_REG_PC, X86_REG_SP, X86_REG_LAST);
  (*regs)[X86_REG_EAX] = user->eax;
  (*regs)[X86_REG_EBX] = user->ebx;
  (*regs)[X86_REG_ECX] = user->ecx;
  (*regs)[X86_REG_EDX] = user->edx;
  (*regs)[X86_REG_EBP] = user->ebp;
  (*regs)[X86_REG_EDI] = user->edi;
  (*regs)[X86_REG_ESI] = user->esi;
  (*regs)[X86_REG_ESP] = user->esp;
  (*regs)[X86_REG_EIP] = user->eip;

  return regs;
}

Regs* ReadX86_64(void* remote_data) {
  x86_64_user_regs* user = reinterpret_cast<x86_64_user_regs*>(remote_data);

  Regs64* regs = new Regs64(X86_64_REG_PC, X86_64_REG_SP, X86_64_REG_LAST);
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

  return regs;
}

Regs* ReadArm(void* remote_data) {
  arm_user_regs* user = reinterpret_cast<arm_user_regs*>(remote_data);

  Regs32* regs = new Regs32(ARM_REG_PC, ARM_REG_SP, ARM_REG_LAST);
  memcpy(regs->raw_data(), &user->regs[0], ARM_REG_LAST * sizeof(uint32_t));

  return regs;
}

Regs* ReadArm64(void* remote_data) {
  arm64_user_regs* user = reinterpret_cast<arm64_user_regs*>(remote_data);

  Regs64* regs = new Regs64(ARM64_REG_PC, ARM64_REG_SP, ARM64_REG_LAST);
  memcpy(regs->raw_data(), &user->regs[0], (ARM64_REG_R31 + 1) * sizeof(uint64_t));
  (*regs)[ARM64_REG_SP] = user->sp;
  (*regs)[ARM64_REG_PC] = user->pc;

  return regs;
}

// This function assumes that reg_data is already aligned to a 64 bit value.
// If not this could crash with an unaligned access.
Regs* RemoteGetRegs(pid_t pid) {
  // Make the buffer large enough to contain the biggest regs.
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
  }
  return nullptr;
}
