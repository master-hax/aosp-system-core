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

#ifndef _LIBUNWINDSTACK_UCONTEXT_H
#define _LIBUNWINDSTACK_UCONTEXT_H

#include <stdint.h>

//-------------------------------------------------------------------
// ARM ucontext structures
//-------------------------------------------------------------------
struct arm_stack_t {
  uint32_t ss_sp;                     // void __user*
  int32_t ss_flags;                   // int
  uint32_t ss_size;                   // size_t
};

struct arm_mcontext_t {
  uint32_t trap_no;                   // unsigned long
  uint32_t error_code;                // unsigned long
  uint32_t oldmask;                   // unsigned long
  uint32_t regs[ARM_REG_R15 + 1];     // unsigned long
  uint32_t cpsr;                      // unsigned long
  uint32_t fault_address;             // unsigned long
};

struct arm_ucontext_t {
  uint32_t uc_flags;                  // unsigned long
  uint32_t uc_link;                   // struct ucontext*
  arm_stack_t uc_stack;
  arm_mcontext_t uc_mcontext;
  // Nothing else is used, so don't define it.
};
//-------------------------------------------------------------------

//-------------------------------------------------------------------
// ARM64 ucontext structures
//-------------------------------------------------------------------
struct arm64_stack_t {
  uint64_t ss_sp;                     // void __user*
  int32_t ss_flags;                   // int
  uint64_t ss_size;                   // size_t
};

struct arm64_sigset_t {
  uint64_t sig;                       // unsigned long
};

struct arm64_mcontext_t {
  uint64_t fault_address;             // __u64
  uint64_t regs[ARM64_REG_PC + 1];    // __u64
  uint64_t pstate;                    // __u64
  // Nothing else is used, so don't define it.
};

struct arm64_ucontext_t {
  uint64_t uc_flags;                  // unsigned long
  uint64_t uc_link;                   // struct ucontext*
  arm64_stack_t uc_stack;
  arm64_sigset_t uc_sigmask;
  // The kernel adds extra padding after uc_sigmask to match glibc sigset_t on ARM64.
  char __padding[128 - sizeof(arm64_sigset_t)];
  arm64_mcontext_t uc_mcontext;
};
//-------------------------------------------------------------------

//-------------------------------------------------------------------
// X86 ucontext structures
//-------------------------------------------------------------------
struct x86_stack_t {
  uint32_t ss_sp;                     // void __user*
  int32_t ss_flags;                   // int
  uint32_t ss_size;                   // size_t
};

struct x86_mcontext_t {
  uint32_t regs[X86_REG_SS + 1];
  // Only care about the registers, skip everything else.
};

struct x86_ucontext_t {
  uint32_t uc_flags;                  // unsigned long
  uint32_t uc_link;                   // struct ucontext*
  x86_stack_t uc_stack;
  x86_mcontext_t uc_mcontext;
  // Nothing else is used, so don't define it.
};
//-------------------------------------------------------------------

//-------------------------------------------------------------------
// X86_64 ucontext structures
//-------------------------------------------------------------------
struct x86_64_stack_t {
  uint64_t ss_sp;                     // void __user*
  int32_t ss_flags;                   // int
  uint64_t ss_size;                   // size_t
};

struct x86_64_mcontext_t {
  uint64_t regs[X86_64_REG_CR2 + 1];
  // Only care about the registers, skip everything else.
};

typedef struct x86_64_ucontext {
  uint64_t uc_flags;                  // unsigned long
  uint64_t uc_link;                   // struct ucontext*
  x86_64_stack_t uc_stack;
  x86_64_mcontext_t uc_mcontext;
  // Nothing else is used, so don't define it.
} x86_64_ucontext_t;
//-------------------------------------------------------------------

#endif  // _LIBUNWINDSTACK_UCONTEXT_H
