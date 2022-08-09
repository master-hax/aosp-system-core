/*
 * Copyright (C) 2022 The Android Open Source Project
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

/* clang-format off */
/* see the comment in lwt_sched.h about issues and the many clang-format bugs */

#ifdef LWT_C //{
#include <sys/ucontext.h>
#endif //}

//  The ctx_t is the integral context of a thread, these comments apply to
//  all architextures.
//
//  The thread integer register context is divided into two parts, the first
//  part is what is informally referred to as a "half" context, it is not the
//  full context, the full context only has to be saved when a thread is
//  interrupted (and preempted) in an arbitrary instruction location.  When a
//  thread is preempted voluntarily, for example when waiting to acquire a
//  mutex, or waiting for a condition to occur.

#define	SIZEOF_UREG_T	8
#define	ENTRY_ALIGN_L2	5			// log2 of entry point size

#ifdef LWT_ARM64 //{

#define	OFFSET_OF_BRANCH_IN_TRAMPOLINE	60

#ifdef LWT_C //{

typedef mcontext_t		fullctx_t;
#define	fullctx_pc		pc
typedef __uint128_t		simdreg_t;

//  Cache line size constants.

#define CACHE_LINE_SIZE_L2      6
#define CACHE_LINE_SIZE         64

//  On ARM64 (without SVE) there are 32 128 bit SIMD registers, the 32 bit
//  floating point registers are held inside of them.  A non-SIMD version of
//  the floating point context could be used by threads that don't use SIMD,
//  if it is possible to disable SIMD while allowing FP to still be used
//  and if it is practical to do so.  TODO review SIMD / FP separation.
//
//  TODO: add support for SVE context.

typedef struct {
	ureg_t		fpctx_magic_size;
	ureg_t		fpctx_fpsr_fpcr;
	simdreg_t	fpctx_q0;
	simdreg_t	fpctx_q1;
	simdreg_t	fpctx_q2;
	simdreg_t	fpctx_q3;
	simdreg_t	fpctx_q4;
	simdreg_t	fpctx_q5;
	simdreg_t	fpctx_q6;
	simdreg_t	fpctx_q7;
	simdreg_t	fpctx_q8;
	simdreg_t	fpctx_q9;
	simdreg_t	fpctx_q10;
	simdreg_t	fpctx_q11;
	simdreg_t	fpctx_q12;
	simdreg_t	fpctx_q13;
	simdreg_t	fpctx_q14;
	simdreg_t	fpctx_q15;
	simdreg_t	fpctx_q16;
	simdreg_t	fpctx_q17;
	simdreg_t	fpctx_q18;
	simdreg_t	fpctx_q19;
	simdreg_t	fpctx_q20;
	simdreg_t	fpctx_q21;
	simdreg_t	fpctx_q22;
	simdreg_t	fpctx_q23;
	simdreg_t	fpctx_q24;
	simdreg_t	fpctx_q25;
	simdreg_t	fpctx_q26;
	simdreg_t	fpctx_q27;
	simdreg_t	fpctx_q28;
	simdreg_t	fpctx_q29;
	simdreg_t	fpctx_q30;
	simdreg_t	fpctx_q31;
} fpctx_t;

//  The ctx_t register context is a subset prefix of the sigcontext structure,
//  its fields are 1-to-1 with the fields of sigcontext, the __reserved[4096]
//  byte array field is ommitted.  This type is used instead of sigcontext
//  because those 4K of reserved space that would go unsued when a ctx_t is
//  declared as a variable on the stack and used to store a "half" context.

//  The sigreturn optional data area (where fpsimd_context would be stored),
//  __reserved array at the end of sigreturn is not part of ctx_t.  The data
//  within it, is represented in other ways.  The __reserved area is already
//  too small for large SVE vectors, hardwiring a fixed sized reserved area
//  is a mistake for the LWT implementation.

//  The context is split into two areas, the "half" context and the "rest" of
//  the context, together they make a "full" context. To keep ctx_t a prefix of
//  sigcontext, the "rest" area is first.  The address of the ctx_t is chosen
//  so that its first three ureg_t are the last three ureg_t of a cache line.
//  This makes the subsequent 32 ureg_t into 4 groups, each cache aligned.

typedef struct {

	//  This is the "rest" of the context.

	ureg_t		 ctx_faultaddr;
	ureg_t		 ctx_x0;	// [x0, x1]
	ureg_t		 ctx_x1;

	ureg_t		 ctx_x2;	// [x2, x3]
	ureg_t		 ctx_x3;
	ureg_t		 ctx_x4;	// [x4, x5]
	ureg_t		 ctx_x5;
	ureg_t		 ctx_x6;	// [x6, x7]
	ureg_t		 ctx_x7;
	ureg_t		 ctx_x8;	// [x8, x9]
	ureg_t		 ctx_x9;

	//  This part is the "half" context.
	//
	//  The first 8 are floating point registers that are callee saved.
	//  In a "half" context d8-d15 are stored in the location for x10-x17
	//  which is not used in a "half" context.  In a half context only the
	//  low 64 bits of v8-v15 need to be saved, those low halves are saved
	//  more efficiently in a single cache line by storing them here.
	//
	//  Last 16 are general purpose registers that are callee saved,
	//  keeping these 16 together puts them in two cache lines.

	ureg_t		 ctx_x10;	// [x10, x11] or [d8, d9]
	ureg_t		 ctx_x11;
	ureg_t		 ctx_x12;	// [x12, x13] or [d10, d11]
	ureg_t		 ctx_x13;
	ureg_t		 ctx_x14;	// [x14, x15] or [d12, d13]
	ureg_t		 ctx_x15;
	ureg_t		 ctx_x16;	// [x16, x17] or [d14, d15]
	ureg_t		 ctx_x17;

	ureg_t		 ctx_x18;	// [x18, x19]
	ureg_t		 ctx_x19;
	ureg_t		 ctx_x20;	// [x20, x21]
	ureg_t		 ctx_x21;
	ureg_t		 ctx_x22;	// [x22, x23]
	ureg_t		 ctx_x23;
	ureg_t		 ctx_x24;	// [x24, x25]
	ureg_t		 ctx_x25;

	ureg_t		 ctx_x26;	// [x26, x27]
	ureg_t		 ctx_x27;
	ureg_t		 ctx_x28;	// [x28, x29]
	ureg_t		 ctx_x29;
        ureg_t		 ctx_x30;	// [x30, sp]
	ureg_t		 ctx_sp;
        ureg_t		 ctx_pc;	// [pc, pstate]
	ureg_t		 ctx_pstate;

	ureg_t		 ctx_pad;	// pad prior to __reserved[4096]
					// in struct sigcontext
} ctx_t;

#define	ctx_start_arg	ctx_x19
#define	ctx_start_func	ctx_x20
#define	ctx_start_pc	ctx_x21

#else //}{ !LWT_C

#define	reg_start_arg	x19
#define	reg_start_func	x20
#define	reg_start_pc	x21

#define	ctx_d8		ctx_x10
#define	ctx_d9		ctx_x11
#define	ctx_d10		ctx_x12
#define	ctx_d11		ctx_x13
#define	ctx_d12		ctx_x14
#define	ctx_d13		ctx_x15
#define	ctx_d14		ctx_x16
#define	ctx_d15		ctx_x17

#endif //} !LWT_C
#endif //} LWT_ARM64

#ifdef LWT_X64 //{

#define	OFFSET_OF_BRANCH_IN_TRAMPOLINE	56	// TODO

#ifdef LWT_C //{

typedef struct sigcontext	fullctx_t;
#define	fullctx_pc		rip

#define CACHE_LINE_SIZE_L2      6
#define CACHE_LINE_SIZE         64

typedef struct _libc_fpstate	fpctx_t;

typedef struct {
	//  This part is the "half" context.
	//
	//  First 8 are callee saved, keeping these 8 together puts them
	//  in two cache lines. The ctx_fpctx is among those 8 so that FP
	//  context, if any can be restored without touching the rest of this
	//  structure.
	//
	//  Newly created threads use a trampoline function (__lwt_thr_start)
	//  to adjust their context, the argument is found in ctx_rbp and the
	//  actual function address in ctx_rbx also known as ctx_start_pc
	//  and ctx_start_arg in portable code.

	fpctx_t		*ctx_fpctx;
	ureg_t		 ctx_pc;
	ureg_t		 ctx_sp;
	ureg_t		 ctx_rbp;
	ureg_t		 ctx_rbx;
	ureg_t		 ctx_r12;
	ureg_t		 ctx_r13;
	ureg_t		 ctx_r14;
	ureg_t		 ctx_r15;	// one past the end of the cache line

	//  This is the rest of the context.

	ureg_t		 ctx_flags;
	ureg_t		 ctx_rax;
	ureg_t		 ctx_rcx;
	ureg_t		 ctx_rdx;
	ureg_t		 ctx_rdi;
	ureg_t		 ctx_rsi;
	ureg_t		 ctx_r8;
	ureg_t		 ctx_r9;
	ureg_t		 ctx_r10;
	ureg_t		 ctx_r11;
} ctx_t;

#define	ctx_start_arg	ctx_rbp
#define	ctx_start_func	ctx_rbx
#define	ctx_start_pc	ctx_r12

#else //}{ !LWT_C

#define	reg_start_arg	rbp
#define	reg_start_func	rbx
#define	reg_start_pc	r12

#endif //} !LWT_C
#endif //} LWT_X64

#ifdef LWT_C //{

//  uptr atomic operations

#if 0 //{
uptr_t uptr_load_acq(uptr_atom_t *m);

inline_only void uptr_store_rel(uptr_atom_t *m, uptr_t v)
{
	__asm__ volatile(
		"stlr	%1, %0"
		: "=m"(*m)
		: "r"(v), "r"(m));
}

inline_only void uptr_store_zero_rel(uptr_atom_t *m)
{
	__asm__ volatile(
		"stlr	xzr, %0"
		: "=m"(*m)
		: "r"(m));
}

inline_only uptr_t uptr_comp_and_swap_acq(uptr_t old, uptr_t new,
					  uptr_atom_t *m)
{
	__asm__ volatile(
		"casa	%0, %2, %1"
		: "+&r"(old), "+Q"(*(uptr_t *)m)
		: "r"(new), "r"(m));
	return old;
}

inline_only uptr_t uptr_comp_and_swap_acq_rel(uptr_t old, uptr_t new,
					      uptr_atom_t *m)
{
	__asm__ volatile(
		"casal	%0, %2, %1"
		: "+&r"(old), "+Q"(*(uptr_t *)m)
		: "r"(new), "r"(m));
	return old;
}
#endif //}

#ifdef LWT_ARM64 //{

//  ARM64 opcodes are 32 bit wide.  The unconditional branch instruction is
//  PC relative, it reaches instructions in the range: [-128MB, 128MB - 4].
//  The 26 bit offset field stores a signed two's complement value.  Because
//  instructions are 32 bit wide, the value doesn't need to store the 2 least
//  significant bits.
//
//   3 3 2 2 2 2 2 2 2 2 2 2 1 1 1 1 1 1 1 1 1 1 0 0 0 0 0 0 0 0 0 0 
//   1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0
//  +-----------+---+-------+-------+-------+-------+-------+-------+
//  |0 0 0 1 0 1|x x X X X X x x x x X X X X x x x x X X X X x x x x|
//  +-----------+---+-------+-------+-------+-------+-------+-------+

typedef u32_t			opcode_t;

#define	BRANCH_ADDR_SHIFT	26
#define	BRANCH_ADDR_MASK	((1u << BRANCH_ADDR_SHIFT) - 1u)
#define	BRANCH_OPCODE		(0b000101u << BRANCH_ADDR_SHIFT)

#define	OPCODE_SIZE_SHIFT	2

//  Generate a branch instruction at location instaddr, the branch target's
//  address is targetaddr.  When a full context is restored, a small trampoline
//  that is context specific is generated, the last instruction in it is the
//  generated branch.  If the targetaddr is too far from the address of the
//  instruction to be generated an error is returned and the branch is not
//  generated.

//  All the address computation is done with signed arithmetic in register
//  sized values.

inline_only bool inst_reachable(ureg_t targetaddr, ureg_t instaddr)
{
	sreg_t pc = (sreg_t) targetaddr;
	sreg_t ia = (sreg_t) instaddr;

	//  TODO: the targetaddr is not exact yet, the cpu has not been chosen
	//  so reachability should be to both ends of the trampoline area not
	//  a specific branch location for a specific CPU, this only matters
	//  when the thread might run on a CPU other than the one from where
	//  it was preempted.

	//  Set delta to the distance, in instructions instead of bytes,
	//  between the target program counter and the instruction address.
	//  If the target program counter is after the instruction address
	//  delta will be a positive value.  If it is before, it will be a
	//  negative value.

	sreg_t delta = (pc - ia) >> OPCODE_SIZE_SHIFT;

	//  A signed shift by the number of bits in the branch offset field
	//  minus one (to preserve the sign bit of offset field) results in
	//  high being:
	//
	//    - 64 zeroes, when pc >= ia, and the distance between them
	//      fits in the 26 bits of the branch offset.  The values of:
	//		(pc >= ia) == 1
	//		high + 1 == 1
	//
	//    - 64 ones, when pc < ia, and the distance between them fits
	//      the 26 bits of the branch offset.
	//		(pc >= ia) == 0
	//		high + 1 == 0
	//
	//  Thus the single "if" tests for both cases.  The generated code
	//  results in a single branch, (the computation of pc >= ia into 1
	//  or 0 is done by a compare and a cset (conditional set) instruction,
	//  i.e. without branching to compute the 1 or 0 value.

	sreg_t high = delta >> (BRANCH_ADDR_SHIFT - 1);
	return ((sreg_t) (pc >= ia)) == high + 1;
}

inline_only void generate_branch(ureg_t targetaddr, ureg_t instaddr)
{
	sreg_t pc = (sreg_t) targetaddr;
	sreg_t ia = (sreg_t) instaddr;
	sreg_t delta = (pc - ia) >> OPCODE_SIZE_SHIFT;
	opcode_t offset = BRANCH_ADDR_MASK & (opcode_t) delta;
	opcode_t opcode = BRANCH_OPCODE | offset;

	//  I/D cache coherency with respect to this code modification is
	//  done at ctx_load() time.  TODO: this istruction generation should
	//  be moved there, or the cache coherency should be moved here.

	*(opcode_t *) ia = opcode;
}

#endif //}

#ifdef LWT_X64 //{

inline_only bool inst_reachable(ureg_t targetaddr, ureg_t instaddr)
{
	//  X64 signal context is complex and non-trivially encoded, for now,
	//  don't implement reloading full context in user mode, this will
	//  cause its reloaded through the sigreturn context reloading path.

	return false;
}

inline_only void generate_branch(ureg_t targetaddr, ureg_t instaddr)
{
	*(volatile ureg_t *) 0x10 = 0xDEADBEEFu;
}

#endif //}

inline_only bool uregx2_equal(uregx2_t a, uregx2_t b)
{
	return ((a.low ^ b.low) | (a.high ^ b.high)) == 0;
}

inline_only uregx2_t uregx2_load(uregx2_t *m) {
	return *m;
}

//  uregx2_t atomic operations

#ifdef LWT_ARM64 //{

inline_only uregx2_t uregx2_comp_and_swap_acq_rel(uregx2_t old, uregx2_t new,
						  uregx2_t *m)
{
	//  Choosing the registers to be register pairs starting at
	//  even register numbers is not properly done by gcc-11

	register ureg_t old_low  __asm__("x0") = old.low;
	register ureg_t old_high __asm__("x1") = old.high;
	register ureg_t new_low  __asm__("x2") = new.low;
	register ureg_t new_high __asm__("x3") = new.high;

	//  Without volatile the compiler sometimes wants to use register
	//  displament addressing: [xN,offset] which is invalid for caspal,
	//  this ensures that the pointer m is in register p.

	register uregx2_t *volatile p = m;

	__asm__ volatile("caspal	%0, %1, %3, %4, %2" // "+Q" vs "+m" ?
			 : "+&r"(old_low), "+&r"(old_high), "+m"(*(uregx2_t *)p)
			 : "r"(new_low), "r"(new_high), "r"(p));
	return (uregx2_t) {.low = old_low, .high = old_high};
}

#endif //}

#ifdef LWT_X64 //{

typedef u8_t			opcode_t;

inline_only uregx2_t uregx2_comp_and_swap_acq_rel(uregx2_t old, uregx2_t new,
						  uregx2_t *m)
{
	register ureg_t old_low  __asm__("rax") = old.low;
	register ureg_t old_high __asm__("rdx") = old.high;
	register ureg_t new_low  __asm__("rbx") = new.low;
	register ureg_t new_high __asm__("rcx") = new.high;
	__asm__ volatile("lock; cmpxchg16b	%2"
			 : "+&r"(old_low), "+&r"(old_high), "+m"(*(uregx2_t *)m)
			 : "r"(new_low), "r"(new_high));
	return (uregx2_t) {.low = old_low, .high = old_high};
}

#ifdef LWT_X64_USE_GS //{

inline_only void cpu_current_set_x64(cpu_t **cpu)
{
	register ureg_t gsb  __asm__("rdi") = (ureg_t) cpu;
	__asm__ volatile("wrgsbase      %0" : : "r"(gsb) : "memory");

}

inline_only cpu_t *cpu_current()
{
	register ureg_t reg  __asm__("rax");
	__asm__ volatile("mov %%gs:0, %0" : "=r"(reg));
	return (cpu_t *) reg;
}

#endif //}

#endif //}

#endif //}
