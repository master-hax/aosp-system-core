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

#include "lwt_config.h"
#ifdef LWT_ARM64 //{
#include "lwt_asm_gen_arm64.h"
#endif //}
#ifdef LWT_X64 //{
#include "lwt_asm_gen_x64.h"
#endif //}
#include "lwt_arch.h"

#define FUNCTION_START_WITH_ALIGN(name, align)				\
        .text; .p2align align; .global name; .type name, %function; name:    

#define FUNCTION_START(name)						\
	FUNCTION_START_WITH_ALIGN(name, 2)

#define FUNCTION_END(name)						\
        .size name, .-name

#ifdef LWT_ARM64 //{

//  This function returns twice, once when called, in which case it returns
//  a non-zero value, x0 which can not be zero.  The second time it returns
//  to its caller is when the context is restored, in which case it returns
//  zero.  The context is restored by __lwt_ctx_load() which does not return.
//
//  two_returns ureg_t __lwt_ctx_save(ctx_t *ctx);

FUNCTION_START(__lwt_ctx_save)
	mov	x17, sp				// sp can not be used with stp

	//  only low 64 bits of simd registers need to be saved

	stp	d8,  d9,  [x0, ctx_d8]
	stp	d10, d11, [x0, ctx_d10]
	stp	d12, d13, [x0, ctx_d12]
	stp	d14, d15, [x0, ctx_d14]

	stp	x18, x19, [x0, ctx_x18]
	stp	x20, x21, [x0, ctx_x20]
	stp	x22, x23, [x0, ctx_x22]
	stp	x24, x25, [x0, ctx_x24]

	stp	x26, x27, [x0, ctx_x26]
	stp	x28, x29, [x0, ctx_x28]
	stp	x30, x17, [x0, ctx_x30]		// [return address, sp]
	stp	x30, xzr, [x0, ctx_pc]		// [pc, pstate]
						// zero pstate means half ctx

	mov	x0,  1				// CTX_SAVED
	ret
FUNCTION_END(__lwt_ctx_save)

//  These functions must not use the run-time (thread or cpu) stack.

//  noreturn void __lwt_ctx_load(thr_t *thr,			x0
//				 ctx_t *ctx,			x1
//				 ctx_t *cpuctx,			x2
//				 bool *new_running,		x3
//				 bool enabled,			x4
//				 bool *curr_running);		x5
//  noreturn void __lwt_ctx_load_on_cpu(thr_t *thr,		x0
//					ctx_t *ctx,		x1
//					ctx_t *cpuctx,		x2
//					bool *new_running,	x3
//					bool enabled);		x4
//  noreturn void __lwt_ctx_load_idle_cpu(bool *curr_running,	x0
//					  ctx_t *ctx);		x1
//
//  new_running and curr_running are updated with these instructions:
//	stlrb - store release register byte
//	ldarb - load acquire register byte
//
//  Storing 0 in curr_running with a store release ensures that all prior
//  stores, particularly the ones that save the register in the ctx_t, are
//  visible to other CPUs by the time they perform their corresponding load
//  acquire thourgh new_running, and loop on that memory location until the
//  value is 0, that transition from 1 to 0 indicates that the thread is no
//  longer running in the other CPU and can now start running on this CPU.

#define	RETRY_COUNT	256

FUNCTION_START(__lwt_ctx_load_idle_cpu)
	stlrb	wzr, [x0]		// current thread is no longer running
	mov	x2,  x1			// x2 = cpuctx
	mov	x4,  0			// x4 = enabled = false
	b	2f
FUNCTION_END(__lwt_ctx_load_idle_cpu)

FUNCTION_START(__lwt_ctx_load)
	stlrb	wzr, [x5]		// current thread is no longer running
FUNCTION_END(__lwt_ctx_load)

FUNCTION_START(__lwt_ctx_load_on_cpu)
	mov	w5, RETRY_COUNT

1:	ldarb	w6, [x3]		// loop while new thr is running ...
	sub	w5, w5, 1
	cbz	w5, 4f
	cbnz	w6, 1b			// ... in another cpu
	mov	w6, 1
	stlrb	w6, [x3]		// new thr is now running on this cpu

2:	mov	x0, 0			// return value, zero is 2nd return

3:	ldp	x6,  x7,  [x1, ctx_pc]	// get [pc, pstate] as early as possible
	ldp	x26, x27, [x1, ctx_x26]
	ldp	x28, x29, [x1, ctx_x28]
	ldp	x30, x8,  [x1, ctx_x30]	// [x30, sp] can not use sp here

	ldp	x18, x19, [x1, ctx_x18]
	ldp	x20, x21, [x1, ctx_x20]
	ldp	x22, x23, [x1, ctx_x22]
	ldp	x24, x25, [x1, ctx_x24]
	cbnz	x7,  ctx_load_rest	// pstate == zero, means "half" context

	//  restore low 64 bits of simd registers for half context load

	ldp	d8,  d9,  [x1, ctx_d8]
	ldp	d10, d11, [x1, ctx_d10]
	ldp	d12, d13, [x1, ctx_d12]
	ldp	d14, d15, [x1, ctx_d14]
	mov	sp,  x8			// MUST change sp last, ctx_t for thread
					// start might be clobbered otherwise by
					// signal handlers (e.g. ktimer_signal)
	strb	w4,  [x2, ENABLED_FROM_CPUCTX]	// cpu->cpu_enabled = w4
	br	x6

4:	// x0 is thr, its the 2nd return value, returned to cpu_main()
	mov	x1,  x2			// switch to cpu_main() to handle thr
	mov	x4,  0			// ensure cpu->cpu_enabled becomes false
	b	3b			// thr->thr_running was set too long

ctx_load_rest:
	//  Restore rest of full context

	ldr	x0, [x2, TRAMPOLINE_FROM_CPUCTX]
					// x0 = cpu->cpu_trampoline
	add	x3, x1, SIZEOF_ctx_t	// x3 = (fpctx_t *)
					//      &(((struct sigcontext *)
					//	   ctx)->__reserved[0])
	add	x5, x0, OFFSET_OF_BRANCH_IN_TRAMPOLINE

	//  Restore rest of full context, registers restored at this point:
	//	x18-x30, sp
	//  Other register values:
	//	x0: trampoline
	//	x1: ctx
	//	x2: cpuctx
	//	x3: fpctx
	//	x4: enabled
	//	x5: address of branch in trampoline
	//	x6: pc
	//	x7: pstate
	//	x8: sp
	//  Registers that need to be restored:
	//	pc, x0-x17, nzcv, fpcr, fpsr, q0-q31

	//  The following 4 instructions are from the example code in:
	//	"Arm Architecture Reference Manual for A-profile architecture"
	//  (the comments are based on the comments there).
	//
	//  DDI0487H_a_a-profile_architecture_reference_manual.pdf
	//  Document: ARM DDI 0487H.a ID020222
	//  B2.2.5 Concurrent modification and execution of instructions
	//  (page: B2-154)
	//
	//	"Coherency example for data and instruction accesses within
	//	 the same Inner Shareable domain."
	//
	//  The branch instruction occurs earlier in C code. Might be moved
	//  here (in that case the reachability error checking and code
	//  generation would have to be separated).

	dc	cvau, x5	// Clean D-cache by VA to Point or Unitication
	dsb	ish		// Ensure visibility of the cleaned data
	ic	ivau, x5	// Invalidate I-cache cache by VA to PoU
	dsb	ish

	ldp	w9,  w10,  [x3, fpctx_fpsr_fpcr]

	msr	nzcv, x7
	msr	fpsr, x9
	msr	fpcr, x10

	ldp	q0,  q1,  [x3, fpctx_q0]
	ldp	q2,  q3,  [x3, fpctx_q2]
	ldp	q4,  q5,  [x3, fpctx_q4]
	ldp	q6,  q7,  [x3, fpctx_q6]

	ldp	x10, x11, [x1, ctx_x10]
	ldp	x12, x13, [x1, ctx_x12]
	ldp	x14, x15, [x1, ctx_x14]
	ldp	x16, x17, [x1, ctx_x16]

	ldp	q8,  q9,  [x3, fpctx_q8]
	ldp	q10, q11, [x3, fpctx_q10]
	ldp	q12, q13, [x3, fpctx_q12]
	ldp	q14, q15, [x3, fpctx_q14]

	br	x0			// Branch to trampoline
FUNCTION_END(__lwt_ctx_load_on_cpu)

FUNCTION_START(__lwt_ctx_load_trampoline)
	//  The generated trampoline code is based on this sample code,
	//  the "b loop" below is patched to branch to the correct location.

	//  The trampoline could just be the last 2 instructions at the end.
	//  Having it be 16 instructions allows the branch to the trampoline
	//  to be far enough away from the patch branch below to allow the
	//  patched branch to be fetched and decoded while the instructions
	//  in between are issued.  The trampolines are cache line sized and
	//  cache line aligned (they are per-CPU), 

	ldp	q16, q17, [x3, fpctx_q16]
	ldp	q18, q19, [x3, fpctx_q18]
	ldp	q20, q21, [x3, fpctx_q20]
	ldp	q22, q23, [x3, fpctx_q22]

	ldp	q24, q25, [x3, fpctx_q24]
	ldp	q26, q27, [x3, fpctx_q26]
	ldp	q28, q29, [x3, fpctx_q28]
	ldp	q30, q31, [x3, fpctx_q30]

	strb	w4,  [x2, ENABLED_FROM_CPUCTX]	// cpu->cpu_enabled = w4
	ldp	x2,  x3,  [x1, ctx_x2]
	ldp	x4,  x5,  [x1, ctx_x4]
	ldp	x6,  x7,  [x1, ctx_x6]
	mov	sp,  x8
	ldp	x8,  x9,  [x1, ctx_x8]

	ldp	x0,  x1,  [x1, ctx_x0]
patch:	b	patch
FUNCTION_END(__lwt_ctx_load_trampoline)

#	if OFFSET_OF_BRANCH_IN_TRAMPOLINE != 60
#	error "OFFSET_OF_BRANCH_IN_TRAMPOLINE is incorrect"
#	endif

//  bool __lwt_bool_load_acq(bool *m);

FUNCTION_START(__lwt_bool_load_acq)
	ldarb	w0, [x0]
	ret
FUNCTION_END(__lwt_bool_load_acq)

//  void __lwt_bool_store_rel(bool *m, bool b);

FUNCTION_START(__lwt_bool_store_rel)
	stlrb	w1, [x0]
	ret
FUNCTION_END(__lwt_bool_store_rel)

//  ureg_t __lwt_ureg_load_acq(ureg_t *m);

FUNCTION_START(__lwt_ureg_load_acq)
	ldar	x0, [x0]
	ret
FUNCTION_END(__lwt_ureg_load_acq)

//  ureg_t __lwt_ureg_atomic_or_acq_rel(ureg_t *m, ureg_t v);

FUNCTION_START(__lwt_ureg_atomic_or_acq_rel)
	ldsetal	x1, x0, [x0]
	ret
FUNCTION_END(__lwt_ureg_atomic_or_acq_rel)

//  ureg_t __lwt_ureg_atomic_add_unseq(ureg_t *m, ureg_t v);

FUNCTION_START(__lwt_ureg_atomic_add_unseq)
	ldadd	x0, x1, [x0]
	ret
FUNCTION_END(__lwt_ureg_atomic_add_unseq)

//  See ctx_init() to understand the register inputs to this function.

FUNCTION_START(__lwt_start_glue)
	mov	x0, reg_start_arg		// arg0
	mov	x1, reg_start_func		// arg1
	br	reg_start_pc
FUNCTION_END(__lwt_start_glue)
 
FUNCTION_START(__lwt_get_fpcr)
	mrs	x0, fpcr
	ret
FUNCTION_END(__lwt_get_fpcr)
FUNCTION_START(__lwt_set_fpcr)
	msr	fpcr, x0
	ret
FUNCTION_END(__lwt_set_fpcr)
 
FUNCTION_START(__lwt_get_fpsr)
	mrs	x0, fpsr
	ret
FUNCTION_END(__lwt_get_fpsr)
FUNCTION_START(__lwt_set_fpsr)
	msr	fpsr, x0
	ret
FUNCTION_END(__lwt_set_fpsr)
 
FUNCTION_START(__lwt_get_nzcv)
	mrs	x0, nzcv
	ret
FUNCTION_END(__lwt_get_nzcv)
FUNCTION_START(__lwt_set_nzcv)
	msr	nzcv, x0
	ret
FUNCTION_END(__lwt_set_nzcv)

#endif //}

#ifdef LWT_X64 //{

//  This function returns twice, once when called, in which case it returns
//  a non-zero value in %rax.  The second time it returns to its caller is
//  when the context is restored, in which case it returns zero.  The context
//  is restored by __lwt_ctx_load() which does not return.
//
//  two_returns ureg_t __lwt_ctx_save(ctx_t *ctx);

FUNCTION_START(__lwt_ctx_save)
	movq	$0, ctx_fpctx(%rdi)
	popq	%rsi				// return address
	movq	$1, %rax			// CTX_SAVED
	movq	%rsp, ctx_sp(%rdi)
	movq	%rbp, ctx_rbp(%rdi)
	movq	%rbx, ctx_rbx(%rdi)
	movq	%r12, ctx_r12(%rdi)
	movq	%r13, ctx_r13(%rdi)
	movq	%r14, ctx_r14(%rdi)
	movq	%r15, ctx_r15(%rdi)
	movq	%rsi, ctx_pc(%rdi)		// save return address
	jmp	*%rsi
FUNCTION_END(__lwt_ctx_save)

//  noreturn void __lwt_ctx_load(thr_t *thr,			rdi
//				 ctx_t *ctx,			rsi
//				 ctx_t *cpuctx,			rdx
//				 bool *new_running,		rcx
//				 bool enabled,			r8
//				 bool *curr_running);		r9
//  noreturn void __lwt_ctx_load_on_cpu(thr_t *thr,		rdi
//					ctx_t *ctx,		rsi
//					ctx_t *cpuctx,		rdx
//					bool *new_running,	rcx
//					bool enabled);		r8
//  noreturn void __lwt_ctx_load_idle_cpu(bool *curr_running,	rdi
//					  ctx_t *ctx);		rsi

#define	RETRY_COUNT	256

FUNCTION_START(__lwt_ctx_load_idle_cpu)
	movb	$0, (%rdi)		// current thread is no longer running
	movq	%rsi, %rdx		// rdx = cpuctx
	movl	$0, %r8d		// r8 = enabled = false
	jmp	2f
FUNCTION_END(__lwt_ctx_load_idle_cpu)
FUNCTION_START(__lwt_ctx_load)
	movb	$0, (%r9)		// current thread is no longer running
FUNCTION_END(__lwt_ctx_load)
FUNCTION_START(__lwt_ctx_load_on_cpu)
	movq	$RETRY_COUNT, %r10
1:	movzbl	(%rcx), %eax
	subq	$1, %r10
	je	4f
	testb	%al, %al		// loop while new thr is running ...
	jne	1b			// ... in another cpu
	movb	$1, (%rcx)		// new thr is now running on this cpu
2:	xor	%rax, %rax		// return value, zero is 2nd return
3:	movq	ctx_fpctx(%rsi), %rcx
	movq	ctx_pc(%rsi),  %rdi
	movq	ctx_rbp(%rsi), %rbp
	movq	ctx_rbx(%rsi), %rbx
	movq	ctx_r12(%rsi), %r12
	movq	ctx_r13(%rsi), %r13
	movq	ctx_r14(%rsi), %r14
	movq	ctx_r15(%rsi), %r15
	testq	%rcx, %rcx
	jne	ctx_load_rest
	movq	ctx_sp(%rsi), %rsp	// MUST change sp last, ctx_t for thread
					// start might be clobbered otherwise by
					// signal handlers (e.g. ktimer_signal)
	movb	%r8b, ENABLED_FROM_CPUCTX(%rdx)	// cpu->cpu_enabled = r8
	jmp	*%rdi			// rax == 0, 2nd __lwt_ctx_save return

4:	// rax is thr, its the 2nd return value, returned to cpu_main()
	mov	%rdi, %rax
	mov	%rdx, %rsi		// switch to cpu_main() to handle thr
	movl	$0, %r8d		// ensure cpu->cpu_enabled becomes false
	jmp	3b			// thr->thr_running was set too long
ctx_load_rest:
	//  Restore rest of full context
	movq	$0, %rcx
	movq	$0, (%rcx)			// TODO cause an exception
	movq	ctx_sp(%rsi), %rsp		// MUST be last
FUNCTION_END(__lwt_ctx_load_on_cpu)
FUNCTION_START(__lwt_ctx_load_trampoline)	// TODO write this
	nop ; nop ; nop ; nop ; nop ; nop ; nop ; nop ; 
	nop ; nop ; nop ; nop ; nop ; nop ; nop ; nop ; 
	nop ; nop ; nop ; nop ; nop ; nop ; nop ; nop ; 
	nop ; nop ; nop ; nop ; nop ; nop ; nop ; nop ; 
	nop ; nop ; nop ; nop ; nop ; nop ; nop ; nop ; 
	nop ; nop ; nop ; nop ; nop ; nop ; nop ; nop ; 
	nop ; nop ; nop ; nop ; nop ; nop ; nop ; nop ; 
	nop ; nop ; nop ; nop ; nop ; nop ; nop ; nop
FUNCTION_END(__lwt_ctx_load_trampoline)

//  bool __lwt_bool_load_acq(bool *m);

FUNCTION_START(__lwt_bool_load_acq)
	movzbl  (%rdi), %eax
	ret
FUNCTION_END(__lwt_bool_load_acq)

//  void __lwt_bool_store_rel(bool *m, bool b);

FUNCTION_START(__lwt_bool_store_rel)
	movb	%sil, (%rdi)
	ret
FUNCTION_END(__lwt_bool_store_rel)

//  ureg_t __lwt_ureg_load_acq(ureg_t *m);

FUNCTION_START(__lwt_ureg_load_acq)
	movq	(%rdi), %rax
	ret
FUNCTION_END(__lwt_ureg_load_acq)

//  ureg_t __lwt_ureg_atomic_add_unseq(ureg_t *m, ureg_t v);

FUNCTION_START(__lwt_ureg_atomic_add_unseq)
	movq		%rsi, %rax
	lock xaddq	%rax, (%rdi)
	ret
FUNCTION_END(__lwt_ureg_atomic_add_unseq)

//  ureg_t __lwt_ureg_atomic_or_acq_rel(ureg_t *m, ureg_t v);

FUNCTION_START(__lwt_ureg_atomic_or_acq_rel)
	movq		%rsi, %rax
	lock orq	%rax, (%rdi)
	ret
FUNCTION_END(__lwt_ureg_atomic_or_acq_rel)

//  See ctx_init() to understand the register inputs to this function.
//
//  The stack pointer is already 16 byte aligned as required for some
//  instructions to work (e.g. movaps %xmm0, ($rsp) ) use call to unalign it
//  by 8, generated C code knows about this and adjusts stack space if it
//  needs to.  Don't replace the call below with a jmp.

FUNCTION_START(__lwt_start_glue)
	movq	%reg_start_arg, %rdi		// arg0
	movq	%reg_start_func, %rsi		// arg1
	call	*%reg_start_pc
	movq	$0, %rcx
	movq	$0, (%rcx)			// TODO cause an exception
FUNCTION_END(__lwt_start_glue)

#endif //}

#define	ENTRY_START(name)						\
	FUNCTION_START_WITH_ALIGN(name, ENTRY_ALIGN_L2)

#define	ENTRY_END(name)							\
	FUNCTION_END(name)

#ifdef LWT_ARM64 //{
#define	ARG1	x0
#define	ARG2	x1
#define	ARG3	x2
#define	ARG4	x3
#define	ARG5	x4

#define	BARG2	w1
#define	BARG3	w2
#define	BARG4	w3
#define	BARG5	w4
#define	BARG6	w5

#define	ENTRY_BODY_REG(target, r1, r2)					\
	adrp	r1, :gottprel:__lwt_cpu_this ;				\
	ldr	r1, [r1, #:gottprel_lo12:__lwt_cpu_this] ;		\
	mrs	x15, tpidr_el0 ;					\
	ldr	r1, [x15, r1] ;						\
	ldrb	r2, [r1, cpu_enabled] ;					\
	strb	wzr, [r1, cpu_enabled] ;				\
	ldr	r1, [r1, cpu_running_thr] ;				\
	b	target
#endif //}

#ifdef LWT_X64 //{
#define	ARG1	%rdi
#define	ARG2	%rsi
#define	ARG3	%rdx
#define	ARG4	%rcx
#define	ARG5	%r8

#define	BARG2	%esi
#define	BARG3	%edx
#define	BARG4	%ecx
#define	BARG5	%r8d
#define	BARG6	%r9d

#define	ENTRY_BODY_REG(target, r1, r2)					\
	movq	__lwt_cpu_this@gottpoff(%rip), r1 ;			\
	movq	%fs:(r1), r1 ;						\
	movsbl	cpu_enabled(r1), r2 ;					\
	movb	$0, cpu_enabled(r1) ;					\
	movq	cpu_running_thr(r1), r1 ;				\
	jmp	target@PLT
#endif //}

#define	ENTRY_BODY_1(target)	ENTRY_BODY_REG(target, ARG1, BARG2)
#define	ENTRY_BODY_2(target)	ENTRY_BODY_REG(target, ARG2, BARG3)
#define	ENTRY_BODY_3(target)	ENTRY_BODY_REG(target, ARG3, BARG4)
#define	ENTRY_BODY_4(target)	ENTRY_BODY_REG(target, ARG4, BARG5)
#define	ENTRY_BODY_5(target)	ENTRY_BODY_REG(target, ARG5, BARG6)

//{ Dummy function to demarcate the end of the entry points for the purpose
//  of making them restartable so that their execution is atomic.

ENTRY_START(__lwt_entry_start)
ENTRY_END(__lwt_entry_start)

//  Each one of the following functions is an entry point to the LWT library,
//  Their signature is part of the API, each one starts by getting the per-cpu
//  pointer, disabling interrupts, and getting the current thread pointer to
//  become an additional argument (the last argument) to the internal function
//  that implements the API.  Each __lwt_xxx() API maps to a corresponding
//  __LWT_xxx() API implemented in C.  The entry points each use 32 bytes of
//  code, if an interrupt (ktimer_signal) occurs in the middle of them, the
//  program counter is rewound to the start of the entry point (by clearing the
//  low 5 bits), thus there is not a race between obtaining the per-cpu pointer
//  and setting cpu_enabled to false.  Note that once it is set to false, the
//  thread can not longer be preempted.

//  int __LWT_mtx_init(mtx_t **mtxpp, const mtxattr_t *mtxattr,
//		       thr_t *thr, bool enabled);

ENTRY_START(__lwt_mtx_init)
ENTRY_BODY_3(__LWT_mtx_init)
ENTRY_END(__lwt_mtx_init)

//  int __LWT_mtx_lock(mtx_t *mtx, thr_t *thr, bool enabled);

ENTRY_START(__lwt_mtx_lock)
ENTRY_BODY_2(__LWT_mtx_lock)
ENTRY_END(__lwt_mtx_lock)

//  int __LWT_mtx_trylock(mtx_t *mtx, thr_t *thr, bool enabled);

ENTRY_START(__lwt_mtx_trylock)
ENTRY_BODY_2(__LWT_mtx_trylock)
ENTRY_END(__lwt_mtx_trylock)

//  int __LWT_mtx_unlock(mtx_t *mtx, thr_t *thr, bool enabled);

ENTRY_START(__lwt_mtx_unlock)
ENTRY_BODY_2(__LWT_mtx_unlock)
ENTRY_END(__lwt_mtx_unlock)

//  int __LWT_cnd_init(cnd_t **cndpp, const cndattr_t *cndattr,
//		       thr_t *thr, bool enabled);

ENTRY_START(__lwt_cnd_init)
ENTRY_BODY_3(__LWT_cnd_init)
ENTRY_END(__lwt_cnd_init)

//  int __LWT_cnd_wait(cnd_t *cnd, mtx_t *mtx, thr_t *thr, bool enabled);

ENTRY_START(__lwt_cnd_wait)
ENTRY_BODY_3(__LWT_cnd_wait)
ENTRY_END(__lwt_cnd_wait)

//  int __LWT_cnd_timedwait(cnd_t *cnd, mtx_t *mtx,
//			    const struct timespec *abstime,
//			    thr_t *thr, bool enabled);

ENTRY_START(__lwt_cnd_timedwait)
ENTRY_BODY_4(__LWT_cnd_timedwait)
ENTRY_END(__lwt_cnd_timedwait)

//  int __LWT_cnd_signal(cnd_t *cnd, mtx_t *mtx, thr_t *thr, bool enabled);

ENTRY_START(__lwt_cnd_signal)
ENTRY_BODY_3(__LWT_cnd_signal)
ENTRY_END(__lwt_cnd_signal)

//  int __LWT_cnd_broadcast(cnd_t *cnd, mtx_t *mtx, thr_t *thr, bool enabled);

ENTRY_START(__lwt_cnd_broadcast)
ENTRY_BODY_3(__LWT_cnd_broadcast)
ENTRY_END(__lwt_cnd_broadcast)

//  int __LWT_spin_init(mtx_t **mtxpp, thr_t *thr, bool enabled);

ENTRY_START(__lwt_spin_init)
ENTRY_BODY_2(__LWT_spin_init)
ENTRY_END(__lwt_spin_init)

//  int __LWT_spin_lock(mtx_t *mtx, thr_t *thr, bool enabled);

ENTRY_START(__lwt_spin_lock)
ENTRY_BODY_2(__LWT_spin_lock)
ENTRY_END(__lwt_spin_lock)

//  int __LWT_spin_trylock(mtx_t *mtx, thr_t *thr, bool enabled);

ENTRY_START(__lwt_spin_trylock)
ENTRY_BODY_2(__LWT_spin_trylock)
ENTRY_END(__lwt_spin_trylock)

//  int __LWT_spin_unlock(mtx_t *mtx, thr_t *thr, bool enabled);

ENTRY_START(__lwt_spin_unlock)
ENTRY_BODY_2(__LWT_spin_unlock)
ENTRY_END(__lwt_spin_unlock)

//  int __LWT_thr_create(lwt_t *thread, const lwt_attr_t *attr,
//			 lwt_function_t function, void *arg,
//			 thr_t *thr, bool enabled);

ENTRY_START(__lwt_thr_create)
ENTRY_BODY_5(__LWT_thr_create)
ENTRY_END(__lwt_thr_create)

//  noreturn void __LWT_thr_exit(void *retval, thr_t *thr, bool enabled);

ENTRY_START(__lwt_thr_exit)
ENTRY_BODY_2(__LWT_thr_exit)
ENTRY_END(__lwt_thr_exit)

//  int __LWT_thr_join(lwt_t thread, void **retval, thr_t *thr, bool enabled);

ENTRY_START(__lwt_thr_join)
ENTRY_BODY_3(__LWT_thr_join)
ENTRY_END(__lwt_thr_join)

//  int __LWT_thr_cancel(lwt_t thread, thr_t *thr, bool enabled);

ENTRY_START(__lwt_thr_cancel)
ENTRY_BODY_2(__LWT_thr_cancel)
ENTRY_END(__lwt_thr_cancel)

//  int __LWT_thr_setcancelstate(int state, int *oldstate,
//				 thr_t *thr, bool enabled);

ENTRY_START(__lwt_thr_setcancelstate)
ENTRY_BODY_3(__LWT_thr_setcancelstate)
ENTRY_END(__lwt_thr_setcancelstate)

//  int __LWT_thr_setcanceltype(int type, int *oldtype,
//				thr_t *thr, bool enabled);

ENTRY_START(__lwt_thr_setcanceltype)
ENTRY_BODY_3(__LWT_thr_setcanceltype)
ENTRY_END(__lwt_thr_setcanceltype)

//  void __LWT_thr_testcancel(thr_t *thr, bool enabled);

ENTRY_START(__lwt_thr_testcancel)
ENTRY_BODY_1(__LWT_thr_testcancel)
ENTRY_END(__lwt_thr_testcancel)

//  Dummy function to demarcate the end of the entry points for the purpose
//  of making them restartable so that their execution is atomic.

ENTRY_START(__lwt_entry_end)
ENTRY_END(__lwt_entry_end)

//}
