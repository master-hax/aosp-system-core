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
#ifndef LWT_CTX_ARRAY
#include "lwt_asm_gen.h"
#endif
#include "lwt_arch.h"

#define FUNCTION_START(name) \
        .text; .align  2; .global name; .type name, %function; name:    

#define FUNCTION_END(name)						\
        .size name, .-name

#define	ENABLED_OFFSET_FROM_CPUCTX	-9

#ifdef LWT_ARM64 //{

//  This function returns twice, once when called, in which case it returns
//  a non-zero value, x0 which can not be zero.  The second time it returns
//  to its caller is when the context is restored, in which case it returns
//  zero.  The context is restored by __lwt_ctx_load() which does not return.
//
//  two_returns ureg_t __lwt_ctx_save(ctx_t *ctx);

FUNCTION_START(__lwt_ctx_save)
	mov	x17, sp				// sp can not be used with stp

	//  8 floating point registers stored into a cache line

	stp	d8,  d9,  [x0, ctx_d8]
	stp	d10, d11, [x0, ctx_d10]
	stp	d12, d13, [x0, ctx_d12]
	stp	d14, d15, [x0, ctx_d14]

	//  8 registers stored into a cache line

	stp	x18, x19, [x0, ctx_x18]
	stp	x20, x21, [x0, ctx_x20]
	stp	x22, x23, [x0, ctx_x22]
	stp	x24, x25, [x0, ctx_x24]

	//  8 registers stored into a cache line
	//  pstate == 0 implies "half" context

	stp	x26, x27, [x0, ctx_x26]
	stp	x28, x29, [x0, ctx_x28]
	stp	x30, x17, [x0, ctx_x30]		// [return address, sp]
	stp	x30, xzr, [x0, ctx_pc]		// [pc, pstate]

	ret					// x0 is non-zero return value
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
	mov	x0,  xzr		// return value, zero is 2nd return
	mov	x2,  x1			// x2 = cpuctx
	mov	x4,  xzr		// x4 = enabled = false
	b	2f
FUNCTION_END(__lwt_ctx_load_idle_cpu)

FUNCTION_START(__lwt_ctx_load)
	stlrb	wzr, [x5]		// current thread is no longer running
FUNCTION_END(__lwt_ctx_load)

FUNCTION_START(__lwt_ctx_load_on_cpu)
	mov	w5, RETRY_COUNT

1:	ldarb	w6, [x3]		// loop while new thr is running ...
	sub	w5, w5, 1
	cbz	w5, 3f
	cbnz	w6, 1b			// ... in another cpu
	mov	w6, 1
	stlrb	w6, [x3]		// new thr is now running on this cpu
	mov	x0, xzr			// return value, zero is 2nd return

2:	//  load 8 registers from a cache line

	ldp	x6,  x7,  [x1, ctx_pc]	// get [pc, pstate] as early as possible
	ldp	x26, x27, [x1, ctx_x26]
	ldp	x28, x29, [x1, ctx_x28]
	ldp	x30, x8,  [x1, ctx_x30]	// [x30, sp] can not use sp here

	//  load 8 registers from a cache line

	ldp	x18, x19, [x1, ctx_x18]
	ldp	x20, x21, [x1, ctx_x20]
	ldp	x22, x23, [x1, ctx_x22]
	ldp	x24, x25, [x1, ctx_x24]
	cbnz	x7,  ctx_load_rest	// pstate == zero, means "half" context

	//  8 floating point registers loaded from a cache line

	ldp	d8,  d9,  [x1, ctx_d8]
	ldp	d10, d11, [x1, ctx_d10]
	ldp	d12, d13, [x1, ctx_d12]
	ldp	d14, d15, [x1, ctx_d14]
	mov	sp,  x8			// MUST change sp last, ctx_t for thread
					// start might be clobbered otherwise by
					// signal handlers (e.g. ktimer_signal)
	strb	w4,  [x2, ENABLED_OFFSET_FROM_CPUCTX]	// cpu->cpu_enabled = w4
	br	x6

3:	// x0 is thr, its the 2nd return value, returned to cpu_main()
	mov	x1,  x2			// switch to cpu_main() to handle thr
	mov	xzr, x4			// ensure cpu->cpu_enabled remains false
	b	2b			// thr->thr_running was set too long

ctx_load_rest:
	ldr	x0,  [x2, -SIZEOF_UREG_T] // cpu_trampoline is before cpu_ctx
	add	x3,  x1,  SIZEOF_CTX_T	  // x3 = &thrx->thrx_fpctx
	add	x5,  x0,  OFFSET_OF_BRANCH_IN_TRAMPOLINE

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

	ldp	w9,  w10,  [x1, ctx_fpcr_fpsr]

	msr	nzcv, x7
	msr	fpsr, x9
	msr	fpcr, x10

	//  load 8 simd registers from 2 cache lines

	ldp	q0,  q1,  [x3, fpctx_q0]
	ldp	q2,  q3,  [x3, fpctx_q2]
	ldp	q4,  q5,  [x3, fpctx_q4]
	ldp	q6,  q7,  [x3, fpctx_q6]

	//  load 8 registers from a cache line

	ldp	x10, x11, [x1, ctx_x10]
	ldp	x12, x13, [x1, ctx_x12]
	ldp	x14, x15, [x1, ctx_x14]
	ldp	x16, x17, [x1, ctx_x16]

	//  load 8 simd registers from 1 cache line

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

	//  load 8 simd registers from 2 cache lines

	ldp	q16, q17, [x3, fpctx_q16]
	ldp	q18, q19, [x3, fpctx_q18]
	ldp	q20, q21, [x3, fpctx_q20]
	ldp	q22, q23, [x3, fpctx_q22]

	//  load 8 simd registers from 2 cache lines

	ldp	q24, q25, [x3, fpctx_q24]
	ldp	q26, q27, [x3, fpctx_q26]
	ldp	q28, q29, [x3, fpctx_q28]
	ldp	q30, q31, [x3, fpctx_q30]


	//  load 8 registers from a cache line

	strb	w4,  [x2, ENABLED_OFFSET_FROM_CPUCTX]	// cpu->cpu_enabled = w4
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
	movq	$1, %rax
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
	xor	%r8,  %r8		// r8 = enabled = false
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
	movb	%r8b, ENABLED_OFFSET_FROM_CPUCTX(%rdx)	// cpu->cpu_enabled = r8
	jmp	*%rdi			// rax == 0, 2nd __lwt_ctx_save return

4:	// rax is thr, its the 2nd return value, returned to cpu_main()
	mov	%rdi, %rax
	mov	%rdx, %rsi		// switch to cpu_main() to handle thr
	xor	%r8,  %r8		// ensure cpu->cpu_enabled remains false
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
