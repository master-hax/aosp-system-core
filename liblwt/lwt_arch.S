/*
 * Copyright (C) 2022 The Android Open Source Project
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

#include "lwt_config.h"
#ifndef LWT_CTX_ARRAY
#include "lwt_asm_gen.h"
#endif
#include "lwt_arch.h"

#define FUNCTION_START(name) \
        .text; .align  2; .global name; .type name, %function; name:    

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
//				 bool *curr_running);		x4
//  noreturn void __lwt_ctx_load_on_cpu(thr_t *thr,		x0
//					ctx_t *ctx,		x1
//					ctx_t *cpuctx,		x2
//					bool *new_running);	x3
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
	mov	x0, xzr			// return value, zero is 2nd return
	b	2f
FUNCTION_END(__lwt_ctx_load_idle_cpu)

FUNCTION_START(__lwt_ctx_load)
	stlrb	wzr, [x4]		// current thread is no longer running
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

2:	//  8 registers loaded from a cache line

	ldp	x14, x15, [x1, ctx_pc]	// get [pc, pstate] as early as possible
	ldp	x26, x27, [x1, ctx_x26]
	ldp	x28, x29, [x1, ctx_x28]
	ldp	x30, x17, [x1, ctx_x30]	// [x30, sp] can not use sp here

	//  8 registers loaded from a cache line

	ldp	x18, x19, [x1, ctx_x18]
	ldp	x20, x21, [x1, ctx_x20]
	ldp	x22, x23, [x1, ctx_x22]
	ldp	x24, x25, [x1, ctx_x24]
	mov	sp, x17
	cbnz	x15, ctx_load_rest	// pstate == zero, means "half" context

	//  8 floating point registers loaded from a cache line

	ldp	d8,  d9,  [x1, ctx_d8]
	ldp	d10, d11, [x1, ctx_d10]
	ldp	d12, d13, [x1, ctx_d12]
	ldp	d14, d15, [x1, ctx_d14]
	br	x14

3:	// x0 is thr, its the 2nd return value, returned to cpu_main()
	mov	x1, x2			// switch to cpu_main() to handle thr
	b	2b			// thr->thr_running was set too long

ctx_load_rest:
	//  Restore rest of full context
	mov	x7, xzr
	str	xzr, [x7]			// TODO cause an exception
FUNCTION_END(__lwt_ctx_load_on_cpu)

//  bool __lwt_bool_load_acq(bool *m);

FUNCTION_START(__lwt_bool_load_acq)
	ldarb	w0, [x0]
	ret
FUNCTION_END(__lwt_bool_load_acq)

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

FUNCTION_START(__lwt_thr_start_glue)
	mov	x0, reg_thr_start_arg0		// arg0
	mov	x1, reg_thr_start_func		// arg1
	br	reg_thr_start_pc
FUNCTION_END(__lwt_thr_start_glue)
 
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
//				 bool *curr_running);		r8
//  noreturn void __lwt_ctx_load_on_cpu(thr_t *thr,		rdi
//					ctx_t *ctx,		rsi
//					ctx_t *cpuctx,		rdx
//					bool *new_running);	rcx
//  noreturn void __lwt_ctx_load_idle_cpu(bool *curr_running,	rdi
//					  ctx_t *ctx);		rsi

#define	RETRY_COUNT	256

FUNCTION_START(__lwt_ctx_load_idle_cpu)
	movb	$0, (%rdi)		// current thread is no longer running
	jmp	2f
FUNCTION_END(__lwt_ctx_load_idle_cpu)
FUNCTION_START(__lwt_ctx_load)
	movb	$0, (%r8)		// current thread is no longer running
FUNCTION_END(__lwt_ctx_load)
FUNCTION_START(__lwt_ctx_load_on_cpu)
	movq	$RETRY_COUNT, %r9
1:	movzbl	(%rcx), %eax
	subq	$1, %r9
	je	4f
	testb	%al, %al		// loop while new thr is running ...
	jne	1b			// ... in another cpu
	movb	$1, (%rcx)		// new thr is now running on this cpu
2:	xor	%rax, %rax		// return value, zero is 2nd return
3:	movq	ctx_fpctx(%rsi), %rcx
	movq	ctx_pc(%rsi), %rdi
	movq	ctx_sp(%rsi), %rsp
	movq	ctx_rbp(%rsi), %rbp
	movq	ctx_rbx(%rsi), %rbx
	movq	ctx_r12(%rsi), %r12
	movq	ctx_r13(%rsi), %r13
	movq	ctx_r14(%rsi), %r14
	movq	ctx_r15(%rsi), %r15
	testq	%rcx, %rcx
	jne	ctx_load_rest
	jmp	*%rdi			// zero rax, 2nd __lwt_ctx_save return
4:	// rax is thr, its the 2nd return value, returned to cpu_main()
	mov	%rdi, %rax
	mov	%rdx, %rsi		// switch to cpu_main() to handle thr
	jmp	3b			// thr->thr_running was set too long
ctx_load_rest:
	//  Restore rest of full context
	movq	$0, %rcx
	movq	$0, (%rcx)			// TODO cause an exception
FUNCTION_END(__lwt_ctx_load_on_cpu)

//  bool __lwt_bool_load_acq(bool *m);

FUNCTION_START(__lwt_bool_load_acq)
	movzbl  (%rdi), %eax
	ret
FUNCTION_END(__lwt_bool_load_acq)

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

FUNCTION_START(__lwt_thr_start_glue)
	movq	%reg_thr_start_arg0, %rdi	// arg0
	movq	%reg_thr_start_func, %rsi	// arg1
	call	*%reg_thr_start_pc
	movq	$0, %rcx
	movq	$0, (%rcx)			// TODO cause an exception
FUNCTION_END(__lwt_thr_start_glue)

#endif //}
