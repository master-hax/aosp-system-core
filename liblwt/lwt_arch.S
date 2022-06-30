
#include "lwt_config.h"
#include "lwt_asm.h"
#ifndef LWT_CTX_ARRAY
#include "lwt_asm_gen.h"
#endif
#include "lwt_arch.h"

#ifdef LWT_ARM64 //{

//  This function returns twice, once when called, in which case it returns
//  a non-zero value, x0 which can not be zero.  The second time it returns
//  to its caller is when the context is restored, in which case it returns
//  zero.  The context is restored by __lwt_ctx_load() which does not return.
//
//  two_returns ureg_t __lwt_ctx_save(ctx_t *ctx);

FUNCTION_START(__lwt_ctx_save)
	mov	x1, sp				// sp can not be used with stp
	stp	x30, x1, [x0, ctx_pc]		// [pc, sp]
	stp	x18, x19, [x0, ctx_x18]
	stp	x20, x21, [x0, ctx_x20]
	stp	x22, x23, [x0, ctx_x22]
	stp	x24, x25, [x0, ctx_x24]
	stp	x26, x27, [x0, ctx_x26]
	stp	x28, x29, [x0, ctx_x28]
	str	xzr, [x0, ctx_fpctx]		// this implies half context
	ret					// x0 is non-zero return value
FUNCTION_END(__lwt_ctx_save)

//  This functions must not use the run-time (thread or cpu) stack.
//
//  noreturn void __lwt_ctx_load_idle_cpu(ctx_t *ctx,		/* rdi */
//					  bool *curr_running);	/* rsi */
//  noreturn void __lwt_ctx_load_on_cpu(ctx_t *ctx,		/* rdi */
//				 	bool *new_running);	/* rsi */
//  noreturn void __lwt_ctx_load(ctx_t *ctx,			/* rdi */
//				 bool *new_running,		/* rsi */
//				 bool *curr_running);		/* rdx */
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
//  long running in the other CPU and can now start running on this CPU.

FUNCTION_START(__lwt_ctx_load_idle_cpu)
	stlrb	wzr, [x1]		// current thread no longer running
	b	2f
FUNCTION_END(__lwt_ctx_load_idle_cpu)
FUNCTION_START(__lwt_ctx_load)
	stlrb	wzr, [x2]		// current thread no longer running
FUNCTION_END(__lwt_ctx_load)
FUNCTION_START(__lwt_ctx_load_on_cpu)
1:	ldarb	w4, [x1]		// loop while new thr is running ...
	cbnz	w4, 1b			// ... in another cpu
	mov	w4, 1
	stlrb	w4, [x1]		// new thr is now running on this cpu
2:	ldp	x30, x1, [x0, ctx_pc]	// [pc, sp] can not use sp here
	ldp	x18, x19, [x0, ctx_x18]
	ldp	x20, x21, [x0, ctx_x20]
	ldp	x22, x23, [x0, ctx_x22]
	ldp	x24, x25, [x0, ctx_x24]
	ldp	x26, x27, [x0, ctx_x26]
	ldp	x28, x29, [x0, ctx_x28]
	ldr	x0, [x0, ctx_fpctx]
	mov	sp, x1
	cbnz	x0, ctx_load_rest
	ret
ctx_load_rest:
	//  Restore rest of full context
	mov	x1, xzr
	str	xzr, [x1]			// TODO cause an exception
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

//  This functions must not use the run-time (thread or cpu) stack.
//
//  noreturn void __lwt_ctx_load_idle_cpu(ctx_t *ctx,		/* rdi */
//					  bool *curr_running);	/* rsi */
//  noreturn void __lwt_ctx_load_on_cpu(ctx_t *ctx,		/* rdi */
//				 	bool *new_running);	/* rsi */
//  noreturn void __lwt_ctx_load(ctx_t *ctx,			/* rdi */
//				 bool *new_running,		/* rsi */
//				 bool *curr_running);		/* rdx */

FUNCTION_START(__lwt_ctx_load_idle_cpu)
	movb	$0, (%rsi)		// current thread no longer running
	jmp	2f
FUNCTION_END(__lwt_ctx_load_idle_cpu)
FUNCTION_START(__lwt_ctx_load)
	movb	$0, (%rdx)		// current thread no longer running
FUNCTION_END(__lwt_ctx_load)
FUNCTION_START(__lwt_ctx_load_on_cpu)
1:	movzbl	(%rsi), %eax
	testb	%al, %al		// loop while new thr is running ...
	jne	1b			// ... in another cpu
	movb	$1, (%rsi)		// new thr is now running on this cpu
2:	movq	ctx_fpctx(%rdi), %rax
	movq	ctx_pc(%rdi), %rsi
	movq	ctx_sp(%rdi), %rsp
	movq	ctx_rbp(%rdi), %rbp
	movq	ctx_rbx(%rdi), %rbx
	movq	ctx_r12(%rdi), %r12
	movq	ctx_r13(%rdi), %r13
	movq	ctx_r14(%rdi), %r14
	movq	ctx_r15(%rdi), %r15
	testq	%rax, %rax
	jne	ctx_load_rest
	jmp	*%rsi			// zero rax, 2nd __lwt_ctx_save return
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
