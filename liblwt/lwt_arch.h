
//  The ctx_t is the integral context of a thread, these comments apply to
//  all architextures.
//
//  The thread integer register context is divided into two parts, the first
//  part is what is informally referred to as a "half" context, it is not the
//  full context, the full context only has to be saved when a thread is
//  interrupted (and preempted) in an arbitrary instruction location.  When a
//  thread is preempted voluntarily, for example when waiting to acquire a
//  mutex, or waiting for a condition to occur.
//
//  A zero least significant bit of ctx_fpctx indicates that only the half
//  context needs to be loaded when switching into the thread. The simplest
//  case is when a half context when no floating point is to be loaded, both
//  conditions are tested with a single compare against zero of ctx_fpctx.

#ifdef LWT_ARM64 //{
#ifdef LWT_C //{

#define CACHE_LINE_SIZE_L2      6
#define CACHE_LINE_SIZE         64

//  On ARM64 (without SVE) there are 32 128 bit SIMD registers, the 32 bit
//  floating point registers are held inside of them.  A non-SIMD version of
//  the floating point context could be used by threads that don't use SIMD,
//  if it is possible to disable SIMD while allowing FP to still be used
//  and if it is practical to do so.  TODO review SIMD / FP separation.
//
//  TODO: add support for SVE context.

#define	FPCTX_NREG	32

typedef struct {
	uregx2_t	fpctx_regs[FPCTX_NREG];
} aligned_cache_line fpctx_t;

typedef struct {
	//  This part is the "half" context.
	//
	//  First 16 are callee saved, keeping these 16 together puts them
	//  in two cache lines. The ctx_fpctx is among those 16 so that FP
	//  context, if any can be restored without touching the rest of this
	//  structure.  Registers are kept as pairs to use load and store pair
	//  instructions, the pairs are shown below as: [x, y].
	//
	//  x0 is not part of the callee saved set of registers, its both the
	//  first argument and the return value of functions, instead of a pad
	//  word to complete the 2nd cache line, having x0 here allows for a
	//  newly created thread to start with a half context with its argument
	//  value because the rest of the context is meaningless at that time.

        ureg_t		 ctx_x0;	// [x0, fpctx]
	fpctx_t		*ctx_fpctx;
        ureg_t		 ctx_pc;	// [pc, sp]
	ureg_t		 ctx_sp;
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

	//  This is the rest of the context.

	ureg_t		 ctx_x30;	// [x30, x1]
	ureg_t		 ctx_x1;
	ureg_t		 ctx_x2;	// [x2, x3]
	ureg_t		 ctx_x3;
	ureg_t		 ctx_x4;	// [x4, x5]
	ureg_t		 ctx_x5;
	ureg_t		 ctx_x6;	// [x6, x7]
	ureg_t		 ctx_x7;

	ureg_t		 ctx_x8;	// [x8, x9]
	ureg_t		 ctx_x9;
	ureg_t		 ctx_x10;	// [x10, x11]
	ureg_t		 ctx_x11;
	ureg_t		 ctx_x12;	// [x12, x13]
	ureg_t		 ctx_x13;
	ureg_t		 ctx_x14;	// [x14, x15]
	ureg_t		 ctx_x15;

	ureg_t		 ctx_x16;	// [x16, x17]
	ureg_t		 ctx_x17;
	ureg_t		 ctx_flags;
} ctx_t;

#define	ctx_thr_start_arg0	ctx_x19
#define	ctx_thr_start_func	ctx_x20
#define	ctx_thr_start_pc	ctx_x21
#else //}{
#define	reg_thr_start_arg0	x19
#define	reg_thr_start_func	x20
#define	reg_thr_start_pc	x21
#endif //}
#endif //} LWT_ARM64

#ifdef LWT_X64 //{
#ifdef LWT_C //{

#define CACHE_LINE_SIZE_L2      6
#define CACHE_LINE_SIZE         64

//  TODO: fix FP context
#define	FPCTX_NREG	16
typedef struct {
	ureg_t		 fpctx_regs[FPCTX_NREG];
} fpctx_t;

typedef struct {
	//  This part is the "half" context.
	//
	//  First 8 are callee saved, keeping these 8 together puts them
	//  in two cache lines. The ctx_fpctx is among those 8 so that FP
	//  context, if any can be restored without touching the rest of this
	//  structure.
	//
	//  Unlike ARM64, there is no extra space for ctx_rdi (first argument)
	//  in this cache line, newly created threads use a trampoline function
	//  (__lwt_thr_start) to adjust their context, the argument is found in
	//  ctx_rbp and the actual function address in ctx_rbx also known as
	//  ctx_thr_start_pc and ctx_thr_start_arg0 in portable code.

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

#define	ctx_thr_start_arg0	ctx_rbp
#define	ctx_thr_start_func	ctx_rbx
#define	ctx_thr_start_pc	ctx_r12
#else //}{
#define	reg_thr_start_arg0	rbp
#define	reg_thr_start_func	rbx
#define	reg_thr_start_pc	r12
#endif //}
#endif //} LWT_X64

#ifdef LWT_C //{

//  uptr atomic operations

#if 0
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
#endif

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

#ifndef LWT_CPU_PTHREAD_KEY //{
void cpu_current_set(cpu_t *cpu)
{
#if 0
	// TODO: use x18 until tpidrro_el0 can be set from the kernel :-(
	*((volatile int *)11) = 0xDEADBEEF;
#else
	__asm__ ("mov	x18, %0" : "=r"(cpu));
#endif
}
inline_only cpu_t *cpu_current(void)
{
	register ureg_t cpureg;
#if 0
	__asm__("mrs	%0, tpidrro_el0" : "=r"(cpureg));
#else
	__asm__ ("mov	%0, x18" : "=r"(cpureg));
#endif
	return (cpu_t *) cpureg;
}
#endif //}
#endif //}

#ifdef LWT_X64 //{
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

// cpu_t *cpu_current(void);
#endif //}

#endif //}
