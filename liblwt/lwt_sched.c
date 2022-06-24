
#include <sys/mman.h>
#include <errno.h>
#include <stdbool.h>
#include <string.h>

#define	LWT_C

#include "lwt.h"
#include "lwt_types.h"
#include "lwt_arch.h"
#include "lwt_sched.h"

//  TODO:
//	The clang C compiler does not implement standard C properly, this
//	produces a compilation error because clang does not allow declarations
//	to have a label prior to them.  This code compiles properly with gcc.
//
//	int bar();
//	int foo(int a) {
//	retry:	int r = bar();
//		if (!r) goto retry;
//		return r;
//	}
//
//	To work around this clang bug, labels are followed by a semicolon when
//	needed in this file, for example:
//
//	int bar();
//	int foo(int a) {
//	retry:;	int r = bar();
//		if (!r) goto retry;
//		return r;
//	}


//{  Various #defines.

#define	NOOP()			do {} while (0)

#ifndef PAGE_SIZE
#define PAGE_SIZE		4096
#endif

#define	PAGE_SIZE_ROUND_UP(size)					\
	(((size) + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1))

#define	THR_ARENA_START		(1uL << 22)
#define	THRX_ARENA_START	(1uL << 23)
#define	FPCTX_ARENA_START	(1uL << 26)
#define	CND_ARENA_START		(2uL << (32 + 5))
#define	MTX_ARENA_START		(3uL << (32 + 6))

#define	THR_ARENA_LENGTH	(sizeof(thr_t) * THRIX_MAX)
#define	THR_ARENA_RESERVED	PAGE_SIZE

#define	THRX_ARENA_LENGTH	(sizeof(thrx_t) * THRIX_MAX)
#define	THRX_ARENA_RESERVED	PAGE_SIZE

#define	FPCTX_ARENA_LENGTH	(sizeof(fpctx_t) * THRIX_MAX)
#define	FPCTX_ARENA_RESERVED	PAGE_SIZE

#define	MTX_ARENA_LENGTH	(sizeof(mtx_t) << 32)
#define	MTX_ARENA_RESERVED	PAGE_SIZE

#define	CND_ARENA_LENGTH	(sizeof(cnd_t) << 32)
#define	CND_ARENA_RESERVED	PAGE_SIZE

#define	THRX_INDEX_BASE		((thrx_t *) THRX_ARENA_START)
#define	THR_INDEX_BASE		((thr_t *) (THR_ARENA_START - sizeof(thr_t)))
#define	MTX_INDEX_BASE		((mtx_t *) (MTX_ARENA_START - sizeof(mtx_t)))

//}{  Global variables.

static lllist_t	 thr_exited_lllist;
static arena_t	 thr_arena;
static arena_t	 thrx_arena;
static arena_t	 fpctx_arena;
static arena_t	 mtx_arena;
static arena_t	 cnd_arena;

static mtx_t	*mtx_by_index = MTX_INDEX_BASE;
static thr_t	*thr_by_index = THR_INDEX_BASE;
static thrx_t	*thrx_by_index = THRX_INDEX_BASE;

//  For debugging only.

static thrx_t *THRX_INDEX_BASE_ = THRX_INDEX_BASE;
static thr_t *THR_INDEX_BASE_ = THR_INDEX_BASE;
static mtx_t *MTX_INDEX_BASE_ = MTX_INDEX_BASE;

#ifdef LWT_ARM64 //{
//  Pixel6 octa-core:
//    2 x Cortex-X1  @ 2.8 GHz
//    2 x Cortex-A76 @ 2.25 GHz 
//    4 x Cortex-A55 @ 1.8 GHz
//
//  This should be determined at run-time from /proc, this is for testing in
//  the meantime (TODO).  At that time deal with kcores too.

#define LWT_HWSYS
#define LWT_MCORES

static sqcl_t sqcls[(1 + 3 + 8) * SQ_PRIO_MAX];
static hw_t hwsys = {.hw_name = "hwsys", .hw_parent = NULL,
		     .hw_schdom = {.schdom_sqcls = &sqcls[0 * SQ_PRIO_MAX]}};
static hw_t mcores[3] = {
	[0] = {.hw_name = "mcore0", .hw_parent = &hwsys,
	       .hw_schdom = {.schdom_sqcls = &sqcls[(1+0) * SQ_PRIO_MAX]}},
	[1] = {.hw_name = "mcore1", .hw_parent = &hwsys,
	       .hw_schdom = {.schdom_sqcls = &sqcls[(1+1) * SQ_PRIO_MAX]}},
	[2] = {.hw_name = "mcore2", .hw_parent = &hwsys,
	       .hw_schdom = {.schdom_sqcls = &sqcls[(1+2) * SQ_PRIO_MAX]}},
};
static core_t cores[8] = {
	[0] = {.core_hw = {.hw_name = "core0", .hw_parent = &mcores[0],
			   .hw_schdom = {.schdom_sqcls =
						&sqcls[(4+0) * SQ_PRIO_MAX],
					 .schdom_core = &cores[0]}}},
	[1] = {.core_hw = {.hw_name = "core1", .hw_parent = &mcores[0],
			   .hw_schdom = {.schdom_sqcls =
						&sqcls[(4+1) * SQ_PRIO_MAX],
					 .schdom_core = &cores[1]}}},
	[2] = {.core_hw = {.hw_name = "core2", .hw_parent = &mcores[1],
			   .hw_schdom = {.schdom_sqcls =
						&sqcls[(4+2) * SQ_PRIO_MAX],
					 .schdom_core = &cores[2]}}},
	[3] = {.core_hw = {.hw_name = "core3", .hw_parent = &mcores[1],
			   .hw_schdom = {.schdom_sqcls =
						&sqcls[(4+3) * SQ_PRIO_MAX],
					 .schdom_core = &cores[3]}}},
	[4] = {.core_hw = {.hw_name = "core4", .hw_parent = &mcores[2],
			   .hw_schdom = {.schdom_sqcls =
						&sqcls[(4+4) * SQ_PRIO_MAX],
					 .schdom_core = &cores[4]}}},
	[5] = {.core_hw = {.hw_name = "core5", .hw_parent = &mcores[2],
			   .hw_schdom = {.schdom_sqcls =
						&sqcls[(4+5) * SQ_PRIO_MAX],
					 .schdom_core = &cores[5]}}},
	[6] = {.core_hw = {.hw_name = "core6", .hw_parent = &mcores[2],
			   .hw_schdom = {.schdom_sqcls =
						&sqcls[(4+6) * SQ_PRIO_MAX],
					 .schdom_core = &cores[6]}}},
	[7] = {.core_hw = {.hw_name = "core7", .hw_parent = &mcores[2],
			   .hw_schdom = {.schdom_sqcls =
						&sqcls[(4+7) * SQ_PRIO_MAX],
					 .schdom_core = &cores[7]}}},
};
static cpu_t cpus[8] = {
	[0] = {.cpu_name = "cpu0(cortex-x1 2.8ghz)",   .cpu_core = &cores[0]},
	[1] = {.cpu_name = "cpu1(cortex-x1 2.8ghz)",   .cpu_core = &cores[1]},
	[2] = {.cpu_name = "cpu2(cortex-a76 2.25ghz)", .cpu_core = &cores[2]},
	[3] = {.cpu_name = "cpu3(cortex-a76 2.25ghz)", .cpu_core = &cores[3]},
	[4] = {.cpu_name = "cpu4(cortex-a55 1.8ghz)",  .cpu_core = &cores[4]},
	[5] = {.cpu_name = "cpu5(cortex-a55 1.8ghz)",  .cpu_core = &cores[5]},
	[6] = {.cpu_name = "cpu6(cortex-a55 1.8ghz)",  .cpu_core = &cores[6]},
	[7] = {.cpu_name = "cpu7(cortex-a55 1.8ghz)",  .cpu_core = &cores[7]},
};
#endif //}

#ifdef LWT_X64 //{
#ifndef LWT_MP //{
static sqcl_t sqcls[1 * SQ_PRIO_MAX];
static core_t cores[1] = {
	[0] = {.core_hw = {.hw_name = "core0", .hw_parent = NULL,
			   .hw_schdom = {.schdom_sqcls = &sqcls[0],
					 .schdom_core = &cores[0]}}},
};
static cpu_t cpus[1] = {
	[0] = {.cpu_name = "cpu0(test)", .cpu_core = &cores[0]},
};
static cpu_t *cpuptrs[1] = {
	[0] = &cpus[0],
};
#else //}{
#define LWT_MCORES
#ifdef LWT_MT_CORES //{
static sqcl_t sqcls[(1 + 4) * SQ_PRIO_MAX];
static hw_t mcores[1] = {
	[0] = {.hw_name = "mcore0", .hw_parent = NULL,
	       .hw_schdom = {.schdom_sqcls = &sqcls[0 * SQ_PRIO_MAX]}},
};
static hw_t cores[4] = {
	[0] = {.core_hw = {.hw_name = "core0", .hw_parent = &mcores[0],
			   .hw_schdom = {.schdom_sqcls =
						&sqcls[(1+0) * SQ_PRIO_MAX],
					 .schdom_core = &cores[0]}}},
	[1] = {.core_hw = {.hw_name = "core1", .hw_parent = &mcores[0],
			   .hw_schdom = {.schdom_sqcls =
						&sqcls[(1+1) * SQ_PRIO_MAX],
					 .schdom_core = &cores[1]}}},
	[2] = {.core_hw = {.hw_name = "core2", .hw_parent = &mcores[0],
			   .hw_schdom = {.schdom_sqcls =
						&sqcls[(1+2) * SQ_PRIO_MAX],
					 .schdom_core = &cores[2]}}},
	[3] = {.core_hw = {.hw_name = "core3", .hw_parent = &mcores[0],
			   .hw_schdom = {.schdom_sqcls =
						&sqcls[(1+3) * SQ_PRIO_MAX],
					 .schdom_core = &cores[3]}}},
};
static cpu_t cpus[8] = {
	[0] = {.cpu_name = "cpu1", .cpu_core = &cores[0]},
	[1] = {.cpu_name = "cpu2", .cpu_core = &cores[0]},
	[2] = {.cpu_name = "cpu3", .cpu_core = &cores[1]},
	[3] = {.cpu_name = "cpu4", .cpu_core = &cores[1]},
	[4] = {.cpu_name = "cpu5", .cpu_core = &cores[2]},
	[5] = {.cpu_name = "cpu6", .cpu_core = &cores[2]},
	[6] = {.cpu_name = "cpu7", .cpu_core = &cores[3]},
	[7] = {.cpu_name = "cpu8", .cpu_core = &cores[3]},
};
#else //}{
static sqcl_t sqcls[(1 + 8) * SQ_PRIO_MAX];
static hw_t mcores[1] = {
	[0] = {.hw_name = "mcore0", .hw_parent = NULL,
	       .hw_schdom = {.schdom_sqcls = &sqcls[0 * SQ_PRIO_MAX]}},
};
static core_t cores[8] = {
	[0] = {.core_hw = {.hw_name = "core0", .hw_parent = &mcores[0],
			   .hw_schdom = {.schdom_sqcls =
						&sqcls[(1+0) * SQ_PRIO_MAX],
					 .schdom_core = &cores[0]}}},
	[1] = {.core_hw = {.hw_name = "core1", .hw_parent = &mcores[0],
			   .hw_schdom = {.schdom_sqcls =
						&sqcls[(1+1) * SQ_PRIO_MAX],
					 .schdom_core = &cores[1]}}},
	[2] = {.core_hw = {.hw_name = "core2", .hw_parent = &mcores[0],
			   .hw_schdom = {.schdom_sqcls =
						&sqcls[(1+2) * SQ_PRIO_MAX],
					 .schdom_core = &cores[2]}}},
	[3] = {.core_hw = {.hw_name = "core3", .hw_parent = &mcores[0],
			   .hw_schdom = {.schdom_sqcls =
						&sqcls[(1+3) * SQ_PRIO_MAX],
					 .schdom_core = &cores[3]}}},
	[4] = {.core_hw = {.hw_name = "core4", .hw_parent = &mcores[0],
			   .hw_schdom = {.schdom_sqcls =
						&sqcls[(1+4) * SQ_PRIO_MAX],
					 .schdom_core = &cores[4]}}},
	[5] = {.core_hw = {.hw_name = "core5", .hw_parent = &mcores[0],
			   .hw_schdom = {.schdom_sqcls =
						&sqcls[(1+5) * SQ_PRIO_MAX],
					 .schdom_core = &cores[5]}}},
	[6] = {.core_hw = {.hw_name = "core6", .hw_parent = &mcores[0],
			   .hw_schdom = {.schdom_sqcls =
						&sqcls[(1+6) * SQ_PRIO_MAX],
					 .schdom_core = &cores[6]}}},
	[7] = {.core_hw = {.hw_name = "core7", .hw_parent = &mcores[0],
			   .hw_schdom = {.schdom_sqcls =
						&sqcls[(1+7) * SQ_PRIO_MAX],
					 .schdom_core = &cores[7]}}},
};
static cpu_t cpus[8] = {
	[0] = {.cpu_name = "cpu1", .cpu_core = &cores[0]},
	[1] = {.cpu_name = "cpu2", .cpu_core = &cores[1]},
	[2] = {.cpu_name = "cpu3", .cpu_core = &cores[2]},
	[3] = {.cpu_name = "cpu4", .cpu_core = &cores[3]},
	[4] = {.cpu_name = "cpu5", .cpu_core = &cores[4]},
	[5] = {.cpu_name = "cpu6", .cpu_core = &cores[5]},
	[6] = {.cpu_name = "cpu7", .cpu_core = &cores[6]},
	[7] = {.cpu_name = "cpu8", .cpu_core = &cores[7]},
};
#endif //}
static cpu_t *cpuptrs[8] = {
	[0] = &cpus[0],
	[1] = &cpus[1],
	[2] = &cpus[2],
	[3] = &cpus[3],
	[4] = &cpus[4],
	[5] = &cpus[5],
	[6] = &cpus[6],
	[7] = &cpus[7],
};
#endif //}
#endif //}

#ifdef LWT_MCORES
#define	NMCORES	(sizeof(mcores) / sizeof(mcores[0]))
#else
#define	NMCORES	0
#endif

#define	NCPUS	(sizeof(cpus) / sizeof(cpus[0]))
#define	NCORES	(sizeof(cores) / sizeof(cores[0]))


//}{  Various function like macros.

//  Outline versions for use within this file map to the __lwt_*() functions
//  to avoid having two versions of them expanded in this file.

#define	mtx_lock_outline(mtx)			__lwt_mtx_lock(mtx)
#define	mtx_unlock_outline(mtx)			__lwt_mtx_unlock(mtx)
#define mtx_create_outline(mtxpp, mtxattr)	__lwt_mtx_init(mtxpp, mtxattr)
#define mtx_destroy_outline(mtxpp)		__lwt_mtx_destroy(mtxpp)

#define	cnd_signal_outline(cnd)			__lwt_cnd_signal(cnd)
#define	cnd_broadcast_outline(cnd)		__lwt_cnd_broadcast(cnd)
#define	cnd_create_outline(cndpp, cndattr)	__lwt_cnd_init(cndpp, cndattr)
#define	cnd_destroy_outline(cndpp)		__lwt_cnd_destroy(cndpp)

//  mtx_lock() calls ctx_save() which returns twice which makes mtx_lock()
//  not elegible for inline expansion, to hide that from internal callers
//  of mtx_lock() we have the macro below.

#define	mtx_lock(mtx)				__lwt_mtx_lock(mtx)

//  cnd_wait() calls ctx_save() which returns twice which makes cnd_wait()
//  not elegible for inline expansion, to hide that from internal callers
//  of cnd_wait() we have the macro below.

#define	cnd_wait(cnd, mtx)		__lwt_cnd_wait(cnd, mtx)


//}  Prototypes.
//{  Only when required because their order in this file.

int			 __lwt_mtx_lock(struct __lwt_mtx_s *mtx);
int			 __lwt_mtx_unlock(struct __lwt_mtx_s *mtx);
int			 __lwt_mtx_init(struct __lwt_mtx_s **mtxpp,
					const struct __lwt_mtxattr_s *mtxattr);
int			 __lwt_mtx_destroy(struct __lwt_mtx_s **mtxpp);
int			 __lwt_cnd_init(struct __lwt_cnd_s **cndpp,
					const struct __lwt_cndattr_s *cndattr);
int			 __lwt_cnd_destroy(struct __lwt_cnd_s **cndpp);
noreturn void		 __lwt_thr_start_glue(void);

static noreturn void	 sched_out(thr_t *thr);
static int		 sched_in(thr_t *in);

static int		 thr_context_save__thr_run(thr_t *currthr, thr_t *thr);

static noreturn void	 thr_block_forever(const char *msg, void *arg);

//  ctx_save() returns twice, one from its caller and another from where the
//  context was saved, e.g. ctx_load() which never returns to its caller. The
//  first return from ctx_save() returns a non-zero value, the second return
//  returs the value zero.

two_returns ureg_t	 __lwt_ctx_save(ctx_t *ctx);
noreturn void		 __lwt_ctx_load(ctx_t *ctx, bool *new_running,
					bool *curr_running);
noreturn void		 __lwt_ctx_load_idle_cpu(ctx_t *ctx,
						 bool *curr_running);
noreturn void		 __lwt_ctx_load_on_cpu(ctx_t *ctx, bool *new_running);

#define	ctx_save(ctx)	 __lwt_ctx_save(ctx)

#define	ctx_load(ctx, new_running, curr_running)			\
	__lwt_ctx_load(ctx, new_running, curr_running)
#define	ctx_load_on_cpu(ctx, new_running)				\
	__lwt_ctx_load_on_cpu(ctx, new_running)
#define	ctx_load_idle_cpu(ctx, curr_running)				\
	__lwt_ctx_load_idle_cpu(ctx, curr_running)

bool 			 __lwt_bool_load_acq(bool *m);
ureg_t			 __lwt_ureg_load_acq(ureg_t *m);
ureg_t			 __lwt_ureg_atomic_add_unseq(ureg_t *m, ureg_t v);
ureg_t			 __lwt_ureg_atomic_or_acq_rel(ureg_t *m, ureg_t v);

#define	bool_load_acq(m)		__lwt_bool_load_acq(m)
#define	ureg_load_acq(m)		__lwt_ureg_load_acq(m)
#define	ureg_atomic_add_unseq(m, v)	__lwt_ureg_atomic_add_unseq(m, v)
#define	ureg_atomic_or_acq_rel(m, v)	__lwt_ureg_atomic_or_acq_rel(m, v)

static schdom_t		*schdom_from_thrattr(const thrattr_t *thrattr);

static thr_t		*schedq_get(schedq_t *schedq, ureg_t sqix);

static alloc_value_t	 arena_alloc(arena_t *arena);
static void		 arena_free(arena_t *arena, void *mem);

static void		 cpu_run(lllist_t *idled_list);

static void		 core_run(core_t *core);

inline_only thr_t *thr_current(void)
{
	cpu_t *cpu = cpu_current();
	return cpu->cpu_running_thr;
}


//}  This section contains entry points into this module and their supporting
///  functions inlined into the corresponding __lwt_() functions at the end of
///  the file.  The entry points are the static inline functions, they might
///  invoke one or more non-inline noreturn related functions to ensure the
//{  compiler puts out-of-line the code that leads to aborting the program.

//{  Implementation and operations on: lllist_t

#define LLLIST_GEN_NEXT		1
#define LLLIST_COUNT_INC_SHIFT	32
#define LLLIST_COUNT_INC	(1uL << LLLIST_COUNT_INC_SHIFT)
#define LLLIST_GEN_COUNT_MASK	(~(1uL << (LLLIST_COUNT_INC_SHIFT - 1)))

static_assert(LLLIST_COUNT_INC_SHIFT == LLLIST_COUNT_SHIFT,
	      "LLLIST_COUNT_INC_SHIFT is known to be 32");

inline_only ureg_t lllist_inc_count_and_next_gen(ureg_t count_and_gen)
{
	return (count_and_gen + LLLIST_COUNT_INC + LLLIST_GEN_NEXT)
		& LLLIST_GEN_COUNT_MASK;
}

inline_only ureg_t lllist_add_count_and_next_gen(ureg_t count_and_gen, size_t n)
{
	return (count_and_gen + (n << LLLIST_COUNT_INC_SHIFT) + LLLIST_GEN_NEXT)
		& LLLIST_GEN_COUNT_MASK;
}

inline_only ureg_t lllist_dec_count_and_next_gen(ureg_t count_and_gen)
{
	return (count_and_gen - LLLIST_COUNT_INC + LLLIST_GEN_NEXT)
		& LLLIST_GEN_COUNT_MASK;
}

inline_only void lllist_init(lllist_t *list)
{
	list->lll_first = NULL;
	list->lll_count_gen = 0;
}

inline_only void *lllist_head(lllist_t *list)
{
	return (void *) ureg_load_acq((ureg_t *) &list->lll_first);
}

inline_only lllist_t lllist_load(lllist_t *list)
{
	lllist_t lll;
	lll.uregx2 = uregx2_load(&list->uregx2);
	return lll;
}

inline_only lllist_t lllist_comp_and_swap_acq_rel(lllist_t old, lllist_t new,
						  lllist_t *list)
{
	uregx2_t pre = uregx2_comp_and_swap_acq_rel(old.uregx2, new.uregx2,
						    &list->uregx2);
	return (lllist_t){.uregx2 = pre};
}

inline_only bool lllist_equal(lllist_t a, lllist_t b)
{
	return uregx2_equal(a.uregx2, b.uregx2);
}

inline_only void lllist_insert(lllist_t *list, llelem_t *elem)
{
	lllist_t new;
	lllist_t old;

	old = lllist_load(list);
	for (;;) {
		elem->lll_next = old.lll_first;
		new.lll_first = elem;
		new.lll_count_gen =
			lllist_inc_count_and_next_gen(old.lll_count_gen);
		lllist_t pre = lllist_comp_and_swap_acq_rel(old, new, list);
		if (lllist_equal(pre, old))
			return;
		old = pre;
	}
}

inline_only void lllist_insert_chain(lllist_t *list, llelem_t *first,
				     llelem_t *last, size_t n)
{
	lllist_t new;
	lllist_t old;

	old = lllist_load(list);
	for (;;) {
		last->lll_next = old.lll_first;
		new.lll_first = first;
		new.lll_count_gen =
			lllist_add_count_and_next_gen(old.lll_count_gen, n);
		lllist_t pre = lllist_comp_and_swap_acq_rel(old, new, list);
		if (lllist_equal(pre, old))
			return;
		old = pre;
	}
}

inline_only llelem_t *lllist_remove(lllist_t *list)
{
	llelem_t *elem;
	lllist_t new;
	lllist_t old;

	old = lllist_load(list);
	for (;;) {
		elem = old.lll_first;
		if (!elem)
			return NULL;
		new.lll_first = elem->lll_next;
		new.lll_count_gen =
			lllist_dec_count_and_next_gen(old.lll_count_gen);
		lllist_t pre = lllist_comp_and_swap_acq_rel(old, new, list);
		if (lllist_equal(pre, old))
			return elem;
		old = pre;
	}
}


//}{  Stack allocation and a their caching.

static alloc_value_t stk_alloc(size_t stacksize, size_t guardsize)
{
	stacksize = PAGE_SIZE_ROUND_UP(stacksize);
	guardsize = PAGE_SIZE_ROUND_UP(guardsize);
	size_t size = stacksize + guardsize;

	void *mem = mmap(NULL, size, PROT_READ | PROT_WRITE,
			 MAP_PRIVATE | MAP_ANONYMOUS, -1, (off_t) 0);
	if ((void *)-1 == mem)
		return (alloc_value_t) {.mem = NULL, .error = errno};
	if (mprotect(mem, guardsize, PROT_NONE) == -1) {
		error_t error = errno;
		(void) munmap(mem, size);
		return (alloc_value_t) {.mem = NULL, .error = error};
	}

	stk_t *stk = (stk_t *) ((uptr_t) mem + size - sizeof(stk_t));
	stk->stk_stacksize = stacksize;
	stk->stk_guardsize = guardsize;
	return (alloc_value_t) {.mem = stk, .error = 0};
}

static void stk_free(stk_t *stk)
{
	size_t size = stk->stk_stacksize + stk->stk_guardsize;
	void *mem = (void *)((uptr_t) stk + sizeof(stk_t) - size);
	if (munmap(mem, size) == -1)
		assert(0);
}

inline_only stkbkta_t stkbkta_load(stkbkta_t *stkbkta)
{
	stkbkta_t sba;
	sba.uregx2 = uregx2_load(&stkbkta->uregx2);
	return sba;
}

inline_only stkbkta_t stkbkta_comp_and_swap_acq_rel(stkbkta_t old,
						    stkbkta_t new,
						    stkbkta_t *stkbkta)
{
	uregx2_t pre = uregx2_comp_and_swap_acq_rel(old.uregx2, new.uregx2,
						    &stkbkta->uregx2);
	return (stkbkta_t){.uregx2 = pre};
}

inline_only bool stkbkta_equal(stkbkta_t a, stkbkta_t b)
{
	return uregx2_equal(a.uregx2, b.uregx2);
}

static void stkcache_init(stkcache_t *stkcache)
{
	stkbkt_t *stkbkt = stkcache->stkcache_buckets;
	stkbkt_t *stkbktend = &stkcache->stkcache_buckets[STKCACHE_BUCKETS];

	for (; stkbkt < stkbktend; ++stkbkt) {
		lllist_init(&stkbkt->stkbkt_lllist);
		stkbkt->stkbkta.stkbkt_stacksize = 0;
		stkbkt->stkbkta.stkbkt_guardsize = 0;
	}
}

static alloc_value_t stkcache_alloc_stk(stkcache_t *stkcache,
					size_t stacksize, size_t guardsize)
{
	stkbkt_t *stkbkt = stkcache->stkcache_buckets;
	stkbkt_t *stkbktend = &stkcache->stkcache_buckets[STKCACHE_BUCKETS];

	for (; stkbkt < stkbktend; ++stkbkt) {
		if (stkbkt->stkbkta.stkbkt_stacksize == stacksize &&
		    stkbkt->stkbkta.stkbkt_guardsize == guardsize) {
			llelem_t *elem;
			elem = lllist_remove(&stkbkt->stkbkt_lllist);
			if (!elem)
				break;
			stk_t *stk = (stk_t *)(elem + 1);
			return (alloc_value_t) {.mem = stk, .error = 0};
		}
	}
	return stk_alloc(stacksize, guardsize);
}

//  Free the stk onto a cache of freed stacks, if there is one available
//  for its stack size and guard size, if not all the stkcache_t have been
//  used allocate one.

static void stkcache_free_stk(stkcache_t *stkcache, stk_t *stk)
{
	stkbkt_t *stkbkt = stkcache->stkcache_buckets;
	stkbkt_t *stkbktend = &stkcache->stkcache_buckets[STKCACHE_BUCKETS];
	size_t stacksize = stk->stk_stacksize;
	size_t guardsize = stk->stk_guardsize;

	for (; stkbkt < stkbktend; ++stkbkt) {
		size_t stksz = stkbkt->stkbkta.stkbkt_stacksize;
		if (stksz == stacksize &&
		    stkbkt->stkbkta.stkbkt_guardsize == guardsize) {
insert:;		llelem_t *elem = (llelem_t *)stk - 1;
			lllist_insert(&stkbkt->stkbkt_lllist, elem);
			return;
		}
		if (!stksz) {
			stkbkta_t old = stkbkta_load(&stkbkt->stkbkta);
retry:;			if (old.stkbkt_stacksize != 0)
				continue;
			stkbkta_t new;
			new.stkbkt_stacksize = stacksize;
			new.stkbkt_guardsize = guardsize;
			stkbkta_t pre = stkbkta_comp_and_swap_acq_rel(old, new,
							&stkbkt->stkbkta);
			if (likely(stkbkta_equal(pre, old)))
				goto insert;
			old = pre;
			goto retry;
		}

	}
	stk_free(stk);
}

//  stk->stk_guardsize with this value means the memory was
//  provided by the user and shold not be kept in a stkcache_t

#define	GUARDSIZE_USER_OWNS_STACK	(~0uL)

inline_only alloc_value_t thr_alloc_stk(const thrattr_t *thrattr)
{
	if (thrattr->thrattr_stackaddr == NULL) {
		cpu_t *cpu = cpu_current();
		return stkcache_alloc_stk(&cpu->cpu_core->core_hw.hw_stkcache,
					  thrattr->thrattr_stacksize,
					  thrattr->thrattr_guardsize);
	}

	stk_t *stk = (stk_t *) ((uptr_t) thrattr->thrattr_stackaddr
				+ thrattr->thrattr_stacksize - sizeof(stk_t));
	stk->stk_stacksize = thrattr->thrattr_stacksize;
	stk->stk_guardsize = GUARDSIZE_USER_OWNS_STACK;
	return (alloc_value_t) {.mem = stk, .error = 0};
}

inline_only void thr_free_stk(stk_t *stk)
{
	// XXX this needs to be called from a different stack or it might be
	// acquired and reused while it is still being used by this thread
	// or it needs to have its work done all in registers and its caller
	// and all the way backwards to the scheduler all not touching the
	// stack.  Lazily releasing the stack when the next thread is given
	// this cpu would be the right way to do it, could be in per-CPU
	// area until then and then this being called from that point.

	if (stk->stk_guardsize != GUARDSIZE_USER_OWNS_STACK) {
		cpu_t *cpu = cpu_current();
		stkcache_free_stk(&cpu->cpu_core->core_hw.hw_stkcache, stk);
	}
}


//}  Operations on thrid_t values and their index into the thr_arena.
///  Also miscellaneous thr_t functions that don't fit elsewhere.
//{  These values live in the lwt_t variables that the API user uses.

inline_only thr_t *thr_from_thrid(thrid_t thrid)
{
	thr_t *thr = THR_INDEX_BASE + THRID_INDEX(thrid);
	if (thr >= (thr_t *) thr_arena.arena_next)
		return NULL;
	if (thrid.thrid_all != thr->thra.thra_thrid.thrid_all)
		return NULL;
	return thr;
}

inline_only thrx_t *thrx_from_thr(thr_t *thr)
{
	return THRX_INDEX_BASE + THRID_INDEX(thr->thra.thra_thrid);
}

inline_only ctx_t *ctx_from_thr(thr_t *thr)
{
	return &thrx_from_thr(thr)->thrx_ctx;
}

inline_only thr_t *thr_from_index(ureg_t index)
{
	return THR_INDEX_BASE + index;
}

static bool thr_can_use_current_cpu(thr_t *in)
{
	//  TODO: revisit with respect to cpu/core affinity.
	return true;
}


//}{  mtxattr_*() functions, mtxattr_t 

inline_only int mtxattr_init(mtxattr_t **mtxattrpp)
{
	*mtxattrpp = (mtxattr_t *) LWT_MTX_FAST;
	return 0;
}

inline_only int mtxattr_destroy(mtxattr_t **mtxattrpp)
{
	*mtxattrpp = (mtxattr_t *) LWT_MTX_FAST;
	return 0;
}

inline_only int mtxattr_settype(mtxattr_t **mtxattrpp, int kind)
{
	switch (kind) {
	default:
		return EINVAL;
	case LWT_MTX_FAST:
	case LWT_MTX_ERRORCHECK:
	case LWT_MTX_RECURSIVE:
		break;
	}
	*mtxattrpp = (mtxattr_t *)(uptr_t) kind;
	return 0;
}

inline_only int mtxattr_gettype(const mtxattr_t *mtxattr, int *kind)
{
	*kind = (int)(uptr_t) mtxattr;
	return 0;
}


//}{  mtx_*() functions

inline_only alloc_value_t mtx_alloc(void)
{
	return arena_alloc(&mtx_arena);
}

inline_only void mtx_free(mtx_t *mtx)
{
	arena_free(&mtx_arena, mtx);
}

inline_only mtx_atom_t mtx_load(mtx_t *mtx)
{
	mtx_atom_t mtx_atom;
	mtx_atom.uregx2 = uregx2_load(&mtx->mtxa.uregx2);
	return mtx_atom;
}

inline_only mtx_atom_t mtx_comp_and_swap_acq_rel(mtx_atom_t old, mtx_atom_t new,
						 mtx_t *mtx)
{
	uregx2_t pre = uregx2_comp_and_swap_acq_rel(old.uregx2, new.uregx2,
						    &mtx->mtxa.uregx2);
	return (mtx_atom_t){.uregx2 = pre};
}

inline_only bool mtx_atom_equal(mtx_atom_t a, mtx_atom_t b)
{
	return uregx2_equal(a.uregx2, b.uregx2);
}

inline_only mtxid_t mtx_get_mtxid(mtx_t *mtx)
{
	mtxid_t mtxid = { .mtxid_reuse = MTXA_REUSE(mtx->mtxa),
			  .mtxid_index = (u32_t)
					 (mtx - (mtx_t *) MTX_ARENA_START) };
	return mtxid;
}

inline_only bool mtxa_locked(mtx_atom_t mtxa)
{
	return MTXA_OWNER(mtxa) != MTX_UNLOCKED;
}

inline_only thr_t *mtx_lllist_to_thr(ureg_t mtxlllist)
{
	if (mtxlllist == MTX_LLLIST_EMPTY)
		return NULL;
	return thr_from_index(mtxlllist);
}

inline_only int mtx_create(mtx_t **mtxpp, const mtxattr_t *mtxattr)
{
	lwt_mtx_type_t type = (int)(uptr_t) mtxattr;
	if (type > LWT_MTX_LAST) {
		*mtxpp = NULL;
		return EINVAL;
	}

	alloc_value_t av = mtx_alloc();
	if (av.error) {
		*mtxpp = NULL;
		return av.error;
	}

	//  DO NOT CHANGE VALUE OF:
	//	mtxa.mtxa_reuse
	//  It is part of the mtxid_t, its incremented by mtx_destroy()

	mtx_t *mtx = av.mem;
	mtx_atom_t mtxa = mtx_load(mtx);

	mtxa.mtxa_reccnt_llasync_llwant = 
		(MTX_LLLIST_EMPTY << MTXA_LLWANT_SHIFT) | 
		(MTX_LLLIST_EMPTY << MTXA_LLASYNC_SHIFT);

	MTXA_TYPE_SET(mtxa, type);
	MTXA_OWNER_SET(mtxa, MTX_UNLOCKED);
	mtx->mtxa = mtxa;
	mtx->mtx_wantpriq = NULL;
	*mtxpp = mtx;
	return 0;
}

inline_only int mtx_destroy(mtx_t **mtxpp)
{
	mtx_t *mtx = *mtxpp;
	*mtxpp = NULL;

	mtx_atom_t old = mtx_load(mtx);

	//  Racing thr_cancel() on a condition that is no longer being
	//  waited upon protected by this mutex that is no longer being
	//  used and is being destroyed requires that the mtxa_reuse and
	//  every other field be updated with a compare and swap to ensure
	//  that the other thread's protocol to asynchronously insert the
	//  thread cancelation doesn't go wrong.

	for (;;) {
		assert(MTXA_RECCNT(old)  == 0 &&
		       MTXA_LLWANT(old)  == MTX_LLLIST_EMPTY &&
		       MTXA_LLASYNC(old) == MTX_LLLIST_EMPTY &&
		       MTXA_OWNER(old)   == MTX_UNLOCKED &&
		       mtx->mtx_wantpriq == NULL);
		mtx_atom_t new = old;
		MTXA_REUSE_INC(new);
		mtx_atom_t pre = mtx_comp_and_swap_acq_rel(old, new, mtx);
		if (likely(mtx_atom_equal(pre, old)))
			break;
		old = pre;
	}

	mtx_free(mtx);
	return 0;
}

inline_only int mtx_trylock(mtx_t *mtx)
{
	thr_t *thr = thr_current();
	mtx_atom_t old = mtx_load(mtx);
	ureg_t thridix = THRID_INDEX(thr->thra.thra_thrid);

retry:;
	mtx_atom_t new = old;
	if (likely(MTXA_OWNER(new) == MTX_UNLOCKED))
		MTXA_OWNER_SET_WHEN_UNLOCKED(new, thridix);
	else {
		lwt_mtx_type_t type = (lwt_mtx_type_t) MTXA_TYPE(old);
		if (likely(type == LWT_MTX_FAST))
			return EBUSY;
		if (likely(MTXA_OWNER(new) != thridix))
			return EBUSY;
		if (unlikely(type == LWT_MTX_ERRORCHECK))
			return EDEADLK;
		//  type == LWT_MTX_RECURSIVE
		MTXA_RECCNT_INC(new);
	}
	mtx_atom_t pre = mtx_comp_and_swap_acq_rel(old, new, mtx);
	if (likely(mtx_atom_equal(pre, old))) {
		++thr->thr_mtxcnt;
		return 0;
	}
	old = pre;
	goto retry;
}

//  This function should have been named:
//      inline_only int mtx_lock(mtx_t *mtx)
//  See comment for __lwt_mtx_lock() towards the end of the file.  There is
//  also a #define for mtx_lock() to this function to avoid this compiler
//  workaround from spreading to internal callers of lwt_lock() in this file.

int __lwt_mtx_lock(mtx_t *mtx)
{
	thr_t *thr = thr_current();
	mtx_atom_t old = mtx_load(mtx);
	ureg_t thridix = THRID_INDEX(thr->thra.thra_thrid);
	ctx_t *ctx = NULL;

retry:;
	mtx_atom_t new = old;
	if (likely(MTXA_OWNER(new) == MTX_UNLOCKED)) {
		MTXA_RECCNT_SET(new, 0uL);
		MTXA_OWNER_SET_WHEN_UNLOCKED(new, thridix);
	} else if (likely(MTXA_OWNER(new) != thridix)) {
		thr->thr_ln.ln_prev = mtx_lllist_to_thr(MTXA_LLWANT(new));
		MTXA_LLWANT_SET(new, thridix);
		if (!ctx) {
			ctx = ctx_from_thr(thr);
			if (!ctx_save(ctx)) {			// returns twice
				//  Second return, when thr resumes
				//  the mtx has been handed off to it.

				debug(thr->thr_mtxcnt &&
				      MTXA_OWNER(mtx->mtxa) ==
				      THRID_INDEX(thr->thra.thra_thrid));
				return 0;
			}
			// first return
		}
	} else {
		lwt_mtx_type_t type = (lwt_mtx_type_t) MTXA_TYPE(old);
		if (type == LWT_MTX_FAST)
			thr_block_forever("mtx_lock", mtx);	// self-deadlock
		if (type == LWT_MTX_ERRORCHECK)
			return EDEADLK;
		//  type == LWT_MTX_RECURSIVE
		MTXA_RECCNT_INC(new);
	}

	mtx_atom_t pre = mtx_comp_and_swap_acq_rel(old, new, mtx);
	if (unlikely(!mtx_atom_equal(pre, old))) {
		old = pre;
		goto retry;
	}
	if (MTXA_LLWANT(new) == thridix)
		sched_out(thr);

	++thr->thr_mtxcnt;
	return 0;
}

inline_only int mtx_unlock_common(mtx_t *mtx, bool from_cond_wait)
{
	thr_t *thr = thr_current();
	mtx_atom_t old = mtx_load(mtx);
	ureg_t thridix = THRID_INDEX(thr->thra.thra_thrid);

	if (MTXA_TYPE(old) != LWT_MTX_ERRORCHECK)
		assert(MTXA_OWNER(old) == thridix);
	else if (MTXA_OWNER(old) != thridix)
		return EPERM;

	ureg_t reccnt = MTXA_RECCNT(old);

retry:;
	mtx_atom_t new = old;
	thr_t *owner = NULL;
	thr_t *tail = NULL;

	if (!from_cond_wait && reccnt != 0) {
		MTXA_RECCNT_DEC(new);
	} else if (mtx->mtx_wantpriq) {
		owner = mtx->mtx_wantpriq;
		MTXA_OWNER_SET(new, THRID_INDEX(owner->thra.thra_thrid));
		MTXA_RECCNT_SET(new, owner->thr_reccnt);
	} else if (MTXA_LLWANT(new) != MTX_LLLIST_EMPTY) {
		tail = mtx_lllist_to_thr(MTXA_LLWANT(new));
		owner = tail;
		thr_t *prev;
		ureg_t loop = 0;
		while ((prev = owner->thr_ln.ln_prev)) {
			owner = prev;
			++loop;		// optimized out when debug() is NOOP()
			debug(loop < 1000);
		}
		MTXA_LLWANT_SET(new, MTX_LLLIST_EMPTY);
		MTXA_OWNER_SET(new, THRID_INDEX(owner->thra.thra_thrid));
		MTXA_RECCNT_SET(new, owner->thr_reccnt);
	} else {
		MTXA_OWNER_SET(new, MTX_UNLOCKED);
		MTXA_RECCNT_SET(new, 0);
	}

	mtx_atom_t pre = mtx_comp_and_swap_acq_rel(old, new, mtx);
	if (unlikely(!mtx_atom_equal(pre, old))) {
		old = pre;
		goto retry;
	}

	thr->thr_mtxcnt -= from_cond_wait ? reccnt + 1 : 1;
	if (!owner)
		return 0;

	owner->thr_mtxcnt += owner->thr_reccnt + 1;
	owner->thr_reccnt = 0;
	if (tail) {
		//  mtx->mtx_wantpriq is empty, MTXA_LLWANT(old) threads
		//  are in reverse order of arrival, they are linked by
		//  their thr_ln.ln_prev fields.  Link them circularly
		//  by their ln_next fields (i.e. arrival order) and
		//  store the list in mtx->mtx_wantpriq.

		thr_t *prev = tail;
		thr_t *head = tail;
		for (;;) {
			thr_t *p = prev->thr_ln.ln_prev;
			if (!p)
				break;
			head = p;
			head->thr_ln.ln_next = prev;
			prev = head;
		}
		head->thr_ln.ln_prev = tail;
		tail->thr_ln.ln_next = head;
		assert(!mtx->mtx_wantpriq);
		mtx->mtx_wantpriq = head;
	}
	assert(mtx->mtx_wantpriq == owner);
	thr_t *next = owner->thr_ln.ln_next;
	if (next == owner)
		mtx->mtx_wantpriq = NULL;
	else {
		thr_t *prev = owner->thr_ln.ln_prev;
		next->thr_ln.ln_prev = prev;
		prev->thr_ln.ln_next = next;
		mtx->mtx_wantpriq = next;
	}

	//  If this is an unlock from cnd_wait()/cnd_timedwait(), then
	//  schedule owner to run but don't switch to it irrespective of
	//  its priority because this thread is about to schedule itself
	//  out shortly in the cnd_wait()/cnd_timedwait() function.
	//  Additionally, if the current thread still owns some mutexes
	//  then don't switch either to the owner, this is because of the
	//  priority ceiling scheme to prevent priority inversion.

	if (from_cond_wait || thr->thr_mtxcnt ||
	    owner->thr_prio <= thr->thr_prio || !thr_can_use_current_cpu(owner))

		//  sched_in() always returns zero, this allows for
		//  tail call elimination by the compiler here.

		return sched_in(owner);

	//  The priority of the current thread is lower than owner's, the
	//  current thread will wait for cpu and owner will run. When the
	//  current thread resumes, the return from the second return from
	//  ctx_save() (which returns the value zero), this allows for tail
	//  call elimination here.

	return thr_context_save__thr_run(thr, owner);
}

inline_only int mtx_unlock(mtx_t *mtx)
{
	return mtx_unlock_common(mtx, false);
}

static int mtx_unlock_from_cond_wait(mtx_t *mtx)
{
	return mtx_unlock_common(mtx, true);
}
 

//}{  cnd_*() functions

//  This function should have been named:
//      inline_only int cnd_wait(cnd_t *cnd, mtx_t *mtx)
//  See comment for __lwt_cnd_wait() towards the end of the file.  There is
//  also a #define for cnd_wait() to this function to avoid this compiler
//  workaround from spreading to internal callers of cnd_wait() in this file.
//
//  The data structure manipulation here is all done under the protection of
//  mtx which is owned by the current thread .

int __lwt_cnd_wait(cnd_t *cnd, mtx_t *mtx)	//  aka cnd_wait()
{
	thr_t *thr = thr_current();
	assert(THRID_INDEX(thr->thra.thra_thrid) == MTXA_OWNER(mtx->mtxa));

	if (cnd->cnd_mtx == NULL)
		cnd->cnd_mtx = mtx;
	else
		assert(mtx == cnd->cnd_mtx);

	thr_t *head = cnd->cnd_waitpriq;
	if (!head) {
		thr->thr_ln.ln_next = thr;
		thr->thr_ln.ln_prev = thr;
		cnd->cnd_waitpriq = thr;
	} else {
		thr_t *tail = head->thr_ln.ln_prev;
		thr ->thr_ln.ln_next = head;
		thr ->thr_ln.ln_prev = tail;
		tail->thr_ln.ln_next = thr;
		head->thr_ln.ln_prev = thr;
	}

	//  Even if the mutex is not recursive saving and restoring the
	//  recursive mutex count is simplest and probably faster than having
	//  several tests on mtx->mtx_type tests or duplicated code to reduce
	//  those tests.

	ureg_t reccnt = MTXA_RECCNT(mtx->mtxa);
	thr->thr_mtxid = mtx_get_mtxid(mtx);
	thr->thr_cnd = cnd;
	ctx_t *ctx = ctx_from_thr(thr);
	if (ctx_save(ctx)) {				// returns twice
		mtx_unlock_from_cond_wait(mtx);		// first return
		sched_out(thr);
	}

	//  Second return, when cnd is awakened the thread is moved to the
	//  mtx->mtx_wantpriq, eventually when the mtx is unlocked the thread
	//  resumes here with the lock already acquired, see cnd_wakeup().

	debug(THRID_INDEX(thr->thra.thra_thrid) == MTXA_OWNER(mtx->mtxa));
	return 0;
}

static inline int cnd_timedwait(cnd_t *cnd,
				mtx_t *mtx,
				const struct timespec *abstime)
{
	TODO();
}

//  Wakeup one or all threads waiting for the condition, the current thread
//  owns mtx, move all the awakened threads to the mtx->mtx_wantpriq, when the
//  mtx is unlocked, the awakened threads will, one by one eventually become
//  the mtx owner, when their context is reloaded their cnd_wait() will be
//  complete (cnd_wait() doesn't need to explicitly re-acquire the mtx because
//  the thread has already been placed on its the mtx->mtx_wantpriq).

//  Note that the mtx's MTXA_LLWANT() might also have threads waiting for the
//  mtx, it is simpler to be unfair to those and place the awakened threads
//  prior to them in the mtx->mtx_wantpriq (at the tail of it) because the
//  threads in MTXA_LLWANT() are all comming from mtx_lock(), mtx->mtx_wantpriq
//  threads are comming from mtx_lock() or earlier cnd_wait() calls, so to be
//  fair to the earlier cnd_wait() threads the awakened threads are placed at
//  the tail of mtx->mtx_wantpriq.  Appart from simplicity, a rationale to let
//  the awakened threads go ahead of the mtx_lock() threads is that they were
//  already in the middle of their mtx/cnd monitor critical section whereas
//  the mtx_lock() ones were wanting to enter their mtx/cnd critical sections
//  so servicing the first group first seems fairer.  The simplicity should
//  not be overestimated, being "fair" to the MTXA_LLWANT() threads would
//  require atomic compara-and-swap manipulation of mtx->mtxa and the resulting
//  complexity.

//  The data structure manipulation here is all done under the protection of
//  mtx which is owned by the current thread .

inline_only int cnd_wakeup(cnd_t *cnd, mtx_t *mtx, bool broadcast)
{
	thr_t *thr = thr_current();
	assert(THRID_INDEX(thr->thra.thra_thrid) == MTXA_OWNER(mtx->mtxa));

	thr_t *head = cnd->cnd_waitpriq;
	if (!head)
		return 0;

	assert(mtx == cnd->cnd_mtx);
	thr_t *tail;
	if (broadcast) {
		tail = head->thr_ln.ln_prev;
		cnd->cnd_waitpriq = NULL;
		cnd->cnd_mtx = NULL;
	} else {
		tail = head;
		if (head == head->thr_ln.ln_prev) {
			cnd->cnd_waitpriq = NULL;
			cnd->cnd_mtx = NULL;
		} else {
			thr_t *next = head->thr_ln.ln_next;
			thr_t *prev = head->thr_ln.ln_prev;
			prev->thr_ln.ln_next = next;
			next->thr_ln.ln_prev = prev;
			cnd->cnd_waitpriq = next;
		}
	}

	thr_t *t = head;
	for (;; t = t->thr_ln.ln_next) {
		t->thr_mtxid = (mtxid_t) {.mtxid_all = MTXID_NULL};
		t->thr_cnd = NULL;
		if (t == tail)
			break;
	}

	thr_t *mhead = mtx->mtx_wantpriq;
	if (!mhead) {
		head->thr_ln.ln_prev = tail;
		tail->thr_ln.ln_next = head;
		mtx->mtx_wantpriq = head;
	} else {
		thr_t *mtail = mhead->thr_ln.ln_prev;
		head ->thr_ln.ln_prev = mtail;
		tail ->thr_ln.ln_next = mhead;
		mhead->thr_ln.ln_prev = tail;
		mtail->thr_ln.ln_next = head;
	}
	return 0;
}

inline_only int cnd_signal(cnd_t *cnd, mtx_t *mtx)
{
	return cnd_wakeup(cnd, mtx, false);
}

inline_only int cnd_broadcast(cnd_t *cnd, mtx_t *mtx)
{
	return cnd_wakeup(cnd, mtx, true);
}

inline_only alloc_value_t cnd_alloc(void)
{
	return arena_alloc(&cnd_arena);
}

inline_only void cnd_free(cnd_t *cnd)
{
	arena_free(&cnd_arena, cnd);
}

inline_only int cnd_create(cnd_t **cndpp, const cndattr_t *cndattr)
{
	alloc_value_t av = cnd_alloc();
	if (av.error) {
		*cndpp = NULL;
		return av.error;
	}

	cnd_t *cnd = av.mem;
	cnd->cnd_waitpriq = NULL;
	cnd->cnd_mtx = NULL;
	*cndpp = cnd;
	return 0;
}

inline_only int cnd_destroy(cnd_t **cndpp)
{
	cnd_t *cnd = *cndpp;
	assert(cnd->cnd_waitpriq == NULL && cnd->cnd_mtx == NULL);
	cnd_free(cnd);
	*cndpp = NULL;
	return 0;
}


//}{  spin_*() functions

#if 0
#define	SPIN_UNLOCKED	((uptr_t) 0)

inline_only int spin_unlock(spin_t *spin)
{
	// TODO: providing spin locks to user mode is a mistake, these
	// ought to be mapped to mutexes, holding a spin lock and taking
	// a page fault while holding it is a horrible thing for the other
	// CPUs wanting the spin locks.  Alternatively these could be adaptive
	// locks that only spin if the lock owner is currently running.

	// Try this for curiosity...
	//	uptr_store_rel(&spin->spin_mem, SPIN_UNLOCKED);
	// we know that SPIN_UNLOCKED is zero ...

	uptr_store_zero_rel(&spin->spin_mem);
	return 0;
}

inline_only bool spin_locked(spin_t *spin)
{
	return spin->spin_mem != SPIN_UNLOCKED;
}

inline_only int spin_init(spin_t *spin)
{
	spin->spin_mem = SPIN_UNLOCKED;
	return 0;
}

inline_only int spin_destroy(spin_t *spin)
{
	return 0;
}

inline_only int spin_lock(spin_t *spin)
{
	thr_t *thr = thr_current();

retry:
	uptr_t pre = uptr_comp_and_swap_acq(SPIN_UNLOCKED, (uptr_t) thr,
					    &spin->spin_mem);
	if (unlikely(pre != SPIN_UNLOCKED))
		goto retry;

	return 0;
}

inline_only int spin_trylock(spin_t *spin)
{
	thr_t *thr = thr_current();
	if (!uptr_comp_and_swap_acq(SPIN_UNLOCKED, (uptr_t) thr,
				    &spin->spin_mem))
		return EBUSY;
	return 0;
}
#endif

//}{  thrattr_*() functions

//  Based on Android Bionic values

#define	THRATTR_STACKSIZE	((1uL << 20) - THRATTR_SIGSTACKSIZE)
#define	THRATTR_GUARDSIZE	PAGE_SIZE
#define	THRATTR_SIGSTACKSIZE	(1uL << 15)
#define	THRATTR_PRIORITY	LWT_PRIO_MID

static thrattr_t thrattr_default = {
	.thrattr_initialized  = true,
	.thrattr_detach       = LWT_CREATE_JOINABLE,
	.thrattr_scope        = LWT_SCOPE_PROCESS,
	.thrattr_inheritsched = LWT_INHERIT_SCHED,
	.thrattr_schedpolicy  = LWT_SCHED_OTHER,
	.thrattr_priority     = THRATTR_PRIORITY,
	.thrattr_stackaddr    = NULL,
	.thrattr_stacksize    = THRATTR_STACKSIZE,
	.thrattr_guardsize    = THRATTR_GUARDSIZE,
};

inline_only int thrattr_init(thrattr_t *thrattr)
{
	*thrattr = thrattr_default;
	return 0;
}

inline_only int thrattr_destroy(thrattr_t *thrattr)
{
	thrattr->thrattr_initialized  = false;
	return 0;
}

#if 0
inline_only int thrattr_setsigmask_np(thrattr_t *thrattr,
				      const sigset_t *sigmask)
{
	if (!thrattr->thrattr_initialized) return EINVAL;
	TODO();
}

inline_only int thrattr_getsigmask_np(const thrattr_t *thrattr,
				      sigset_t *sigmask)
{
	if (!thrattr->thrattr_initialized) return EINVAL;
	TODO();
}

inline_only int thrattr_setaffinity_np(thrattr_t *thrattr, size_t cpusetsize,
				       const cpu_set_t *cpuset)
{
	if (!thrattr->thrattr_initialized) return EINVAL;
	TODO();
}

inline_only int thrattr_getaffinity_np(const thrattr_t *thrattr,
				       size_t cpusetsize, cpu_set_t *cpuset)
{
	if (!thrattr->thrattr_initialized) return EINVAL;
	TODO();
}
#endif

inline_only int thrattr_setdetachstate(thrattr_t *thrattr, int detachstate)
{
	if (!thrattr->thrattr_initialized || detachstate > LWT_CREATE_LAST)
		return EINVAL;
	thrattr->thrattr_detach = detachstate;
	return 0;
}

inline_only int thrattr_getdetachstate(const thrattr_t *thrattr,
				       int *detachstate)
{
	if (!thrattr->thrattr_initialized) return EINVAL;
	*detachstate = thrattr->thrattr_detach;
	return 0;
}

inline_only int thrattr_setscope(thrattr_t *thrattr, int scope)
{
	if (!thrattr->thrattr_initialized || scope > LWT_SCOPE_LAST)
		return EINVAL;
	thrattr->thrattr_scope = scope;
	return 0;
}

inline_only int thrattr_getscope(const thrattr_t *thrattr, int *scope)
{
	if (!thrattr->thrattr_initialized) return EINVAL;
	*scope = thrattr->thrattr_scope;
	return 0;
}

inline_only int thrattr_setschedpolicy(thrattr_t *thrattr, int policy)
{
	if (!thrattr->thrattr_initialized || policy > LWT_SCHED_LAST)
		return EINVAL;
	thrattr->thrattr_schedpolicy = policy;
	return 0;
}

inline_only int thrattr_getschedpolicy(const thrattr_t *thrattr, int *policy)
{
	if (!thrattr->thrattr_initialized) return EINVAL;
	*policy = thrattr->thrattr_schedpolicy;
	return 0;
}

inline_only int thrattr_setinheritsched(thrattr_t *thrattr, int inheritsched)
{
	if (!thrattr->thrattr_initialized ||
	    inheritsched > LWT_INHERITSCHED_LAST)
		return EINVAL;
	thrattr->thrattr_inheritsched = inheritsched;
	return 0;
}

inline_only int thrattr_getinheritsched(const thrattr_t *thrattr,
					int *inheritsched)
{
	if (!thrattr->thrattr_initialized) return EINVAL;
	*inheritsched = thrattr->thrattr_inheritsched;
	return 0;
}

inline_only int thrattr_setschedparam(thrattr_t *thrattr,
				      const lwt_sched_param_t *param)
{
	if (!thrattr->thrattr_initialized) return EINVAL;
	int prio = param->sched_priority;
	if (prio < LWT_PRIO_LOW || prio > LWT_PRIO_HIGH) return EINVAL;
	thrattr->thrattr_priority = prio;
	return 0;
}

inline_only int thrattr_getschedparam(const thrattr_t *thrattr,
				     lwt_sched_param_t *param)
{
	if (!thrattr->thrattr_initialized) return EINVAL;
	param->sched_priority = thrattr->thrattr_priority;
	return 0;
}

inline_only int thrattr_setstack(thrattr_t *thrattr,
				 void *stackaddr, size_t stacksize)
{
	if (!thrattr->thrattr_initialized) return EINVAL;
	thrattr->thrattr_stackaddr = stackaddr;
	thrattr->thrattr_stacksize = stacksize;
	return 0;
}

inline_only int thrattr_getstack(const thrattr_t *thrattr,
				 void **stackaddr, size_t *stacksize)
{
	if (!thrattr->thrattr_initialized) return EINVAL;
	*stackaddr = thrattr->thrattr_stackaddr;
	*stacksize = thrattr->thrattr_stacksize;
	return 0;
}

inline_only int thrattr_setstacksize(thrattr_t *thrattr, size_t stacksize)
{
	if (!thrattr->thrattr_initialized) return EINVAL;
	thrattr->thrattr_stacksize = stacksize;
	return 0;
}

inline_only int thrattr_getstacksize(const thrattr_t *thrattr,
				     size_t *stacksize)
{
	if (!thrattr->thrattr_initialized) return EINVAL;
	*stacksize = thrattr->thrattr_stacksize;
	return 0;
}

inline_only int thrattr_setstackaddr(thrattr_t *thrattr, void *stackaddr)
{
	if (!thrattr->thrattr_initialized) return EINVAL;
	thrattr->thrattr_stackaddr = stackaddr;
	return 0;
}

inline_only int thrattr_getstackaddr(const thrattr_t *thrattr,
				     void **stackaddr)
{
	if (!thrattr->thrattr_initialized) return EINVAL;
	*stackaddr = thrattr->thrattr_stackaddr;
	return 0;
}

inline_only int thrattr_setguardsize(thrattr_t *thrattr, size_t guardsize)
{
	if (!thrattr->thrattr_initialized) return EINVAL;
	thrattr->thrattr_guardsize = guardsize;
	return 0;
}

inline_only int thrattr_getguardsize(const thrattr_t *thrattr,
				     size_t *guardsize)
{
	if (!thrattr->thrattr_initialized) return EINVAL;
	*guardsize = thrattr->thrattr_guardsize;
	return 0;
}


//}{ thr_*() functions

inline_only alloc_value_t thr_alloc(void)
{
	return arena_alloc(&thr_arena);
}

inline_only void thr_free(thr_t *thr)
{
	arena_free(&thr_arena, thr);
}

inline_only thr_atom_t thr_load(thr_t *thr)
{
	thr_atom_t thr_atom;
	thr_atom.uregx2 = uregx2_load(&thr->thra.uregx2);
	return thr_atom;
}

inline_only thr_atom_t thr_comp_and_swap_acq_rel(thr_atom_t old, thr_atom_t new,
						 thr_t *thr)
{
	uregx2_t pre = uregx2_comp_and_swap_acq_rel(old.uregx2, new.uregx2,
						    &thr->thra.uregx2);
	return (thr_atom_t){.uregx2 = pre};
}

inline_only bool thr_atom_equal(thr_atom_t a, thr_atom_t b)
{
	return uregx2_equal(a.uregx2, b.uregx2);
}

static mtx_t *thr_block_forever_mtx;

static noreturn void thr_block_forever(const char *msg, void *arg)
{
	(void) mtx_lock_outline(thr_block_forever_mtx);
	assert(0);
}

inline_only int thr_init(thr_t *thr, thrx_t *thrx,
			 const thrattr_t *thrattr, stk_t *stk)
{
	bool detached = (thrattr->thrattr_detach == LWT_CREATE_DETACHED);

        thr->thr_running = false;
        thr->thr_prio = thrattr->thrattr_priority;
        thr->thr_schdom = schdom_from_thrattr(thrattr);
	thr->thr_cnd = NULL;
	thr->thr_mtxid = (mtxid_t) {.mtxid_all = MTXID_NULL};
	thr->thr_mtxcnt = 0;
	thr->thr_reccnt = 0;
	thr->thr_ln.ln_next = NULL;
	thr->thr_ln.ln_prev = NULL;

	mtx_t *mtx = NULL;
	cnd_t *cnd = NULL;
	if (!detached) {
		error_t error = mtx_create_outline(&mtx, NULL);
		if (error)
			return error;

		error = cnd_create_outline(&cnd, NULL);
		if (error) {
			mtx_destroy_outline(&mtx);
			return error;
		}
	}

	thrx->thrx_join_mtx = mtx;
	thrx->thrx_join_cnd = cnd;
	thrx->thrx_exited = false;
	thrx->thrx_joining = false;
	thrx->thrx_detached = detached;
	thrx->thrx_retval = NULL;
	thrx->thrx_stk = stk;
	return 0;
}

inline_only void thr_destroy(thr_t *thr)
{
	thrx_t *thrx = thrx_from_thr(thr);
	if (thrx->thrx_detached) {
		mtx_destroy(&thrx->thrx_join_mtx);
		cnd_destroy(&thrx->thrx_join_cnd);
	}
	thr_free_stk(thrx->thrx_stk);
	thr_free(thr);
}

static void thr_exited_cleanup(void)
{
	llelem_t *elem;
	while ((elem = lllist_remove(&thr_exited_lllist))) {
		thr_t *thr = (thr_t *) elem;
		thr->thr_cnd = NULL;
		while (bool_load_acq(&thr->thr_running))
			{}
		thr_destroy(thr);
	}
}

static void thr_exit(void *retval)
{
	thr_exited_cleanup();

	//  If thrx->thrx_stk is NULL its the main() thread.

	thr_t *thr = thr_current();
	thrx_t *thrx = thrx_from_thr(thr);

	assert(thr->thr_cnd == NULL);
	assert(thr->thr_mtxcnt == 0);

	if (!thrx->thrx_detached) {
		mtx_lock_outline(thrx->thrx_join_mtx);
		thrx->thrx_retval = retval;
		thrx->thrx_exited = true;
		cnd_broadcast(thrx->thrx_join_cnd, thrx->thrx_join_mtx);
		while (!thrx->thrx_joining)
			cnd_wait(thrx->thrx_join_cnd, thrx->thrx_join_mtx);
		mtx_unlock_outline(thrx->thrx_join_mtx);
	}

	thr_atom_t old = thr_load(thr);
retry:;
	thr_atom_t new = old;
	THRA_REUSE_INC(new);
	thr_atom_t pre = thr_comp_and_swap_acq_rel(old, new, thr);
	if (unlikely(!thr_atom_equal(pre, old))) {
		old = pre;
		goto retry;
	}

	lllist_insert(&thr_exited_lllist, (llelem_t *) thr);
	sched_out(thr);
}

static int thr_join(lwt_t thread, void **retvalpp)
{
	thr_exited_cleanup();

	thrid_t	thrid = *(thrid_t *) &thread;
	thr_t *thr = THR_INDEX_BASE + THRID_INDEX(thrid);
	if (THRID_REUSE(thrid) != THRA_REUSE(thr->thra))
		return ESRCH;

	if (thr == thr_current())
		return EDEADLK;

	thrx_t *thrx = thrx_from_thr(thr);
	if (thrx->thrx_detached)
		return EINVAL;

	mtx_lock_outline(thrx->thrx_join_mtx);
	if (thrx->thrx_joining) {
		mtx_unlock_outline(thrx->thrx_join_mtx);
		return EINVAL;
	}
	thrx->thrx_joining = true;
	cnd_broadcast(thrx->thrx_join_cnd, thrx->thrx_join_mtx);
	while (!thrx->thrx_exited)
		cnd_wait(thrx->thrx_join_cnd, thrx->thrx_join_mtx);
	void *retval = thrx->thrx_retval;
	mtx_unlock_outline(thrx->thrx_join_mtx);

	*retvalpp = retval;
	return 0;
}

static void thr_start(void *arg, void *(*function)(void *))
{
	thr_exit(function(arg));
}

inline_only void ctx_init(ctx_t *ctx, uptr_t sp, lwt_function_t function,
			  void *arg)
{
	ctx->ctx_pc = (ureg_t) __lwt_thr_start_glue;
	ctx->ctx_thr_start_func = (ureg_t) function;
	ctx->ctx_thr_start_arg0 = (ureg_t) arg;
	ctx->ctx_thr_start_pc = (ureg_t) thr_start;
	ctx->ctx_sp = sp;
	ctx->ctx_fpctx = NULL;
}

static int thr_create(lwt_t *thread, const thrattr_t *thrattr,
		      lwt_function_t function, void *arg)
{
	if (thrattr == NULL) thrattr = &thrattr_default;
	else if (!thrattr->thrattr_initialized) return EINVAL;

	alloc_value_t av = thr_alloc_stk(thrattr);
	if (av.error) return av.error;
	stk_t *stk = av.mem;

	//  The entries of the thr_arena and the thrx_arena are parallel to
	//  each other, the thread's thread index for its thr_t is also its
	//  index for its thrx_t.  Thus thrx_t are not allocated explicitly
	//  from the thrx_arena, doing so, because of concurrency would cause
	//  the entries to be mismatched because the allocation from both
	//  lockless lists would not be serialized without adding a lock.

	av = thr_alloc();
	if (av.error) {
		thr_free_stk(stk);
		return av.error;
	}
	thr_t *thr = av.mem;
	ureg_t thridix = thr - THR_INDEX_BASE;

	thr_atom_t old = thr_load(thr);
retry:;
	thr_atom_t new = old;
	THRA_INDEX_SET(new, thridix);
	thr_atom_t pre = thr_comp_and_swap_acq_rel(old, new, thr);
	if (unlikely(!thr_atom_equal(pre, old))) {
		old = pre;
		goto retry;
	}

	thrx_t *thrx = thrx_from_thr(thr);
	error_t error = thr_init(thr, thrx, thrattr, stk);
	if (error) {
		TODO();
		return error;
	}
	ctx_init(&thrx->thrx_ctx, (uptr_t) (stk - 1), function, arg);
	*(lwt_t *) thread = (lwt_t) thr->thra.thra_thrid.thrid_all;
	sched_in(thr);
	return 0;
}

static thr_t *thr_create_main(void)
{
	alloc_value_t av = thr_alloc();
	assert(!av.error);			// thr_arena already grown
	thr_t *thr = av.mem;
	THRA_INDEX_SET(thr->thra, thr - THR_INDEX_BASE);
	thrx_t *thrx = thrx_from_thr(thr);
	error_t error = thr_init(thr, thrx, &thrattr_default, NULL);
	assert(!error);
	cpu_t *cpu = cpu_current();
	thr->thr_running = true;
	cpu->cpu_running_thr = thr;
	return thr;
}

static int thr_cancel(lwt_t thread)
{
	TODO();
}

static void thr_testcancel(void)
{
	TODO();
}

static int thr_setcancelstate(int state, int *oldstate)
{
	TODO();
}

static int thr_setcanceltype(int type, int *oldtype)
{
	TODO();
}


//}{ Scheduler functions.

//  This is a light touch examination of schedq to see if it is empty,
//  it does not touch the memory with a compare-and-swap, which most
//  likely might cause unwanted cache effects.

inline_only bool schedq_is_empty(schedq_t *schedq)
{
	return *(volatile ureg_t *)
	       &schedq->sq_rem_remnxt_insprv_ins_state == 0;
}

inline_only ureg_t schedq_index(schedq_t *schedq)
{
	//  sqcl_t has pad space, as long as a uniform set of indexes is
	//  generated that is all that is needed by the caller
	//  TODO: fix qhen sqcls[] and related are generated from /proc

	return schedq - &sqcls[0].sqcl_schedq;
}

inline_only schedq_t schedq_comp_and_swap_acq_rel(schedq_t old, schedq_t new,
						  schedq_t *schedq)
{
	uregx2_t pre = uregx2_comp_and_swap_acq_rel(old.uregx2, new.uregx2,
						    &schedq->uregx2);
	return (schedq_t){.uregx2 = pre};
}

inline_only schedq_t schedq_loadatomic(schedq_t *schedq)
{
	//  Both old and new are impossible values, the compare and swap
	//  will fail, but as a result of that the returned value will
	//  be the atomical fetch of memory that schedq points to.

	return schedq_comp_and_swap_acq_rel(SCHEDQ_INVALID_1, SCHEDQ_INVALID_2,
					    schedq);
}

inline_only bool schedq_equal(schedq_t a, schedq_t b)
{
	return uregx2_equal(a.uregx2, b.uregx2);
}

inline_only thrln_t thrln_comp_and_swap_acq_rel(thrln_t old,
						thrln_t new,
						thrln_t *thrln)
{
	uregx2_t pre = uregx2_comp_and_swap_acq_rel(old.uregx2, new.uregx2,
						    &thrln->uregx2);
	return (thrln_t){.uregx2 = pre};
}

inline_only thrln_t thrln_loadatomic(thrln_t *thrln)
{
	//  Both old and new are impossible values, the compare and swap
	//  will fail, but as a result of that the returned value will
	//  be the atomical fetch of memory that thrln points to.

	return thrln_comp_and_swap_acq_rel(THRLN_INVALID_1,
					   THRLN_INVALID_2, thrln);
}

inline_only bool thrln_equal(thrln_t a, thrln_t b)
{
	return uregx2_equal(a.uregx2, b.uregx2);
}

static void schdom_init(schdom_t *schdom, core_t *core)
{
	schdom->schdom_core = core;
	schdom->schdom_mask = 0uL;
	sqcl_t *sqcl = schdom->schdom_sqcls;
	sqcl_t *sqclend = sqcl + SQ_PRIO_MAX;
	for (; sqcl < sqclend; ++sqcl) {
		SCHEDQ_STATE_SET(sqcl->sqcl_schedq, 0b000);
		SCHEDQ_INS_SET   (sqcl->sqcl_schedq, THRID_NULL);
		SCHEDQ_INSPRV_SET(sqcl->sqcl_schedq, THRID_NULL);
		SCHEDQ_REMNXT_SET(sqcl->sqcl_schedq, THRID_NULL);
		SCHEDQ_REM_SET   (sqcl->sqcl_schedq, THRID_NULL);
		SCHEDQ_ICNT_SET(sqcl->sqcl_schedq, 0uL);
		SCHEDQ_ISER_SET(sqcl->sqcl_schedq, 0uL);
		SCHEDQ_RSER_SET(sqcl->sqcl_schedq, 0uL);
		SCHEDQ_RCNT_SET(sqcl->sqcl_schedq, 0uL);
	}
}

static ureg_t schedom_core_rotor = 0;

static schdom_t *schdom_from_thrattr(const thrattr_t *thrattr)
{
	// TODO: cpu/core affinity
#if 0
#	ifdef LWT_HWSYS
		return &hwsys.hw_schdom;
#	elif defined(LWT_MCORES)
		return &mcores[0].hw_schdom;
#	else
		return &cores[0].core_hw.hw_schdom;
#	endif
#endif
	ureg_t rotor = ureg_atomic_add_unseq(&schedom_core_rotor, 1);
	rotor %= NCORES;
	return &cores[rotor].core_hw.hw_schdom;
}

static thr_t *schdom_get_thr(schdom_t *schdom)
{
	ureg_t mask = schdom->schdom_mask;
	while (mask) {
		int index = ffsl(mask);
		--index;
		ureg_t prio = LWT_PRIO_HIGH - index;
		schedq_t *schedq = &schdom->schdom_sqcls[prio].sqcl_schedq;
		ureg_t sqix = schedq_index(schedq);
		thr_t *thr = schedq_get(schedq, sqix);
		if (thr)
			return thr;
		mask &= ~(1uL << index);
	}
	return NULL;
}

//  Low touch examination of schdom to see if it is empty.

static bool schdom_is_empty(schdom_t *schdom)
{
	ureg_t mask = schdom->schdom_mask;
	while (mask) {
		int index = ffsl(mask);
		--index;
		ureg_t prio = LWT_PRIO_HIGH - index;
		schedq_t *schedq = &schdom->schdom_sqcls[prio].sqcl_schedq;
		if (!schedq_is_empty(schedq))
			return false;
		mask &= ~(1uL << index);
	}
	return true;
}

//}{ Insert and remove algorithm for schedq_t.

//  An schedq_t is a scheduler queue that is manipulated atomically.
//  This is a lock-less and wait-free data structure.  Its implementation
//  depends on the ability to convert quickly from pointer to thr_t into a
//  thread index and back (which is achieved by ensuring that sizeof(thr_t)
//  is a power of two.

//  This is required to compress pointers to indexes which occupy much less
//  space.  The number of threads supported by an instance of the scheduler
//  is limited to THRIX_MAX (32K - 256).  This allows thread indexes to be
//  stored in 15 bits.

//  Currently there is one scheduler per process, but it would be easy to
//  support multiple completely isolated schedulers in a process where the
//  threads can not coordinate or synchronize with each other by the mechanisms
//  implemented here, but could communicate by other means (for example other
//  lock-less/wait-free data structures).  Multiple schedulers would only be
//  required by a very large server process in the largest of SMP systems.
//  Even then, for fault isolation, it is best to have multi-process servers
//  in such situations.

//  A schedq_t operates as a strict FIFO queue, entries can not be removed out
//  of order, though allowing entries to added at the head of the queue would
//  be easy but is not needed at this time. Concurrent insertions and removals
//  don't need to be serialized externally by the caller.  N concurrent
//  insertions end up in the FIFO queue in arbitrary order with respect
//  to each other, but become the last N entries in the queue, as expected.
//  Similarly, N removals, result in the first N entries in the queue being
//  removed and returned to the N callers in arbitrary order.

//  This algorithm could be generalized and isolated from it being an
//  implementation of a scheduler queue that queues threads (as long as
//  the limitations on the maximun number of entries and that entries be
//  quickly indexable are met).

//  For the purposes of explaing the algorithm the remaining comments below
//  refer to the thr_t structures being queued as entries, and are named with
//  uppercase letters in the examples.

//  The lists below, bracketed by {} are stacks (i.e. LIFO), items can only
//  be added or removed from the front, ins(X) indicates that item X is being
//  inserted, rem()==Y indicates that an entry was removed from the stack and
//  that the entry returned was Y.  For example:

//  before    operation   after
//  {}        ins(A)      {A}
//  {A}       ins(B)      {B,A}
//  {B,A}     ins(C)      {C,B,A}
//  {C,B,A}   rem()==C    {B,A}
//  {B,A}     rem()==B    {A}
//  {A}       rem()==A    {}

//  To implement a schedq_t 4 stacks are used: INS, INSPRV, REMNXT, and REM.

//  Threads are inserted lock-lessly into the INS stack when they are added to
//  a scheduling queue (sched_in) and removed lock-lessly from the REM stack
//  for the thread to become the running thread.  Implementing stacks that
//  are lock-less and wait-free is well known and used elsewhere by this LWT
//  implementation.

//  Because of the LIFO behaviour of stacks, two intermediate stacks are used,
//  INSPRV (previous content of INS) and REMNEXT (next content for REM). They
//  are used to reverse a previous INS stack before moving it to the REM stack
//  so that the whole scheduling queue behaves as a FIFO queue.

//  A whole stack can be moved from a non-empty stack into an empty stack, all
//  at once.  The only whole stack movements are from INS to INSPRV and from
//  REMNXT to REM.  All the transitions in the schedq_t state are atomic, state
//  in a thr_t thrln_t prev/next pointers are also updated atomically, those
//  changes occur when poping an entry from the INSPRV stack and pushing it
//  into the REMNXT stack.  Because those two atomic state changes are related,
//  they have to be carefully coordinated to ensure that the whole state of
//  schedq_t and its entries behaves as a lock-less wait-free queue.  This
//  algorithm is original work by the author and is not related to other work
//  published in technical papers, all other algorithms known to the author
//  require complex garbage collection aspects, scanning, and virtually long
//  index spaces for their implementation which are too complex.

//  Assume, without optimizations, that 3 items are inserted:

//  Insert 3 items into INS stack:
//   INS
//    before    operation   after
//    {}        ins(A)      {A}
//    {A}       ins(B)      {B,A}
//    {B,A}     ins(C)      {C,B,A}

//  Move INS stack to INSPRV, remove items from INSPRV, one by one, and
//  insert them into the REMNXT stack:
//   INSPRV:                          REMNXT:
//    before    operation   after      before    operation   after
//    {C,B,A}   rem()==C    {B,A}      {}        ins(C)      {C}
//    {B,A}     rem()==B    {A}        {C}       ins(B)      {B,C}
//    {A}       rem()==A    {}         {B,C}     ins(A)      {A,B,C}

//  Note that after these movements, the contents of REMNXT are in arrival
//  order, when REMNXT is moved to REM, and items are removed from REM they
//  will be removed in FIFO order with respect to when they were inserted
//  into the schedq_t.

//  Some optimizations are performed to prevent extra stack manipulations
//  as shown in the scenarios below.  For example when all the stacks are
//  empty, and an element is inserted, it can go directly in REM; when the
//  first 3 stacks are empty, a new element inserted can go into REMNXT;
//  thereafter when only the first two stacks are empty all new entries must
//  go into INS.  Note that when the items in the stack INSPRV are being
//  reversed into the REMNXT stack, any new items being inserted have to be
//  inserted into INS.  Similarly, when REM becomes empty, and INSPRV and
//  REMNXT are not empty, the stack reversal has to be finished before the
//  resulting REMNXT stack can be moved to REM.

//  Note that in each state transition, multiple manipulations of the
//  stacks occur in parallel in the pipeline during insertion or removal,
//  items and stacks can be moved as appropriately between the stacks.

//  The 4-bit mask state below shows whether the lists are non-empty (1) or
//  empty (0). The value of NIL for TIX in the examples below is THRID_NULL.

//  The items in the INS and INSPRV lists are linked by the thr_ln.ln_prev
//  pointers, their thr_ln.ln_next pointers are set to a special value
//  described below.

//  The items in the REMNXT and REM lists are linked by the thr_ln.ln_next
//  pointers, their thr_ln.ln_prev pointers are set to a special value
//  described below.

//  The links in thr_ln are interpreted as thread indexes and not as thr_t
//  pointers (as they are used elsewhere in this file).  This is required
//  to have additional space for insertion and removal serial numbers tied
//  to the pointers (insertion serial number with the prev pointer and removal
//  serial number with the next pointer).  Additionally, the specific schedq_t,
//  via an index into it in its arena (referred to as an sqix), is identified
//  within the thr_ln fields to further ensure that races between the atomic
//  update of the thr_ln fields and the schedq_t are not confused between a
//  thread being in an schedq_t and a different schedq_t that the thread might
//  later be inserted into (for example because its priority has changed, for
//  example related to priority ceiling for mutexes).

//  The thr_ln and schedq_t are each properly aligned and able to be updated
//  atomically (each being internally a uregx2_t) with a compare and swap
//  sequence.

//  Every schedq_t has an index that can be computed efficiently relative
//  to the start of the schedq_array_arena they were allocated from.  Even
//  though the schedq_t are allocated in arrays of schedq_t (e.g. the array
//  that the schdom->schdom_schedqs pointer points to, which has SQ_PRIO_MAX
//  entries).  The index is for each schedq_t, the first array having
//  indexes 0 through SQ_PRIO_MAX-1, the next one SQ_PRIO_MAX through
//  2*SQ_PRIO_MAX-1, and so forth.  That index is referred to as an sqix.

//  The schedq_t has 4 counts and serial numbers all of them are the same size
//  16 bits (THRID_BITS + 1). The counts and serial numbers are incremented
//  module that size.  The ICNT is an insertion count it is incremented each
//  time an element is inserted and serves as a tag, or serial number for the
//  element while it is in the schedq_t.  Similarly the RCNT is a removal
//  count, it is incremented each time an element is removed from the queue.
//  The ISER value is a copy of the ICNT value when the INS stack is moved to
//  the INSPRV stack, its value, at that time is the insertion serial number
//  of the element at the top of the INSPRV stack.  Each time an element is
//  removed from the INSPRV stack, the ISER number is decremented. An invariant
//  then is that the ISER value is the insertion serial number of the top
//  helement of the INSPRV stack, and that the insertion serial number of each
//  element on the stack is one lower than the one on top of it.  The RSER
//  serial number is used to tag the forward pointers of elements when they
//  are inserted into the REMNEXT stack, their purpose is to couple the two
//  atomic actions (the updates to the thr_ln and schedq_t).  The RSER value is
//  just a generation number and has no monotonic correlation with insertion
//  or removal order.  The number of entries currently in the queue is:
//      (ICNT - RCNT) & ((1 << (THRID_BITS + 1)) - 1)
//  That is unsigned two's complement modular arithmetic of THRID_BITS+1 bits.
//  For example if ICNT is 2 and RCNT is 0xFFF0 then there are 18 entries
//  in the queue (18 == ((2u - 0xFFF0u) & 0xFFFFu))

//  Each atomic update to the schedq_t involves updates to one or more of
//  the ICNT, ISER, RSER, or RCNT counters and serial numbers, and to the 4
//  stacks (INS, INSPRV, REMNXT, and REM).  Those changes ensure the atomicity
//  generation number behaviour required for the insertion and removal of
//  elements onto the various stacks.

//  The pointer in thr_ln in their index form have their least significant
//  bit set to 1 (this ensures that they can be easily distinguished from
//  their regular use as pointers).  Their most significant nible is set to
//  a patterns (0b1010) that ensures that if they are used as pointers they
//  will cause an exception on 64 bit address spaces that usually require
//  those bits to be all ones or all zeros (e.g. x86/64 and ARM 64), and any
//  other architecture where the kernel implementation that doesn't allow
//  those virtual addresses to be valid.

//  In the diagrams below an element of a stack is shown as lists with its
//  two pointers thr_ln.ln_next and thr_ln.ln_prev, the prev pointer points
//  left (e.g. <-) and the next pointer points right (e.g. ->).

//  Element X is shown in square brackets (e.g. [X]) to signify that that is
//  the data structure that has the memory for X.  Pointers comming out of it
//  (e.g. <-[X]->) are its prev and next pointers.

//  The pointers are tagged in the middle of the pointer with the the name
//  of the element that they point to and the corresponding serial number
//  stored with the pointer, if a pointer is NULL it has the value N.
//  For example in the first example:
//          REM
//           |
//           v
//     1:N<-[A]->1:N
//  Entry [A] has its prev pointer (e.g. 1:N<-[A]) with ISER serial number
//  value of 1 and pointing to NULL.  It has its next pointer (e.g. [A]->1:N)
//  with RSER serial number also 1 and also pointing to NULL.

//  To be able to fit in the space below linked lists have their elements in
//  different lines and the pointers might point upwards (e.g. -^) or downwards
//  (e.g. -v) to link the entries.
//                   INS               When a list is empty its value is
//                    |                THRID_NULL, e.g. a non empty REM:
//                    v                             REM
//            v--4:C-[D]->x:x                        |
//      3:N<-[C]->x:x                                =

//  In the list above the INS stack points to D which is at the top of the
//  stack which then points to C which is the last element on the stack.
//  That linkage is via the prev pointers (e.g. v--4:C-[D] and 3:N<-[C]).
//  Both of their next pointers are set to a dummy value (e.g. ->x:x) which
//  means the value is not yet set to link into REMNXT or REM, that special
//  value depended upon later on when setting that pointer as part of the
//  atomic popping from INSPRV and pushing onto REMNXT.

//  The algorithm above requires one compare and swap for each insertion (into
//  INS) or removal (from REM), the internal moving of stacks and popping of
//  entries from INSPRV and pushing onto REMNXT requires an additional compare
//  and swap on the thr_ln prev/next pointers of the entry being moved.
//  Stack movements from INS to INSPRV, and from REMNXT to REM are subsumed
//  under the compare and swap of whatever ongoing operation is occurring,
//  insertion or removal, so they have no additional cost.  The only additional
//  cost occurs under removal when REM is empty, and INSPRV is not empty and
//  its elements have to be popped, one by one, and pushed onto REMNXT.  Each
//  one of those operations requires one compare and swap on the schedq_t and
//  another on the thr_ln.  Thus worst case, each element requires a maximum
//  of 4 compares and swaps, one to insert, one to pop/push from INSPRV onto
//  REMNXT, one to update the thr_ln links, and finally one more to remove
//  from REM.  Four compare and swaps is comparable to a spin-lock based
//  implementation (which is not apprpriate for a user mode scheduler which
//  is at the whim of the kernel mode scheduler who might preempt the user mode
//  scheduler while holing the spin-lock and all the complexity of scheduler
//  activations, preemption control, restartable regions and all other kinds
//  of schemes that have been attempted in this aree by other implementations
//  of user mode schedulers.

//  An example of a thread inserted into a schedq_t is when the thread was
//  waiting to acquire a mutex, and is handed the mutex for it to own it by the
//  thread that has just released it, and that later thread is now ready to
//  run, and if it has the same or lower priority than the current thread has
//  (so it shouldn't preempt it from its CPU).  The thread that was just added
//  to the schedq_t might run shortly thereafter, possibly in another CPU. This
//  insertion can occur concurrently, lock-free and wait-free, with another CPU
//  removing a thread from the head of the queue for it to use that CPU.

//  Finally for each operation below, the previous 4 bit state is shown under
//  "before", and after the operation the 4 bit state is shown under "after".
//  Each operation is shown with a one-line summary followed by a drawing of
//  the various stacks after the operation has occurred.  All the operations
//  are sequential, thus the drawing of the prior state is the one above it.
//  The initial state has all the lists empty and state == 0000

#define	INS	0b1000
#define	INSPRV	0b0100
#define	REMNXT	0b0010
#define	REM	0b0001

//        state           +-counters--+
//  +----- INS -----+     ICNT        |
//  |+---- INSPRV --|+     | ISER     |
//  ||+--- REMNXT --||+    |  | RSER  |
//  |||+-- REM -----|||+   |  |  | RCNT +------------ stacks -----------+
//  ||||            ||||   |  |  |  |   INS       INSPRV    REMNXT    REM
//  before  op      after  |  |  |  |    |         |         |         |
//  ||||            ||||   |  |  |  |    |         |         |         |
//  vvvv            vvvv   v  v  v  v    v         v         v         v
//  ????  init      0000   0  0  0  0    {}        {}        {}        {}

//{ 0000  ins(A)    0001   1  0  1  0    {}        {}        {}        {A}
//
//                                                                    REM
//                                                                     |
//                                                                     v
//                                                               1:N<-[A]->1:N

//                                      INS       INSPRV    REMNXT    REM
//  0001  ins(B)    0011   2  0  2  0    {}        {}        {B}       {A}
//
//                                      INS       INSPRV    REMNXT    REM
//                                       |         |         |         |
//                                       =         =         v         |
//                                                     2:N<-[B]->2:N   |
//                                                                     v
//                                                               1:N<-[A]->1:N

//                                      INS       INSPRV    REMNXT    REM
//  0011  ins(C)    1011   3  0  2  0    {C}       {}        {B}       {A}
//
//                                      INS       INSPRV    REMNXT    REM
//                                       |         |         |         |
//                                       v         =         v         |
//                                 3:N<-[C]->x:x       2:N<-[B]->2:N   |
//                                                                     v
//                                                               1:N<-[A]->1:N

//                                      INS       INSPRV    REMNXT    REM
//  1011  ins(D)    1011   4  0  2  0    {D,C}     {}        {B}       {A}
//
//                                      INS       INSPRV    REMNXT    REM
//                                       |         |         |         |
//                                       v         =         v         |
//                               v--4:C-[D]->x:x       2:N<-[B]->2:N   |
//                         3:N<-[C]->x:x                               v
//                                                               1:N<-[A]->1:N

//                                      INS       INSPRV    REMNXT    REM
//  1011  ins(E)    1011   5  0  2  0    {E,D,C}   {}        {B}       {A}
//
//                                      INS       INSPRV    REMNXT    REM
//                                       |         |         |         |
//                                       v         =         v         |
//                               v--5:D-[E]->x:x       2:N<-[B]->2:N   |
//                       v--4:C-[D]->x:x                               v
//                 3:N<-[C]->x:x                                 1:N<-[A]->1:N

//                                      INS       INSPRV    REMNXT    REM
//  1011  ins(F)    1011   6  0  2  0    {F,E,D,C} {}        {B}       {A}
//
//                                      INS       INSPRV    REMNXT    REM
//                                       |         |         |         |
//                                       v         =         v         |
//                               v--6:E-[F]->x:x       2:N<-[B]->2:N   |
//                       v--5:D-[E]->x:x                               v
//               v--4:C-[D]->x:x                                 1:N<-[A]->1:N
//         3:N<-[C]->x:x                                          

//                                      INS       INSPRV    REMNXT    REM
//  1011  rem()==A  0101   6  6  2  1    {}        {F,E,D,C} {}        {B}
//
//                                      INS       INSPRV    REMNXT    REM
//                                       |         |         |         |
//                                       =         |         =         |
//                                                 v                   v
//                                         v--6:E-[F]->x:x       2:N<-[B]->2:N
//                                 v--5:D-[E]->x:x                          
//                         v--4:C-[D]->x:x                                  
//                   3:N<-[C]->x:x                                          

//                                      INS       INSPRV    REMNXT    REM
//  0101  ins(G)    1111   7  5  3  1    {G}       {E,D,C}   {F}       {B}
//
//                                      INS       INSPRV    REMNXT    REM
//                                       |         |         |         |
//                                       v         |         |         |
//                                 7:N<-[G]->x:x   |         v         |
//                                                 v---6:E--[F]->3:N   |
//                                       v---5:D--[E]->x:x             |
//                             v---4:C--[D]->x:x                       v
//                       3:N<-[C]->x:x                           2:N<-[B]->2:N 

//                                      INS       INSPRV    REMNXT    REM
//  1111  ins(H)    1111   8  4  4  1    {H,G}     {D,C}     {E,F}     {B}
//
//                                      INS       INSPRV    REMNXT    REM
//                                       |         |         |         |
//                                       |         |         |         v
//                                       v         |         |   2:N<-[B]->2:N
//                              v--8:G--[H]->x:x   |         |
//                        7:N<-[G]->x:x            |         |
//                                                 |         v---6:E--[F]->3:N
//                                                 v---5:D--[E]--4:F---^
//                                       v---4:C--[D]->x:x
//                                 3:N<-[C]->x:x                           

//  (drawings shifted left and packed to fit within 80 columns)
//
//                                      INS       INSPRV    REMNXT    REM
//  1111  rem()==B  1110   8  3  5  2    {H,G}     {C}       {D,E,F}   {}
//
//                  INS     INSPRV  REMNXT  REM
//                   |       |       |       |
//                   v       |       |       =
//          v--8:G--[H]->x:x |       |
//    7:N<-[G]->x:x          |       |
//                           |       |       v--6:E-[F]->3:N
//                           |       v--5:D-[E]-4:F--^
//                           v--4:C-[D]-5:E--^
//                     3:N<-[C]->x:x                           

//  The next removal has to complete the poping from INSPRV and pushing to
//  REMNXT before completing, this occurs in 3 atomic operations (one to
//  complete that, the next to move REMNXT to REM, and the third to remove
//  the entry [C] from REM), thus the rem() doesn't complete until the third
//  drawing below.  Note that that in the second step INS moves to INSPRV
//  and in the third step popping from INSPRV and pushing to REMNXT occurs
//  in those transactions.

//                                      INS       INSPRV    REMNXT    REM
//  1110  rem()...  1010   8  2  6  2    {H,G}     {}        {C,D,E,F} {}
//
//                  INS     INSPRV  REMNXT  REM
//                   |       |       |       |
//                   v       =       |       =
//           v--8:G-[H]->x:x         |               v--6:E-[F]->3:N
//     7:N<-[G]->x:x                 |       v--5:D-[E]-4:F--^
//                                   v--4:C-[D]-5:E--^
//                             3:N<-[C]-6:D--^

//                                      INS       INSPRV    REMNXT    REM
//  1010  rem()...  0101   8  8  6  2    {}        {H,G}     {}        {C,D,E,F}
//
//                  INS     INSPRV  REMNXT  REM
//                   |       |       |       |
//                   =       |       =       |
//                           v               |
//                   v--8:G-[H]->x:x         |               v--6:E-[F]->3:N
//             7:N<-[G]->x:x                 |       v--5:D-[E]-4:F--^
//                                           v--4:C-[D]-5:E--^
//                                     3:N<-[C]-6:D--^ 

//                                      INS       INSPRV    REMNXT    REM
//  0101  rem()==C  0111   8  7  7  3    {}        {G}       {H}       {D,E,F}
//
//
//                  INS     INSPRV  REMNXT  REM
//                   |       |       |       |
//                   =       |       |       |
//                           |       v       |
//                           v--8:G-[H]->7:N |
//                     7:N<-[G]->x:x         |       v--6:E-[F]->3:N
//                                           v--5:D-[E]-4:F--^
//                                   v--4:C-[D]-5:E--^

//  The remaining operations are all removals until the schedq_t empties.

//                                      INS       INSPRV    REMNXT    REM
//  0111  rem()==D  0011   8  6  8  4    {}        {}        {G,H}     {E,F}
//
//
//                  INS     INSPRV  REMNXT  REM
//                   |       |       |       |
//                   =       =       |       |
//                                   |       v--6:E-[F]->3:N
//                                   |v-5:D-[E]-4:F--^
//                                   |       
//                                   v--8:G-[H]->7:N
//                             7:N<-[G]-8:H--^

//                                      INS       INSPRV    REMNXT    REM
//  0011  rem()==E  0011   8  6  8  5    {}        {}        {G,H}    {F}
//
//
//                  INS     INSPRV  REMNXT  REM
//                   |       |       |       |
//                   =       =       |       v
//                                   |v-6:E-[F]->3:N
//                                   |       
//                                   v--8:G-[H]->7:N
//                             7:N<-[G]-8:H--^

//                                      INS       INSPRV    REMNXT    REM
//  0011  rem()==F  0010   8  6  8  6    {}        {}        {G,H}     {}
//
//
//                  INS     INSPRV  REMNXT  REM
//                   |       |       |       |
//                   =       =       |       =
//                                   |       
//                                   v--8:G-[H]->7:N
//                             7:N<-[G]-8:H--^

//                                      INS       INSPRV    REMNXT    REM
//  0010  rem()...  0001   8  6  8  6    {}        {}        {}        {G,H}
//
//
//                  INS     INSPRV  REMNXT  REM
//                   |       |       |       |
//                   =       =       =       |       
//                                           v--8:G-[H]->7:N
//                                     7:N<-[G]-8:H--^

//                                      INS       INSPRV    REMNXT    REM
//  0001  rem()==G  0001   8  6  8  7    {}        {}        {}        {H}
//
//
//                  INS     INSPRV  REMNXT  REM
//                   |       |       |       |
//                   =       =       =       |
//                                           v
//                                   v--8:G-[H]->7:N

//                                      INS       INSPRV    REMNXT    REM
//  0001  rem()==H  0000   8  6  8  8    {}        {}        {}        {}
//
//
//                  INS     INSPRV  REMNXT  REM
//                   |       |       |       |
//}                  =       =       =       =

//  There are 19 drawings above, i.e. 19 schedq_t compare-and-swap operations.
//  There are 6 pops from INSPRV and 6 pushes to REMNXT, those are 6 compare-
//  and-swap on the thr_ln fields.  Thus there were all together 25 compare-
//  and-swaps (19+6) that were required for the insertion and later removal
//  of 8 elements (A-H), a total of 16 (8+8) logical operations (8 insertions
//  plus 8 removals).  An evarage of 25/16=1.625 compare-and-swaps per logical
//  operation, better than the worst case of 2 compara-and-swaps per logical
//  operation.  This is the result of the folding of the bundling of multiple
//  stack manipulations into a single compare-and-swap, i.e. the pop/push
//  from INSPRV to REMNXT folded into the push onto INS (when an ins(X) is
//  done) or onto the pop from REM (when a rem()==X is shown).  Only 3 of those
//  pop/push were not folded (the ones shown with rem()...).

//  The state is the non-empty (1) or empty (0) state of each on of the lists:
//      INS, INSPRV, REMNXT, REM
//  Note that the order of the stacks implies this movement between the entries:
//      INS -> INSPRV -> REMNXT -> REM

//}{ Functions that implement parts of schedq_insert().

//  The following functions up to schedq_insert() are inlined into
//  schedq_insert() which is then inlined into sched_in(), some of these
//  functions are inlined into schedq_remove().
//
//  If the compiler does a proper job, the only memory accesses should be
//  those related to atomically locading and compare-and-swapping the schedq_t
//  value, and in the pop/push case, atomically locading and compare-and
//  swapping the thrln_t value or storing those values directly when a thread
//  is initially inserted.  Every other computation is done in registers, at
//  least on a RISC processor, this is easily verified by examining the
//  generated machine code.  Once inlined the sched_in() function becomes a
//  leaf function.  The only extra memory accesses performed by the resulting
//  code are callee preserved register saving and restoring.

inline_only void schedq_debug(schedq_t schedq)
{
	debug(((SCHEDQ_STATE(schedq) & INS)
	       && SCHEDQ_INS(schedq) != THRID_NULL) ||
	      (!(SCHEDQ_STATE(schedq) & INS)
	       && SCHEDQ_INS(schedq) == THRID_NULL));

	debug(((SCHEDQ_STATE(schedq) & INSPRV)
	       && SCHEDQ_INSPRV(schedq) != THRID_NULL) ||
	      (!(SCHEDQ_STATE(schedq) & INSPRV)
	       && SCHEDQ_INSPRV(schedq) == THRID_NULL));

	debug(((SCHEDQ_STATE(schedq) & REMNXT)
	       && SCHEDQ_REMNXT(schedq) != THRID_NULL) ||
	      (!(SCHEDQ_STATE(schedq) & REMNXT)
	       && SCHEDQ_REMNXT(schedq) == THRID_NULL));

	debug(((SCHEDQ_STATE(schedq) & REM)
	       && SCHEDQ_REM(schedq) != THRID_NULL) ||
	      (!(SCHEDQ_STATE(schedq) & REM)
	       && SCHEDQ_REM(schedq) == THRID_NULL));
}

inline_only schedq_t schedq_insert_simple(schedq_t schedq, ureg_t sqix,
					  thr_t *thr, ureg_t thridix,
					  ureg_t state,
					  ureg_t icnt, ureg_t oldicnt)
{
	debug(!(state & INSPRV) && SCHEDQ_INSPRV(schedq) == THRID_NULL);
	switch (state) {	// 16 cases, INSPRV is empty, only 8 cases here
	case 0: {		
		state = REM;
		SCHEDQ_REM_SET(schedq, thridix);
		goto common_simple_insert;
	case REM:
		state = REMNXT | REM;
		SCHEDQ_REMNXT_SET(schedq, thridix);
		goto common_simple_insert;
	case REMNXT:
		state = REMNXT | REM;
		SCHEDQ_REM_SET(schedq, SCHEDQ_REMNXT(schedq));
		SCHEDQ_REMNXT_SET(schedq, thridix);
		//  fallthrough
	common_simple_insert:
		SCHEDQ_RSER_INC(schedq);
		ureg_t rser = SCHEDQ_RSER(schedq);
		THRLN_NEXT_INIT_NULL(thr->thr_ln, sqix, rser);
		THRLN_PREV_INIT_NULL(thr->thr_ln, sqix, icnt);
		break;
	    }

	case REMNXT | REM:
		state = INS | REMNXT | REM;
		goto common_insert_into_INS;
	case INS:
	case INS | REM:
		state |= INSPRV;
		SCHEDQ_INSPRV_SET(schedq, SCHEDQ_INS(schedq));
		SCHEDQ_ISER_SET(schedq, oldicnt);
		goto common_insert_into_INS;
	case INS | REMNXT:
		state = INS | INSPRV | REM;
		SCHEDQ_INSPRV_SET(schedq, SCHEDQ_INS(schedq));
		SCHEDQ_REM_SET(schedq, SCHEDQ_REMNXT(schedq));
		SCHEDQ_REMNXT_SET(schedq, THRID_NULL);
		SCHEDQ_ISER_SET(schedq, oldicnt);
		//  fallthrough
	common_insert_into_INS:
		THRLN_PREV_INIT_NULL(thr->thr_ln, sqix, icnt);
		THRLN_NEXT_INIT_INS(thr->thr_ln, sqix);
		SCHEDQ_INS_SET(schedq, thridix);
		break;

	case INS | REMNXT | REM:
		//  state remains the same
		THRLN_PREV_INIT(thr->thr_ln, sqix, icnt, SCHEDQ_INS(schedq));
		THRLN_NEXT_INIT_INS(thr->thr_ln, sqix);
		SCHEDQ_INS_SET(schedq, thridix);
		break;
	}

	SCHEDQ_STATE_SET(schedq, state);
	schedq_debug(schedq);
	return schedq;
}

//  Pop an entry from INSPRV and push onto REMNXT.
//
//  The resulting state will be non-zero unless retrying is required, in which
//  case SCHEDQ_RETRY will be the value returned (known to be zero).

#define	SCHEDQ_RETRY	     ((schedq_t){.sq_rem_remnxt_insprv_ins_state = 0uL})
#define	SCHEDQ_IS_RETRY(sq)  ((sq).sq_rem_remnxt_insprv_ins_state == 0uL)

inline_only schedq_t schedq_pop_push(schedq_t schedq, ureg_t sqix, ureg_t state)
{
	ureg_t tix = SCHEDQ_INSPRV(schedq);
	debug((state & INSPRV) && tix != THRID_NULL);
	thr_t *t = thr_from_index(tix);
	SCHEDQ_RSER_INC(schedq);
	ureg_t rser = SCHEDQ_RSER(schedq);
	thrln_t oldln = thrln_loadatomic(&t->thr_ln);
	thrln_t newln = oldln;
	if (unlikely(THRLN_PREV_ISER(newln) != SCHEDQ_ISER(schedq)))
		return SCHEDQ_RETRY;

	SCHEDQ_ISER_DEC(schedq);
	thrln_t iniln, afterln;
	THRLN_NEXT_INIT_INS(iniln, sqix);
	afterln.ln_next_ureg = iniln.ln_next_ureg;
	THRLN_NEXT_TIX_SET(afterln, SCHEDQ_REMNXT(schedq));
	THRLN_NEXT_RSER_SET(afterln, rser);

	if (likely(newln.ln_next_ureg == iniln.ln_next_ureg)) {
		newln.ln_next_ureg = afterln.ln_next_ureg;
		thrln_t preln = thrln_comp_and_swap_acq_rel(oldln, newln,
							    &t->thr_ln);
		if (unlikely(!thrln_equal(preln, oldln)))
			return SCHEDQ_RETRY;
	} else if (unlikely((newln.ln_next_ureg != afterln.ln_next_ureg)))
		return SCHEDQ_RETRY;

	SCHEDQ_REMNXT_SET(schedq, tix);
	ureg_t prev_tix = THRLN_PREV_TIX(newln);
	SCHEDQ_INSPRV_SET(schedq, prev_tix);
	if (prev_tix == THRID_NULL)
		state &= ~INSPRV;
	state |= REMNXT;
	SCHEDQ_STATE_SET(schedq, state);
	schedq_debug(schedq);
	return schedq;
}

//  Eight cases that require poping from INSPRV and pushing into REMNXT:
//	0b0100	0b0110	0b1100	0b1110
//	0b0101	0b0111	0b1101	0b1111

//  The resulting state will be non-zero unless retrying is required, in which
//  case SCHEDQ_RETRY will be the value returned (known to be zero).

inline_only schedq_t schedq_insert_pop_push(schedq_t schedq, ureg_t sqix,
					    thr_t *thr, ureg_t thridix,
					    ureg_t state, ureg_t icnt)
{
	schedq = schedq_pop_push(schedq, sqix, state);
	if (SCHEDQ_IS_RETRY(schedq))
		return schedq;

	state = SCHEDQ_STATE(schedq);
	THRLN_PREV_INIT(thr->thr_ln, sqix, icnt, SCHEDQ_INS(schedq));
	THRLN_NEXT_INIT_INS(thr->thr_ln, sqix);
	SCHEDQ_INS_SET(schedq, thridix);
	state |= INS;
	SCHEDQ_STATE_SET(schedq, state);
	schedq_debug(schedq);
	return schedq;
}

inline_only void schedq_insert(schedq_t *schedq, ureg_t sqix,
			       thr_t *thr, ureg_t thridix)
{
reload_and_retry:;
	schedq_t old = schedq_loadatomic(schedq);
retry:;
	schedq_debug(old);
	ureg_t state = SCHEDQ_STATE(old);
	schedq_t new = old;
	ureg_t oldicnt = SCHEDQ_ICNT(new);
	SCHEDQ_ICNT_INC(new);
	ureg_t icnt = SCHEDQ_ICNT(new);
	if (!(state & INSPRV))
		new = schedq_insert_simple(new, sqix, thr, thridix,
					   state, icnt, oldicnt);
	else {
		//  When schedq_insert_pop_push() is inlined, the value
		//  SCHEDQ_RETRY and its testing sould to be optimized out.

		new = schedq_insert_pop_push(new, sqix, thr, thridix,
					     state, icnt);
		if (unlikely(SCHEDQ_IS_RETRY(new)))
			goto reload_and_retry;
	}
	schedq_debug(new);
	schedq_t pre = schedq_comp_and_swap_acq_rel(old, new, schedq);
	if (unlikely(!schedq_equal(pre, old))) {
		old = pre;
		goto retry;
	}
	schedq_debug(new);
}


//}{ Functions that implement parts of schedq_remove().

//  The following functions up to schedq_remove() are inlined into 
//  schedq_remove() which is then inlined into sched_out().

//  Move the INS stack to INSPRV and update ISER from ICNT.

inline_only schedq_t schedq_move_ins_to_insprv(schedq_t schedq, ureg_t sqix,
					       ureg_t state)
{
	ureg_t ins = SCHEDQ_INS(schedq);
	if (ins != THRID_NULL) {
		SCHEDQ_INS_SET(schedq, THRID_NULL);
		SCHEDQ_INSPRV_SET(schedq, ins);
		SCHEDQ_ISER_SET(schedq, SCHEDQ_ICNT(schedq));
		state &= ~INS;
		state |= INSPRV;
		SCHEDQ_STATE_SET(schedq, state);
	}
	schedq_debug(schedq);
	return schedq;
}

//  Move the REMNXT stack to REM.

inline_only schedq_t schedq_move_remnxt_to_rem(schedq_t schedq, ureg_t sqix,
					       ureg_t state)
{
	ureg_t remnxt = SCHEDQ_REMNXT(schedq);
	if (remnxt != THRID_NULL) {
		SCHEDQ_REMNXT_SET(schedq, THRID_NULL);
		SCHEDQ_REM_SET(schedq, remnxt);
		state &= ~REMNXT;
		state |= REM;
		SCHEDQ_STATE_SET(schedq, state);
	}
	schedq_debug(schedq);
	return schedq;
}

//  Remove an entry from schedq when there are entries in REM and INSPRV is
//  empty, this is the simple case because INSPRV is empty, then no entries
//  can be popped from it and pushed onto REMNXT (which is handled elsewhere).
//  These preconditions imply that this function handles these states:
//	0b0001	0b0011	0b1001	0b1011

inline_only schedq_t schedq_remove_simple(schedq_t schedq, ureg_t sqix,
					  ureg_t state, thr_t *thr,
					  ureg_t thridix, ureg_t nextix)
{
	if (nextix != THRID_NULL)
		SCHEDQ_REM_SET(schedq, nextix);
	else {
		// Move REMNXT, whether empty or not, to REM.

		ureg_t remnxt = SCHEDQ_REMNXT(schedq);
		SCHEDQ_REM_SET(schedq, remnxt);
		SCHEDQ_REMNXT_SET(schedq, THRID_NULL);
		state &= ~REMNXT;			// REMNXT now empty
		if (remnxt == THRID_NULL)
			state &= ~REM;			// REM now empty
	}
	SCHEDQ_STATE_SET(schedq, state);
	schedq_debug(schedq);
	return schedq_move_ins_to_insprv(schedq, sqix, state);
}

//  Remove an entry from schedq when there are entries in REM and INSPRV is not
//  empty, so additionally pop an entry from INSPRV and push it onto REMNXT.
//  These preconditions imply that this function handles these states:
//	0b0101	0b0111	0b1101	0b1111

//  The resulting state will be non-zero unless retrying is required, in which
//  case SCHEDQ_RETRY will be the value returned (known to be zero).

inline_only schedq_t schedq_remove_from_rem_pop_push(schedq_t schedq,
						     ureg_t sqix, ureg_t state,
						     ureg_t nextix)
{
	schedq = schedq_pop_push(schedq, sqix, state);
	if (SCHEDQ_IS_RETRY(schedq))
		return schedq;

	state = SCHEDQ_STATE(schedq);
	SCHEDQ_REM_SET(schedq, nextix);
	if (nextix == THRID_NULL)
		state &= ~REM;
	SCHEDQ_STATE_SET(schedq, state);
	schedq_debug(schedq);
	return schedq;
}

inline_only thr_t *schedq_remove(schedq_t *schedq, ureg_t sqix)
{
reload_and_retry:;
	schedq_t old = schedq_loadatomic(schedq);
retry:;
	schedq_debug(old);
	thr_t *thr = NULL;
	ureg_t state = SCHEDQ_STATE(old);
	if (state == 0)
		return NULL;

	schedq_t new = old;
	if (state & REM) {
		ureg_t thridix = SCHEDQ_REM(new);
		thr = thr_from_index(thridix);
		ureg_t nextix = THRLN_NEXT_TIX(thr->thr_ln);
		if (state & INSPRV) {
			new = schedq_remove_from_rem_pop_push(new, sqix, state,
							      nextix);
			if (SCHEDQ_IS_RETRY(new))
				goto reload_and_retry;
		} else
			new = schedq_remove_simple(new, sqix, state,
						   thr, thridix, nextix);
		SCHEDQ_RCNT_INC(new);
	} else {
		//  REM is empty, must check if INSPRV is not empty and
		//  handle popping from INSPRV and pushing to REMNXT first.

		if (state & INSPRV) {
			new = schedq_pop_push(new, sqix, state);
			if (SCHEDQ_IS_RETRY(new))
				goto reload_and_retry;
		} else {
			//  These two moves can be done in one compare-and-swap.

			if (state & REMNXT) {
				new = schedq_move_remnxt_to_rem(new, sqix,
								state);
				state = SCHEDQ_STATE(new);
			}
			if (state & INS)
				new = schedq_move_ins_to_insprv(new, sqix,
								state);
		}
	}

	schedq_debug(new);
	schedq_t pre = schedq_comp_and_swap_acq_rel(old, new, schedq);
	if (unlikely(!schedq_equal(pre, old))) {
		old = pre;
		goto retry;
	}
	if (!thr)
		goto reload_and_retry;
	schedq_debug(new);
	thr->thr_ln.ln_next = NULL;
	thr->thr_ln.ln_prev = NULL;
	return thr;
}


//}{ More scheduler functions

inline_only ureg_t thr_get_prio_with_ceiling(thr_t *thr)
{
	// TODO
	//  A thread that owns mutexes has its priority boosted to the
	//  maximum, this is a trivial implementation of priority ceiling
	//  that prevents priority inversion for mutexes.
	//
	//  ureg_t prio = thr->thr_mtxcnt ? LWT_PRIO_HIGH : thr->thr_prio;

	ureg_t prio = thr->thr_prio;
	return prio;
}

//  This function must always return zero, its callers depend on it.
//  Thr is ready to run, add it to the appropriate scheduling queue.

static int sched_in(thr_t *thr)
{
	schdom_t *schdom = thr->thr_schdom;
	ureg_t prio = thr_get_prio_with_ceiling(thr);
	ureg_t priomask = 1uL << (LWT_PRIO_HIGH - prio);
	if (! (schdom->schdom_mask & priomask))
		ureg_atomic_or_acq_rel(&schdom->schdom_mask, priomask);

	schedq_t *schedq = &schdom->schdom_sqcls[prio].sqcl_schedq;
	ureg_t thridix = THRID_INDEX(thr->thra.thra_thrid);
	ureg_t sqix = schedq_index(schedq);
	schedq_insert(schedq, sqix, thr, thridix);
	core_run(schdom->schdom_core);
	return 0;	// must return zero for tail-recursion by caller
}

noreturn inline_only void thr_run(thr_t *thr, thr_t *currthr)
{
	cpu_t *cpu = cpu_current();
	cpu->cpu_running_thr = thr;
	ctx_t *ctx = ctx_from_thr(thr);
	ctx_load(ctx, &thr->thr_running, &currthr->thr_running);
}

noreturn inline_only void thr_run_on_cpu(thr_t *thr, cpu_t *cpu)
{
	cpu->cpu_running_thr = thr;
	ctx_t *ctx = ctx_from_thr(thr);
	ctx_load_on_cpu(ctx, &thr->thr_running);
}

noreturn inline_only void cpu_idle(cpu_t *cpu, thr_t *currthr)
{
	cpu->cpu_running_thr = NULL;
	ctx_load_idle_cpu(&cpu->cpu_ctx, &currthr->thr_running);
}

static thr_t *schedq_get(schedq_t *schedq, ureg_t sqix)
{
	thr_t *thr = schedq_remove(schedq, sqix);
	return thr;
}

static int sched_attempts = 1;

#ifdef LWT_NEW
static noreturn void sched_out(thr_t *currthr)
{
	schdom_t *schdom = currthr->thr_schdom;
	ureg_t prio = thr_get_prio_with_ceiling(currthr);
	schedq_t *schedq = &schdom->schdom_sqcls[prio].sqcl_schedq;
	ureg_t sqix = schedq_index(schedq);
retry:;	thr_t *thr = schedq_get(schedq, sqix);
	if (!thr) {
		int attempts = sched_attempts;	// don't idle CPUs too quickly
		while (--attempts >= 0)
			if (!schedq_is_empty(schedq))
				goto retry;
		cpu_t *cpu = cpu_current();
		cpu_idle(cpu, currthr);
	}
	thr_run(thr, currthr);
}
#else
static noreturn void sched_out(thr_t *currthr)
{
	schdom_t *schdom = currthr->thr_schdom;
	ureg_t prio = thr_get_prio_with_ceiling(currthr);

retry:;	thr_t *thr = schdom_get_thr(schdom);
	if (!thr) {
		int attempts = sched_attempts;	// don't idle CPUs too quickly
		while (--attempts >= 0)
			if (!schdom_is_empty(schdom))
				goto retry;

		cpu_t *cpu = cpu_current();
		cpu_idle(cpu, currthr);
	}
	thr_run(thr, currthr);
}
#endif

static int thr_context_save__thr_run(thr_t *currthr, thr_t *thr)
{
	//  This function is out-of-line from mtx_unlock_common(), this part
	//  can not be inlined because ctx_save() returns twice and GCC can
	//  not inline those functions.

	ctx_t *ctx = ctx_from_thr(currthr);
	if (ctx_save(ctx)) 				// returns twice
		thr_run(thr, currthr);			// first return
	return 0;			// second return, must return zero
}


//}{  Implementation of operations on: arena_t

inline_only error_t arena_init_without_mtx(arena_t *arena, void *base,
					   size_t elemsize, size_t length,
					   size_t reserved)
{
	if (elemsize < sizeof(uptr_t) ||
            (elemsize & (sizeof(uptr_t) - 1)) != 0 ||
            elemsize > PAGE_SIZE ||
	    length < 16 * PAGE_SIZE ||
	    (length & (PAGE_SIZE - 1)) != 0 ||
	    (reserved & (PAGE_SIZE - 1)) != 0) {
		return EINVAL;
	}

	void *start = mmap(base, length + reserved, PROT_READ | PROT_WRITE,
			   MAP_PRIVATE | MAP_ANONYMOUS, -1, (off_t) 0);

	if (start == (void *) -1)
		return errno;

	if (start != base) {
		munmap(start, length + reserved);
		return EINVAL;
	}

	lllist_init(&arena->arena_lllist);

	uptr_t ptr = (uptr_t) start;
	arena->arena_next =  ptr;
	arena->arena_start = ptr;

	ptr += length;
	arena->arena_end = ptr;

	ptr += reserved;
	arena->arena_reservedend = ptr;

	arena->arena_elemsize = elemsize;
	arena->arena_mtx = NULL;
	return 0;
}

static void arena_deinit(arena_t *arena)
{
	if (arena->arena_mtx != NULL)
		mtx_destroy(&arena->arena_mtx);
	TODO();
}

inline_only error_t arena_grow_common(arena_t *arena)
{
	size_t elemsize = arena->arena_elemsize;
	uptr_t end = arena->arena_end;
	uptr_t next = arena->arena_next;
	if (next + elemsize > end)
		return ENOMEM;

	uptr_t locked_addr = (next + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1);
	assert(next + PAGE_SIZE <= end);
	uptr_t unlocked_addr = locked_addr + PAGE_SIZE;

	llelem_t *first;
	llelem_t **prevpp = &first;
	llelem_t *last = (llelem_t *) next;
	size_t n = 1;

	for (;;) {
		*prevpp = last;
		next += elemsize;
		if (next >= unlocked_addr) {
			last->lll_next = NULL;
			break;
		}

		prevpp = &last->lll_next;
		last = (llelem_t *) next;
		++n;
	}

	arena->arena_next = next;
	lllist_insert_chain(&arena->arena_lllist, first, last, n);
	return 0;
}

static error_t arena_grow_common_outline(arena_t *arena)
{
	return arena_grow_common(arena);
}

static error_t arena_init(arena_t *arena, void *base, size_t elemsize,
			  size_t length, size_t reserved)
{
	error_t error;
	error = arena_init_without_mtx(arena, base, elemsize, length, reserved);
	if (error)
		return error;

	//  Initial growth, not strictly required, but to be able to allocate
	//  the initial thr_t for the main() thread, that allocation must not
	//  attempt to acqure the arena_mtx, because that requires a current
	//  thread to already exist.  The growth allows the first thr_alloc()
	//  to succeed.  Additionally, the arena_mtx allocation requires its
	//  arena to already be initialized and grown, this solves that too.

	error = arena_grow_common_outline(arena);
	if (error)
		return error;

	error = mtx_create_outline(&arena->arena_mtx, NULL);
	if (!error)
		return 0;

	arena_deinit(arena);
	return error;
}

static error_t arena_grow(arena_t *arena)
{
	mtx_lock_outline(arena->arena_mtx);
	error_t error = arena_grow_common(arena);
	mtx_unlock_outline(arena->arena_mtx);
	return error;
}

typedef struct {
	arena_t		*ai_arena;
	void		*ai_start;
	size_t		 ai_elemsize;
	size_t		 ai_length;
	size_t		 ai_reserved;
} arena_init_t;

static arena_init_t arena_init_table[] = {

	//  Must be first, this allows the mtx_alloc() for the subsequent
	//  arenas to be possible.

	{.ai_arena    = &mtx_arena,
	 .ai_start    = (void *) MTX_ARENA_START,
	 .ai_elemsize = sizeof(mtx_t),
	 .ai_length   = MTX_ARENA_LENGTH,
	 .ai_reserved = MTX_ARENA_RESERVED},

	{.ai_arena    = &cnd_arena,
	 .ai_start    = (void *) CND_ARENA_START,
	 .ai_elemsize = sizeof(cnd_t),
	 .ai_length   = CND_ARENA_LENGTH,
	 .ai_reserved = CND_ARENA_RESERVED},

	{.ai_arena    = &thr_arena,
	 .ai_start    = (void *) THR_ARENA_START,
	 .ai_elemsize = sizeof(thr_t),
	 .ai_length   = THR_ARENA_LENGTH,
	 .ai_reserved = THR_ARENA_RESERVED},

	{.ai_arena    = &thrx_arena,
	 .ai_start    = (void *) THRX_ARENA_START,
	 .ai_elemsize = sizeof(thrx_t),
	 .ai_length   = THRX_ARENA_LENGTH,
	 .ai_reserved = THRX_ARENA_RESERVED},

	{.ai_arena    = &fpctx_arena,
	 .ai_start    = (void *) FPCTX_ARENA_START,
	 .ai_elemsize = sizeof(fpctx_t),
	 .ai_length   = FPCTX_ARENA_LENGTH,
	 .ai_reserved = FPCTX_ARENA_RESERVED},
};

static error_t arenas_init(void)
{
	arena_init_t *ai = arena_init_table;
	arena_init_t *aiend = ai + sizeof(arena_init_table) /
				   sizeof(arena_init_table[0]);

	for (; ai < aiend; ++ai) {
		error_t error = arena_init(ai->ai_arena, ai->ai_start,
					   ai->ai_elemsize, ai->ai_length,
					   ai->ai_reserved);
		if (error) {
			for (; ai >= arena_init_table; --ai)
				arena_deinit(ai->ai_arena);
			return error;
		}
	}

	//  Arena growth is protected by its mutex, which when acquired
	//  requires that a current thread already exist,

	return 0;
}

static void arenas_deinit(void)
{
	TODO();
}

static alloc_value_t arena_alloc(arena_t *arena)
{
	llelem_t *elem;
	for (;;) {
		elem = lllist_remove(&arena->arena_lllist);
		if (elem)
			break;
		error_t error = arena_grow(arena);
		if (error)
			return (alloc_value_t) {.mem = NULL, .error = error};
	}
	return (alloc_value_t) {.mem = elem, .error = 0};
}

inline_only void arena_free(arena_t *arena, void *mem)
{
	lllist_insert(&arena->arena_lllist, mem);
}


//} A kcore_t is a kernel supported core, for now implemented on top of
//  pthreads but might later be implemented on top of clone(2) and futex(2).
//  A kcore_t has the kernel synchronizers required to run and idle cpus
//  associated with the core (e.g. a multi-threaded core might have more
//{ than on cpu.

#include <pthread.h>
#define	CPU_STACKSIZE	(16 * 1024)
#define	CPU_NOT_IDLED	((llelem_t *) 0x1)

#ifdef LWT_NEW
struct kcore_s {
	pthread_cond_t	 kcore_cond;
	pthread_mutex_t	 kcore_mutex;
} aligned_cache_line;
#else
struct kcpu_s {
	pthread_cond_t	 kcpu_cond;
	pthread_mutex_t	 kcpu_mutex;
	pthread_t	 kcpu_pthread;
} aligned_cache_line;
#endif

#ifdef LWT_NEW
static kcore_t	kcores[NCORES];
#else
static kcpu_t	kcpus[NCPUS];
#endif

static pthread_attr_t cpu_pthread_attr;

#ifdef LWT_X64
static void cpu_current_set(cpu_t *cpu)
{
	//  X64 needs an extra level of indirection to use gs:
	//  this is not used often enough to optimize further.

	cpu_current_set_x64(&cpuptrs[cpu - cpus]);
}
#endif

static void cpu_run(lllist_t *idled_list)
{
	llelem_t *elem = lllist_remove(idled_list);
	if (!elem)
		return;

	cpu_t *cpu = (cpu_t *) elem;
	kcpu_t *kcpu = cpu->cpu_kcpu;
	pthread_mutex_lock(&kcpu->kcpu_mutex);
	cpu->cpu_idled_elem.lll_next = CPU_NOT_IDLED;
	pthread_cond_signal(&kcpu->kcpu_cond);
	pthread_mutex_unlock(&kcpu->kcpu_mutex);
}

static void core_run(core_t *core)
{
	cpu_run(&core->core_idled_cpus);
}

static void *cpu_main(cpu_t *cpu)
{
	cpu_current_set(cpu);
	kcpu_t *kcpu = cpu->cpu_kcpu;
	core_t *core = cpu->cpu_core;
	schdom_t *schdom = &core->core_hw.hw_schdom;

	for (;;) {
		pthread_mutex_lock(&kcpu->kcpu_mutex);
retry:;		ureg_t mask = schdom->schdom_mask;
rescan:;	int index = ffsl(mask);
		thr_t *thr;
		if (index != 0) {
			--index;
			index = LWT_PRIO_HIGH - index;
			schedq_t *schedq =
				&schdom->schdom_sqcls[index].sqcl_schedq;
			ureg_t sqix = schedq_index(schedq);
			thr = schedq_get(schedq, sqix);
			if (!thr)
				mask &= ~(1uL << index);
		}
		if (!thr) {
			if (mask)
				goto rescan;
			if (cpu->cpu_idled_elem.lll_next == CPU_NOT_IDLED) {
				lllist_insert(&core->core_idled_cpus,
					      &cpu->cpu_idled_elem);
			}
			pthread_cond_wait(&kcpu->kcpu_cond, &kcpu->kcpu_mutex);
			goto retry;
		}
		pthread_mutex_unlock(&kcpu->kcpu_mutex);

		if (ctx_save(&cpu->cpu_ctx))		// returs twice
			thr_run_on_cpu(thr, cpu);	// first return

		//  On the second return there are no runable threads the
		//  kcpu might be parked after it tries schedq_get() above.
	}
	return NULL;
}

static error_t kcpu_init_common(kcpu_t *kcpu, cpu_t *cpu)
{
	cpu->cpu_kcpu = kcpu;

	error_t error = pthread_cond_init(&kcpu->kcpu_cond, NULL);
	if (error)
		return error;

	error = pthread_mutex_init(&kcpu->kcpu_mutex, NULL);
	if (error)
		pthread_cond_destroy(&kcpu->kcpu_cond);

	return error;
}

inline_only void kcpu_deinit_common(kcpu_t *kcpu)
{
	pthread_mutex_destroy(&kcpu->kcpu_mutex);
	pthread_cond_destroy(&kcpu->kcpu_cond);
}

static stk_t *stk_cpu0;		// TODO: needs deinit error cleanup

inline_only error_t kcpu_init_cpu0(kcpu_t *kcpu, cpu_t *cpu)
{
	//  The main() program as a kcpu has its own stack being used by main()
	//  as a thr, it needs another stack to be used as a kcpu so it can be
	//  cpu_idle()'d like other kcpus.  The first time the main() pthread
	//  calls cpu_idle() it ends up in cpu_main() which makes it a proper
	//  kcpu to do its thr running duties and its kcpu idling duties.

	alloc_value_t av = stk_alloc(CPU_STACKSIZE, PAGE_SIZE);
	if (av.error)
		return av.error;
	stk_t *stk = av.mem;
	stk_cpu0 = stk;

	error_t error = kcpu_init_common(kcpu, cpu);
	if (!error) {
		kcpu->kcpu_pthread = pthread_self();
		ctx_init(&cpu->cpu_ctx, (uptr_t) (stk - 1),
			 (lwt_function_t) cpu_main, cpu);
	}
	return error;
}

static error_t kcpu_start(kcpu_t *kcpu, cpu_t *cpu)
{
	cpu->cpu_kcpu = kcpu;

	error_t error = kcpu_init_common(kcpu, cpu);
	if (error)
		return error;

	error = pthread_create(&kcpu->kcpu_pthread, &cpu_pthread_attr,
			       (void *(*)(void *)) cpu_main, cpu);
	if (error)
		kcpu_deinit_common(kcpu);
	return error;
}


//}{ Initialization functions.

static error_t cpus_start(void)
{
	//  TODO: more work wrt LWT_PRIO_MID priorities and kcpu engines

	cpu_t *cpu = cpus;
	cpu_t *cpuend = &cpus[NCPUS];
	kcpu_t *kcpu = kcpus;

	//  Current cpu[0].

	kcpu_init_cpu0(kcpu, cpu);

	while (++kcpu, ++cpu < cpuend) {	// cpu[0] already started
		error_t error = kcpu_start(kcpu, cpu);
		if (error) {
			TODO();
			return error;
		}
	}
	return 0;
}

inline_only void hw_init(hw_t *hw, core_t *core)
{
	schdom_init(&hw->hw_schdom, core);
	stkcache_init(&hw->hw_stkcache);
}

inline_only void hw_deinit(hw_t *hw)
{
	TODO();
}

inline_only void cpu_init(cpu_t *cpu)
{
	cpu->cpu_idled_elem.lll_next = CPU_NOT_IDLED;
	cpu->cpu_running_thr = NULL;
}

inline_only void core_init(core_t *core)
{
	hw_init(&core->core_hw, core);
	lllist_init(&core->core_idled_cpus);
}

#ifdef LWT_HWSYS
void hwsys_init()
{
	hw_init(&hwsys, NULL);
}
#else
#define	hwsys_init()	NOOP()
#endif

#ifdef LWT_MCORES
void mcores_init(void)
{
	int i;
	for (i = 0; i < NMCORES; ++i)
		hw_init(&mcores[i], NULL);
}
#else
#define	mcores_init()	NOOP()
#endif

static error_t kcores_init(void)
{
	error_t error = pthread_attr_init(&cpu_pthread_attr);
	if (error)
		return error;
	error = pthread_attr_setstacksize(&cpu_pthread_attr, CPU_STACKSIZE);
	if (error)
		pthread_attr_destroy(&cpu_pthread_attr);
	return error;
}

static thr_t *thr_dummy;
static lwt_t lwt_main;
static volatile ureg_t lwt_debugref;		//  reference debug data

inline_only error_t init_data(size_t sched_attempt_steps)
{
	if (sched_attempt_steps > 0 && sched_attempt_steps <= 1000)
		sched_attempts = (int) sched_attempt_steps;
	hwsys_init();
	mcores_init();
	error_t error = kcores_init();
	if (error)
		return error;

	int i;
	for (i = 0; i < NCORES; ++i)
		core_init(&cores[i]);
	for (i = 0; i < NCPUS; ++i)
		cpu_init(&cpus[i]);

	cpu_current_set(&cpus[0]);

	lllist_init(&thr_exited_lllist);
	error = arenas_init();
	if (!error) {
		error = mtx_create_outline(&thr_block_forever_mtx, NULL);
		if (!error) {
			alloc_value_t av = thr_alloc();
			if (!av.error) {
				thr_dummy = av.mem;
				MTXA_OWNER_SET_WHEN_UNLOCKED(
					thr_block_forever_mtx->mtxa,
					MTXID_DUMMY);
				THRA_INDEX_SET(thr_dummy->thra, 
					       thr_dummy - THR_INDEX_BASE);
				thr_dummy->thr_mtxcnt = 1;
				lwt_main = (lwt_t) thr_create_main()->
						   thra.thra_thrid.thrid_all;

				lwt_debugref = *(ureg_t *) (thr_by_index + 1) +
					       *(ureg_t *) (thrx_by_index + 1) +
					       *(ureg_t *) (mtx_by_index + 1);
				return 0;
			}
			error = av.error;
		}
		arenas_deinit();
	}
	return error;
}

inline_only error_t init(size_t sched_attempt_steps)
{
	error_t error = init_data(sched_attempt_steps);
	if (error)
		return error;

	error = cpus_start();
	return error;
}

static noreturn void lwt_assert_fail(const char *file, int line,
				     const char *msg)
{
	volatile int l = line;
	const char *volatile m = msg;
	const char *volatile f = file;
	for (;;)
		*((volatile int *)11) = 0xDEADBEEF;
}


//}  End of section with entry points into this module inlined into the
///  corresponding __lwt_() functions that follow.
///
///  The rest of this source file are the ABI entry points, they call the
///  internal implementation functions which are inlined into these functions.
///
///  This level of indirection costs nothing and removes the eye-sore of
//{  all the __lwt_ prefixes.

error_t __lwt_init(size_t sched_attempt_steps)
{
	return init(sched_attempt_steps);
}

//  __lwt_mtxattr_*() ABI entry points

int __lwt_mtxattr_init(struct __lwt_mtxattr_s **mtxattrpp)
{
	return mtxattr_init(mtxattrpp);
}

int __lwt_mtxattr_destroy(struct __lwt_mtxattr_s **mtxattrpp)
{
	return mtxattr_destroy(mtxattrpp);
}

int __lwt_mutexattr_settype(struct __lwt_mtxattr_s **mtxattrpp, int kind)
{
	return mtxattr_settype(mtxattrpp, kind);
}

int __lwt_mutexattr_gettype(struct __lwt_mtxattr_s *mtxattr, int *kind)
{
	return mtxattr_gettype(mtxattr, kind);
}


//  __lwt_mtx_*() ABI entry points

int __lwt_mtx_init(struct __lwt_mtx_s **mtxpp,
		   const struct __lwt_mtxattr_s *mtxattr)
{
	return mtx_create(mtxpp, mtxattr);
}

int __lwt_mtx_destroy(struct __lwt_mtx_s **mtxpp)
{
	return mtx_destroy(mtxpp);
}

#if 0
//  mtx_lock() can't be inline here by gcc because of its call to a setjmp()
//  like function, inline_only for mtx_lock() doesn't work, so __lwt_mtx_lock()
//  is above where mtx_lock() would have been if gcc didn't have trouble with
//  such a trivial inline (into this one line function)!

int __lwt_mtx_lock(struct __lwt_mtx_s *mtx)
{
	return mtx_lock(mtx);
}
#endif

int __lwt_mtx_trylock(struct __lwt_mtx_s *mtx)
{
	return mtx_trylock(mtx);
}

int __lwt_mtx_unlock(struct __lwt_mtx_s *mtx)
{
	return mtx_unlock(mtx);
}


//  __lwt_cnd_*() ABI entry points

int __lwt_cnd_init(struct __lwt_cnd_s **cndpp,
		   const struct __lwt_cndattr_s *cndattr)
{
	return cnd_create(cndpp, cndattr);
}

int __lwt_cnd_destroy(struct __lwt_cnd_s **cndpp)
{
	return cnd_destroy(cndpp);
}

#if 0
//  cnd_wait() can't be inline here by gcc because of its call to a setjmp()
//  like function, inline_only for cnd_wait() doesn't work, so __lwt_cnd_wait()
//  is above where cnd_wait() would have been if gcc didn't have trouble with
//  such a trivial inline (into this one line function)!

int __lwt_cnd_wait(struct __lwt_cnd_s *cnd,
		   struct __lwt_mtx_s *mtx)
{
	return cnd_wait(cnd, mtx);
}
#endif

int __lwt_cnd_timedwait(struct __lwt_cnd_s *cnd,
			struct __lwt_mtx_s *mtx,
			const struct timespec *abstime)
{
	return cnd_timedwait(cnd, mtx, abstime);
}

int __lwt_cnd_signal(struct __lwt_cnd_s *cnd, struct __lwt_mtx_s *mtx)
{
	return cnd_signal(cnd, mtx);
}

int __lwt_cnd_broadcast(struct __lwt_cnd_s *cnd, struct __lwt_mtx_s *mtx)
{
	return cnd_broadcast(cnd, mtx);
}


//  __lwt_spin_*() ABI entry points

#if 0
int __lwt_spin_init(struct __lwt_spin_s *spin)
{
	return spin_init(spin);
}

int __lwt_spin_destroy(struct __lwt_spin_s *spin)
{
	return spin_destroy(spin);
}

int __lwt_spin_lock(struct __lwt_spin_s *spin)
{
	return spin_lock(spin);
}

int __lwt_spin_trylock(struct __lwt_spin_s *spin)
{
	return spin_trylock(spin);
}

int __lwt_spin_unlock(struct __lwt_spin_s *spin)
{
	return spin_unlock(spin);
}
#endif


//  __lwt_thrattr_*() ABI entry points

int __lwt_thrattr_init(lwt_attr_t *attr)
{
	return thrattr_init((thrattr_t *) attr);
}

int __lwt_thrattr_destroy(lwt_attr_t *attr)
{
	return thrattr_destroy((thrattr_t *) attr);
}

#if 0
int __lwt_thrattr_setsigmask_np(lwt_attr_t *attr, const sigset_t *sigmask)
{
	return thrattr_setsigmask_np((thrattr_t *) attr, sigmask);
}

int __lwt_thrattr_getsigmask_np(const lwt_attr_t *attr, sigset_t *sigmask)
{
	return thrattr_getsigmask_np((thrattr_t *) attr, sigmask);
}

int __lwt_thrattr_setaffinity_np(lwt_attr_t *attr,
				 size_t cpusetsize, const cpu_set_t *cpuset)
{
	return thrattr_setaffinity_np((thrattr_t *) attr, cpusetsize, cpuset);
}

int __lwt_thrattr_getaffinity_np(const lwt_attr_t *attr,
				 size_t cpusetsize, cpu_set_t *cpuset)
{
	return thrattr_getaffinity_np((thrattr_t *) attr, cpusetsize, cpuset);
}
#endif

int __lwt_thrattr_setdetachstate(lwt_attr_t *attr,
				 int detachstate)
{
	return thrattr_setdetachstate((thrattr_t *) attr, detachstate);
}

int __lwt_thrattr_getdetachstate(const lwt_attr_t *attr,
				 int *detachstate)
{
	return thrattr_getdetachstate((thrattr_t *) attr, detachstate);
}

int __lwt_thrattr_setscope(lwt_attr_t *attr, int scope)
{
	return thrattr_setscope((thrattr_t *) attr, scope);
}

int __lwt_thrattr_getscope(const lwt_attr_t *attr, int *scope)
{
	return thrattr_getscope((thrattr_t *) attr, scope);
}

int __lwt_thrattr_setschedpolicy(lwt_attr_t *attr, int policy)
{
	return thrattr_setschedpolicy((thrattr_t *) attr, policy);
}

int __lwt_thrattr_getschedpolicy(const lwt_attr_t *attr,
				 int *policy)
{
	return thrattr_getschedpolicy((thrattr_t *) attr, policy);
}

int __lwt_thrattr_setinheritsched(lwt_attr_t *attr, int inheritsched)
{
	return thrattr_setinheritsched((thrattr_t *) attr, inheritsched);
}

int __lwt_thrattr_getinheritsched(const lwt_attr_t *attr, int *inheritsched)
{
	return thrattr_getinheritsched((thrattr_t *) attr, inheritsched);
}

int __lwt_thrattr_setschedparam(lwt_attr_t *attr,
				const lwt_sched_param_t *param)
{
	return thrattr_setschedparam((thrattr_t *) attr, param);
}

int __lwt_thrattr_getschedparam(const lwt_attr_t *attr,
				lwt_sched_param_t *param)
{
	return thrattr_getschedparam((thrattr_t *) attr, param);
}

int __lwt_thrattr_setstack(lwt_attr_t *attr, void *stackaddr, size_t stacksize)
{
	return thrattr_setstack((thrattr_t *) attr, stackaddr, stacksize);
}

int __lwt_thrattr_getstack(const lwt_attr_t *attr,
			   void **stackaddr, size_t *stacksize)
{
	return thrattr_getstack((thrattr_t *) attr, stackaddr, stacksize);
}

int __lwt_thrattr_setstacksize(lwt_attr_t *attr, size_t stacksize)
{
	return thrattr_setstacksize((thrattr_t *) attr, stacksize);
}

int __lwt_thrattr_getstacksize(const lwt_attr_t *attr, size_t *stacksize)
{
	return thrattr_getstacksize((thrattr_t *) attr, stacksize);
}

int __lwt_thrattr_setstackaddr(lwt_attr_t *attr, void *stackaddr)
{
	return thrattr_setstackaddr((thrattr_t *) attr, stackaddr);
}

int __lwt_thrattr_getstackaddr(const lwt_attr_t *attr, void **stackaddr)
{
	return thrattr_getstackaddr((thrattr_t *) attr, stackaddr);
}

int __lwt_thrattr_setguardsize(lwt_attr_t *attr, size_t guardsize)
{
	return thrattr_setguardsize((thrattr_t *) attr, guardsize);
}

int __lwt_thrattr_getguardsize(const lwt_attr_t *attr, size_t *guardsize)
{
	return thrattr_getguardsize((thrattr_t *) attr, guardsize);
}


//  __lwt_thr_*() ABI entry points

int __lwt_thr_create(lwt_t *thread, const lwt_attr_t *attr,
		     lwt_function_t function, void *arg)
{
	return thr_create(thread, (thrattr_t *) attr, function, arg);
}

void __lwt_thr_exit(void *retval)
{
	thr_exit(retval);
}

int __lwt_thr_join(lwt_t thread, void **retval)
{
	return thr_join(thread, retval);
}

int __lwt_thr_cancel(lwt_t thread)
{
	return thr_cancel(thread);
}

int __lwt_thr_setcancelstate(int state, int *oldstate)
{
	return thr_setcancelstate(state, oldstate);
}

int __lwt_thr_setcanceltype(int type, int *oldtype)
{
	return thr_setcanceltype(type, oldtype);
}

void __lwt_thr_testcancel(void)
{
	thr_testcancel();
}

//}
