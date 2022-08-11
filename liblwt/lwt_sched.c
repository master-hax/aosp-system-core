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

#include "lwt_config.h"
#include <sys/mman.h>
#include <errno.h>
#include <stdbool.h>
#include <string.h>
#include <strings.h>
#include <sched.h>
#include "lwt.h"
#define	LWT_C
#include "lwt_types.h"
#include "lwt_arch.h"
#include "lwt_sched.h"

//{  S_INTRO - Introduction

//  This source file is organized into multiple sections, each documented and
//  easily navigated by using the curly-brace matching and navigation functions
//  in most editors.  For example in "vi" the "%" scans forwards in the line
//  for a brace and jumps to the matching brace by moving to it in the file.

//  The curly-braces that demarcate each section are found next to the comment
//  at the start of the comment that describes the section (as shown in the
//  paragraph above).  This file could be broken into many small files, one per
//  section, but that would require many of prototypes in header files and make
//  a lot of the functions not easily inlined (unless those are further split
//  out into header files) thus needing a lot of jumping around between files
//  when reading or changing the code.  Any editor worth being used properly
//  supports multiple editing windows operating concurrently into the same file.
//  Thus keepig this file as is, without being split, is much easier to examine
//  and maintain.

//  A different way to navigate this file is by searching for the keywords in
//  the table below, they are the headings of the sections that can be reached
//  by curly brace matching.  If your editor supports a command to grab a word
//  and search for it (as in BSD nvi with control-A), then that can be used to
//  go directly to a section, repeating the search brings you back to the table.
//  All section names start with S_ (and no other identifiers are named that
//  way, so searching for "<beginning_of_word>S_" (e.g. \<S_ in nvi) is another
//  way to navigate through all the sections.
/*

S_INTRO		- Introduction
  S_DEBUG	- Debugging support
  S_DEFS	- Various #defines
  S_GLOBALS	- Global variables
  S_PROTOS	- Prototypes
S_INTERNAL	- Internal function
  S_MACROS	- functions that must be implemented as #define macros
  S_MISC_INLINE	- Miscellaneous inline functions:
  S_LLLIST	- Implementation and operations on lllist_t
  S_STACK	- Stack allocation and their caching
  S_MTXATTR	- mtxattr_*() functions
  S_MTX		- mtx_*() functions
  S_CND		- cnd_*() functions
  S_SPIN	- spin_*() functions
  S_THRATTR	- thrattr_*() functions
  S_THR		- thr_*() functions
  S_SCHED_FUNCS	- Scheduler functions
  S_SCHEDQ_ALGO	- Insert and remove algorithm for schedq_t
  S_SCHEDQ_INS  - Functions that implement parts of schedq_insert()
  S_SCHEDQ_REM  - Functions that implement parts of schedq_remove()
  S_SCHED_MORE	- More scheduler functions
  S_ARENA	- Implementation of operations on arena_t
  S_KCORE	- A kcore_t is a kernel supported core, implemented on pthreads
  S_CTXCK	- ctx_t related checks
  S_API		- support for LWT API entry and exit, common code for __LWT_*()
  S_INIT	- Initialization functions
S_LWT		- LWT entry points

*/
//  To avoid having to have an excessive number of prototypes, the code in this
//  file is organized bottom-up, with the lowest level sections of code at the
//  start and the code that depends on them after those.

//  Note:
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


//}{  S_DEBUG - Debugging support

//	assert(expr)	are always compiled in, always run correct code
//	debug(expr)	are only compiled in if LWT_DEBUG is defined
// 	TODO()		is for code that has not been written yet

static const char *volatile __lwt_assert_file;
static const char *volatile __lwt_assert_msg;
static int volatile __lwt_assert_line;

static noreturn void lwt_assert_fail(const char *file, int line,
				     const char *msg)
{
	__lwt_assert_line = line;
	__lwt_assert_msg = msg;
	__lwt_assert_file = file;
	for (;;)
		*((volatile int *)11) = 0xDEADBEEF;
}

#define	assert(expr)							\
	do {								\
		if (really_unlikely(!(expr)))				\
			lwt_assert_fail(__FILE__, __LINE__, #expr);	\
	} while (0)

#define	dbgchk(expr)	assert(expr)

#ifdef LWT_DEBUG
#define	debug(expr)	assert(expr)
#else
#define	debug(expr)	NOOP()
#endif

#define	TODO()		assert(0)


//}{  S_DEFS - Various #defines

#define	NOOP()			do {} while (0)

#ifndef PAGE_SIZE
#define PAGE_SIZE		4096
#endif

#define	PAGE_SIZE_ROUND_UP(size)					\
	(((size) + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1))

#ifdef LWT_FIXED_ADDRESSES //{

#define	THR_ARENA_START		(1uL << 22)
#define	THRX_ARENA_START	(1uL << 23)
#define	FPCTX_ARENA_START	(1uL << 26)
#define	CND_ARENA_START		(2uL << (32 + 5))
#define	MTX_ARENA_START		(3uL << (32 + 6))
#define	MTX_ARENA_START_VALUE	MTX_ARENA_START

#else //}{

#define	THR_ARENA_START		0uL
#define	THRX_ARENA_START	0uL
#define	FPCTX_ARENA_START	0uL
#define	CND_ARENA_START		0uL
#define	MTX_ARENA_START		0uL
#define	MTX_ARENA_START_VALUE	mtx_arena_start

#endif //}

static ureg_t	thr_arena_start;
static ureg_t	fpctx_arena_start;
static ureg_t	cnd_arena_start;
static ureg_t	mtx_arena_start;

#define	THR_ARENA_LENGTH	(sizeof(thr_t) * THRIX_MAX)
#define	THR_ARENA_RESERVED	PAGE_SIZE

#define	FPCTX_ARENA_LENGTH	(sizeof(fpctx_t) * THRIX_MAX)
#define	FPCTX_ARENA_RESERVED	PAGE_SIZE

#define	MTX_ARENA_LENGTH	(sizeof(mtx_t) << 32)
#define	MTX_ARENA_RESERVED	PAGE_SIZE

#define	CND_ARENA_LENGTH	(sizeof(cnd_t) << 32)
#define	CND_ARENA_RESERVED	PAGE_SIZE

#ifdef LWT_FIXED_ADDRESSES //{

#define	THR_INDEX_BASE		((thr_t *) (THR_ARENA_START - sizeof(thr_t)))
#define	MTX_INDEX_BASE		((mtx_t *) (MTX_ARENA_START - sizeof(mtx_t)))

//  For debugging only.

static mtx_t	*mtx_by_index = MTX_INDEX_BASE;
static thr_t	*thr_by_index = THR_INDEX_BASE;

#else //}{

#define	THR_INDEX_BASE		((thr_t *) (thr_arena_start - sizeof(thr_t)))
#define	MTX_INDEX_BASE		((mtx_t *) (mtx_arena_start - sizeof(mtx_t)))

//  For debugging only.

static mtx_t	*mtx_by_index;
static thr_t	*thr_by_index;

#endif //}


//}{  S_GLOBALS - Global variables

static lllist_t	 thr_exited_lllist;
static arena_t	 thr_arena;
static arena_t	 fpctx_arena;
static arena_t	 mtx_arena;
static arena_t	 cnd_arena;

//  The following example configurations can be chosen at compile time.
//  TODO: eventually these should be built dynamically at init() time, or
//  alternatively, at library installation time (on systems where software
//  installation allows for the underlying software configuration).  All of
//  this should be derived from /proc on Linux kernel based systems.
//
//  get_nprocs()
//  get_nprocs_conf()

#ifndef LWT_MP //{

static cpu_t cpus[];

static sqcl_t sqcls[1 * SQ_PRIO_MAX];
static hw_t cores_[1] = {
	[0] = {.hw_name = "core0", .hw_parent = NULL,
	       .hw_first_cpu = &cpus[0], .hw_last_cpu = &cpus[0],
	       .hw_schdom = {.schdom_sqcls = &sqcls[0]}},
};
static core_t cores[1] = {
	[0] = {.core_hw = &cores_[0]},
};
static cpu_t cpus[1] = {
	[0] = {.cpu_name = "cpu0(test)", .cpu_core = &cores[0]},
};

#ifdef LWT_X64_USE_GS //{
static cpu_t *cpuptrs[1] = {
	[0] = &cpus[0],
};
#endif //}

#else //}{

#ifdef LWT_ARM64 //{

//  Pixel6 octa-core:
//    2 x Cortex-X1  @ 2.8 GHz
//    2 x Cortex-A76 @ 2.25 GHz 
//    4 x Cortex-A55 @ 1.8 GHz
//
//  This should be determined at run-time from /proc, this is for testing in
//  the meantime (TODO).  At that time deal with kcores too.

#define LWT_CHIPS
#define LWT_MCORES

static cpu_t cpus[];
static hw_t cores_[];
static hw_t mcores[];

static sqcl_t sqcls[(1 + 3 + 8) * SQ_PRIO_MAX];
static hw_t chips[1] = {
	[0] = {.hw_name = "Google Tensor Pixel 6", .hw_parent = NULL,
	       .hw_first_child = &mcores[0],
	       .hw_last_child = &mcores[2],
	       .hw_schdom = {.schdom_sqcls = &sqcls[0 * SQ_PRIO_MAX]}}};
static hw_t mcores[3] = {
	[0] = {.hw_name = "mcore0", .hw_parent = &chips[0],
	       .hw_first_child = &cores_[0],
	       .hw_last_child = &cores_[1],
	       .hw_schdom = {.schdom_sqcls = &sqcls[(1+0) * SQ_PRIO_MAX]}},
	[1] = {.hw_name = "mcore1", .hw_parent = &chips[0],
	       .hw_first_child = &cores_[2],
	       .hw_last_child = &cores_[3],
	       .hw_schdom = {.schdom_sqcls = &sqcls[(1+1) * SQ_PRIO_MAX]}},
	[2] = {.hw_name = "mcore2", .hw_parent = &chips[0],
	       .hw_first_child = &cores_[4],
	       .hw_last_child = &cores_[7],
	       .hw_schdom = {.schdom_sqcls = &sqcls[(1+2) * SQ_PRIO_MAX]}},
};
static hw_t cores_[8] = {
	[0] = {.hw_name = "core0", .hw_parent = &mcores[0],
	       .hw_first_cpu = &cpus[0], .hw_last_cpu = &cpus[0],
	       .hw_schdom = {.schdom_sqcls = &sqcls[(4+0) * SQ_PRIO_MAX]}},
	[1] = {.hw_name = "core1", .hw_parent = &mcores[0],
	       .hw_first_cpu = &cpus[1], .hw_last_cpu = &cpus[1],
	       .hw_schdom = {.schdom_sqcls = &sqcls[(4+1) * SQ_PRIO_MAX]}},
	[2] = {.hw_name = "core2", .hw_parent = &mcores[1],
	       .hw_first_cpu = &cpus[2], .hw_last_cpu = &cpus[2],
	       .hw_schdom = {.schdom_sqcls = &sqcls[(4+2) * SQ_PRIO_MAX]}},
	[3] = {.hw_name = "core3", .hw_parent = &mcores[1],
	       .hw_first_cpu = &cpus[3], .hw_last_cpu = &cpus[3],
	       .hw_schdom = {.schdom_sqcls = &sqcls[(4+3) * SQ_PRIO_MAX]}},
	[4] = {.hw_name = "core4", .hw_parent = &mcores[2],
	       .hw_first_cpu = &cpus[4], .hw_last_cpu = &cpus[4],
	       .hw_schdom = {.schdom_sqcls = &sqcls[(4+4) * SQ_PRIO_MAX]}},
	[5] = {.hw_name = "core5", .hw_parent = &mcores[2],
	       .hw_first_cpu = &cpus[5], .hw_last_cpu = &cpus[5],
	       .hw_schdom = {.schdom_sqcls = &sqcls[(4+5) * SQ_PRIO_MAX]}},
	[6] = {.hw_name = "core6", .hw_parent = &mcores[2],
	       .hw_first_cpu = &cpus[6], .hw_last_cpu = &cpus[6],
	       .hw_schdom = {.schdom_sqcls = &sqcls[(4+6) * SQ_PRIO_MAX]}},
	[7] = {.hw_name = "core7", .hw_parent = &mcores[2],
	       .hw_first_cpu = &cpus[7], .hw_last_cpu = &cpus[7],
	       .hw_schdom = {.schdom_sqcls = &sqcls[(4+7) * SQ_PRIO_MAX]}},
};
static core_t cores[8] = {
	[0] = {.core_hw = &cores_[0]},
	[1] = {.core_hw = &cores_[1]},
	[2] = {.core_hw = &cores_[2]},
	[3] = {.core_hw = &cores_[3]},
	[4] = {.core_hw = &cores_[4]},
	[5] = {.core_hw = &cores_[5]},
	[6] = {.core_hw = &cores_[6]},
	[7] = {.core_hw = &cores_[7]},
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

#ifdef LWT_SMT //{

#define LWT_MCORES

//  Multi-threaded cores for testing.

static cpu_t cpus[];
static hw_t cores_[];

static sqcl_t sqcls[(1 + 4) * SQ_PRIO_MAX];
static hw_t mcores[1] = {
	[0] = {.hw_name = "mcore0", .hw_parent = NULL,
	       .hw_first_child = &cores_[0],
	       .hw_last_child = &cores_[7],
	       .hw_schdom = {.schdom_sqcls = &sqcls[0 * SQ_PRIO_MAX]}},
};
static hw_t cores_[4] = {
	[0] = {.hw_name = "core0", .hw_parent = &mcores[0],
	       .hw_first_cpu = &cpus[0], .hw_last_cpu = &cpus[1],
	       .hw_schdom = {.schdom_sqcls = &sqcls[(1+0) * SQ_PRIO_MAX]}},
	[1] = {.hw_name = "core1", .hw_parent = &mcores[0],
	       .hw_first_cpu = &cpus[2], .hw_last_cpu = &cpus[3],
	       .hw_schdom = {.schdom_sqcls = &sqcls[(1+1) * SQ_PRIO_MAX]}},
	[2] = {.hw_name = "core2", .hw_parent = &mcores[0],
	       .hw_first_cpu = &cpus[4], .hw_last_cpu = &cpus[5],
	       .hw_schdom = {.schdom_sqcls = &sqcls[(1+2) * SQ_PRIO_MAX]}},
	[3] = {.hw_name = "core3", .hw_parent = &mcores[0],
	       .hw_first_cpu = &cpus[6], .hw_last_cpu = &cpus[7],
	       .hw_schdom = {.schdom_sqcls = &sqcls[(1+3) * SQ_PRIO_MAX]}},
};
static core_t cores[4] = {
	[0] = {.core_hw = &cores_[0]},
	[1] = {.core_hw = &cores_[1]},
	[2] = {.core_hw = &cores_[2]},
	[3] = {.core_hw = &cores_[3]},
};
static cpu_t cpus[8] = {
	[0] = {.cpu_name = "cpu0", .cpu_core = &cores[0]},
	[1] = {.cpu_name = "cpu1", .cpu_core = &cores[0]},
	[2] = {.cpu_name = "cpu2", .cpu_core = &cores[1]},
	[3] = {.cpu_name = "cpu3", .cpu_core = &cores[1]},
	[4] = {.cpu_name = "cpu4", .cpu_core = &cores[2]},
	[5] = {.cpu_name = "cpu5", .cpu_core = &cores[2]},
	[6] = {.cpu_name = "cpu6", .cpu_core = &cores[3]},
	[7] = {.cpu_name = "cpu7", .cpu_core = &cores[3]},
};

#else //}{

#define LWT_MCORES

//  Single-threaded cores for testing.

static cpu_t cpus[];
static hw_t cores_[];

static sqcl_t sqcls[(1 + 8) * SQ_PRIO_MAX];
static hw_t mcores[1] = {
	[0] = {.hw_name = "mcore0", .hw_parent = NULL,
	       .hw_first_child = &cores_[0],
	       .hw_last_child = &cores_[7],
	       .hw_schdom = {.schdom_sqcls = &sqcls[0 * SQ_PRIO_MAX]}},
};
static hw_t cores_[8] = {
	[0] = {.hw_name = "core0", .hw_parent = &mcores[0],
	       .hw_first_cpu = &cpus[0], .hw_last_cpu = &cpus[0],
	       .hw_schdom = {.schdom_sqcls = &sqcls[(1+0) * SQ_PRIO_MAX]}},
	[1] = {.hw_name = "core1", .hw_parent = &mcores[0],
	       .hw_first_cpu = &cpus[1], .hw_last_cpu = &cpus[1],
	       .hw_schdom = {.schdom_sqcls = &sqcls[(1+1) * SQ_PRIO_MAX]}},
	[2] = {.hw_name = "core2", .hw_parent = &mcores[0],
	       .hw_first_cpu = &cpus[2], .hw_last_cpu = &cpus[2],
	       .hw_schdom = {.schdom_sqcls = &sqcls[(1+2) * SQ_PRIO_MAX]}},
	[3] = {.hw_name = "core3", .hw_parent = &mcores[0],
	       .hw_first_cpu = &cpus[3], .hw_last_cpu = &cpus[3],
	       .hw_schdom = {.schdom_sqcls = &sqcls[(1+3) * SQ_PRIO_MAX]}},
	[4] = {.hw_name = "core4", .hw_parent = &mcores[0],
	       .hw_first_cpu = &cpus[4], .hw_last_cpu = &cpus[4],
	       .hw_schdom = {.schdom_sqcls = &sqcls[(1+4) * SQ_PRIO_MAX]}},
	[5] = {.hw_name = "core5", .hw_parent = &mcores[0],
	       .hw_first_cpu = &cpus[5], .hw_last_cpu = &cpus[5],
	       .hw_schdom = {.schdom_sqcls = &sqcls[(1+5) * SQ_PRIO_MAX]}},
	[6] = {.hw_name = "core6", .hw_parent = &mcores[0],
	       .hw_first_cpu = &cpus[6], .hw_last_cpu = &cpus[6],
	       .hw_schdom = {.schdom_sqcls = &sqcls[(1+6) * SQ_PRIO_MAX]}},
	[7] = {.hw_name = "core7", .hw_parent = &mcores[0],
	       .hw_first_cpu = &cpus[7], .hw_last_cpu = &cpus[7],
	       .hw_schdom = {.schdom_sqcls = &sqcls[(1+7) * SQ_PRIO_MAX]}},
};
static core_t cores[8] = {
	[0] = {.core_hw = &cores_[0]},
	[1] = {.core_hw = &cores_[1]},
	[2] = {.core_hw = &cores_[2]},
	[3] = {.core_hw = &cores_[3]},
	[4] = {.core_hw = &cores_[4]},
	[5] = {.core_hw = &cores_[5]},
	[6] = {.core_hw = &cores_[6]},
	[7] = {.core_hw = &cores_[7]},
};
static cpu_t cpus[8] = {
	[0] = {.cpu_name = "cpu0", .cpu_core = &cores[0]},
	[1] = {.cpu_name = "cpu1", .cpu_core = &cores[1]},
	[2] = {.cpu_name = "cpu2", .cpu_core = &cores[2]},
	[3] = {.cpu_name = "cpu3", .cpu_core = &cores[3]},
	[4] = {.cpu_name = "cpu4", .cpu_core = &cores[4]},
	[5] = {.cpu_name = "cpu5", .cpu_core = &cores[5]},
	[6] = {.cpu_name = "cpu6", .cpu_core = &cores[6]},
	[7] = {.cpu_name = "cpu7", .cpu_core = &cores[7]},
};

#endif //}

#ifdef LWT_X64_USE_GS //{
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
#endif //}

#ifdef LWT_MCORES
#define	NMCORES		(sizeof(mcores) / sizeof(mcores[0]))
#else
#define	NMCORES		0
#endif

#ifdef LWT_CHIPS
#define	NCHIPS		(sizeof(chips) / sizeof(chips[0]))
#else
#define	NCHIPS		0
#endif

#ifdef LWT_MCMS
#define	NMCMS		(sizeof(mcms) / sizeof(mcms[0]))
#else
#define	NMCMS		0
#endif

#ifdef LWT_HWUNITS
#define	NHWUNITS	(sizeof(hwunits) / sizeof(hwunits[0]))
#else
#define	NHWUNITS	0
#endif

#define	NCPUS		(sizeof(cpus) / sizeof(cpus[0]))
#define	NCORES		(sizeof(cores) / sizeof(cores[0]))
#define	CPUS_PER_CORE	(NCPUS / NCORES)

#if (defined(LWT_HWSYS) || defined(LWT_HWUNITS) || defined(LWT_MCMS) || \
     defined(LWT_CHIPS) || defined(LWT_MCORES))
#define	LWT_HIERARCHICAL_HW
#endif


//}{  S_PROTOS - Prototypes

//  Only prototypes required because of their order in this file or becahse
//  they are implemented in lwt_sched.S

noreturn void		 __lwt_start_glue(void);
noreturn void		 __lwt_thr_exit(void *retval);

static noreturn void	 sched_out(thr_t *thr, bool enabled);
static int		 sched_in_with_qix(thr_t *thr, ureg_t qix);

static int		 thr_context_save__thr_run(thr_t *currthr, thr_t *thr);

static noreturn void	 thr_block_forever(thr_t *thr, const char *msg,
					   void *arg);

two_returns ureg_t	 __lwt_ctx_save(ctx_t *ctx);
two_returns thr_t	*__lwt_ctx_save_for_cpu_main(ctx_t *ctx);

noreturn void		 __lwt_ctx_load(thr_t *thr, ctx_t *ctx, ctx_t *cpuctx,
					bool *new_running, bool enabled,
					bool *curr_running);
noreturn void		 __lwt_ctx_load_on_cpu(thr_t *thr, ctx_t *ctx,
					       ctx_t *cpuctx, bool *new_running,
					       bool enabled);
noreturn void		 __lwt_ctx_load_idle_cpu(bool *curr_running,
						 ctx_t *ctx);

void			 __lwt_ctx_load_trampoline(void);

ureg_t			 __lwt_get_fpcr(void);
void			 __lwt_set_fpcr(ureg_t fpcr);

ureg_t			 __lwt_get_fpsr(void);
void			 __lwt_set_fpsr(ureg_t fpsr);

ureg_t			 __lwt_get_nzcv(void);
void			 __lwt_set_nzcv(ureg_t nzcv);

void			 __lwt_entry_start(void);
void			 __lwt_entry_end(void);

bool 			 __lwt_bool_load_acq(bool *m);
void 			 __lwt_bool_store_rel(bool *m, bool b);
ureg_t			 __lwt_ureg_load_acq(ureg_t *m);
ureg_t			 __lwt_ureg_atomic_add_unseq(ureg_t *m, ureg_t v);
ureg_t			 __lwt_ureg_atomic_or_acq_rel(ureg_t *m, ureg_t v);

#define	bool_load_acq(m)		__lwt_bool_load_acq(m)
#define	bool_store_rel(m, b)		__lwt_bool_store_rel(m, b)
#define	ureg_load_acq(m)		__lwt_ureg_load_acq(m)
#define	ureg_atomic_add_unseq(m, v)	__lwt_ureg_atomic_add_unseq(m, v)
#define	ureg_atomic_or_acq_rel(m, v)	__lwt_ureg_atomic_or_acq_rel(m, v)

static core_t		*core_from_thrattr(const thrattr_t *thrattr);

static thr_t		*schedq_get(schedq_t *schedq, ureg_t sqix);

static alloc_value_t	 arena_alloc(arena_t *arena, thr_t *thr);
static void		 arena_free(arena_t *arena, void *mem);

static void		 core_run(core_t *core);

static void		 ktimer_tick(cpu_t *cpu);

#ifdef LWT_CPU_PTHREAD_KEY //{
static void		 cpu_current_set(cpu_t *cpu);
static cpu_t		*cpu_current(void);
#endif //}


//}  S_INTERNAL - Internal functions
///
///  This section contains internal functions and their supporting functions,
///  they are inlined into the corresponding __lwt_*() and __LWT_*() functions
///  at the end of this file which are the actual entry points into this module
//{  that implement the LWT API.


//{  S_MACROS - functions that must be implemented as #define macros

//  ctx_save() returns twice, one from its caller and another from where the
//  context was saved, e.g. ctx_load() which never returns to its caller. The
//  first return from ctx_save() returns a non-zero value, the second return
//  returs the value zero.

//  ctx_save() is implemented as a macro, it can not be an inline_only function,
//  beacuse __lwt_ctx_save() is a two_returns function, which would required
//  that ctx_save() also be a two_returns functions, which can not be inline.

#define	ctx_save(ctx, thr) ({						\
	debug(!cpu_current()->cpu_enabled);				\
	(thr)->thr_ctx = (ctx);					\
	(thr)->thr_is_fullctx = false;				\
	__lwt_ctx_save(ctx);						\
})

//  ctx_save_for_cpu_main() is used by cpu_main() to save its CPU context, the
//  first return returns CTX_SAVED at context saving time, the second return
//  is either a thread pointer or CTX_LOADED.  It is usually CTX_LOADED, but
//  infrequently it is a thread pointer which corresponds to a thread whose
//  context was being attempted to be loaded but the thread for that context
//  kept its thr_running set to true for too long, so instead the context of
//  the CPU was loaded itself to have it handle the thread whose thr_running
//  field remained true too long.  CTX_SAVED and CTX_LOADED have to be the
//  values for true and false, ctx_save_returs_thr() behaves as a threelean 
//  (instead of as a boolean), it returns on of these 3 values: CTX_SAVED,
//  CTX_LOADED, or a thread pointer (which also implies that the cpu context
//  has just been loaded but a thread pointer is being retured also)..

#define	CTX_SAVED	((thr_t *) 1)
#define	CTX_LOADED	((thr_t *) 0)

#define	ctx_save_for_cpu_main(ctx)					\
	__lwt_ctx_save_for_cpu_main(ctx)

//  The signatures of ctx_load(), ctx_load_on_cpu() and ctx_load_idle_cpu()
//  have ctx as their first argument, that is per the naming conventions used
//  by the LWT implementation.  The functions that implement them (with the
//  __lwt_ prefix) are best implemented with the ctx argument as the second
//  argument, and the thr argument (for the first two) as their first argument.

#define	ctx_load(ctx, thr, cpuctx, new_running, enabled, curr_running)	\
	__lwt_ctx_load(thr, ctx, cpuctx, new_running, enabled, curr_running)

#define	ctx_load_on_cpu(ctx, thr, cpuctx, new_running, enabled)		\
	__lwt_ctx_load_on_cpu(thr, ctx, cpuctx, new_running, enabled)

#define	ctx_load_idle_cpu(ctx, curr_running)				\
	__lwt_ctx_load_idle_cpu(curr_running, ctx)


//}{  S_MISC_INLINE - Miscellaneous inline functions

#ifdef LWT_X64_USE_GS //{
static void cpu_current_set(cpu_t *cpu)
{
	//  X64 needs an extra level of indirection to use gs:
	//  this is not used often enough to optimize further.

	cpu_current_set_x64(&cpuptrs[cpu - cpus]);
}
#endif //}

#ifdef LWT_CPU_THREAD_KEYWORD //{
__thread cpu_t *__lwt_cpu_this;

inline_only void cpu_current_set(cpu_t *cpu)
{
	__lwt_cpu_this = cpu;
}

inline_only cpu_t *cpu_current(void)
{
	return __lwt_cpu_this;
}
#endif //}

inline_only ureg_t counter_get_before(void)
{
	return lwt_counter_get_before();
}

inline_only ureg_t counter_get_after(void)
{
	return lwt_counter_get_after();
}

inline_only int sched_in(thr_t *thr)
{
	return sched_in_with_qix(thr, SQCL_SCHEDQ_IX);
}

inline_only int sched_in_ts(thr_t *thr)
{
	return sched_in_with_qix(thr, SQCL_SCHEDQTS_IX);
}

inline_only bool thr_can_use_current_cpu(unused thr_t *in)
{
	//  TODO: revisit with respect to cpu/core affinity.
	return true;
}

inline_only void cpu_enable_with_ktimer_tick(cpu_t *cpu)
{
	debug(!cpu->cpu_enabled);
	if (cpu->cpu_timerticked) {
		cpu->cpu_timerticked = false;
		ktimer_tick(cpu);
		cpu = cpu_current();		// might be on a different cpu
	}
	cpu->cpu_enabled = true;
}

inline_only void cpu_enable(cpu_t *cpu)
{
	debug(!cpu->cpu_enabled);
	cpu->cpu_enabled = true;
}

inline_only thr_t *thr_from_index(ureg_t index)
{
	return THR_INDEX_BASE + index;
}


//}{  S_LLLIST - Implementation and operations on lllist_t

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

inline_only void *arena_tryalloc(arena_t *arena)
{
	return lllist_remove(&arena->arena_lllist);
}


//}{  S_STACK - Stack allocation and their caching

static alloc_value_t rawstk_alloc(size_t stacksize, size_t guardsize)
{
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
	return (alloc_value_t) {.mem = mem, .error = 0};
}

#define	SIGSTK_GUARDSIZE	(4 * PAGE_SIZE)
#define	SIGSTK_STACKSIZE	(4 * PAGE_SIZE)

#if 0 // TODO
static alloc_value_t sigstk_alloc(void)
{
	alloc_value_t av = rawstk_alloc(SIGSTK_STACKSIZE, SIGSTK_GUARDSIZE);
	if (av.error)
		return av;

	void *top = av.mem;
	top = (void *) ((uptr_t) top + SIGSTK_GUARDSIZE);
	return (alloc_value_t) {.mem = top, .error = 0};
}
#endif

static alloc_value_t stk_alloc(size_t stacksize, size_t guardsize)
{
	stacksize = PAGE_SIZE_ROUND_UP(stacksize);
	guardsize = PAGE_SIZE_ROUND_UP(guardsize);
	size_t size = stacksize + guardsize;
	alloc_value_t av = rawstk_alloc(stacksize, guardsize);
	if (av.error)
		return av;

	void *mem = av.mem;
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
		return stkcache_alloc_stk(&cpu->cpu_core->core_hw->hw_stkcache,
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
	if (stk->stk_guardsize != GUARDSIZE_USER_OWNS_STACK) {
		cpu_t *cpu = cpu_current();
		stkcache_free_stk(&cpu->cpu_core->core_hw->hw_stkcache, stk);
	}
}


//}{  S_MTXATTR - mtxattr_*() functions

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


//}{  S_MTX - mtx_*() functions

inline_only alloc_value_t mtx_alloc(thr_t *thr)
{
	return arena_alloc(&mtx_arena, thr);
}

inline_only mtx_t *mtx_tryalloc(void)
{
	return arena_tryalloc(&mtx_arena);
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
				(mtx - (mtx_t *) MTX_ARENA_START_VALUE) };
	return mtxid;
}

inline_only thr_t *mtx_lllist_to_thr(ureg_t mtxlllist)
{
	if (mtxlllist == MTX_LLLIST_EMPTY)
		return NULL;
	return thr_from_index(mtxlllist);
}

inline_only void mtx_init(mtx_t *mtx, lwt_mtx_type_t type)
{
	//  DO NOT CHANGE VALUE OF:
	//	mtxa.mtxa_reuse
	//  It is part of the mtxid_t, it is incremented by mtx_destroy()

	mtx_atom_t mtxa = mtx_load(mtx);

	mtxa.mtxa_reccnt_llasync_llwant = 
		(MTX_LLLIST_EMPTY << MTXA_LLWANT_SHIFT) | 
		(MTX_LLLIST_EMPTY << MTXA_LLASYNC_SHIFT);

	MTXA_TYPE_SET(mtxa, type);
	MTXA_OWNER_SET(mtxa, MTX_UNLOCKED);
	mtx->mtxa = mtxa;
	mtx->mtx_wantpriq = NULL;
}

inline_only int mtx_create(mtx_t **mtxpp, lwt_mtx_type_t type, thr_t *thr)
{
	alloc_value_t av = mtx_alloc(thr);
	if (av.error) {
		*mtxpp = NULL;
		return av.error;
	}

	mtx_t *mtx = av.mem;
	mtx_init(mtx, type);
	*mtxpp = mtx;
	return 0;
}

inline_only int mtx_create_with_mtxattr(mtx_t **mtxpp, const mtxattr_t *mtxattr,
					thr_t *thr)
{
	lwt_mtx_type_t type = (int)(uptr_t) mtxattr;
	if (type > LWT_MTX_LAST) {
		*mtxpp = NULL;
		return EINVAL;
	}
	return mtx_create(mtxpp, type, thr);
}

static int mtx_trycreate_outline(mtx_t **mtxpp, lwt_mtx_type_t type)
{
	mtx_t *mtx = mtx_tryalloc();
	if (!mtx) {
		*mtxpp = NULL;
		return EAGAIN;
	}

	mtx_init(mtx, type);
	*mtxpp = mtx;
	return 0;
}

static int mtx_create_outline(mtx_t **mtxpp, lwt_mtx_type_t type, thr_t *thr)
{
	return mtx_create(mtxpp, type, thr);
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

static int mtx_destroy_outline(mtx_t **mtxpp)
{
	return mtx_destroy(mtxpp);
}

inline_only int mtx_trylock(mtx_t *mtx, thr_t *thr)
{
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

static error_t mtx_lock(mtx_t *mtx, thr_t *thr)
{
	ctx_t ctx;
	mtx_atom_t old = mtx_load(mtx);
	ureg_t thridix = THRID_INDEX(thr->thra.thra_thrid);

retry:;
	mtx_atom_t new = old;
	if (likely(MTXA_OWNER(new) == MTX_UNLOCKED)) {
		MTXA_RECCNT_SET(new, 0uL);
		MTXA_OWNER_SET_WHEN_UNLOCKED(new, thridix);
	} else if (likely(MTXA_OWNER(new) != thridix)) {
		thr->thr_ln.ln_prev = mtx_lllist_to_thr(MTXA_LLWANT(new));
		MTXA_LLWANT_SET(new, thridix);

		debug(!cpu_current()->cpu_enabled);
		if (!ctx_save(&ctx, thr)) {		// returns twice
			//  Second return, when thr resumes
			//  the mtx has been handed off to it.

			debug(thr->thr_mtxcnt &&
			      MTXA_OWNER(mtx->mtxa) ==
			      THRID_INDEX(thr->thra.thra_thrid));
			debug(!cpu_current()->cpu_enabled);
			return 0;
		}
		// first return
	} else {
		lwt_mtx_type_t type = (lwt_mtx_type_t) MTXA_TYPE(old);
		if (type == LWT_MTX_FAST)
			thr_block_forever(thr, "mtx_lock", mtx);// self-deadlock
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
		sched_out(thr, false);

	++thr->thr_mtxcnt;
	return 0;
}

inline_only int mtx_unlock_common(mtx_t *mtx, thr_t *thr, bool from_cond_wait)
{
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

inline_only int mtx_unlock(mtx_t *mtx, thr_t *thr)
{
	return mtx_unlock_common(mtx, thr, false);
}

static int mtx_unlock_outline(mtx_t *mtx, thr_t *thr)
{
	return mtx_unlock(mtx, thr);
}

static int mtx_unlock_from_cond_wait(mtx_t *mtx, thr_t *thr)
{
	return mtx_unlock_common(mtx, thr, true);
}
 

//}{  S_CND - cnd_*() functions

//  The data structure manipulation here is all done under the protection of
//  mtx which is owned by the current thread .

static int cnd_wait(cnd_t *cnd, mtx_t *mtx, thr_t *thr)
{
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

	thr->thr_mtxid = mtx_get_mtxid(mtx);
	thr->thr_cnd = cnd;
	ctx_t ctx;
	debug(!cpu_current()->cpu_enabled);
	if (ctx_save(&ctx, thr)) {			// returns twice
		mtx_unlock_from_cond_wait(mtx, thr);	// first return
		sched_out(thr, false);
	}
	debug(!cpu_current()->cpu_enabled);

	//  Second return, when cnd is awakened the thread is moved to the
	//  mtx->mtx_wantpriq, eventually when the mtx is unlocked the thread
	//  resumes here with the lock already acquired, see cnd_wakeup().

	debug(THRID_INDEX(thr->thra.thra_thrid) == MTXA_OWNER(mtx->mtxa));
	return 0;
}

static inline int cnd_timedwait(unused cnd_t *cnd, unused mtx_t *mtx,
				unused thr_t *thr,
				unused const struct timespec *abstime)
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

inline_only int cnd_wakeup(cnd_t *cnd, mtx_t *mtx, thr_t *thr, bool broadcast)
{
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

inline_only int cnd_signal(cnd_t *cnd, mtx_t *mtx, thr_t *thr)
{
	return cnd_wakeup(cnd, mtx, thr, false);
}

inline_only int cnd_broadcast(cnd_t *cnd, mtx_t *mtx, thr_t *thr)
{
	return cnd_wakeup(cnd, mtx, thr, true);
}

inline_only alloc_value_t cnd_alloc(thr_t *thr)
{
	return arena_alloc(&cnd_arena, thr);
}

inline_only void cnd_free(cnd_t *cnd)
{
	arena_free(&cnd_arena, cnd);
}

inline_only int cnd_create(cnd_t **cndpp, unused const cndattr_t *cndattr,
			   thr_t *thr)
{
	alloc_value_t av = cnd_alloc(thr);
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

static int cnd_create_outline(cnd_t **cndpp, unused const cndattr_t *cndattr,
			      thr_t *thr)
{
	return cnd_create(cndpp, cndattr, thr);
}

inline_only int cnd_destroy(cnd_t **cndpp)
{
	cnd_t *cnd = *cndpp;
	assert(cnd->cnd_waitpriq == NULL && cnd->cnd_mtx == NULL);
	cnd_free(cnd);
	*cndpp = NULL;
	return 0;
}

static int cnd_destroy_outline(cnd_t **cndpp)
{
	return cnd_destroy(cndpp);
}


//}{  S_SPIN - spin_*() functions

//  Spin locks are implemented as mtx_t, 100% spinning locks in user mode lead
//  to performance anomalies when the owning thread is preempted by the kernel.
//  They are provided for Pthread compatibility, they are implemented as mtx_t
//  with a bit of spinning on acquisitioin.
//
//  TODO: to prevent programmers from misusing spin locks could count number
//  of spin locks owned by a thread and assert() that threads don't block
//  on regular mutexes or condition variables while holding spin locks.  I am
//  not sure if the added overhead is worth the "protection."

static int lwt_spin_attempts = 32;		//  TODO make this tunable

inline_only int spin_lock(mtx_t *spin, thr_t *thr)
{
	int attempts = lwt_spin_attempts;
	do {
		error_t error = mtx_trylock(spin, thr);
		if (!error)
			return 0;
	} while (--attempts > 0);
	return mtx_lock(spin, thr);
}

inline_only int spin_trylock(mtx_t *spin, thr_t *thr)
{
	return mtx_trylock(spin, thr);
}

inline_only int spin_unlock(mtx_t *mtx, thr_t *thr)
{
	return mtx_unlock(mtx, thr);
}


//}{  S_THRATTR - thrattr_*() functions

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


//}{  S_THR - thr_*() functions

inline_only alloc_value_t thr_alloc(thr_t *thr)
{
	return arena_alloc(&thr_arena, thr);
}

inline_only thr_t *thr_tryalloc(void)
{
	return arena_tryalloc(&thr_arena);
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

static noreturn void thr_block_forever(thr_t *thr, unused const char *msg,
				       unused void *arg)
{
	(void) mtx_lock(thr_block_forever_mtx, thr);
	assert(0);
}

inline_only int thr_init(thr_t *t, const thrattr_t *thrattr,
			 stk_t *stk, thr_t *thr)
{
	bool detached = (thrattr->thrattr_detach == LWT_CREATE_DETACHED);

        t->thr_running = false;
        t->thr_prio = thrattr->thrattr_priority;
        t->thr_core = core_from_thrattr(thrattr);
	t->thr_cnd = NULL;
	t->thr_mtxid = (mtxid_t) {.mtxid_all = MTXID_NULL};
	t->thr_mtxcnt = 0;
	t->thr_reccnt = 0;
	t->thr_ln.ln_next = NULL;
	t->thr_ln.ln_prev = NULL;

	mtx_t *mtx = NULL;
	cnd_t *cnd = NULL;
	if (!detached) {
		error_t error = mtx_create_outline(&mtx, LWT_MTX_FAST, thr);
		if (error)
			return error;

		error = cnd_create_outline(&cnd, NULL, thr);
		if (error) {
			mtx_destroy_outline(&mtx);
			return error;
		}
	}

	t->thr_join_mtx = mtx;
	t->thr_join_cnd = cnd;
	t->thr_exited = false;
	t->thr_joining = false;
	t->thr_detached = detached;
	t->thr_retval = NULL;
	t->thr_stk = stk;
	return 0;
}

inline_only void thr_destroy(thr_t *thr)
{
	if (thr->thr_detached) {
		mtx_destroy_outline(&thr->thr_join_mtx);
		cnd_destroy_outline(&thr->thr_join_cnd);
	}
	thr_free_stk(thr->thr_stk);
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

static noreturn void thr_exit(thr_t *thr, void *retval)
{
	thr_exited_cleanup();

	//  If thr->thr_stk is NULL its the main() thread.

	assert(thr->thr_cnd == NULL);
	assert(thr->thr_mtxcnt == 0);

	if (!thr->thr_detached) {
		mtx_lock(thr->thr_join_mtx, thr);
		thr->thr_retval = retval;
		thr->thr_exited = true;
		cnd_broadcast(thr->thr_join_cnd, thr->thr_join_mtx, thr);
		while (!thr->thr_joining)
			cnd_wait(thr->thr_join_cnd, thr->thr_join_mtx, thr);
		mtx_unlock_outline(thr->thr_join_mtx, thr);
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
	sched_out(thr, false);
}

static int thr_join(thr_t *thr, lwt_t thread, void **retvalpp)
{
	thr_exited_cleanup();

	thrid_t	thrid = *(thrid_t *) &thread;
	thr_t *t = THR_INDEX_BASE + THRID_INDEX(thrid);
	if (THRID_REUSE(thrid) != THRA_REUSE(t->thra))
		return ESRCH;

	if (t == thr)
		return EDEADLK;

	if (t->thr_detached)
		return EINVAL;

	mtx_lock(t->thr_join_mtx, thr);
	if (t->thr_joining) {
		mtx_unlock_outline(t->thr_join_mtx, thr);
		return EINVAL;
	}
	t->thr_joining = true;
	cnd_broadcast(t->thr_join_cnd, t->thr_join_mtx, thr);
	while (!t->thr_exited)
		cnd_wait(t->thr_join_cnd, t->thr_join_mtx, thr);
	void *retval = t->thr_retval;
	mtx_unlock_outline(t->thr_join_mtx, thr);

	*retvalpp = retval;
	return 0;
}

typedef void (*glue_t)(void *arg, lwt_function_t function);

static noreturn void thr_start_glue(void *arg, lwt_function_t function)
{
	cpu_t *cpu = cpu_current();
	cpu_enable(cpu);
	__lwt_thr_exit(function(arg));
}

static void cpu_start_glue(void *arg, lwt_function_t function)
{
	function(arg);
}

inline_only void ctx_init_common(ctx_t *ctx, uptr_t sp, lwt_function_t function,
				 void *arg, glue_t glue)
{
	ctx->ctx_pc = (ureg_t) __lwt_start_glue;
	ctx->ctx_start_func = (ureg_t) function;
	ctx->ctx_start_arg = (ureg_t) arg;
	ctx->ctx_start_pc = (ureg_t) glue;
	ctx->ctx_sp = sp;

	//  TODO: This way of describing half contexts is going away shortly
#ifdef LWT_X64
	ctx->ctx_fpctx = 0;	// half context
#endif
#ifdef LWT_ARM64
	ctx->ctx_pstate = 0;	// half context
#endif
}

inline_only void ctx_init(ctx_t *ctx, uptr_t sp, lwt_function_t function,
			  void *arg)
{
	ctx_init_common(ctx, sp, function, arg, thr_start_glue);
}

inline_only void ctx_init_for_cpu(ctx_t *ctx, uptr_t sp,
				  lwt_function_t function, void *arg)
{
	ctx_init_common(ctx, sp, function, arg, cpu_start_glue);
}

static int thr_create(lwt_t *thread, const thrattr_t *thrattr,
		      lwt_function_t function, void *arg, thr_t *thr)
{
	if (thrattr == NULL) thrattr = &thrattr_default;
	else if (!thrattr->thrattr_initialized) return EINVAL;

	alloc_value_t av = thr_alloc_stk(thrattr);
	if (av.error) return av.error;
	stk_t *stk = av.mem;

	av = thr_alloc(thr);
	if (av.error) {
		thr_free_stk(stk);
		return av.error;
	}
	thr_t *t = av.mem;
	ureg_t thridix = t - THR_INDEX_BASE;

	thr_atom_t old = thr_load(t);
retry:;
	thr_atom_t new = old;
	THRA_INDEX_SET(new, thridix);
	thr_atom_t pre = thr_comp_and_swap_acq_rel(old, new, t);
	if (unlikely(!thr_atom_equal(pre, old))) {
		old = pre;
		goto retry;
	}

	error_t error = thr_init(t, thrattr, stk, thr);
	if (error) {
		TODO();
		return error;
	}

	//  Memory for the ctx_t is ephemeral, its on the stack and will
	//  immediately become the stack frame for the thread function,
	//  ctx_load() carefully loads the stack pointer last to prevent
	//  it from being clobbered by signal handlers.

	ctx_t *ctx = ((ctx_t *) (stk - 1)) - 1;
	t->thr_ctx = ctx;
	t->thr_is_fullctx = false;
	t->thr_enabled = false;
	ctx_init(ctx, (uptr_t) (stk - 1), function, arg);
	*(lwt_t *) thread = (lwt_t) t->thra.thra_thrid.thrid_all;

	//  sched_in() always returns zero, this allows for
	//  tail call elimination by the compiler here.

	return sched_in(t);
}

static thr_t *thr_create_main(void)
{
	thr_t *t = thr_tryalloc();
	assert(t);				// thr_arena already grown
	THRA_INDEX_SET(t->thra, t - THR_INDEX_BASE);
	error_t error = thr_init(t, &thrattr_default, NULL, NULL);
	assert(!error);
	cpu_t *cpu = cpu_current();
	t->thr_running = true;
	cpu->cpu_running_thr = t;
	return t;
}

static int thr_cancel(unused thr_t *thr, unused lwt_t thread)
{
	TODO();
}

static void thr_testcancel(unused thr_t *thr)
{
	TODO();
}

static int thr_setcancelstate(unused thr_t *thr, unused int state,
			      unused int *oldstate)
{
	TODO();
}

static int thr_setcanceltype(unused thr_t *thr, unused int type,
			     unused int *oldtype)
{
	TODO();
}


//}{  S_SCHED_FUNCS - Scheduler functions

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
	//  generated that is all that is needed by the caller.  Note that
	//  this also gives a unique index for the sqcl_schedqts queues.
	//  TODO: revisit when sqcls[] and related are generated from /proc

	return schedq - &sqcls[0].sqcl_schedq;
}

inline_only ureg_t sqix_to_ts_sqix(ureg_t sqix)
{
	//  This function knows that sqcl_schedqts index is immediately after
	//  the index of its peer sqcl_schedq, this function is used to track
	//  this in case that relationship changes.

	return sqix + 1;
}

static_assert(offsetof(sqcl_t, sqcl_schedq) + sizeof(schedq_t) ==
	      offsetof(sqcl_t, sqcl_schedqts),
	     "sqix_to_ts_sqix() assumption broken");

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

inline_only void schedq_init(schedq_t *schedq)
{
	SCHEDQ_STATE_SET(*schedq, 0b000);
	SCHEDQ_INS_SET   (*schedq, THRID_NULL);
	SCHEDQ_INSPRV_SET(*schedq, THRID_NULL);
	SCHEDQ_REMNXT_SET(*schedq, THRID_NULL);
	SCHEDQ_REM_SET   (*schedq, THRID_NULL);
	SCHEDQ_ICNT_SET(*schedq, 0uL);
	SCHEDQ_ISER_SET(*schedq, 0uL);
	SCHEDQ_RSER_SET(*schedq, 0uL);
	SCHEDQ_RCNT_SET(*schedq, 0uL);
}

static void schdom_init(schdom_t *schdom)
{
	schdom->schdom_mask = 0uL;
	sqcl_t *sqcl = schdom->schdom_sqcls;
	sqcl_t *sqclend = sqcl + SQ_PRIO_MAX;
	for (; sqcl < sqclend; ++sqcl) {
		schedq_init(&sqcl->sqcl_schedq);
		schedq_init(&sqcl->sqcl_schedqts);
	}
}

#define	SCHDOM_UNINITIALIZED_LOWER	((schdom_t *) 1)

static ureg_t schedom_core_rotor = 0;

static core_t *core_from_thrattr(unused const thrattr_t *thrattr)
{
	// TODO: cpu/core affinity

	ureg_t rotor = ureg_atomic_add_unseq(&schedom_core_rotor, 1);
	rotor %= NCORES;
	return &cores[rotor];
}

inline_only void schdom_summary_update(schdom_t *schdom, ureg_t prio)
{
	ureg_t priomask = 1uL << (LWT_PRIO_HIGH - prio);
	if (! (schdom->schdom_mask & priomask))
		ureg_atomic_or_acq_rel(&schdom->schdom_mask, priomask);
}

static thr_t *schdom_get_thr(schdom_t *schdom)
{
	ureg_t mask = schdom->schdom_mask;
	while (mask) {
		int index = ffsl(mask);
		--index;
		ureg_t prio = LWT_PRIO_HIGH - index;
		sqcl_t *sqcl = &schdom->schdom_sqcls[prio];

		schedq_t *schedq = &sqcl->sqcl_schedq;
		ureg_t sqix = schedq_index(schedq);
		thr_t *thr = schedq_get(schedq, sqix);
		if (thr)
			return thr;

		schedq = &sqcl->sqcl_schedqts;
		thr = schedq_get(schedq, sqix_to_ts_sqix(sqix));
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
		sqcl_t *sqcl = &schdom->schdom_sqcls[prio];

		schedq_t *schedq = &sqcl->sqcl_schedq;
		if (!schedq_is_empty(schedq))
			return false;

		schedq = &sqcl->sqcl_schedqts;
		if (!schedq_is_empty(schedq))
			return false;

		mask &= ~(1uL << index);
	}
	return true;
}


//}{  S_SCHEDQ_ALGO - Insert and remove algorithm for schedq_t.

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


//}{  S_SCHEDQ_INS - Functions that implement parts of schedq_insert().

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

inline_only void schedq_insert_at_head(schedq_t *schedq, ureg_t sqix,
				       thr_t *thr, ureg_t thridix)
{
	schedq_t old = schedq_loadatomic(schedq);
retry:;
	schedq_debug(old);
	schedq_t new = old;
	ureg_t state = SCHEDQ_STATE(new);
	SCHEDQ_RCNT_DEC(new);
	ureg_t rcnt = SCHEDQ_RCNT(new);
	THRLN_NEXT_INIT(thr->thr_ln, sqix, rcnt, SCHEDQ_REM(new));
	THRLN_PREV_INIT_INS(thr->thr_ln, sqix);
	SCHEDQ_REM_SET(new, thridix);
	state |= REM;
	SCHEDQ_STATE_SET(new, state);
	schedq_debug(new);
	schedq_t pre = schedq_comp_and_swap_acq_rel(old, new, schedq);
	if (unlikely(!schedq_equal(pre, old))) {
		old = pre;
		goto retry;
	}
	schedq_debug(new);
}


//}{  S_SCHEDQ_REM - Functions that implement parts of schedq_remove().

//  The following functions up to schedq_remove() are inlined into 
//  schedq_remove() which is then inlined into sched_out().

//  Move the INS stack to INSPRV and update ISER from ICNT.

inline_only schedq_t schedq_move_ins_to_insprv(schedq_t schedq, ureg_t state)
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

inline_only schedq_t schedq_move_remnxt_to_rem(schedq_t schedq, ureg_t state)
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

inline_only schedq_t schedq_remove_simple(schedq_t schedq,  ureg_t state,
					  ureg_t nextix)
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
	return schedq_move_ins_to_insprv(schedq, state);
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
			new = schedq_remove_simple(new, state, nextix);
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
				new = schedq_move_remnxt_to_rem(new, state);
				state = SCHEDQ_STATE(new);
			}
			if (state & INS)
				new = schedq_move_ins_to_insprv(new, state);
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


//}{  S_SCHED_MORE - More scheduler functions

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

static int sched_in_with_qix(thr_t *thr, ureg_t qix)
{
	core_t *core = thr->thr_core;
	schdom_t *schdom = &core->core_hw->hw_schdom;
	ureg_t prio = thr_get_prio_with_ceiling(thr);
	schdom_summary_update(schdom, prio);
	schedq_t *schedq = &schdom->schdom_sqcls[prio].sqcl_schedqs[qix];
	ureg_t thridix = THRID_INDEX(thr->thra.thra_thrid);
	ureg_t sqix = schedq_index(schedq);
	schedq_insert(schedq, sqix, thr, thridix);
	core_run(core);
	return 0;	// must return zero for tail-recursion by caller
}

//  TODO: if called too frequently, a CPU has definitely been preempted while
//  the thread scheduling itself out was almost done doing so, but remained
//  thread running, if that is the case, the thr should be queued to a less
//  frequently examined schdom.  How this is handled now by cpu_main(), allows
//  for another thread to run prior to this one, and that will continue to be
//  the case while runnable threads are found in the schdom, the only issue is
//  that there is probably a measurable amount of overhead.  An alternative is
//  to insert the thr at the tail of the queue instead of inserting at the head
//  of the queue.  Inserting at the head of the queue is done for fairnes to
//  the thread, the CPU it is running on might just be in an interrupt handler
//  and when that returns all is well, the alternative is that the CPU (the
//  kernel thread that supports it) has actually been context switched and the
//  time until it resumes and allows the underlying LWT to finish scheduling
//  itself out might be quire significant.

static void sched_in_at_head(thr_t *thr)
{
	schdom_t *schdom = &thr->thr_core->core_hw->hw_schdom;
	ureg_t prio = thr_get_prio_with_ceiling(thr);
	schedq_t *schedq = &schdom->schdom_sqcls[prio].sqcl_schedq;
	ureg_t sqix = schedq_index(schedq);
	ureg_t thridix = THRID_INDEX(thr->thra.thra_thrid);
	schedq_insert_at_head(schedq, sqix, thr, thridix);
}

#ifdef LWT_X64 //{

//  The GNU libc sigcontext definition mimics but is different than the Linux
//  definition, this file is included by <signal.h> which is included much
//  further below:
//	<x86_64-linux-gnu/bits/sigcontext.h>
//
//  The correct Linux file is included here, including both causes type
//  redefinition errors.

#include <x86_64-linux-gnu/asm/sigcontext.h>

//  Prevent the wrong one from being included by <signal.h> by pretending
//  that it was already included:

#define _BITS_SIGCONTEXT_H  1

#endif //}

inline_only void cpu_generate_branch(cpu_t *cpu, thr_t *thr)
{
	ureg_t instaddr = (ureg_t) cpu->cpu_trampoline;
	instaddr += OFFSET_OF_BRANCH_IN_TRAMPOLINE;
	ureg_t pc = thr->thr_fullctx->fullctx_pc;
	debug(inst_reachable(pc, instaddr));
	generate_branch(pc, instaddr);
}

noreturn inline_only void thr_run(thr_t *thr, thr_t *currthr)
{
	cpu_t *cpu = cpu_current();
	cpu->cpu_running_thr = thr;
	if (thr->thr_is_fullctx)
		cpu_generate_branch(cpu, thr);
	ctx_t *ctx = thr->thr_ctx;
	ctx_load(ctx, thr, &cpu->cpu_ctx, &thr->thr_running,
		 thr->thr_enabled, &currthr->thr_running);
}

noreturn inline_only void thr_run_on_cpu(thr_t *thr, cpu_t *cpu)
{
	cpu->cpu_running_thr = thr;
	if (thr->thr_is_fullctx)
		cpu_generate_branch(cpu, thr);
	ctx_t *ctx = thr->thr_ctx;
	ctx_load_on_cpu(ctx, thr, &cpu->cpu_ctx, &thr->thr_running,
			thr->thr_enabled);
}

noreturn inline_only void cpu_idle(cpu_t *cpu, thr_t *thr)
{
	cpu->cpu_running_thr = NULL;
	ctx_load_idle_cpu(&cpu->cpu_ctx, &thr->thr_running);
}

static thr_t *schedq_get(schedq_t *schedq, ureg_t sqix)
{
	thr_t *thr = schedq_remove(schedq, sqix);
	return thr;
}

static noreturn void sched_out(thr_t *thr, bool enabled)
{
	thr->thr_enabled = enabled;
	schdom_t *schdom = &thr->thr_core->core_hw->hw_schdom;
	thr_t *t = schdom_get_thr(schdom);
	if (!t) {
		cpu_t *cpu = cpu_current();
		cpu_idle(cpu, thr);
	}
	thr_run(t, thr);
}

static noreturn void sched_timeslice(thr_t *thr, bool enabled)
{
	sched_in_ts(thr);
	sched_out(thr, enabled);
}

static int thr_context_save__thr_run(thr_t *currthr, thr_t *thr)
{
	//  This function is out-of-line from mtx_unlock_common(), this part
	//  can not be inlined because ctx_save() returns twice and GCC can
	//  not inline those functions.

	ctx_t ctx;
	debug(!cpu_current()->cpu_enabled);
	if (ctx_save(&ctx, thr)) 			// returns twice
		thr_run(thr, currthr);			// first return
	debug(!cpu_current()->cpu_enabled);
	return 0;			// second return, must return zero
}


//}{  S_ARENA - Implementation of operations on arena_t

inline_only error_t arena_init_without_mtx(arena_t *arena, void *base,
					   size_t elemsize, size_t length,
					   size_t reserved, ureg_t *saveaddr)
{
	if (elemsize < sizeof(uptr_t) ||
            (elemsize & (sizeof(uptr_t) - 1)) != 0 ||
            elemsize > PAGE_SIZE ||
	    length < 16 * PAGE_SIZE ||
	    (length & (PAGE_SIZE - 1)) != 0 ||
	    (reserved & (PAGE_SIZE - 1)) != 0) {
		return EINVAL;
	}

	//  Two reserved redzones, one before and one after, to ensure that
	//  MTXID_NULL and THRID_NULL cause exceptions if used incorrectly.

	void *addr = base;
	if (addr)
		addr = (void *) ((uptr_t) addr - reserved);

	void *start = mmap(addr, length + 2 * reserved, PROT_READ | PROT_WRITE,
			   MAP_PRIVATE | MAP_ANONYMOUS, -1, (off_t) 0);

	if (start == (void *) -1)
		return errno;

	if ((addr && start != addr) ||
	    mprotect(start, reserved, PROT_NONE) < 0 ||
	    mprotect((void *) ((uptr_t) start + length + reserved),
		     reserved, PROT_NONE) < 0) {
		munmap(start, length + 2 * reserved);
		return EINVAL;
	}

	start = (void *) ((uptr_t) start + reserved);
	*saveaddr = (ureg_t) start;
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
			  size_t length, size_t reserved, ureg_t *saveaddr)
{
	error_t error;
	error = arena_init_without_mtx(arena, base, elemsize,
				       length, reserved, saveaddr);
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

	error = mtx_trycreate_outline(&arena->arena_mtx, LWT_MTX_FAST);
	assert(!error);
	return error;
}

static error_t arena_grow(arena_t *arena, thr_t *thr)
{
	mtx_lock(arena->arena_mtx, thr);
	error_t error = arena_grow_common(arena);
	mtx_unlock_outline(arena->arena_mtx, thr);
	return error;
}

typedef struct {
	arena_t		*ai_arena;
	void		*ai_start;
	size_t		 ai_elemsize;
	size_t		 ai_length;
	size_t		 ai_reserved;
	ureg_t		*ai_saveaddr;
} arena_init_t;


static arena_init_t arena_init_table[] = {

	//  Must be first, this allows the mtx_alloc() for the subsequent
	//  arenas to be possible.

	{.ai_arena    = &mtx_arena,
	 .ai_start    = (void *) MTX_ARENA_START,
	 .ai_elemsize = sizeof(mtx_t),
	 .ai_length   = MTX_ARENA_LENGTH,
	 .ai_reserved = MTX_ARENA_RESERVED,
	 .ai_saveaddr = &mtx_arena_start},

	{.ai_arena    = &cnd_arena,
	 .ai_start    = (void *) CND_ARENA_START,
	 .ai_elemsize = sizeof(cnd_t),
	 .ai_length   = CND_ARENA_LENGTH,
	 .ai_reserved = CND_ARENA_RESERVED,
	 .ai_saveaddr = &cnd_arena_start},

	{.ai_arena    = &thr_arena,
	 .ai_start    = (void *) THR_ARENA_START,
	 .ai_elemsize = sizeof(thr_t),
	 .ai_length   = THR_ARENA_LENGTH,
	 .ai_reserved = THR_ARENA_RESERVED,
	 .ai_saveaddr = &thr_arena_start},

	{.ai_arena    = &fpctx_arena,
	 .ai_start    = (void *) FPCTX_ARENA_START,
	 .ai_elemsize = sizeof(fpctx_t),
	 .ai_length   = FPCTX_ARENA_LENGTH,
	 .ai_reserved = FPCTX_ARENA_RESERVED,
	 .ai_saveaddr = &fpctx_arena_start},
};

static error_t arenas_init(void)
{
	arena_init_t *ai = arena_init_table;
	arena_init_t *aiend = ai + sizeof(arena_init_table) /
				   sizeof(arena_init_table[0]);

	for (; ai < aiend; ++ai) {
		error_t error = arena_init(ai->ai_arena, ai->ai_start,
					   ai->ai_elemsize, ai->ai_length,
					   ai->ai_reserved, ai->ai_saveaddr);
		if (error) {
			for (; ai >= arena_init_table; --ai)
				arena_deinit(ai->ai_arena);
			return error;
		}
	}

#	ifndef LWT_FIXED_ADDRESSES
		mtx_by_index = MTX_INDEX_BASE;
		thr_by_index = THR_INDEX_BASE;
#	endif

	//  Arena growth is protected by its mutex, which when acquired
	//  requires that a current thread already exist,

	return 0;
}

static void arenas_deinit(void)
{
	TODO();
}

static alloc_value_t arena_alloc(arena_t *arena, thr_t *thr)
{
	void *mem;
	for (;;) {
		mem = arena_tryalloc(arena);
		if (mem)
			break;
		error_t error = arena_grow(arena, thr);
		if (error)
			return (alloc_value_t) {.mem = NULL, .error = error};
	}
	return (alloc_value_t) {.mem = mem, .error = 0};
}

inline_only void arena_free(arena_t *arena, void *mem)
{
	lllist_insert(&arena->arena_lllist, mem);
}


//}{  S_KCORE - A kcore_t is a kernel supported core, implemented on pthreads

//  Might later be implemented on top of clone(2) and futex(2).  A kcore_t has
//  the kernel synchronizers required to run and idle cpus associated with the
//  core (e.g. a multi-threaded core might have more than on cpu).

//  Included late in this file to prevent misuse in code above that should
//  not depend on these.

#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

#define	CPU_STACKSIZE	(16 * 1024)
#define	CPU_NOT_IDLED	((llelem_t *) 0x1)

struct kcore_s {
	pthread_cond_t	 kcore_cond;
	pthread_mutex_t	 kcore_mutex;
} aligned_cache_line;

static kcore_t		kcores[NCORES];

inline_only void core_run_locked(core_t *core, kcore_t *kcore)
{
	if (core->core_ncpus_idled > 0)
		pthread_cond_signal(&kcore->kcore_cond);
}

static void core_run(core_t *core)
{
#if 0 // TODO
	if (core->core_ncpus_idled == 0)
		return;
#endif

	kcore_t *kcore = core->core_kcore;
	error_t error = pthread_mutex_trylock(&kcore->kcore_mutex);
	if (error) {
		assert(error == EBUSY);
		return;
	}
	core_run_locked(core, kcore);
	pthread_mutex_unlock(&kcore->kcore_mutex);
}

inline_only int cpu_gettid(void)
{
	return syscall(SYS_gettid);
}

#define	MAX_CPU	1024

#ifdef LWT_PTHREAD_SETAFFINITY
inline_only int cpu_setaffinity(size_t size, cpu_set_t *cpu_set)
{
	return pthread_setaffinity_np(pthread_self(), size, cpu_set);
}
#else
inline_only int cpu_setaffinity(size_t size, cpu_set_t *cpu_set)
{
	return sched_setaffinity(gettid(), size, cpu_set);
}
#endif

static error_t cpu_bind(cpu_t *cpu)
{
	int hwix = cpu->cpu_hwix;
	cpu_set_t *cpuset = CPU_ALLOC(MAX_CPU);
	if (!cpuset)
		return ENOMEM;
	size_t cpuset_size = CPU_ALLOC_SIZE(MAX_CPU);
	CPU_ZERO_S(cpuset_size, cpuset);
	CPU_SET_S(hwix, cpuset_size, cpuset);
	error_t error = cpu_setaffinity(cpuset_size, cpuset);
	CPU_FREE(cpuset);
	return error;
}

#ifdef LWT_X64 //{

inline_only void fullctx_check(unused fullctx_t *fullctx)
{
}

#endif //}

#ifdef LWT_ARM64 //{

typedef struct _aarch64_ctx	aarch64_ctx_t;
typedef struct fpsimd_context	fpsimd_context_t;

static_assert(offsetof(fpsimd_context_t, fpsr) + sizeof(__u32) ==
	      offsetof(fpsimd_context_t, fpcr),
	      "fpsr expected to be before fpcr");

inline_only void fullctx_check(fullctx_t *fullctx)
{
	aarch64_ctx_t *ctxhdr = (aarch64_ctx_t *) &fullctx->__reserved[0];
        assert(ctxhdr->magic == FPSIMD_MAGIC &&
	       ctxhdr->size == sizeof(fpsimd_context_t));
	fpsimd_context_t *fpsimd_context = (fpsimd_context_t *) ctxhdr;
	ctxhdr = (aarch64_ctx_t *)(fpsimd_context + 1);
        assert(ctxhdr->magic == 0 && ctxhdr->size == 0);
}

#if 0 // TODO XXX
inline_only void context_init_from_mcontext(context_t *context,
					    mcontext_t *mcontext)
{
	context->c_ctx = *(ctx_t *) mcontext;
	aarch64_ctx_t *ctxhdr = (aarch64_ctx_t *) &mcontext->__reserved[0];
        assert(ctxhdr->magic == FPSIMD_MAGIC &&
	       ctxhdr->size == sizeof(fpsimd_context_t));
	fpsimd_context_t *fpsimd_context = (fpsimd_context_t *) ctxhdr;
	context->c_ctx.ctx_fpcr_fpsr = (ureg_t) fpsimd_context->fpsr |
				     (((ureg_t) fpsimd_context->fpcr) << 32);
	context->c_fpctx = *(fpctx_t *)(char *) &fpsimd_context->vregs[0];
}
#endif

#endif //}

static void ktimer_tick(unused cpu_t *cpu)
{
	ctx_t ctx;
	thr_t *thr = cpu->cpu_running_thr;
	debug(!cpu_current()->cpu_enabled);
	if (ctx_save(&ctx, thr))			// returns twice
		sched_timeslice(thr, false);		// first return.
	debug(!cpu_current()->cpu_enabled);
}

static void ktimer_signal(unused int signo, siginfo_t *siginfo, void *ucontextp)
{      
	cpu_t *cpu = (cpu_t *) siginfo->si_value.sival_ptr;
	debug(cpu == cpu_current());
	thr_t *thr = cpu->cpu_running_thr;
	if (unlikely(!thr))
		return;
	if (unlikely(!cpu->cpu_enabled)) {
		++cpu->cpu_counts.count_disabled;
		cpu->cpu_timerticked = true;
		return;
	}

	cpu->cpu_enabled = false;
        ucontext_t *ucontext = ucontextp;
	fullctx_t *fullctx = (fullctx_t *) &ucontext->uc_mcontext;
	ureg_t instaddr = (ureg_t) cpu->cpu_trampoline;
	instaddr += OFFSET_OF_BRANCH_IN_TRAMPOLINE;
	ureg_t pc = fullctx->fullctx_pc;

	//  If the interrupted program counter is within the __lwt_*() stubs
	//  stubs in lwt_arch.S, then rewind the program counter back to the
	//  start of the stub, thus ensuring that its work is not preempted in
	//  the middle of it, i.e. in the middle of fetching the cpu pointer
	//  and disabling preemption by setting cpu->cpu_enabled to false.

	if (pc >= (ureg_t) __lwt_entry_start && pc < (ureg_t) __lwt_entry_end) {
		pc &= ~((1uL << ENTRY_ALIGN_L2) - 1);
		fullctx->fullctx_pc = pc;
	}

	//  instaddr is not exact here if resumed in another cpu

	if (!inst_reachable(pc, instaddr)) {
		++cpu->cpu_counts.count_unreachable;
		ctx_t ctx;
		if (ctx_save(&ctx, thr))
			sched_timeslice(thr, false);
		cpu = cpu_current();		// might be on a different cpu
		cpu->cpu_enabled = true;
		return;
	}

	//  TODO: this path doesn't return to kernel mode to restore the
	//  full context, an issue (for now) about this path (which has been
	//  tested and implemented only on arm64), is that the signal that
	//  triggered this function invocation remains blocked, thus the way
	//  this is currently implemented (this "reachable") path needs more
	//  work.  An approach to deal with this is to provide user mode only
	//  signal masking and unmasking through per pthread memory, where the
	//  kernel examines it to see if a signal is masked or not, and sets
	//  the pending flags in user mode, and user mode, when enabling tests
	//  the pending flags and causes the signal delivery to occur.  This
	//  of course only makes sense for asynchronous signals (timers, etc)
	//  and not for instruction synchronous signals (SIGILL, SIGSEGV, etc).
	//  This requires a kernel change.  The overhead of the kernel normal
	//  signal return path is proportional to the fequency of the time
	//  slice timer, after measurement how to proceed will be determined.

	++cpu->cpu_counts.count_reachable;
	thr->thr_is_fullctx = true;
	thr->thr_fullctx = fullctx;
	fullctx_check(fullctx);
	sched_timeslice(thr, true);
}

static_assert(sizeof(mcontext_t) == sizeof(fullctx_t), "fullctx_t is wrong");

static_assert(sizeof(timer_t) <= sizeof(ktimer_t *),
	      "unexpected sizeof(timer_t) value");

static int	 lwt_rtsigno;
static sigset_t	 lwt_rtsigno_sigset;

#define	TIME_SLICE_NSECS	(10000000L)

inline_only void ktimer_start(ktimer_t *ktimer)
{
	timer_t timer = (timer_t) ktimer;
	struct itimerspec it = {
		.it_interval = {.tv_sec = 0, .tv_nsec = TIME_SLICE_NSECS},
		.it_value    = {.tv_sec = 0, .tv_nsec = TIME_SLICE_NSECS}
	};
	if (timer_settime(timer, 0, &it, NULL) < 0) {
		error_t error = errno;
		assert(error);
	}
}

inline_only void ktimer_unblock(void)
{
        error_t error = pthread_sigmask(SIG_UNBLOCK, &lwt_rtsigno_sigset, NULL);
	assert(!error);
}

#ifndef sigev_notify_thread_id 
#define sigev_notify_thread_id	_sigev_un._tid
#endif

static error_t ktimer_create(ktimer_t **ktimerpp, cpu_t *cpu)
{
	*ktimerpp = NULL;

	sigset_t prev_sigset;
        error_t error = pthread_sigmask(SIG_BLOCK, &lwt_rtsigno_sigset,
					&prev_sigset);
	if (error)
		return error;

	struct sigevent sigev;
	sigev.sigev_notify = SIGEV_THREAD_ID;
	sigev.sigev_signo = lwt_rtsigno;
	sigev.sigev_notify_thread_id = cpu_gettid();
	sigev.sigev_value.sival_ptr = cpu;
	timer_t timer;

	if (timer_create(CLOCK_PROCESS_CPUTIME_ID, &sigev, &timer) < 0) {
		(void) pthread_sigmask(SIG_SETMASK, &prev_sigset, NULL);
		return errno;
	}
	*ktimerpp = (ktimer_t *) timer;
	return 0;
}

static int sched_attempts = 1;

static error_t cpu_ktimer_init_and_start(cpu_t *cpu)
{
	error_t error = ktimer_create(&cpu->cpu_ktimer, cpu);
	if (error)
		return error;

	ktimer_unblock();
	ktimer_start(cpu->cpu_ktimer);
	return 0;
}

//  This function is run on each cpu when a cpu is started, it either blocks
//  (i.e. the cpu idles) awaiting for a thread to be ready to run on the cpu
//  or it switches to the thread so it runs on the cpu.

//  A thread might be made runable while its the process of descheduling itself
//  via sched_out(), in those cases the ctx_load() or ctx_load_on_cpu() that
//  would switch to the thread causes instead a return to cpu_main() with the
//  thread pointer value as the value of ctx_save_for_cpu_main() so that rare
//  case be handled by cpu_main().

//  This function does not use floating point registers, nor do any inline
//  function it might call, this function also does not return, so callee saved
//  floating point registers don't have to be saved by ctx_save_for_cpu_main()
//  nor do they have to be restored when switching back to cpu_main(), thus
//  ctx_load_idle_cpu() doesn't restore them.  This is only applicable to arm64,
//  x64 doesn't have callee preserved floating point registers.

static noreturn void *cpu_main(cpu_t *cpu)
{
	assert(cpu >= &cpus[0] && cpu < &cpus[NCPUS]);
	cpu_current_set(cpu);
	core_t *core = cpu->cpu_core;
	kcore_t *kcore = core->core_kcore;
	schdom_t *schdom = &core->core_hw->hw_schdom;
	error_t error;

	if (cpu != &cpus[0]) {		// cpu0 handled in cpus_start()
		error = cpu_bind(cpu);
		if (error)
			TODO();
		error = cpu_ktimer_init_and_start(cpu);
		if (error)
			TODO();
	}

	thr_t *thr_switching_out = NULL;
	for (;;) {
		debug(!cpu->cpu_enabled);
		if (unlikely(thr_switching_out != NULL)) {
			//  Should not block on kcore->kcore_mutex if there
			//  is a thread in our control in thr_switching_out,
			//  try locking kcore_mutex, if it succeeds then its
			//  ok, otherwise put the thread back at the head of
			//  its schedulig queue and then lock the kcore_mutex
			//  in a blocking way.

			error = pthread_mutex_trylock(&kcore->kcore_mutex);
			if (likely(!error))
				goto restart;

			assert(error == EBUSY);
			sched_in_at_head(thr_switching_out);
			thr_switching_out = NULL;
		}
		pthread_mutex_lock(&kcore->kcore_mutex);

restart:;	int attempts = sched_attempts;
retry:;		thr_t *thr = schdom_get_thr(schdom);

		//  A thread whose context could not be loaded because it's
		//  cpu_running remained true too long (most likely because
		//  the kernel preempted that CPU) has been returned by the
		//  call to ctx_save_for_cpu_main(), schedule it out again by
		//  putting it at the head of the right schedq within its
		//  schdom above, after trying to remove some other thread to
		//  run on this cpu.

		if (unlikely(thr_switching_out != NULL)) {
			if (!thr)
				thr = thr_switching_out;
			else
				sched_in_at_head(thr_switching_out);
			thr_switching_out = NULL;
		}

		if (!thr) {
			if (schdom->schdom_mask != 0)
				goto retry;
			//  Don't idle CPU too quickly, kernel context switch is
			//  expensive, wasting cycles here saves overall cycles.
			if (attempts >= 2) {
				while (--attempts >= 0)
					if (schdom_is_empty(schdom))
						break;
				goto retry;
			}
			++core->core_ncpus_idled;
			pthread_cond_wait(&kcore->kcore_cond,
					  &kcore->kcore_mutex);
			debug(!cpu->cpu_enabled);
			--core->core_ncpus_idled;
			goto restart;
		}
		if (CPUS_PER_CORE > 1 &&
		    core->core_ncpus_idled > 0 &&
		    !schdom_is_empty(schdom))
			core_run_locked(core, kcore);
		pthread_mutex_unlock(&kcore->kcore_mutex);

		thr_switching_out = ctx_save_for_cpu_main(&cpu->cpu_ctx);
		debug(!cpu->cpu_enabled);
		if (thr_switching_out == CTX_SAVED)
			thr_run_on_cpu(thr, cpu);	// first return

		//  Second return.  There probably are runable threads now.

		if (likely(thr_switching_out == CTX_LOADED))
			thr_switching_out = NULL;
	}
}

inline_only error_t kcore_init(kcore_t *kcore, core_t *core)
{
	core->core_kcore = kcore;
	error_t error = pthread_cond_init(&kcore->kcore_cond, NULL);
	if (error)
		return error;
	error = pthread_mutex_init(&kcore->kcore_mutex, NULL);
	if (error)
		pthread_cond_destroy(&kcore->kcore_cond);
	return error;
}

inline_only void kcore_deinit(kcore_t *kcore)
{
	pthread_cond_destroy(&kcore->kcore_cond);
	pthread_mutex_destroy(&kcore->kcore_mutex);
}

static stk_t *stk_cpu0;		// TODO: needs deinit error cleanup

inline_only error_t cpu_init_cpu0(cpu_t *cpu)
{
	//  The main() program as a cpu has its own stack being used by main()
	//  as a thr, it needs another stack to be used as a cpu so it can be
	//  cpu_idle()'d like other cpus.  The first time the main() pthread
	//  calls cpu_idle() it ends up in cpu_main() which makes it a proper
	//  cpu to do its thr running duties and its cpu idling duties.

	alloc_value_t av = stk_alloc(CPU_STACKSIZE, PAGE_SIZE);
	if (av.error)
		return av.error;
	stk_t *stk = av.mem;
	stk_cpu0 = stk;

	cpu->cpu_kcpu = (kcpu_t *) pthread_self();
	ctx_init_for_cpu(&cpu->cpu_ctx, (uptr_t) (stk - 1),
			 (lwt_function_t) cpu_main, cpu);
	return 0;
}

static pthread_attr_t cpu_pthread_attr;

static error_t cpu_start(cpu_t *cpu)
{
	pthread_t pthread;
	error_t error = pthread_create(&pthread, &cpu_pthread_attr,
				       (void *(*)(void *)) cpu_main, cpu);
	if (!error)
		cpu->cpu_kcpu = (kcpu_t *) pthread;
	return error;
}


//}{  S_CTXCK - ctx_t related checks

//  The aligned attribute of sigcontext would seem to add 8 bytes of padding
//  prior to __reserved[], that is for the benefit of struct fpsimd_context
//  which requires 16 byte alignment:
//
//	struct sigcontext {
//		...
//		__u64 pstate;
//		/* 4K reserved for FP/SIMD state and future expansion */
//		__u8 __reserved[4096] __attribute__((__aligned__(16)));
//	}
//
//  These assertions ensure ctx_t's fields indeed track sigcontext's fields.

#ifdef LWT_ARM64 //{
static_assert(offsetof(struct sigcontext, fault_address) ==
	      offsetof(ctx_t, ctx_faultaddr), "ctx_faultaddr is wrong");
static_assert(offsetof(struct sigcontext, regs[0]) ==
	      offsetof(ctx_t, ctx_x0), "ctx_x0 is wrong");
static_assert(offsetof(struct sigcontext, sp) ==
	      offsetof(ctx_t, ctx_sp), "ctx_sp is wrong");
static_assert(offsetof(struct sigcontext, pc) ==
	      offsetof(ctx_t, ctx_pc), "ctx_pc is wrong");
static_assert(offsetof(struct sigcontext, pstate) ==
	      offsetof(ctx_t, ctx_pstate), "ctx_pstate is wrong");
static_assert(offsetof(struct sigcontext, __reserved[0]) ==
	      offsetof(struct sigcontext, pstate) + 2 * sizeof(__u64),
	      "__reserved[] offset not as expected");
static_assert(offsetof(struct sigcontext, __reserved[0]) == sizeof(ctx_t),
	      "sizeof(ctx__t) is wrong");
#endif //}

//  TODO: x64 ctx_t should also track struct sigcontext, that is only important
//  once the full context reload is done in user mode, add relevant assertions
//  here.


//}{  S_API - support for LWT API entry and exit, common code for __LWT_*()

inline_only void api_enter(unused int api, bool enabled)
{
	debug(enabled);
}

inline_only void api_exit(unused int api)
{
	//  An api_exit() that follows an api_enter() might occur on a different
	//  cpu, thus having the caller do cpu_current() once, and pass a cpu
	//  argument to both api_enter() and api_exit(), would be incorrent.

	cpu_t *cpu = cpu_current();
	cpu_enable_with_ktimer_tick(cpu);
}


//}{  S_INIT - Initialization functions

struct sigaction ktimer_prevsa;

static error_t ktimer_signal_init(void)
{
	int rtsigno = lwt_rtsigno;
	struct sigaction sa;
	sa.sa_sigaction = ktimer_signal;
#if 1
        sa.sa_flags = SA_SIGINFO;
        sa.sa_mask = lwt_rtsigno_sigset;
#else
        sa.sa_flags = SA_SIGINFO | SA_NODEFER;
        sigemptyset(&sa.sa_mask);
#endif

	if (sigaction(rtsigno, &sa, &ktimer_prevsa) < 0)
		return errno;

	//  Signal handlers are process-wide, this function should find it
	//  to be SIG_DFL, otherwise it is in use already for another purpose.

	if (ktimer_prevsa.sa_sigaction ==
	    (void (*)(int, siginfo_t *, void *)) SIG_DFL)
		return 0;

	return EINVAL;
}

static void ktimer_signal_deinit(void)
{
	sigaction(lwt_rtsigno, &ktimer_prevsa, NULL);
}

static error_t cpus_start(void)
{
	//  TODO: more work wrt priorities

	error_t error = ktimer_signal_init();
	if (error)
		return error;

	error = cpu_init_cpu0(&cpus[0]);
	if (error) {
		ktimer_signal_deinit();
		return error;
	}

	cpu_set_t *cpuset = CPU_ALLOC(MAX_CPU);
	size_t cpuset_size = CPU_ALLOC_SIZE(MAX_CPU);
	CPU_ZERO_S(cpuset_size, cpuset);
	if (sched_getaffinity(getpid(), cpuset_size, cpuset) < 0) {
		ktimer_signal_deinit();
		return errno;
	}

	int cpu_count = CPU_COUNT_S(cpuset_size, cpuset);
	assert(cpu_count >= NCPUS);

	int hwix = 0;
	int cpuix;
	int coreix;

	//  Handling all the per-CPU cpu_set_t in this function causes
	//  CPU_ALLOC() to crash. Each cpu should set its own affinitiy
	//  once it starts other than cpu0 which is set below.

	for (cpuix = 0; cpuix < CPUS_PER_CORE; ++cpuix) {
		for (coreix = 0; coreix < NCORES; ++coreix) {
			while (!CPU_ISSET_S(hwix, cpuset_size, cpuset))
				++hwix;

			int index = coreix * CPUS_PER_CORE + cpuix;
			cpu_t *cpu = &cpus[index];
			cpu->cpu_hwix = hwix;
			++hwix;
			if (cpu == &cpus[0])
				continue;

			error = cpu_start(cpu);
			if (error) {
				TODO();
				return error;
			}
		}
	}
	CPU_FREE(cpuset);

	error = cpu_bind(&cpus[0]);
	if (error) {
		TODO();
		return error;
	}

	return 0;
}

inline_only void hw_init(hw_t *hw)
{
	schdom_init(&hw->hw_schdom);
	stkcache_init(&hw->hw_stkcache);
}

#ifdef LWT_HIERARCHICAL_HW

static void hws_init(hw_t *hw, size_t n)
{
	hw_t *hwend = hw + n;
	for (; hw < hwend; ++hw)
		hw_init(hw);
}

#endif

static cacheline_t *trampolines;

#ifdef LWT_ARM64 //{
//  TODO: well known address on adeb on Pixel6, needs to be determined
//  at run-time, the dynamic linker might export a symbol for this
#define	TRAMPOLINE_ADDR	((void *) (0x400000 - PAGE_SIZE))
#endif //}

#ifdef LWT_X64 //{
#define	TRAMPOLINE_ADDR	NULL
#endif //}

static error_t trampolines_init(void)
{
	int i;
	size_t size = NCPUS * CACHE_LINE_SIZE;
	void *start = mmap(TRAMPOLINE_ADDR, PAGE_SIZE_ROUND_UP(size),
			   PROT_READ | PROT_WRITE | PROT_EXEC,
			   MAP_PRIVATE | MAP_ANONYMOUS, -1, (off_t) 0);
	if (start == (void *) -1)
		return errno;

	//  Copy the per-CPU trampoline instructions to each trampoline.

	trampolines = (cacheline_t *) start;
	for (i = 0; i < NCPUS; ++i)
		trampolines[i] = *(cacheline_t *) __lwt_ctx_load_trampoline;

	return 0;
}

static void trampolines_deinit(void)
{
	TODO();
}

inline_only error_t cpu_init(cpu_t *cpu, cacheline_t *trampoline)
{
	cpu->cpu_running_thr = NULL;
	cpu->cpu_trampoline = trampoline;
	cpu->cpu_counts.count_disabled = 0;
	cpu->cpu_counts.count_unreachable = 0;
	cpu->cpu_counts.count_reachable = 0;
	cpu->cpu_enabled = false;
	cpu->cpu_timerticked = false;

#if 0 // TODO
	alloc_value_t av = sigstk_alloc();
	if (av.error)
		return av.error;

	cpu->cpu_sigstk = av.mem;
#endif
	return 0;
}

static void cpu_deinit(unused cpu_t *cpu)
{
	TODO();
}

inline_only void core_init(core_t *core)
{
	hw_init(core->core_hw);
	core->core_ncpus_idled = 0;
}

#ifdef LWT_HWSYS
inline_only void hwsys_init(void) { hw_init(&hwsys); }
#else
#define	hwsys_init()	NOOP()
#endif
#ifdef LWT_HWUNITS
inline_only void hwunits_init() { hws_init(hwunits, NHWUNITS) }
#else
#define	hwunits_init()	NOOP()
#endif
#ifdef LWT_MCMS
inline_only void mcms_init() { hws_init(mcms, NMCMS); }
#else
#define	mcms_init()	NOOP()
#endif
#ifdef LWT_CHIPS
inline_only void chips_init() { hws_init(chips, NCHIPS); }
#else
#define	chips_init()	NOOP()
#endif
#ifdef LWT_MCORES
inline_only void mcores_init(void) { hws_init(mcores, NMCORES); }
#else
#define	mcores_init()	NOOP()
#endif

inline_only void cores_init(void)
{
	int i;
	for (i = 0; i < NCORES; ++i)
		core_init(&cores[i]);
}

inline_only error_t cpus_init(void)
{
	int i;
	for (i = 0; i < NCPUS; ++i) {
		error_t error = cpu_init(&cpus[i], &trampolines[i]);
		if (error) {
			while (--i >= 0)
				cpu_deinit(&cpus[i]);
			return error;
		}
	}
	return 0;
}

static void cpus_deinit(void)
{
	int i;
	for (i = 0; i < NCPUS; ++i)
		cpu_deinit(&cpus[i]);
}

#ifdef LWT_CPU_PTHREAD_KEY
pthread_key_t pthread_key;
#endif

static error_t kcores_init(void)
{

	error_t error = pthread_attr_init(&cpu_pthread_attr);
	if (error)
		return error;
#if 0
	error = pthread_attr_setstacksize(&cpu_pthread_attr, CPU_STACKSIZE);
	if (error) {
		pthread_attr_destroy(&cpu_pthread_attr);
		return error;
	}
#endif

#	ifdef LWT_CPU_PTHREAD_KEY
		error = pthread_key_create(&pthread_key, NULL);
		if (error) {
			pthread_attr_destroy(&cpu_pthread_attr);
			return error;
		}
#	endif

	int i;
	for (i = 0; i < NCORES; ++i)
		if ((error = kcore_init(&kcores[i], &cores[i])))
			break;

	if (error) {
		while (--i >= 0)
			kcore_deinit(&kcores[i]);
		pthread_attr_destroy(&cpu_pthread_attr);
		return error;
	}

	return 0;
}

static void kcores_deinit(void)
{
	int i;
	for (i = 0; i < NCORES; ++i)
		kcore_deinit(&kcores[i]);
}

#ifdef LWT_CPU_PTHREAD_KEY //{
static void cpu_current_set(cpu_t *cpu)
{
	pthread_setspecific(pthread_key, cpu);
}

static cpu_t *cpu_current(void)
{
	return (cpu_t *) pthread_getspecific(pthread_key);
}
#endif //}

static thr_t	*thr_dummy;
static lwt_t	 lwt_main;

inline_only error_t data_init(size_t sched_attempt_steps, int rtsigno)
{
	if (rtsigno < SIGRTMIN || rtsigno > SIGRTMAX)
		return EINVAL;

	lwt_rtsigno = rtsigno;
        sigemptyset(&lwt_rtsigno_sigset);
	sigaddset(&lwt_rtsigno_sigset, rtsigno);

	if (sched_attempt_steps > 0 && sched_attempt_steps <= 1000)
		sched_attempts = (int) sched_attempt_steps;

	error_t error = trampolines_init();
	if (error)
		return error;

	hwsys_init();
	hwunits_init();
	mcms_init();
	chips_init();
	mcores_init();
	cores_init();
	error = cpus_init();
	if (error) {
		trampolines_deinit();
		return error;
	}

	error = kcores_init();
	if (error) {
		cpus_deinit();
		trampolines_deinit();
		return error;
	}

	cpu_current_set(&cpus[0]);

	lllist_init(&thr_exited_lllist);
	error = arenas_init();
	if (error) {
		kcores_deinit();
		cpus_deinit();
		trampolines_deinit();
		return error;
	}

	//  The arenas were just created, the following two can't fail.

	error = mtx_trycreate_outline(&thr_block_forever_mtx, LWT_MTX_FAST);
	assert(!error);

	thr_dummy = thr_tryalloc();
	assert(thr_dummy);

	MTXA_OWNER_SET_WHEN_UNLOCKED(
		thr_block_forever_mtx->mtxa,
		MTXID_DUMMY);
	THRA_INDEX_SET(thr_dummy->thra, 
		       thr_dummy - THR_INDEX_BASE);
	thr_dummy->thr_mtxcnt = 1;
	lwt_main = (lwt_t) thr_create_main()->thra.thra_thrid.thrid_all;

	//  Prevent removal of these debug variables

	ureg_load_acq((ureg_t *) (thr_by_index + 1));
	ureg_load_acq((ureg_t *) (mtx_by_index + 1));

	return 0;
}

static void data_deinit(void)
{
	arenas_deinit();
	kcores_deinit();
	cpus_deinit();
	trampolines_deinit();
}

inline_only error_t init(size_t sched_attempt_steps, int rtsigno)
{
	error_t error = data_init(sched_attempt_steps, rtsigno);
	if (error)
		return error;

	error = cpus_start();
	if (error) {
		data_deinit();
		return error;
	}

	error = cpu_ktimer_init_and_start(&cpus[0]);
	if (error)
		return error;

	cpu_enable(&cpus[0]);
	return error;
}

//}

///  End of section with internal functions, those functions are used to
///  implement the LWT API entry points, they are usually inlined into their
///  corresponding __lwt_*() and __LWT_*() functions, which follow.

//}{  S_LWT - LWT entry points.

///  The rest of this source file are the API/ABI entry points, they call the
///  internal implementation functions which are inlined into these functions.
///
///  This level of indirection costs nothing and removes the eye-sore of the
///  __lwt_ and prefixes, additionally makes very clear what are the entry
///  points.
///
///  The entry points of 3 types:
///	__lwt_init() initialization function for the LWT API.
///
///	__lwt_*() functions, other than __lwt_init():
///		They are not allowed to block, they usually free memory
///		lock-lessly into arenas (for mtx_t, cnd_t, etc) are are trivial
///		functions that set and get attribute values.  Involuntary
///		preemptiom of these functions is allowed.
///
///	__LWT_*() functions:
///		They might block internally, and perform non trivial data
///		structure manipulations (some lock-lessly some under the
///		protection of a mtx_t owned by the calling thread).  These
///		functions can not be preempted, to prevent their preemptiom
///		the __LWT_*() functions are calling by a corresponding
///		__lwt_*() function stub implemented in assembly in lwt_arch.S.
///		Those stubs are restartable, see ktimer_signal(), their work is
///		to get the per-CPU ponter, disable time slicing by seeting
///		cpu->cpu_enabled to false.  As an optimization the stubs also
///		obtain the current thread and pass it as an extra argument to
///		the __LWT_*() functions, thus their signatures is the signature
///		of the LWT API/ABI extended with an extra thr_t pointer argument
///		(doing this last step in the assembly stub is easy a cheap).
///		 The __LWT_*() functions return directly to the API caller, not
///		to the __lwt_*() assembly stub, which just directly jumps into
///		the __LWT_*() functions without a call and return path back to
///		them.  The __LWT_*() functions have a 2nd additional argument,
///		enabled, which is the value of cpu->cpu_enabled prior to setting
///		it to false (this value is passed for debugging purposes).
///
///  When API functions change, they might need to be changed from __lwt_*()
///  functions an into __LWT_*() functions, all functions could be proactively
///  made __lwt_*() functions but that would just add unneeded overhead.
///
///  The __LWT_*() functions must all use api_enter() and api_exit() to
///  enable time slicing by setting cpu->cpu_enabled to true.

error_t __lwt_init(size_t sched_attempt_steps, int rtsigno)
{
	//  TODO: add flags value to choose:
	//	- sane "spin locks" that assert if mutex acquired inside
	//	  spin owning code
	//	- time slicing on/off
	//	- time slice period
	//  The rtsigno signal handler should be SIG_DFL, if it is currently
	//  in use, EINVAL is returned to avoid conflicts if other code using
	//  that signal number.

	return init(sched_attempt_steps, rtsigno);
}

//  __lwt_mtxattr_*() ABI entry points

int __lwt_mtxattr_init(mtxattr_t **mtxattrpp)
{
	return mtxattr_init(mtxattrpp);
}

int __lwt_mtxattr_destroy(mtxattr_t **mtxattrpp)
{
	return mtxattr_destroy(mtxattrpp);
}

int __lwt_mutexattr_settype(mtxattr_t **mtxattrpp, int kind)
{
	return mtxattr_settype(mtxattrpp, kind);
}

int __lwt_mutexattr_gettype(mtxattr_t *mtxattr, int *kind)
{
	return mtxattr_gettype(mtxattr, kind);
}


//  __lwt_mtx_*() ABI entry points

int __LWT_mtx_init(mtx_t **mtxpp, const mtxattr_t *mtxattr,
		   thr_t *thr, bool enabled)
{
	api_enter(API_MTX_INIT, enabled);
	error_t error = mtx_create_with_mtxattr(mtxpp, mtxattr, thr);
	api_exit(API_MTX_INIT);
	return error;
}

int __lwt_mtx_destroy(mtx_t **mtxpp)
{
	return mtx_destroy(mtxpp);
}

int __LWT_mtx_lock(mtx_t *mtx, thr_t *thr, bool enabled)
{
	api_enter(API_MTX_LOCK, enabled);
	error_t error = mtx_lock(mtx, thr);
	api_exit(API_MTX_LOCK);
	return error;
}

int __LWT_mtx_trylock(mtx_t *mtx, thr_t *thr, bool enabled)
{
	api_enter(API_MTX_TRYLOCK, enabled);
	error_t error = mtx_trylock(mtx, thr);
	api_exit(API_MTX_TRYLOCK);
	return error;
}

int __LWT_mtx_unlock(mtx_t *mtx, thr_t *thr, bool enabled)
{
	api_enter(API_MTX_UNLOCK, enabled);
	error_t error = mtx_unlock(mtx, thr);
	api_exit(API_MTX_UNLOCK);
	return error;
}


//  __lwt_cnd_*() ABI entry points

int __LWT_cnd_init(cnd_t **cndpp, const cndattr_t *cndattr,
		   thr_t *thr, bool enabled)
{
	api_enter(API_CND_INIT, enabled);
	error_t error = cnd_create(cndpp, cndattr, thr);
	api_exit(API_CND_INIT);
	return error;
}

int __lwt_cnd_destroy(cnd_t **cndpp)
{
	return cnd_destroy(cndpp);
}

int __LWT_cnd_wait(cnd_t *cnd, mtx_t *mtx, thr_t *thr, bool enabled)
{
	api_enter(API_CND_WAIT, enabled);
	error_t error = cnd_wait(cnd, mtx, thr);
	api_exit(API_CND_WAIT);
	return error;
}

int __LWT_cnd_timedwait(cnd_t *cnd, mtx_t *mtx,
			const struct timespec *abstime,
			thr_t *thr, bool enabled)
{
	api_enter(API_CND_TIMEDWAIT, enabled);
	error_t error = cnd_timedwait(cnd, mtx, thr, abstime);
	api_exit(API_CND_TIMEDWAIT);
	return error;
}

int __LWT_cnd_signal(cnd_t *cnd, mtx_t *mtx, thr_t *thr, bool enabled)
{
	api_enter(API_CND_SIGNAL, enabled);
	error_t error = cnd_signal(cnd, mtx, thr);
	api_exit(API_CND_SIGNAL);
	return error;
}

int __LWT_cnd_broadcast(cnd_t *cnd, mtx_t *mtx, thr_t *thr, bool enabled)
{
	api_enter(API_CND_BROADCAST, enabled);
	error_t error = cnd_broadcast(cnd, mtx, thr);
	api_exit(API_CND_BROADCAST);
	return error;
}


//  __lwt_spin_*() ABI entry points

int __LWT_spin_init(mtx_t **mtxpp, thr_t *thr, bool enabled)
{
	api_enter(API_SPIN_INIT, enabled);
	error_t error = mtx_create(mtxpp, LWT_MTX_FAST, thr);
	api_exit(API_SPIN_INIT);
	return error;
}

int __lwt_spin_destroy(spin_t **spinpp)
{
	mtx_t **mtxpp = (mtx_t **) spinpp;
	return mtx_destroy(mtxpp);
}

int __LWT_spin_lock(mtx_t *mtx, thr_t *thr, bool enabled)
{
	api_enter(API_SPIN_LOCK, enabled);
	error_t error = spin_lock(mtx, thr);
	api_exit(API_SPIN_LOCK);
	return error;
}

int __LWT_spin_trylock(mtx_t *mtx, thr_t *thr, bool enabled)
{
	api_enter(API_SPIN_TRYLOCK, enabled);
	error_t error = spin_trylock(mtx, thr);
	api_exit(API_SPIN_TRYLOCK);
	return error;
}

int __LWT_spin_unlock(mtx_t *mtx, thr_t *thr, bool enabled)
{
	api_enter(API_SPIN_UNLOCK, enabled);
	error_t error = spin_unlock(mtx, thr);
	api_exit(API_SPIN_UNLOCK);
	return error;
}


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

int __lwt_thrattr_setdetachstate(lwt_attr_t *attr, int detachstate)
{
	return thrattr_setdetachstate((thrattr_t *) attr, detachstate);
}

int __lwt_thrattr_getdetachstate(const lwt_attr_t *attr, int *detachstate)
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

int __lwt_thrattr_getschedpolicy(const lwt_attr_t *attr, int *policy)
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

int __LWT_thr_create(lwt_t *thread, const lwt_attr_t *attr,
		     lwt_function_t function, void *arg,
		     thr_t *thr, bool enabled)
{
	api_enter(API_THR_CREATE, enabled);
	unused ureg_t before = counter_get_before();
	error_t error = thr_create(thread, (thrattr_t *) attr,
				   function, arg, thr);
	unused ureg_t after = counter_get_after();
	api_exit(API_THR_CREATE);
	return error;
}

noreturn void __LWT_thr_exit(void *retval, thr_t *thr, bool enabled)
{
	api_enter(API_THR_EXIT, enabled);
	thr_exit(thr, retval);
}

int __LWT_thr_join(lwt_t thread, void **retval, thr_t *thr, bool enabled)
{
	api_enter(API_THR_JOIN, enabled);
	error_t error = thr_join(thr, thread, retval);
	api_exit(API_THR_JOIN);
	return error;
}

int __LWT_thr_cancel(lwt_t thread, thr_t *thr, bool enabled)
{
	api_enter(API_THR_CANCEL, enabled);
	error_t error = thr_cancel(thr, thread);
	api_exit(API_THR_CANCEL);
	return error;
}

int __LWT_thr_setcancelstate(int state, int *oldstate, thr_t *thr, bool enabled)
{
	api_enter(API_THR_SETCANCELSTATE, enabled);
	error_t error = thr_setcancelstate(thr, state, oldstate);
	api_exit(API_THR_SETCANCELSTATE);
	return error;
}

int __LWT_thr_setcanceltype(int type, int *oldtype, thr_t *thr, bool enabled)
{
	api_enter(API_THR_SETCANCELTYPE, enabled);
	error_t error = thr_setcanceltype(thr, type, oldtype);
	api_exit(API_THR_SETCANCELTYPE);
	return error;
}

void __LWT_thr_testcancel(thr_t *thr, bool enabled)
{
	api_enter(API_THR_TESTCANCEL, enabled);
	thr_testcancel(thr);
	api_exit(API_THR_TESTCANCEL);
}

//}
