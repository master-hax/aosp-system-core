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

//  There are bugs in clang-format where it can not align bit fields when the
//  number of bits is an identifier instead of an integer constant.  There are
//  additional bugs in the AlignConsecutiveDeclarations mode where it sometimes
//  misaligns them.  Additionally, clang-format wants to reflow #defines when
//  a continuation line is used that it decides should not be used and there
//  is not way to override that, specific #defines are more readable when in
//  their own line, specifically many of the ones that use BITS_GET() which
//  are in blocks and immediately before the matching BITS_SET() macro use.
//  For these and other reasons, using clang-format significantly reduces
//  readability of the code, and too much time is was spent working around its
//  flaws  with too many sprinklings of clang-format directives to turn it off
//  and back on all over the code.  The result of using clang-format ends up
//  being reduced readability, when it should be the opposite. Thus if is
//  turned off for the whole file.

//  Many of the structures in this file use bitfields within 2 word structures
//  that are updates with double word compare and swap.  The bit fields are
//  implemented as bit masks that use BITS_SET() and BITS_GET(), the equivalent
//  code using C bitfields generated poorer code under both GCC and Clang.
//  The bitfields are shown under a "bits" bitfield union to make debugging
//  easier.

typedef struct hw_s		hw_t;
typedef struct schdom_s		schdom_t;
typedef struct core_s		core_t;
typedef struct thr_s		thr_t;
typedef union thrln_s		thrln_t;

typedef struct __lwt_mtx_s	mtx_t;
typedef struct __lwt_cnd_s	cnd_t;

//  API numbers used for optional statistics and tracing

typedef enum {
	API_MTX_INIT		= 0,
	API_MTX_LOCK		= 1,
	API_MTX_TRYLOCK		= 2,
	API_MTX_UNLOCK		= 3,
	API_CND_INIT		= 4,
	API_CND_WAIT		= 5,
	API_CND_TIMEDWAIT	= 6,
	API_CND_SIGNAL		= 7,
	API_CND_BROADCAST	= 8,
	API_THR_CREATE		= 9,
	API_THR_EXIT		= 10,
	API_THR_JOIN		= 11,
	API_THR_CANCEL		= 12,
	API_THR_SETCANCELSTATE	= 13,
	API_THR_SETCANCELTYPE	= 14,
	API_THR_TESTCANCEL	= 15,
	API_SPIN_INIT		= 16,
	API_SPIN_LOCK		= 17,
	API_SPIN_TRYLOCK	= 18,
	API_SPIN_UNLOCK		= 19,
} api_t;


//  Generic lockless list with support for insertion and removal from
//  the head, the element in the list must have space for a uptr_t and
//  be uptr_t aligned.

typedef struct llelem_s		llelem_t;

struct llelem_s {
	llelem_t		*lll_next;
};

#define	LLLIST_GEN_SHIFT	0
#define	LLLIST_GEN_BITS		32

#define	LLLIST_COUNT_SHIFT	(LLLIST_GEN_SHIFT + LLLIST_GEN_BITS)
#define	LLLIST_COUNT_BITS	32

typedef union lllist_s {
	struct {
		llelem_t	*lll_first;
		ureg_t		 lll_count_gen;
	};
#	ifdef LWT_BITS
	    struct {
		ureg_t		 lll_first_ureg : 64;
		ureg_t		 lll_gen        : LLLIST_GEN_BITS;
		ureg_t		 lll_count      : LLLIST_COUNT_BITS;
	    } bits;
#	endif
	uregx2_t		 uregx2;
} aligned_uregx2 lllist_t;

#define	LLLIST_GEN(lllist)						\
	BITS_GET(LLLIST_GEN, (lllist).lll_count_gen)
#define	LLLIST_COUNT(lllist)						\
	BITS_GET(LLLIST_COUNT, (lllist).lll_count_gen)


//  Raw cache line.

typedef struct {
	ureg_t	cl_uregs[CACHE_LINE_SIZE / sizeof(ureg_t)];
} aligned_cache_line cacheline_t;


//  A contiguous arena of memory which is permanently locked to ensure that
//  accesses to it do not cause page faults.

typedef struct {
	void		*mem;
	error_t		 error;
} alloc_value_t;

typedef struct {
	lllist_t	 arena_lllist;
	mtx_t		*arena_mtx;
	size_t		 arena_elemsize;
	uptr_t		 arena_next;
	uptr_t		 arena_end;
	uptr_t		 arena_start;
	uptr_t		 arena_reservedend;
} arena_t;


//  A stk_t is an allocated thread stack and its guard area, the stk_t memory
//  lives at the very bottom of the stack memory, from its stk_stacksize the
//  address of the start of the memory for the stack can be computed, and from
//  that and stk_guardsize the address of the start of the guard memory area
//  can be computed.

//  Stacks, when released are cached in case a stack with the same sizes is
//  needed again.  Caching stacks reduces the cost of a continuous stream of
//  thread creations and destructions, and removes from the application to have
//  to implement thread caching to work around thread creation and destruction
//  performance issues.  To increase CPU cache locality, the stacks are cached
//  on a per-cpu basis, and are allocated in a a LIFO order, the most recently
//  freed stack has the highest chances of having some of its memory still in
//  the CPU cache.

//  When the stack is free in its per-CPU stack cache, the pointer immediately
//  before the stk_t structure is used to link the stack into its cache.  Note
//  that while the stack is in use, the fields of stk_t are preserved and are
//  not clobbered by the values stored on that run-time call-chain stack. The
//  pointer used for linkage is clobbered because its meaningless then.

struct stk_s {
	size_t		 stk_stacksize;
	size_t		 stk_guardsize;
};

typedef union stkbkt_atom_u {
	struct {
		size_t	 stkbkt_stacksize;
		size_t	 stkbkt_guardsize;
	};
	uregx2_t	 uregx2;
} aligned_uregx2 stkbkta_t;

typedef struct {
	stkbkta_t	 stkbkta;
	lllist_t	 stkbkt_lllist;
} aligned_uregx2 stkbkt_t;

#define	STKCACHE_BUCKETS	6

typedef struct {
	stkbkt_t	stkcache_buckets[STKCACHE_BUCKETS];
} stkcache_t;


//  A stable mtxid_t used in the implementation of thread cancelation,
//  condition wait naked signaling, and condition wait timeouts.  A mtxid_t
//  index starts with value 1, value 0 is reserved to implement MTXID_NULL.

//  MTXID_DUMMY is a dummy thread index used to make thr_block_forever_mtx,
//  a mutex, be in a state that is always locked without having to attribute
//  its lock count to a real thread.  The first thr_t corresponds to this
//  thread index, see __lwt_init().

#define	MTXID_NULL	0uL
#define	MTXID_DUMMY	1uL

typedef union {
	ureg_t	mtxid_all;
	struct {
		u32_t	mtxid_reuse;
		u32_t	mtxid_index;
	};
} mtxid_t;


//  A stable thrid_t used in the implementation of thread cancelation,
//  condition wait naked signaling, and condition wait timeouts.  A thrid_t
//  index starts with value 1, value 0 is reserved to implement THRID_NULL.

//  SCHEDQ_EMPTY() depends on THRID_NULL being zero, don't change.

#define	THRID_NULL		0uL

#if (UREG_BITS == 64)
#define	THRIX_BITS		15
#endif

#if (UREG_BITS == 32)
#define	THRIX_BITS		7
#endif

#define	THRIX_MASK		((1uL << THRIX_BITS) - 1)
#define	THRIX_RESERVED_COUNT	256
#define	THRIX_MAX		((1uL << THRIX_BITS) - THRIX_RESERVED_COUNT)

#define	THRIX_RESERVED_THRLN	THRIX_MASK
#define	THRIX_INVALID_1		(THRIX_MASK - 1)
#define	THRIX_INVALID_2		(THRIX_MASK - 2)

#define	THRID_INDEX_SHIFT	0
#define	THRID_INDEX_BITS	THRIX_BITS

#define	THRID_REUSE_SHIFT	(THRID_INDEX_SHIFT + THRID_INDEX_BITS)
#define	THRID_REUSE_BITS	(UREG_BITS - THRID_INDEX_BITS)

typedef union {
	ureg_t	thrid_all;
#	ifdef LWT_BITS
	    struct {
		ureg_t	thrid_index : THRID_INDEX_BITS;
		ureg_t	thrid_reuse : THRID_REUSE_BITS;
	    };
#	endif
} thrid_t;

#define	THRID_INDEX(thrid)						\
	BITS_GET(THRID_INDEX, (thrid).thrid_all)
#define	THRID_INDEX_SET(thrid, index)					\
	BITS_SET(THRID_INDEX, (thrid).thrid_all, index)

#define	THRID_REUSE(thrid)						\
	BITS_GET(THRID_REUSE, (thrid).thrid_all)
#define	THRID_REUSE_SET(thrid, reuse)					\
	BITS_SET(THRID_REUSE, (thrid).thrid_all, reuse)


//  Scheduler queue.

#define	SCHEDQ_STATE_SHIFT	0
#define	SCHEDQ_STATE_BITS	4

#define	SCHEDQ_INS_SHIFT	(SCHEDQ_STATE_SHIFT + SCHEDQ_STATE_BITS)
#define	SCHEDQ_INS_BITS		THRIX_BITS

#define	SCHEDQ_INSPRV_SHIFT	(SCHEDQ_INS_SHIFT + SCHEDQ_INS_BITS)
#define	SCHEDQ_INSPRV_BITS	THRIX_BITS

#define	SCHEDQ_REMNXT_SHIFT	(SCHEDQ_INSPRV_SHIFT + SCHEDQ_INSPRV_BITS)
#define	SCHEDQ_REMNXT_BITS	THRIX_BITS

#define	SCHEDQ_REM_SHIFT	(SCHEDQ_REMNXT_SHIFT + SCHEDQ_REMNXT_BITS)
#define	SCHEDQ_REM_BITS		THRIX_BITS

static_assert(UREG_BITS == SCHEDQ_STATE_BITS +
			   SCHEDQ_INS_BITS + SCHEDQ_INSPRV_BITS +
			   SCHEDQ_REMNXT_BITS + SCHEDQ_REM_BITS,
	      "schedq_t sq_rem_remnext_insprv_ins_state");

#define	SCHEDQ_GEN_BITS		(THRIX_BITS + 1)

#define	SCHEDQ_RCNT_SHIFT	0
#define	SCHEDQ_RCNT_BITS	SCHEDQ_GEN_BITS

#define	SCHEDQ_RSER_SHIFT	(SCHEDQ_RCNT_SHIFT + SCHEDQ_RCNT_BITS)
#define	SCHEDQ_RSER_BITS	SCHEDQ_GEN_BITS

#define	SCHEDQ_ISER_SHIFT	(SCHEDQ_RSER_SHIFT + SCHEDQ_RSER_BITS)
#define	SCHEDQ_ISER_BITS	SCHEDQ_GEN_BITS

#define	SCHEDQ_ICNT_SHIFT	(SCHEDQ_ISER_SHIFT + SCHEDQ_ISER_BITS)
#define	SCHEDQ_ICNT_BITS	SCHEDQ_GEN_BITS

static_assert(UREG_BITS == SCHEDQ_RCNT_BITS + SCHEDQ_RSER_BITS + 
			   SCHEDQ_ISER_BITS + SCHEDQ_ICNT_BITS,
	      "schedq sq_rcnt_rser_iser_icnt");

#define	SCHEDQ_INVALID_1						\
	((schedq_t) {.sq_rem_remnxt_insprv_ins_state = 0b1111uL,	\
		     .sq_rcnt_rser_iser_icnt = 0uL})

#define	SCHEDQ_INVALID_2						\
	((schedq_t) {.sq_rem_remnxt_insprv_ins_state = ~0b1111uL,	\
		     .sq_rcnt_rser_iser_icnt = 0uL})

typedef union {
	struct {
		ureg_t	 sq_rem_remnxt_insprv_ins_state;
		ureg_t	 sq_rcnt_rser_iser_icnt;
	};
#	ifdef LWT_BITS
	    struct {
		ureg_t	 sq_state  : SCHEDQ_STATE_BITS;
		ureg_t	 sq_ins    : THRIX_BITS;
		ureg_t	 sq_insprv : THRIX_BITS;
		ureg_t	 sq_remnxt : THRIX_BITS;
		ureg_t	 sq_rem    : THRIX_BITS;
		ureg_t	 sq_rcnt   : SCHEDQ_GEN_BITS;
		ureg_t	 sq_rser   : SCHEDQ_GEN_BITS;
		ureg_t	 sq_iser   : SCHEDQ_GEN_BITS;
		ureg_t	 sq_icnt   : SCHEDQ_GEN_BITS;
	    } bits;
#	endif
	uregx2_t	 uregx2;
} aligned_uregx2 schedq_t;

//  This separate type:
//	sqcl_t
//  is needed because schedq_t are passed by value as two registers in the
//  calling convention, alignning the schedq_t type to a cache line would make
//  that type larger and values of that type could not be passed in registers.
//  Thus this separate type is used when isolating the schedq_t entries in
//  arrays where each element is in its own cache line.  To take advantage of
//  the extra space in the cache line, and allow for each scheduling priority
//  to have two scheduling queues, one for voluntary preemption, and another
//  for time slicing, these two  related schedq_t are placed in the sqcl_t.
//  There is additional pad space at least for two additional queues, assuming
//  the smallest common cache line size of 64 bytes, this would allow for a
//  hierarchy of time sliced queues where the more frequently sliced threads
//  could have an inherent internal lower priority than ones not time slices
//  as often.

typedef struct {
	schedq_t	 sqcl_schedq;		// voluntarily preempted threads
	schedq_t	 sqcl_schedqts;		// time sliced threads
} aligned_cache_line sqcl_t;

#define	SQ_PRIO_MAX	 (LWT_PRIO_HIGH + 1)

//  All SMP hardware is organized hierarchically, because of how it is built
//  from building blocks at various levels.  See the much larger comment about
//  hardware organization below.  Scheduling domain queues exist at all levels
//  of the hardware to ensure dynamic schduling affinity as much as possible
//  while also ensuring good hardware utilization.

//  A schdom_t is a scheduling domain, at the lowest level of the hardware
//  representation, at the core_t level, the schdom_t refers to the underlying
//  core_t which has one or more cpu_t associated with it (e.g. a hardware
//  multi-threaded core).  At a higher level, a schdom_t covers scheduling to
//  hardware entities that share hardware resources, for example caches, memory
//  ports, etc.

//  The schdom_sqcls field points to an array of SQ_PRIO_MAX scheduling queues,
//  one per priority.  When a sqcl in a schdom becomes non-empty, its index
//  in the array is used to set its corresponding bit in schdom_mask to one
//  to indicate that the sqcl might have threads queued in it (this is used to
//  reduce the scanning of the sqcl queues within the array to the ones that
//  have ever been non-empty.

struct schdom_s {
	sqcl_t		*schdom_sqcls;	  // points to array of SQ_PRIO_MAX
	ureg_t		 schdom_mask;
};

#define	SCHEDQ_STATE(sq)						\
	BITS_GET(SCHEDQ_STATE, (sq).sq_rem_remnxt_insprv_ins_state)
#define	SCHEDQ_STATE_SET(sq, state)					\
	BITS_SET(SCHEDQ_STATE, (sq).sq_rem_remnxt_insprv_ins_state, state)

#define	SCHEDQ_INS(sq)							\
	BITS_GET(SCHEDQ_INS, (sq).sq_rem_remnxt_insprv_ins_state)
#define	SCHEDQ_INS_SET(sq, thridix)					\
	BITS_SET(SCHEDQ_INS, (sq).sq_rem_remnxt_insprv_ins_state, thridix)

#define	SCHEDQ_INSPRV(sq)						\
	BITS_GET(SCHEDQ_INSPRV, (sq).sq_rem_remnxt_insprv_ins_state)
#define	SCHEDQ_INSPRV_SET(sq, thridix)					\
	BITS_SET(SCHEDQ_INSPRV, (sq).sq_rem_remnxt_insprv_ins_state, thridix)

#define	SCHEDQ_REMNXT(sq)						\
	BITS_GET(SCHEDQ_REMNXT, (sq).sq_rem_remnxt_insprv_ins_state)
#define	SCHEDQ_REMNXT_SET(sq, thridix)					\
	BITS_SET(SCHEDQ_REMNXT, (sq).sq_rem_remnxt_insprv_ins_state, thridix)

#define	SCHEDQ_REM(sq)							\
	BITS_GET(SCHEDQ_REM, (sq).sq_rem_remnxt_insprv_ins_state)
#define	SCHEDQ_REM_SET(sq, thridix)					\
	BITS_SET(SCHEDQ_REM, (sq).sq_rem_remnxt_insprv_ins_state, thridix)

#define	SCHEDQ_ICNT(sq)							\
	BITS_GET(SCHEDQ_ICNT, (sq).sq_rcnt_rser_iser_icnt)
#define	SCHEDQ_ICNT_SET(sq, rcnt)					\
	BITS_SET(SCHEDQ_ICNT, (sq).sq_rcnt_rser_iser_icnt, (ureg_t)(rcnt))
#define	SCHEDQ_ICNT_INC(sq)						\
	((sq).sq_rcnt_rser_iser_icnt += 1uL << SCHEDQ_ICNT_SHIFT)
static_assert(SCHEDQ_ICNT_SHIFT + SCHEDQ_ICNT_BITS == UREG_BITS,
	      "SCHEDQ_ICNT_INC() requires SCHEDQ_ICNT to be the highest field");

#define	SCHEDQ_ISER(sq)							\
	BITS_GET(SCHEDQ_ISER, (sq).sq_rcnt_rser_iser_icnt)
#define	SCHEDQ_ISER_SET(sq, rcnt)					\
	BITS_SET(SCHEDQ_ISER, (sq).sq_rcnt_rser_iser_icnt, (ureg_t)(rcnt))
#define	SCHEDQ_ISER_DEC(sq)						\
	SCHEDQ_ISER_SET(sq, SCHEDQ_ISER(sq) - 1)

#define	SCHEDQ_RSER(sq)							\
	BITS_GET(SCHEDQ_RSER, (sq).sq_rcnt_rser_iser_icnt)
#define	SCHEDQ_RSER_SET(sq, rcnt)					\
	BITS_SET(SCHEDQ_RSER, (sq).sq_rcnt_rser_iser_icnt, (ureg_t)(rcnt))
#define	SCHEDQ_RSER_INC(sq)						\
	SCHEDQ_RSER_SET(sq, SCHEDQ_RSER(sq) + 1)

#define	SCHEDQ_RCNT(sq)							\
	BITS_GET(SCHEDQ_RCNT, (sq).sq_rcnt_rser_iser_icnt)
#define	SCHEDQ_RCNT_SET(sq, rcnt)					\
	BITS_SET(SCHEDQ_RCNT, (sq).sq_rcnt_rser_iser_icnt, (ureg_t)(rcnt))
#define	SCHEDQ_RCNT_INC(sq)						\
	SCHEDQ_RCNT_SET(sq, SCHEDQ_RCNT(sq) + 1)
#define	SCHEDQ_RCNT_DEC(sq)						\
	SCHEDQ_RCNT_SET(sq, SCHEDQ_RCNT(sq) - 1)


//  Thread links.

#define	THRLN_NEXT_BIT0_SHIFT	0
#define	THRLN_NEXT_BIT0_BITS	1

#define	THRLN_NEXT_TIX_SHIFT	(THRLN_NEXT_BIT0_SHIFT + THRLN_NEXT_BIT0_BITS)
#define	THRLN_NEXT_TIX_BITS	THRIX_BITS

#define	THRLN_NEXT_RSER_SHIFT	(THRLN_NEXT_TIX_SHIFT + THRLN_NEXT_TIX_BITS)
#define	THRLN_NEXT_RSER_BITS	SCHEDQ_GEN_BITS

#define	THRLN_NEXT_SQIX_SHIFT	(THRLN_NEXT_RSER_SHIFT + THRLN_NEXT_RSER_BITS)
#define	THRLN_NEXT_SQIX_BITS	16

#define	THRLN_NEXT_PAD_SHIFT	(THRLN_NEXT_SQIX_SHIFT + THRLN_NEXT_SQIX_BITS)
#define	THRLN_NEXT_PAD_BITS	12

#define	THRLN_NEXT_HIGH_SHIFT	(THRLN_NEXT_PAD_SHIFT + THRLN_NEXT_PAD_BITS)
#define	THRLN_NEXT_HIGH_BITS	4

static_assert(UREG_BITS == THRLN_NEXT_BIT0_BITS + THRLN_NEXT_TIX_BITS +
			   THRLN_NEXT_RSER_BITS + THRLN_NEXT_SQIX_BITS +
			   THRLN_NEXT_PAD_BITS  + THRLN_NEXT_HIGH_BITS,
	      "thrln_t next bitfields wrong");

#define	THRLN_PREV_BIT0_SHIFT	0
#define	THRLN_PREV_BIT0_BITS	1

#define	THRLN_PREV_TIX_SHIFT	(THRLN_PREV_BIT0_SHIFT + THRLN_PREV_BIT0_BITS)
#define	THRLN_PREV_TIX_BITS	THRIX_BITS

#define	THRLN_PREV_ISER_SHIFT	(THRLN_PREV_TIX_SHIFT + THRLN_PREV_TIX_BITS)
#define	THRLN_PREV_ISER_BITS	SCHEDQ_GEN_BITS

#define	THRLN_PREV_SQIX_SHIFT	(THRLN_PREV_ISER_SHIFT + THRLN_PREV_ISER_BITS)
#define	THRLN_PREV_SQIX_BITS	16

#define	THRLN_PREV_PAD_SHIFT	(THRLN_PREV_SQIX_SHIFT + THRLN_PREV_SQIX_BITS)
#define	THRLN_PREV_PAD_BITS	12

#define	THRLN_PREV_HIGH_SHIFT	(THRLN_PREV_PAD_SHIFT + THRLN_PREV_PAD_BITS)
#define	THRLN_PREV_HIGH_BITS	4

#define	THRLN_HIGH_VALUE	0b1010uL

static_assert(UREG_BITS == THRLN_PREV_BIT0_BITS + THRLN_PREV_TIX_BITS +
			   THRLN_PREV_ISER_BITS + THRLN_PREV_SQIX_BITS +
			   THRLN_PREV_PAD_BITS  + THRLN_PREV_HIGH_BITS,
	      "thrln_t prev bitfields wrong");

#define	THRLN_INVALID_1							\
	((thrln_t) {.ln_next_ureg =					\
			(1uL << THRLN_NEXT_BIT0_SHIFT) |		\
			(THRIX_INVALID_1 << THRLN_NEXT_TIX_SHIFT) |	\
			(THRLN_HIGH_VALUE << THRLN_NEXT_HIGH_SHIFT),	\
		    .ln_prev_ureg =					\
			(1uL << THRLN_PREV_BIT0_SHIFT) |		\
			(THRIX_INVALID_1 << THRLN_PREV_TIX_SHIFT) |	\
			(THRLN_HIGH_VALUE << THRLN_PREV_HIGH_SHIFT) })

#define	THRLN_INVALID_2							\
	((thrln_t) {.ln_next_ureg =					\
			(1uL << THRLN_NEXT_BIT0_SHIFT) |		\
			(THRIX_INVALID_2 << THRLN_NEXT_TIX_SHIFT) |	\
			(THRLN_HIGH_VALUE << THRLN_NEXT_HIGH_SHIFT),	\
		    .ln_prev_ureg =					\
			(1uL << THRLN_PREV_BIT0_SHIFT) |		\
			(THRIX_INVALID_2 << THRLN_PREV_TIX_SHIFT) |	\
			(THRLN_HIGH_VALUE << THRLN_PREV_HIGH_SHIFT) })

union thrln_s {
	struct {
		thr_t	*ln_next;
		thr_t	*ln_prev;
	};
	struct {
		ureg_t	 ln_next_ureg;
		ureg_t	 ln_prev_ureg;
	};
#	ifdef LWT_BITS
	    struct {
		ureg_t	 ln_next_bit0 : THRLN_NEXT_BIT0_BITS;
		ureg_t	 ln_next_tix  : THRIX_BITS;
		ureg_t	 ln_next_rser : SCHEDQ_GEN_BITS;
		ureg_t	 ln_next_sqix : THRLN_NEXT_SQIX_BITS;
		ureg_t	 ln_next_pad  : THRLN_NEXT_PAD_BITS;
		ureg_t	 ln_next_high : THRLN_NEXT_HIGH_BITS;

		ureg_t	 ln_prev_bit0 : THRLN_PREV_BIT0_BITS;
		ureg_t	 ln_prev_tix  : THRIX_BITS;
		ureg_t	 ln_prev_iser : SCHEDQ_GEN_BITS;
		ureg_t	 ln_prev_sqix : THRLN_PREV_SQIX_BITS;
		ureg_t	 ln_prev_pad  : THRLN_PREV_PAD_BITS;
		ureg_t	 ln_prev_high : THRLN_PREV_HIGH_BITS;
	    } bits;
#	endif
	uregx2_t	 uregx2;
} aligned_uregx2;

#define	THRLN_NEXT_INIT_NULL(thrln, sqix, rser)				\
	THRLN_NEXT_INIT(thrln, sqix, rser, THRID_NULL)

#define	THRLN_NEXT_INIT(thrln, sqix, rser, tix)				\
	((thrln).ln_next_ureg =						\
		(1uL << THRLN_NEXT_BIT0_SHIFT) |			\
		((tix) << THRLN_NEXT_TIX_SHIFT) |			\
		((rser) << THRLN_NEXT_RSER_SHIFT) |			\
		((sqix) << THRLN_NEXT_SQIX_SHIFT) |			\
		(THRLN_HIGH_VALUE << THRLN_NEXT_HIGH_SHIFT))

#define	THRLN_NEXT_INIT_INS(thrln, sqix)				\
	THRLN_NEXT_INIT(thrln, sqix, 0uL, THRIX_RESERVED_THRLN)

#define	THRLN_PREV_INIT_INS(thrln, sqix)				\
	THRLN_PREV_INIT(thrln, sqix, 0uL, THRIX_RESERVED_THRLN)

#define	THRLN_PREV_INIT_NULL(thrln, sqix, icnt)				\
	THRLN_PREV_INIT(thrln, sqix, icnt, THRID_NULL)

#define	THRLN_PREV_INIT(thrln, sqix, icnt, tix)				\
	((thrln).ln_prev_ureg =						\
		(1uL << THRLN_PREV_BIT0_SHIFT) |			\
		((tix) << THRLN_PREV_TIX_SHIFT) |			\
		((icnt) << THRLN_PREV_ISER_SHIFT) |			\
		((sqix) << THRLN_PREV_SQIX_SHIFT) |			\
		(THRLN_HIGH_VALUE << THRLN_PREV_HIGH_SHIFT))

#define	THRLN_NEXT_BIT0(thrln)						\
	BITS_GET(THRLN_NEXT_BIT0, (thrln).ln_next_ureg)
#define	THRLN_NEXT_BIT0_SET(thrln, bit)					\
	BITS_SET(THRLN_NEXT_BIT0, (thrln).ln_next_ureg, bit)

#define	THRLN_NEXT_TIX(thrln)						\
	BITS_GET(THRLN_NEXT_TIX, (thrln).ln_next_ureg)
#define	THRLN_NEXT_TIX_SET(thrln, thridix)				\
	BITS_SET(THRLN_NEXT_TIX, (thrln).ln_next_ureg, thridix)

#define	THRLN_NEXT_RSER(thrln)						\
	BITS_GET(THRLN_NEXT_RSER, (thrln).ln_next_ureg)
#define	THRLN_NEXT_RSER_SET(thrln, rser)				\
	BITS_SET(THRLN_NEXT_RSER, (thrln).ln_next_ureg, rser)

#define	THRLN_NEXT_SQIX(thrln)						\
	BITS_GET(THRLN_NEXT_SQIX, (thrln).ln_next_ureg)
#define	THRLN_NEXT_SQIX_SET(thrln, sqix)				\
	BITS_SET(THRLN_NEXT_SQIX, (thrln).ln_next_ureg, sqix)

#define	THRLN_NEXT_HIGH(thrln)						\
	BITS_GET(THRLN_NEXT_HIGH, (thrln).ln_next_ureg)
#define	THRLN_NEXT_HIGH_SET(thrln, high)				\
	BITS_SET(THRLN_NEXT_HIGH, (thrln).ln_next_ureg, high)

#define	THRLN_PREV_BIT0(thrln)						\
	BITS_GET(THRLN_PREV_BIT0, (thrln).ln_prev_ureg)
#define	THRLN_PREV_BIT0_SET(thrln, bit)					\
	BITS_SET(THRLN_PREV_BIT0, (thrln).ln_prev_ureg, bit)

#define	THRLN_PREV_TIX(thrln)						\
	BITS_GET(THRLN_PREV_TIX, (thrln).ln_prev_ureg)
#define	THRLN_PREV_TIX_SET(thrln, thridix)				\
	BITS_SET(THRLN_PREV_TIX, (thrln).ln_prev_ureg, thridix)

#define	THRLN_PREV_ISER(thrln)						\
	BITS_GET(THRLN_PREV_ISER, (thrln).ln_prev_ureg)
#define	THRLN_PREV_ISER_SET(thrln, rser)				\
	BITS_SET(THRLN_PREV_ISER, (thrln).ln_prev_ureg, rser)

#define	THRLN_PREV_SQIX(thrln)						\
	BITS_GET(THRLN_PREV_SQIX, (thrln).ln_prev_ureg)
#define	THRLN_PREV_SQIX_SET(thrln, sqix)				\
	BITS_SET(THRLN_PREV_SQIX, (thrln).ln_prev_ureg, sqix)

#define	THRLN_PREV_HIGH(thrln)						\
	BITS_GET(THRLN_PREV_HIGH, (thrln).ln_prev_ureg)
#define	THRLN_PREV_HIGH_SET(thrln, high)				\
	BITS_SET(THRLN_PREV_HIGH, (thrln).ln_prev_ureg, high)


//  Per cpu data, cpu_t, corresponds to each hardware thread supported by the
//  hardware.  For example, a multi-threaded core that supports 8 hardware
//  threads would have 8 cpu_t structures.  There is a per-core data structure,
//  core_t, which corresponds to each physical hardware core, whether it is
//  single threaded or multi threaded.  If the cores are single threaded, then
//  the correspondence of cpu_t to core_t are one to one, otherwise there are
//  multiple cpu_t per core_t.

//  A processor hardware chip contains one or more cores, usually organized
//  in multicore tightly coupled groups, that share hardware resources, for
//  example a multicore group might have a shared cache (e.g. an L3 cache) or
//  might have a memory interface where the memory attached to the multicore
//  group can be accessed faster from cores in that grop than the memory
//  attached to other multicore groups (similar to a NUMA multiprocessor
//  organization).

//  A mcore_t structure represents a multicore group.  A system with two
//  multicore groups, one with high performance cores and another with power
//  efficient cores is represented as having two mcore_t structures.  If
//  the multicore groups can not operate concurrently (because of hardware
//  reasons, for example if their caches not being coherent) and the workload
//  is transparently switched between the multicore groups only other under
//  careful coordination (by the kernel or some other lower level software), 
//  then they are logically considered one multicore group and this user mode
//  scheduler is unware of them separately.

//  A hardware chip contains one or more multicore groups, and is represented
//  by the chip_t structure.  When multiple chips are mounted on a shared
//  substrate in a single hardware modulo that allows faster communication
//  between them, those multiple chips are represented by a mcm_t structure,
//  such multi-chip modulo (MCM) structures are found in AMD processors that
//  use chiplet organizations or in IBM POWER systems that use DCM (dual-chip
//  module).

//  On the largest systems, rack mountable units contain multiple MCMs and
//  the memory attached to them, multiple such units are attached to each other
//  through cross-unit cables or a backplane, to form a complete system.  These
//  are represented by hwunit_t and hwsys_t respectively.

//  The relationship between these structures are:
//      cpu_t      N:1   core_t
//      core_t     N:1   mcore_t
//      mcore_t    N:1   chip_t
//      chip_t     N:1   mcm_t
//      mcm_t      N:1   hwunit_t
//      hwunit_t   N:1   hwsys_t

//  System wide scheduling queues are held in the hwsys_t structure.  By
//  default, new threads are queued into the hwsys_t scheduling queues,
//  eventually a hwproc_t is chosen for it, and a core_t within it, and unless
//  decided dynamically otherwise, the thread remains bound to that core_t
//  to aid in its performance with respect to hardware resources (TLB, branch
//  predictors, caches, and memory).

//  A thread can be bound to a specific core_t, mcore_t, chip_t, mcm_t, or a
//  hwunit_t through a cpuset set specified to include only the underlying
//  required hardware.  Note that choosing specific hardware threads to run
//  on a cpu_t and others on another cpu_t on the same core_t is a way of
//  assigning resources within a core between threads, such an assignement is
//  equivalent to dividing the resources of the core_t between threads in fixed
//  ratios, but mandating that exact cpus be used is non-optimal because to
//  mandate the ratios as a hard choice to ensure resource dedication also
//  ensures resource non-use when they are available to be used, thus dedicated
//  scheduling queues at the cpu_t level are a mistake.  Additionally, the
//  interference between hardware threads with each other by affecting their
//  shared L1 (and possibly their L2 cache if that is per-core) doesn't allow
//  for good performance isolation anyway.

//  The only reason that a thread might benefit from running on the same cpu_t
//  that it most recently ran on (as opposed to running on any cpu_t within the
//  the core_t that contains that most recently ran on cpu_t) is if some part
//  of the thread's context is still stored in the cpu_t, for example in a
//  system with lazy floating point, SIMD, vector, hardware switching having
//  the thread run on that cpu_t would be beneficial.  The complexity of
//  implementing lazy switching, particularly lazy saving, of these resources,
//  multi-CPU schedulers usually don't use such an approach.  For a user mode
//  thread scheduler the complexities would be even larger, thus there are no
//  reasons to support scheduling queues at cpu_t level.

//  Many of these structures are meaningless when their relationship to others
//  are 1:1, a system might not have multithreaded cores (i.e. each core_t has
//  a single cpu_t), each chip_t might just have a single mcore_t, each mcm_t
//  might just have a single chip_t, there might just be a single mcm_t per
//  hwunit_t, and the whole system might just have a single hwsys_t.

//  Instead of each lower level hardware entity pointing to the entity that
//  contains it in the hardware hierarchy outlined above, and having fixed
//  types for each, when many of those will be 1:1 having fixed types just
//  adds complexity.

//  An example system with two mcore_t, one with 4 high performance cores, and
//  another with 2 power efficient cores, none of them multi-threaded, and no
//  additional hardware structures would be represented by this tree of hw_t
//  structures, their hw_name would be set to the names shown.  The arrows
//  are the hw_parent field, the root of the tree doesn't have a parent so its
//  hw_parent is set to NULL (shown as =-- )
//
//  =-- hwsys0
//       ^
//       |
//       +-- mcore0
//       |    ^
//       |    |
//       |    +-- core0 <-- cpu0
//       |    +-- core1 <-- cpu1
//       |    +-- core2 <-- cpu2
//       |    +-- core3 <-- cpu3
//       |
//       +-- mcore1
//            ^
//            |
//            +-- core4 <-- cpu4
//            +-- core5 <-- cpu5
//
//  A single-threaded, single core system would be:
//
//  =-- core0 <-- cpu0

struct hw_s {
	schdom_t	 hw_schdom;
	hw_t		*hw_parent;
	union {
	    struct {			//  When the hw_t is a core_t
		cpu_t	*hw_first_cpu;
		cpu_t	*hw_last_cpu;
	    };
	    struct {			//  When the hw_t is not a core_t
		hw_t	*hw_first_child;
		hw_t	*hw_last_child;
	    };
	};
	stkcache_t	 hw_stkcache;
	char		*hw_name;
} aligned_cache_line;

struct core_s {
	ureg_t		 core_ncpus_idled;
	hw_t		*core_hw;
	kcore_t		*core_kcore;
};

struct cpu_s {
	thr_t		*cpu_running_thr;
	core_t		*cpu_core;
	char		*cpu_name;
	kcpu_t		*cpu_kcpu;
	ktimer_t	*cpu_ktimer;
	ureg_t		 cpu_ktimer_calls;
	int		 cpu_hwix;
	volatile bool	 cpu_enabled;
	volatile bool	 cpu_timerticked;
	bool		 cpu_pad[2];
	cacheline_t	*cpu_trampoline; // Must be immediately before cpu_ctx
	ctx_t		 cpu_ctx;	 // Must be immediately after trampoline
} aligned_cache_line;

static_assert((sizeof(cpu_t) & (CACHE_LINE_SIZE - 1)) == 0, "cpu_t wrong size");

//  To avoid more use of lwt_genassym.c (because of Android build integration)
//  ctx_load_rest: in lwt_arch.S assumes that cpu_trampoline is immediately
//  before cpu_ctx.

static_assert(offsetof(cpu_t, cpu_trampoline) + sizeof(opcode_t *) ==
	      offsetof(cpu_t, cpu_ctx), "cpu_trampoline is not before cpu_ctx");


//  Thread attribute, the user of this library allocates a lwt_attr_t, which
//  has room for growth and to contain this structure. If the needs for memory
//  increase past the reserved space, then this structure can be split into
//  two a base area and an overflow area allocated dynamically.  To avoid this
//  library depending on malloc()/free() or having another internal arena for
//  for these, this is a good enough design balance.  Most applications will
//  have one, or at most a few, of these structures, from which all their
//  threads be created.

typedef struct __lwt_thrattr_s {
	unsigned		 thrattr_initialized  : 1;
	lwt_thr_detach_t	 thrattr_detach       : 1;
	lwt_thr_scope_t		 thrattr_scope        : 1;
	lwt_thr_inheritsched_t	 thrattr_inheritsched : 1;
	lwt_thr_schedpolicy_t	 thrattr_schedpolicy  : 2;
	u32_t			 pad		      : 26;
	int			 thrattr_priority     : 32;
	void			*thrattr_stackaddr;
	size_t			 thrattr_stacksize;
	size_t			 thrattr_guardsize;
} thrattr_t;

static_assert(sizeof(thrattr_t) <= sizeof(lwt_attr_t),
	      "thrattr_t size is wrong");

//  XXX below needs to be reviewed and adjusted to work for 32 bits

#define	THRA_HOLD_SHIFT		0
#define	THRA_HOLD_BITS		16

#define	THRA_STATE_SHIFT	(THRA_HOLD_SHIFT + THRA_HOLD_BITS)
#define	THRA_STATE_BITS		3

#define	THRA_CANCEL_SHIFT	(THRA_STATE_SHIFT + THRA_STATE_BITS)
#define	THRA_CANCEL_BITS	1

#define	THRA_WAITTIMEDOUT_SHIFT	(THRA_CANCEL_SHIFT + THRA_CANCEL_BITS)
#define	THRA_WAITTIMEDOUT_BITS	1

#define	THRA_PAD_SHIFT		(THRA_WAITTIMEDOUT_SHIFT+THRA_WAITTIMEDOUT_BITS)
#define	THRA_PAD_BITS		28

#define	THRA_LLASYNCNEXT_SHIFT	(THRA_PAD_SHIFT + THRA_PAD_BITS)
#define	THRA_LLASYNCNEXT_BITS	THRIX_BITS

static_assert(UREG_BITS == THRA_HOLD_BITS + THRA_STATE_BITS +
			   THRA_CANCEL_BITS + THRA_WAITTIMEDOUT_BITS +
			   THRA_PAD_BITS + THRA_LLASYNCNEXT_BITS,
	      "thr_atom_t thra_low bits wrong");

#define	THRA_INDEX_SHIFT	0
#define	THRA_INDEX_BITS		THRIX_BITS

#define	THRA_REUSE_SHIFT	(THRA_INDEX_SHIFT + THRA_INDEX_BITS)
#define	THRA_REUSE_BITS		(UREG_BITS - THRA_INDEX_BITS)

typedef union {
	struct {
		ureg_t	 thra_other;
		ureg_t	 thra_reuse_index;
	};
	struct {
		ureg_t	 thra_low;
		thrid_t	 thra_thrid;
	};
#	ifdef LWT_BITS
	    struct {
		ureg_t	 thra_hold         : THRA_HOLD_BITS;
		ureg_t	 thra_state        : THRA_STATE_BITS;
		ureg_t	 thra_cancel       : THRA_CANCEL_BITS;
		ureg_t	 thra_waittimedout : THRA_WAITTIMEDOUT_BITS;
		ureg_t	 thra_pad          : THRA_PAD_BITS;
		ureg_t	 thra_llasyncnext  : THRA_LLASYNCNEXT_BITS;
		ureg_t	 thra_index        : THRA_INDEX_BITS;
		ureg_t	 thra_reuse        : THRA_REUSE_BITS;
	    } bits;
#	endif
	uregx2_t	 uregx2;
} aligned_uregx2 thr_atom_t;

//  The thr_t is sized as a power of two.  Additional per thread fields are
//  in thrx_t (thread extension), making it easy to keep the size of thr_t a
//  size a power of two.  Conversion of a thr_t pointer to a thread index is
//  done frequently, because thr_t is a power of two, what would otherwise be
//  a substraction and a division, is just a substraction and a shift. To go
//  from a thread index to a thr_t pointer it is a shift and an addition. The
//  corresponding thrx_t is  allocated from their its arena.  Every thr_t has
//  a corresponding thrx_t the address of which is computed by using the thread
//  index to index into the thrx_t arena.

//  A thread while still running, enqueues itself onto queues or lists as
//  part of voluntarily releasing the CPU (for example blocking on a mutex
//  or waiting for a condition to occur), thr_running is used, and behaves as
//  spinning barrier, when a thread is running its value is true, when it is
//  no longer running its value is false, a thread can very quickly insert
//  itself into a queue to wait (for a mutex or a condition) save its register
//  context for when it resumes execution, and call into the scheduler to
//  schedule itself out, after which another thread will run on that CPU, or
//  if no threads are runnable, the CPU will be idled by switching to its
//  cpu_main() function which eventually parks the CPU until there are runnable
//  threads for it.

//  Concurrently with the thread being on its way to schedule itself out, a
//  different thread on a different CPU can awaken the first thread, insert it
//  into a scheduling queue, schedule itself out and have the first thread
//  chosen to run and have its context loaded on that different CPU (through
//  ctx_load() or ctx_load_on_cpu()), thus that first thread could be running 
//  on both CPUs (on the first CPU on the final throws of scheduling itself out
//  and on the second CPU by loading its register context and resume from where
//  it initially saved its context).  To prevent this concurrent execution:
//  ctx_load_idle_cpu(), ctx_load() and ctx_load_on_cpu() serialize through
//  cpu_running as a spinning barrier.  If the spinning is too much, it means
//  that the first thread was involuntarily preempted by the kernel while
//  thr_running was still set, in that case, the thread context can not be
//  loaded, instead a switch to the per-CPU context is done and the thread
//  pointer is returned as the value of the per-CPU ctx_save(), cpu_main()
//  puts the thread back into a scheduling queue for it to be chosen to run
//  later (once cpu_running is false).

struct thr_s {
	cnd_t		*thr_cnd;		// |	0-...
	mtxid_t		 thr_mtxid;		//  > protected by mtx_lock
	u32_t		 thr_mtxcnt;		// |	16-...
	u16_t		 thr_reccnt;		// |
	u8_t		 thr_prio;
	bool		 thr_running;		//
	core_t		*thr_core;		//	...-31
	thr_atom_t	 thra;			//	32-47
	thrln_t		 thr_ln;		//	48-63
};

//  thr_cnd is overlaid while thread has exited an is in thr_exited_lllist

static_assert(offsetof(thr_t, thr_cnd) == 0, "thr_cnd must be first");
static_assert(POWER_OF_TWO(sizeof(thr_t)), "thr_t size is wrong");

#define	THRA_HOLD(thra)							\
	BITS_GET((thra).thra_other)
#define	THRA_HOLD_SET(thra, hold)					\
	BITS_SET((thra).thra_other, (hold))

#define	THRA_STATE(thra)						\
	BITS_GET(THRA_STATE, (thra).thra_other)
#define	THRA_STATE_SET(thra, state)					\
	BITS_SET(THRA_STATE, (thra).thra_other, (state))

#define	THRA_CANCEL(thra)						\
	BITS_GET(THRA_CANCEL, (thra).thra_other)
#define	THRA_CANCEL_SET(thra, cancel)					\
	BITS_SET(THRA_CANCEL, (thra).thra_other, (cancel))

#define	THRA_WAITTIMEDOUT(thra)						\
	BITS_GET(THRA_WAITTIMEDOUT, (thra).thra_other)
#define	THRA_WAITTIMEDOUT_SET(thra, tout)				\
	BITS_SET(THRA_WAITTIMEDOUTthra.thra_other, (tout))

#define	THRA_LLASYNCNEXT(thra)						\
	BITS_GET(THRA_LLASYNCNEXT, (thra).thra_other)
#define	THRA_LLASYNCNEXT_SET(thra, next)				\
	BITS_SET(THRA_LLASYNCNEXT, (thra).thra_other, (next))

#define	THRA_INDEX(thra)						\
	BITS_GET(THRA_INDEX, (thra).thra_reuse_index)
#define	THRA_INDEX_SET(thra, index)					\
	BITS_SET(THRA_INDEX, (thra).thra_reuse_index, (index))

#define	THRA_REUSE(thra)						\
	BITS_GET(THRA_REUSE, (thra).thra_reuse_index)
#define	THRA_REUSE_SET(thra, reuse)					\
	BITS_GET(THRA_REUSE, (thra).thra_reuse_index, (reuse))
#define	THRA_REUSE_INC(thra)						\
	((thra).thra_reuse_index += 1uL << THRA_REUSE_SHIFT)


//  The layout of thrx_t is chosen carefully to ensure cache alignedment and
//  a size that is a multiple of the cache line size.

//  The fields prior to thrx_ctx use 5 ureg_t, this ensures both on ARM64 and
//  X64 that thrx_ctx uses the cache lines's last 3 ureg_t, and the remaining
//  ureg_t (32 in ARM64 and 16 in X64) of ctx_t fit exactly in 4 cache lines
//  in ARM64 and 2 cache lines in X64.  This reduces cache lines touched for
//  a "half" context register save and restore to 3 cache lines in ARM64 and
//  2 cache lines in X64.

//  The fpctx_t is known to be an exact multiple of the cache line size (the
//  fpcr and fpsr are in ctx_t).

//  TODO: review this with respect to the X64 context.

typedef struct {
	stk_t		*thrx_stk;
	void		*thrx_retval;
	mtx_t		*thrx_join_mtx;
	cnd_t		*thrx_join_cnd;
	bool		 thrx_detached;
	bool		 thrx_exited;
	bool		 thrx_joining;
	bool		 thrx_is_fullctx;
	bool		 thrx_pad[sizeof(ureg_t) - 4];
	union {
	    ctx_t	*thrx_ctx;
	    fullctx_t	*thrx_fullctx;
	};
} aligned_cache_line thrx_t;


//  A mtx_t is a mutual exclusion lock, optionally recursive.
//  The first mtx_atom_t within it, is atomically fetched and updated with
//  compare and swap to implement: lock acquisition; queuing of threads
//  waiting to acquire the lock; and thread cancelation when waiting for
//  a condition protected by the mutex.

//  Don't change MTX_UNLOCKED from 0 to another value, the thrid_t to thr_t
//  code knows that the first index is 1; and MTXA_OWNER_SET_WHEN_UNLOCKED_SET
//  assumes value is zero to make that macro simpler (faster).

//  XXX below needs to be reviewed and adjusted to work for 32 bits

#define	MTX_UNLOCKED		0
#define	MTX_LLLIST_EMPTY	0

#define	MTXA_LLWANT_SHIFT	0
#define	MTXA_LLWANT_BITS	THRIX_BITS

#define	MTXA_LLASYNC_SHIFT	(MTXA_LLWANT_SHIFT + MTXA_LLWANT_BITS)
#define	MTXA_LLASYNC_BITS	THRIX_BITS

#define	MTXA_PADLO_BITS		18

#define	MTXA_RECCNT_SHIFT	(THRIX_BITS + THRIX_BITS + MTXA_PADLO_BITS)
#define	MTXA_RECCNT_BITS	(UREG_BITS - MTXA_RECCNT_SHIFT)

static_assert(SIZEOF_FIELD(thr_t, thr_reccnt) * 8 == MTXA_RECCNT_BITS,
	      "thr_t thr_reccnt size is wrong");

#define	MTXA_OWNER_SHIFT	0
#define	MTXA_OWNER_BITS		THRIX_BITS

#define	MTXA_TYPE_SHIFT		THRIX_BITS
#define	MTXA_TYPE_BITS		2

#define	MTXA_PADHI_BITS		6

#define	MTXA_REUSE_SHIFT	(THRIX_BITS + MTXA_TYPE_BITS + MTXA_PADHI_BITS)
#define	MTXA_REUSE_BITS		(UREG_BITS - MTXA_REUSE_SHIFT)

typedef union {
	struct {
		ureg_t	 mtxa_reccnt_llasync_llwant;	  // must be first
		ureg_t	 mtxa_reuse_type_owner;
	};
#	ifdef LWT_BITS
	    struct {
		ureg_t	 mtxa_llwant  : THRIX_BITS;	  // |
		ureg_t	 mtxa_llasync : THRIX_BITS;	  //  > clobbered when
		ureg_t	 mtxa_padlo   : MTXA_PADLO_BITS;  // |           freed
		ureg_t	 mtxa_reccnt  : MTXA_RECCNT_BITS; // |
		ureg_t	 mtxa_owner   : THRIX_BITS;
		ureg_t	 mtxa_type    : MTXA_TYPE_BITS;
		ureg_t	 mtxa_padhi   : MTXA_PADHI_BITS;
		ureg_t	 mtxa_reuse   : MTXA_REUSE_BITS;  // must be in 2nd ureg
	    } bits;
#	endif
	uregx2_t	 uregx2;
} aligned_uregx2 mtx_atom_t;

struct __lwt_mtx_s {
	mtx_atom_t	 mtxa;
	thr_t		*mtx_wantpriq;
	ureg_t		 mtx_pad;
};

#define	MTXA_LLWANT(mtxa)						\
	BITS_GET(MTXA_LLWANT, (mtxa).mtxa_reccnt_llasync_llwant)
#define	MTXA_LLWANT_SET(mtxa, thridix)					\
	BITS_SET(MTXA_LLWANT, (mtxa).mtxa_reccnt_llasync_llwant, thridix)

#define	MTXA_LLASYNC(mtxa)						\
	BITS_GET(MTXA_LLASYNC, (mtxa).mtxa_reccnt_llasync_llwant)
#define	MTXA_LLASYNC_SET(mtxa, thridix)					\
	BITS_SET(MTXA_LLASYNC, (mtxa).mtxa_reccnt_llasync_llwant, thridix)

#define	MTXA_RECCNT(mtxa)						\
	BITS_GET(MTXA_RECCNT, (mtxa).mtxa_reccnt_llasync_llwant)
#define	MTXA_RECCNT_SET(mtxa, reccnt)					\
	BITS_SET(MTXA_RECCNT, (mtxa).mtxa_reccnt_llasync_llwant,	\
		 (ureg_t)(reccnt))
#define	MTXA_RECCNT_INC(mtxa)						\
	((mtxa).mtxa_reccnt_llasync_llwant += 1uL << MTXA_RECCNT_SHIFT)
#define	MTXA_RECCNT_DEC(mtxa)						\
	((mtxa).mtxa_reccnt_llasync_llwant -= 1uL << MTXA_RECCNT_SHIFT)

#define	MTXA_OWNER(mtxa)						\
	BITS_GET(MTXA_OWNER, (mtxa).mtxa_reuse_type_owner)
#define	MTXA_OWNER_SET(mtxa, thridix)					\
	BITS_SET(MTXA_OWNER, (mtxa).mtxa_reuse_type_owner, (thridix))
#define	MTXA_OWNER_SET_WHEN_UNLOCKED(mtxa, thridix)			\
	((mtxa).mtxa_reuse_type_owner |= (thridix))

#define	MTXA_TYPE(mtxa)							\
	BITS_GET(MTXA_TYPE, (mtxa).mtxa_reuse_type_owner)
#define	MTXA_TYPE_SET(mtxa, type)					\
	BITS_SET(MTXA_TYPE, (mtxa).mtxa_reuse_type_owner, (type))

#define	MTXA_REUSE(mtxa)						\
	BITS_GET(MTXA_REUSE, (mtxa).mtxa_reuse_type_owner)
#define	MTXA_REUSE_SET(mtxa, reuse)					\
	BITS_SET(MTXA_REUSE, (mtxa).mtxa_reuse_type_owner, (reuse))
#define	MTXA_REUSE_INC(mtxa)						\
	((mtxa).mtxa_reuse_type_owner += 1uL << MTXA_REUSE_SHIFT)


//  Mutex attributes reduce to whether they are fast, checked, or recursive
//  no additional memory (other than the API user's memory) is used for them
//  the value is stored in a pointer mtxattr_t (which is purposely left as an
//  undefined structure so nothing can be done with pointers to it other than
//  to store values in the pointer, this allows in the future to preserve
//  the ABI and allocate and release underlying memory if it is ever needed.

typedef struct __lwt_mtxattr_s	mtxattr_t;


//  A condition variable contains a linked list of threads waiting for the
//  condition to occur.  Signaling an broadcasting of a condition must be
//  done with the mutex that protects the condition acquired, the mutex
//  associated with the condition is known to the condition and a pointer to
//  it stored in cnd_mtx.  The association between the mutex and the condition
//  is established when a thread blocks on a condition, the mutex specified
//  as an argument at that time becomes the mutex associated with the condition
//  and no other mutex can be associated with the condition at that time.
//  Once there are no more threads waiting for the condition to occur, the
//  association is broken, and the condition variable in the future can become
//  associated with a different mutex.  Support for this dynamic association
//  costs very little and for the rare cases where this feature is required
//  it can be used.

//  Signaling and broadcasting of a condition without the mutex being acquired,
//  so called naked signaling and broadcasting, is not supported, such support
//  would possibly only make sense from a signal(2) handler, but that support
//  is usually not available for POSIX threads (pthreads) and providing it
//  adds no real value.

typedef struct __lwt_cndattr_s	cndattr_t;

struct __lwt_cnd_s {
	thr_t		*cnd_waitpriq;
	mtx_t		*cnd_mtx;
};

// XXX priority ceiling with autodiscovery and boosting?

