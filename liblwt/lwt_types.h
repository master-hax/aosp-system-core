
#ifndef __cplusplus
#define static_assert(expr, msg)	_Static_assert(expr, msg)
#endif
#define SIZEOF_FIELD(type, field)	((uptr_t) sizeof(((type *) 0)->field))

typedef int			error_t;

typedef signed char		s8_t;
typedef short			s16_t;
typedef int			s32_t;

typedef unsigned char		u8_t;
typedef unsigned short		u16_t;
typedef unsigned int		u32_t;

#if (LWT_PTR_BITS == 64)
typedef long			s64_t;
typedef unsigned long		u64_t;
typedef u64_t			uptr_t;
typedef u64_t			ureg_t;
#define	UREG_BITS		64
#endif

#if (LWT_PTR_BITS == 32)
typedef long long		s64_t;
typedef unsigned long long	u64_t;
typedef u32_t			uptr_t;
typedef u32_t			ureg_t;
typedef UREG_BITS		32
#endif

static_assert(sizeof(s8_t)  == 1,  "s8_t wrong size");
static_assert(sizeof(s16_t) == 2, "s16_t wrong size");
static_assert(sizeof(s32_t) == 4, "s32_t wrong size");
static_assert(sizeof(s64_t) == 8, "s64_t wrong size");

static_assert(sizeof(u8_t)  == 1,  "u8_t wrong size");
static_assert(sizeof(u16_t) == 2, "u16_t wrong size");
static_assert(sizeof(u32_t) == 4, "u32_t wrong size");
static_assert(sizeof(u64_t) == 8, "u64_t wrong size");

#if (LWT_PTR_BITS == 64)
static_assert(sizeof(uptr_t) == 8, "uptr_t wrong size");
static_assert(sizeof(ureg_t) == 8, "ureg_t wrong size");
#endif

#if (LWT_PTR_BITS == 32)
static_assert(sizeof(uptr_t) == 4, "uptr_t wrong size");
static_assert(sizeof(ureg_t) == 4, "ureg_t wrong size");
#endif

typedef struct stk_s	stk_t;
typedef struct cpu_s	cpu_t;
typedef struct kcpu_s	kcpu_t;
typedef struct kcore_s	kcore_t;

//  Very unlikely code should use unlikely() and if it is an aborting error
//  path should call a noreturn function, this allows for better optimization
//  of the surrounding code.  Note that if the function is not noreturn then
//  the compiler won't treat the function as a leaf function or do tail-call
//  optimization because it gets bogged down in needless linkage convention
//  setup for the unlikely path.  When possible the code should be:
//
//      if (unlikely(expr))
//          call_noreturn_function();

#ifndef __cplusplus
#define	noreturn _Noreturn
#endif

#ifdef __clang__
#define	__builtin_expect_with_probability(e, v, p) __builtin_expect(e, v)
#endif

#define	likely(expr)							\
	__builtin_expect_with_probability(!!(expr), 1, 0.99999d)

#define	unlikely(expr)							\
	__builtin_expect_with_probability((expr), 0, 0.00001d)

#define	really_unlikely(expr)						\
	__builtin_expect_with_probability((expr), 0, 1e-100d)

static noreturn void lwt_assert_fail(const char *file, int line,
				     const char *msg);
static noreturn void lwt_abort_fail(const char *file, int line);

#define	lwt_abort()							\
	lwt_abort_fail(__FILE__, __LINE__)

#define	assert(expr)							\
	do {								\
		if (really_unlikely(!(expr)))				\
			lwt_assert_fail(__FILE__, __LINE__, #expr);	\
	} while (0)

#ifdef LWT_DEBUG
#define	debug(expr)	assert(expr)
#else
#define	debug(expr)	NOOP()
#endif

#define	TODO()		assert(0)

#ifdef LWT_DEBUG
#define	inline_only	static
#define	LWT_BITS
#else
#define	inline_only	static inline __attribute__((always_inline))
#endif

#define two_returns	__attribute__((__returns_twice__))
#define	unused		__attribute__((__unused__))

// __attribute__((__const__))
// __attribute__((__pure__))
// __attribute__((__malloc__))
// __attribute__((__used__))

#define aligned_uregx2		__attribute__ ((aligned(2 * sizeof(ureg_t))))
#define	aligned_cache_line	__attribute__ ((aligned(CACHE_LINE_SIZE)))

typedef struct {
	ureg_t	low;
	ureg_t	high;
} aligned_uregx2 uregx2_t;

#define	BITS_MASK(name)		(((1uL << name##_BITS) - 1) << (name##_SHIFT))

#define	BITS_SET(name, var, value)					\
	((var) = ((var) & ~BITS_MASK(name)) |				\
	 (((value) << name##_SHIFT) & BITS_MASK(name)))

#define	BITS_GET(name, var)						\
	(((var) & BITS_MASK(name)) >> name##_SHIFT)

#define	POWER_OF_TWO(n)		(((n) & ((n) - 1)) == 0)

