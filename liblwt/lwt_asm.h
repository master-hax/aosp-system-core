
#define	ALIGN(bits)	.align bits

// In ARM64 the register name conveys the width of the operation being
// performed.  This is the case mostly as it relates to 64 and 32 bit
// instructions, where the register names xN or wN are used (where N is
// the register number).  For example x0 or w0.  For other instructions
// the width of the operation is conveyed in the actual instruction name
// (for example the load and store instructions) and the register name used 
// is not orthogonal.  Loads and stores of 1, 2, or 4 bytes requires that
// the wN form be used, and the xN form is only allowed for 8 byte accesses.
// All of this makes ARM64 a cumbersome architecture to abstract among fairly
// similar architectures because of the register naming requirements.
// To work around all of that and to make the assembly code portable these
// are the register names used, and the translation to ARM64 xN or wN is all
// done in this file.

#define R0	0
#define R1	1
#define R2	2
#define R3	3
#define R4	4
#define R5	5
#define R6	6
#define R7	7
#define R8	8
#define R9	9
#define R10	10
#define R11	11
#define R12	12
#define R13	13
#define R14	14
#define R15	15
#define R16	16
#define R17	17
#define R18	18
#define R19	19
#define R20	20
#define R21	21
#define R22	22
#define R23	23
#define R24	24
#define R25	25
#define R26	26
#define R27	27
#define R28	28
#define R29	29
#define R30	30

#define	REG32(reg)	w##reg
#define	REG64(reg)	x##reg



#define FUNCTION_START(name) \
        .text; .align  2; .global name; .type name, %function; name:    

#define FUNCTION_END(name)						\
        .size name, .-name


//  u64_t compare and branches

#define	U64_IF_EQUAL_TO_ZERO_GOTO(reg, label)				\
	cbz	REG64(reg), label

#define	U64_IF_NOT_EQUAL_TO_ZERO_GOTO(reg, label)			\
	cbnz	REG64(reg), label

#define	U64_IF_EQUAL_GOTO(reg1, reg2, label)				\
	cmp	REG64(reg1), REG64(reg2);				\
	beq	label

// No branch-not-equal instruction in ARM64, using cmp requires two branches

#define	U64_IF_NOT_EQUAL_GOTO_SLOWER(reg1, reg2, label)			\
	cmp	REG64(reg1), REG64(reg2);				\
	beq	999f;							\
	b	label;							\
999:

// Faster but requires a temporary register

#define	U64_IF_NOT_EQUAL_GOTO(reg1, reg2, label, temp)			\
	eor	REG64(temp), REG64(reg1), REG64(reg2);			\
	cbnz	REG64(temp), label

#define	U64_IF_LESS_GOTO(reg1, reg2, label)				\
	cmp	REG64(reg1), REG64(reg2);				\
	bcc	label

#define	U64_IF_LESS_OR_EQUAL_GOTO(reg1, reg2, label)			\
	cmp	REG64(reg1), REG64(reg2);				\
	bls	label

#define	U64_IF_GREATER_GOTO(reg1, reg2, label)				\
	cmp	REG64(reg1), REG64(reg2);				\
	bhi	label

#define	U64_IF_GREATER_OR_EQUAL_GOTO(reg1, reg2, label)			\
	cmp	REG64(reg1), REG64(reg2);				\
	bcs	label


//  misc

#define	GOTO(label)							\
	b	label

#define	LABEL(label)							\
	label:

#define	CODE_ADDR_LOAD(reg, label)					\
	adr	REG64(reg), label

// load address of data into reg
// TODO: this should be a single "adr" instruction
#define DATA_ADDR_LOAD(reg, data)	/* reg = &data */		\
        adrp	REG64(reg), :got:data;					\
        ldr	REG64(reg), [REG64(reg), #:got_lo12:data]

#define	REG_LOAD_IMMED(reg, value)	/* reg = value */		\
	mov	REG64(reg), value			

#define	REG_LOAD_ZERO(reg)						\
	mov	REG64(reg), xzr

#define CPU_GET(reg)			/* cpu_t *reg_t = cpu_get(); */	\
        mrs	REG64(reg), tpidrro_el0


// Clear high bits so that ptr is a user mode address,
// (so that it can can not be a kernel address).

#define MAKE_USER_MODE_ADDR(ptr)					\
	and	REG64(ptr), REG64(ptr), #0xfFFffFFfffFF

#define	THRSTATE_MAKE_RUNNING(dest, field)				\
	strb	wzr, [REG64(dest), field]


//  ptr_t operations

#define PTR_LOAD(dest, source, field)	/* uptr_t dest = source->field; */ \
        ldr	REG64(dest), [REG64(source), field]

#define PTR_STORE(dest, field, source)	/* dest->field = source */	\
        str	REG64(source), [REG64(dest), field]

#define	PTR_MOVE(dest, source)		/* dest = source */		\
	mov	REG64(dest), REG64(source)

#define PTR_ADD(dest, source, field)	/* dest = &source->field */	\
        add	REG64(dest), REG64(source), field


//  unsigned loads

#define	U8_LOAD(dest, source, field)					\
	ldrb	REG32(dest), [REG64(source), field]

#define	U16_LOAD(dest, source, field)					\
	ldrh	REG32(dest), [REG64(source), field]

#define	U32_LOAD(dest, source, field)					\
	ldr	REG32(dest), [REG64(source), field]

#define	U64_LOAD(dest, source, field)					\
	ldr	REG64(dest), [REG64(source), field]


//  signed loads

#define	S8_LOAD(dest, source, field)					\
	ldrsb	REG32(dest), [REG64(source), field]

#define	S16_LOAD(dest, source, field)					\
	ldrsh	REG32(dest), [REG64(source), field]

#define	S32_LOAD(dest, source, field)					\
	ldrsw	REG32(dest), [REG64(source), field]

#define	S64_LOAD(dest, source, field)					\
	ldr	REG64(dest), [REG64(source), field]


//  unsigned stores

#define	U8_STORE(dest, field, source)					\
	strb	REG32(source), [REG64(dest), field]

#define	U16_STORE(dest, field, source)					\
	strh	REG32(source), [REG64(dest), field]

#define	U32_STORE(dest, field, source)					\
	str	REG32(source), [REG64(dest), field]

#define	U64_STORE(dest, field, source)					\
	str	REG64(source), [REG64(dest), field]


//  signed stores

#define	S8_STORE(dest, field, source)					\
	strb	REG32(source), [REG64(dest), field]

#define	S16_STORE(dest, field, source)					\
	strh	REG32(source), [REG64(dest), field]

#define	S32_STORE(dest, field, source)					\
	str	REG32(source), [REG64(dest), field]

#define	S64_STORE(dest, field, source)					\
	str	REG64(source), [REG64(dest), field]


// load from ptr into reg setting a reservation with acquire semantics

#define	PTR_LOAD_LINKED_ACQUIRE(reg, ptr)	/* reg = *ptr */	\
	ldaxr	REG64(reg), [REG64(ptr)]


// conditional store of reg into ptr with release semantics

#define	PTR_STORE_CONDITIONAL_RELEASE(ptr, reg)				\
	stlxr	REG64(reg), [REG64(ptr)]


// Two versions of SPIN_LOCK() and SPIN_UNLOCK() are provided, one
// used load-linked and store-conditional and the other using compara-
// and-swap.  Two versions of the user mode scheduler are built, one
// using each pair depending on whether the system supports compara-and-
// swap or not.  The kernel installs the correct version.

#define	SPIN_LOCK(ptr, thr, temp)					\
999:	ldaxr	REG64(temp), [REG64(ptr)];				\
	cbnz	REG64(temp), 999b;					\
	stxr	REG32(temp), REG64(thr), [REG64(ptr)];			\
	cbnz	REG32(temp), 999b

#define	SPIN_UNLOCK(ptr)						\
	stlr	xzr, [REG64(ptr)]

#define	SPIN_UNLOCK_IF_OWNED(ptr, thr, temp)				\
	ldr	REG64(temp), [REG64(ptr), 0];				\
	eor	REG64(temp), REG64(temp), REG64(thr);			\
	cbnz	REG64(temp), 999f;					\
	stlr	xzr, [REG64(ptr)];					\
999:

#define	SPIN_UNLOCK_TWO(ptr1, ptr2)					\
	str	xzr, [REG64(ptr1)];					\
	stlr	xzr, [REG64(ptr2)]

