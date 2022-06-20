
#include "lwt_asm.h"
#include "lwt_asm_gen.h"
#include "lwt_kabi.h"

#if (SIZEOF_thrstate_atom_t == 1)
#define THRSTATE_STORE(ptr, field, value)	U8_STORE(ptr, field, value)
#else
#error "unexpected sizeof(thrstate_atom_t)"
#endif

// Values of intrjmp_r are labels in this function, if an asynchronous
// interrupt occurs while this function is running, and intrjmp_r is non-zero
// prior to handling the interrupt control flow is redirected to the value
// in intrjmp_r, when that code completes the kernel is re-entered to actually
// handle the interrupt.
//
// zero
//     - no spin locks acquired and nothing to undo
//     - the caller of sched_out_in passes zero as its first argument
//       which is intrjmp_r
//
// sched_out_in_unlock_and_restart
//     - release two spin locks (if owned by this thread); and
//     - restart (resets intrjmp_r to zero as part restarting)
//
// sched_out_in_complete
//     - perform stores (spin unlocks are part of the stores)
//     - the next thread to run is in_thr_r
//
// sched_out_in_higher_pri_complete
//     - perform stores (spin unlocks are part of the stores)
//     - in this case a thread with priority higher than in_thr_r's
//       priority is the next thread to run

// Undo clears enough low bits in program counter to have it be reset to
// the first instruction sched_out_in(), it must be aligned appropriately

ALIGN(NUMBER_OF_BITS_TO_CLEAR_IN_PC_TO_RESTART)
FUNCTION_START(sched_out_in)

  // Function arguments, caller must pass zero as first argument (R0)

#define intrjmp_r      R0    // reg_t intrjmp_r; // interrupt control register
#define in_thr_r       R1    // thr_t *in_thr_r;
#define out_state_r    R2    // thrstate_atom_t out_state_r;

  // Local registers

#define cpu_r          R3    // cpu_t *cpu_r = cpu_get();
#define out_thr_r      R17   // thr_t *out_thr_r = sched_get_running_thr();
#define in_sq_r        R4    // sq_t *in_sq_r = in_thr_r->thr_sq;
#define run_sq_r       R5    // sq_t *run_sq_r = ready_sq_tab_r
#define ready_sq_tab_r R14   // sq_t *ready_sq_tab_r = sched_ready_sq_tab;
#define ctxt_r         R29   // ctxt_t *ctxt_r;

  CPU_GET(cpu_r)
  PTR_LOAD(out_thr_r, cpu_r, cpu_running_thr)
  PTR_LOAD(in_sq_r, in_thr_r, thr_sq)
  DATA_ADDR_LOAD(run_sq_r, sched_ready_sq_tab)

  // To undo the work below, two spin locks, their addresses in R15 and R16,
  // should be released if their value is R17 (the current thread pointer).
  // The correct sq_t for a ready to run thread is not known yet, having
  // run_sq_spin_r point to the same spin_t that in_sq_spin_r points to
  // provides a valid address, on undo, once in_sq_spin_r is released, the
  // run_sq_spin_r pointer will point to a spin lock not owned by this thread.
  // This simplifies the undo/complete function implementation and does not
  // add extra code to this function.

#define in_sq_spin_r   R16   // spin_t *in_sq_spin_r = &in_sq_r->sq_spin;
#define run_sq_spin_r  R15   // spin_t *run_sq_spin_r = in_sq_spin_r;

  PTR_LOAD(in_sq_spin_r, in_sq_r, sq_spin)
  PTR_MOVE(run_sq_spin_r, in_sq_spin_r)
  CODE_ADDR_LOAD(intrjmp_r, sched_out_in_unlock_and_restart)

#define run_thr_r      R6    // thr_t *run_thr_r;
#define temp_r         R13   // reg_t temp_r;

restart_search:
  PTR_MOVE(run_sq_r, ready_sq_tab_r)

search:
  U64_IF_GREATER_OR_EQUAL_GOTO(run_sq_r, in_sq_r, not_found)

  // run_thr_r = run_sq_r.sq_list.ln_next;

  PTR_LOAD(run_thr_r, run_sq_r, ln_next)
  U64_IF_EQUAL_GOTO(run_thr_r, run_sq_r, empty)

  // run_sq_spin_r = &run_sq_r->sq_spin;

  PTR_ADD(run_sq_spin_r, run_sq_r, sq_spin)
  SPIN_LOCK(run_sq_spin_r, out_thr_r, temp_r)

  // refetch after spin lock is held
  // run_thr_r = run_sq_r.sq_list.ln_next;

  PTR_LOAD(run_thr_r, run_sq_r, ln_next)
  U64_IF_NOT_EQUAL_GOTO(run_thr_r, run_sq_r, found, temp_r)

  SPIN_UNLOCK(run_sq_spin_r)
  GOTO(restart_search)

empty:
  PTR_ADD(run_sq_r, run_sq_r, SIZEOF_sq_t)   // ++run_sq_r;
  GOTO(search)

not_found:
  // undo by restarting function
  // cpu_r->cpu_running_thr = in_thr_r;
  // out_thr_r->thr_state = out_state_r;

  PTR_ADD(ctxt_r, in_thr_r, thr_ctxt)
  CODE_ADDR_LOAD(intrjmp_r, sched_out_in_complete)

  // SCHED_OUT_IN_STORES()
  //
  // Expanded immediately below and elsewhere.

#define SCHED_OUT_IN_STORES()						\
  THRSTATE_MAKE_RUNNING(in_thr_r, thr_state);				\
  PTR_STORE(cpu_r, cpu_running_thr, in_thr_r);				\
  THRSTATE_STORE(out_thr_r, thr_state, out_state_r)

  SCHED_OUT_IN_STORES()
  GOTO(ctxt_load)            // loads context from ctxt_r

found:
  SPIN_LOCK(in_sq_spin_r, out_thr_r, temp_r)

#define next_r         R7    // thr_t *next_r = in_sq_r->sq_list.ln_next;
#define n_r            R8    // thr_t *n_r = run_thr_r->thr_link.ln_next;
#define p_r            R9    // thr_t *p_r = run_thr_r->thr_link.ln_prev;

  PTR_LOAD(next_r, in_sq_r, ln_next)
  PTR_LOAD(n_r, run_thr_r, ln_next)
  PTR_LOAD(p_r, run_thr_r, ln_prev)

  // SCHED_OUT_IN_STORES_HIGHER_PRI()
  //
  // Expanded immediately below and elsewhere.
  //
  // list_insert(&in_sq_r->sq_list, &in_thr_r->thr_link);
  //
  // in_sq_r->sq_list.ln_next = in_thr_r;
  // next_r->thr_link.ln_prev = in_thr_r;
  // in_thr_r->thr_link.ln_prev = (thr_t *) in_sq_r;
  // in_thr_r->thr_link.ln_next = next_r;
  //
  // list_remove(&run_thr_r->thr_link);
  //
  // n_r->thr_link.ln_prev = p_r;
  // p_r->thr_link.ln_next = n_r;

  PTR_ADD(ctxt_r, run_thr_r, thr_ctxt)
  CODE_ADDR_LOAD(intrjmp_r, sched_out_in_higher_pri_complete)

#define SCHED_OUT_IN_STORES_HIGHER_PRI()				\
									\
  PTR_STORE(n_r, ln_prev, p_r);						\
  PTR_STORE(p_r, ln_next, n_r);						\
									\
  PTR_STORE(in_sq_r,  ln_next, in_thr_r);				\
  PTR_STORE(next_r,   ln_prev, in_thr_r);				\
  PTR_STORE(in_thr_r, ln_prev, in_sq_r);				\
  PTR_STORE(in_thr_r, ln_next, next_r);					\
									\
  SPIN_UNLOCK_TWO(in_sq_spin_r, run_sq_spin_r);				\
  THRSTATE_MAKE_RUNNING(in_thr_r, thr_state);				\
  PTR_STORE(cpu_r, cpu_running_thr, run_thr_r);				\
  THRSTATE_STORE(out_thr_r, thr_state, out_state_r)

  SCHED_OUT_IN_STORES_HIGHER_PRI()

  GOTO(ctxt_load)            // loads context from ctxt_r

// Completion function for sched_out_in(), run to complete its work if it
// progressed to the point where memory was modified and in consequence all
// the changes have to be finished.
//
// TODO:
// - If kernel bounces to user mode briefly to complete this work then
//   enough state in the kernel would recover from any fault and regain
//   control when the system call to return to kernel is done, in that
//   case MAKE_USER_MODE_ADDR() doesn't need to be invoked.
// - If this was called from the kernel, then a lightweight exception
//   handler needs to be setup in case any of the stores fail, and the
//   store instruction might need to be different and/or user mode might
//   need to be made addressable in address space or via PAN (privileged
//   access none) bit manipulation.

LABEL(sched_out_in_higher_pri_complete)
  MAKE_USER_MODE_ADDR(n_r)
  MAKE_USER_MODE_ADDR(p_r)
  MAKE_USER_MODE_ADDR(in_sq_r)
  MAKE_USER_MODE_ADDR(next_r)
  MAKE_USER_MODE_ADDR(in_thr_r)
  MAKE_USER_MODE_ADDR(run_thr_r)
  MAKE_USER_MODE_ADDR(out_thr_r)
  MAKE_USER_MODE_ADDR(cpu_r)
  MAKE_USER_MODE_ADDR(in_sq_spin_r)
  MAKE_USER_MODE_ADDR(run_sq_spin_r)
  SCHED_OUT_IN_STORES_HIGHER_PRI()
  GOTO(complete_done)

LABEL(sched_out_in_complete)
  MAKE_USER_MODE_ADDR(in_thr_r)
  MAKE_USER_MODE_ADDR(cpu_r)
  MAKE_USER_MODE_ADDR(out_thr_r)
  SCHED_OUT_IN_STORES()
  GOTO(complete_done)

LABEL(sched_out_in_unlock_and_restart)
  SPIN_UNLOCK_IF_OWNED(in_sq_spin_r, out_thr_r, temp_r)
  SPIN_UNLOCK_IF_OWNED(run_sq_spin_r, out_thr_r, temp_r)
  REG_LOAD_ZERO(intrjmp_r)
  GOTO(complete_restart)

FUNCTION_END(sched_out_in)

