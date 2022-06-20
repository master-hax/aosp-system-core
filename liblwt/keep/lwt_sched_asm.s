# 0 "slk_sched_asm.S"
# 0 "<built-in>"
# 0 "<command-line>"
# 1 "/usr/aarch64-linux-gnu/include/stdc-predef.h" 1 3
# 0 "<command-line>" 2
# 1 "slk_sched_asm.S"




ALIGN(NUMBER_OF_BITS_TO_CLEAR_IN_PC_TO_RESTART)
FUNCTION_START(sched_out_in)
# 24 "slk_sched_asm.S"
  GET_CPU(x3)
  PTR_LOAD(x17, x3, cpu_running_thr)
  PTR_LOAD(x4, x1, thr_sq)
  ADDR_LOAD(run_sq_r, sched_ready_sq_tab)
# 41 "slk_sched_asm.S"
  PTR_LOAD(x16, x4, sq_spin)
  PTR_MOVE(x15, x16)
  REG_LOAD(intrctrl_r, 2)






restart_search:
  PTR_MOVE(x5, x14)

search:
  IF_GREATER_OR_EQUAL_GOTO(x5, x4, not_found)



  PTR_LOAD(x6, x5, ln_next)
  IF_EQUAL_GOTO(x6, x5, empty)



  PTR_LOAD_FIELD_ADDR(x15, x5, sq_spin)
  SPIN_LOCK(x15, x17, x13, w13)




  PTR_LOAD(x6, x5, ln_next)
  IF_NOT_EQUAL_GOTO(x6, x5, found)
  STORE_ZERO_TO_RELEASE_PTR(x15)
  GOTO(restart_search)

empty:
  ADD_PTR(x5, x5, SIZEOF_SQ_T)
  GOTO(search)

not_found:




  REG_LOAD(intrctrl_r, 0)
  STORE_THRSTATE(x1, thr_state, THR_RUNNING)
  STORE_PTR(x3, cpu_running_thr, x1)
  STORE_THRSTATE(x17, thr_state, thrstate_r)
  PTR_LOAD_FIELD_ADDR(x29, x1, thr_ctxt)
  GOTO(ctxt_load)

found:
  SPIN_LOCK(x16, x17, x13, w13)




  PTR_LOAD(x7, x4, ln_next)
  PTR_LOAD(x8, x6, ln_next)
  PTR_LOAD(x9, x6, ln_prev)
# 129 "slk_sched_asm.S"
  STORE_PTR(x8, ln_prev, x9); STORE_PTR(x9, ln_next, x8); STORE_PTR(x4, ln_next, x1); STORE_PTR(x7, ln_prev, x1); STORE_PTR(x1, ln_prev, x4); STORE_PTR(x1, ln_next, x7); STORE_ZERO_TO_RELEASE_TWO_PTR(x16, x15); STORE_THRSTATE(x6, thr_state, THR_RUNNING); STORE_PTR(x3, cpu_running_thr, x6); STORE_THRSTATE(x17, thr_state, x2)

  PTR_LOAD_FIELD_ADDR(x29, x6, thr_ctxt)
  GOTO(ctxt_load)

FUNCTION_END(sched_out_in)
# 157 "slk_sched_asm.S"
FUNCTION_START(sched_out_in_complete)
  and x8, x8, #0xffffffffffff
  and x9, x9, #0xffffffffffff
  and x4, x4, #0xffffffffffff
  and x7, x7, #0xffffffffffff
  and x1, x1, #0xffffffffffff
  and x6, x6, #0xffffffffffff
  and x17, x17, #0xffffffffffff)
  and x3, x3, #0xffffffffffff
  and x16, x16, #0xffffffffffff
  and x15, x15, #0xffffffffffff
  STORE_PTR(x8, ln_prev, x9); STORE_PTR(x9, ln_next, x8); STORE_PTR(x4, ln_next, x1); STORE_PTR(x7, ln_prev, x1); STORE_PTR(x1, ln_prev, x4); STORE_PTR(x1, ln_next, x7); STORE_ZERO_TO_RELEASE_TWO_PTR(x16, x15); STORE_THRSTATE(x6, thr_state, THR_RUNNING); STORE_PTR(x3, cpu_running_thr, x6); STORE_THRSTATE(x17, thr_state, x2)
  ...
FUNCTION_END(sched_out_in_complete)
