# 0 "slk_sched_asm.S"
# 0 "<built-in>"
# 0 "<command-line>"
# 1 "/usr/aarch64-linux-gnu/include/stdc-predef.h" 1 3
# 0 "<command-line>" 2
# 1 "slk_sched_asm.S"

# 1 "slk_asm.h" 1
# 3 "slk_sched_asm.S" 2
# 1 "slk_asm_gen.h" 1
# 4 "slk_sched_asm.S" 2
# 1 "slk_kabi.h" 1
# 5 "slk_sched_asm.S" 2
# 39 "slk_sched_asm.S"
.align 7
.global sched_out_in; .type sched_out_in, %function; sched_out_in:
# 57 "slk_sched_asm.S"
  mrs x3, tpidrro_el0
  ldr x17, [x3, 0x00000000]
  ldr x4, [x1, 0x00000038]
  adrp x5, :got:sched_ready_sq_tab; ldr x5, [x5, #:got_lo12:sched_ready_sq_tab]
# 74 "slk_sched_asm.S"
  ldr x16, [x4, sq_spin]
  mov x15, x16
  adr x0, sched_out_in_unlock_and_restart




restart_search:
  mov x5, x14

search:
  cmp x5, x4; bcs not_found



  ldr x6, [x5, 0x00000000]
  cmp x6, x5; beq empty



  add x15, x5, sq_spin
  999: ldaxr x13, [x15]; cbnz x13, 999b; stxr w13, x17, [x15]; cbnz w13, 999b




  ldr x6, [x5, 0x00000000]
  eor x13, x6, x5; cbnz x13, found

  stlr xzr, [x15]
  b restart_search

empty:
  add x5, x5, 0x00000840
  b search

not_found:




  add x29, x1, 0x00000048
  adr x0, sched_out_in_complete
# 127 "slk_sched_asm.S"
  strb wzr, [x1, thr_state]; str x1, [x3, 0x00000000]; THRSTATE_STORE(17, thr_state, 2)
  b ctxt_load

found:
  999: ldaxr x13, [x16]; cbnz x13, 999b; stxr w13, x17, [x16]; cbnz w13, 999b





  ldr x7, [x4, 0x00000000]
  ldr x8, [x6, 0x00000000]
  ldr x9, [x6, 0x00000008]
# 157 "slk_sched_asm.S"
  add x29, x6, 0x00000048
  adr x0, sched_out_in_higher_pri_complete
# 175 "slk_sched_asm.S"
  str x9, [x8, 0x00000008]; str x8, [x9, 0x00000000]; str x1, [x4, 0x00000000]; str x1, [x7, 0x00000008]; str x4, [x1, 0x00000008]; str x7, [x1, 0x00000000]; str xzr, [x16]; stlr xzr, [x15]; strb wzr, [x1, thr_state]; str x6, [x3, 0x00000000]; THRSTATE_STORE(17, thr_state, 2)

  b ctxt_load
# 194 "slk_sched_asm.S"
sched_out_in_higher_pri_complete:
  and x8, x8, #0xfFFffFFfffFF
  and x9, x9, #0xfFFffFFfffFF
  and x4, x4, #0xfFFffFFfffFF
  and x7, x7, #0xfFFffFFfffFF
  and x1, x1, #0xfFFffFFfffFF
  and x6, x6, #0xfFFffFFfffFF
  and x17, x17, #0xfFFffFFfffFF
  and x3, x3, #0xfFFffFFfffFF
  and x16, x16, #0xfFFffFFfffFF
  and x15, x15, #0xfFFffFFfffFF
  str x9, [x8, 0x00000008]; str x8, [x9, 0x00000000]; str x1, [x4, 0x00000000]; str x1, [x7, 0x00000008]; str x4, [x1, 0x00000008]; str x7, [x1, 0x00000000]; str xzr, [x16]; stlr xzr, [x15]; strb wzr, [x1, thr_state]; str x6, [x3, 0x00000000]; THRSTATE_STORE(17, thr_state, 2)
  b complete_done

sched_out_in_complete:
  and x1, x1, #0xfFFffFFfffFF
  and x3, x3, #0xfFFffFFfffFF
  and x17, x17, #0xfFFffFFfffFF
  strb wzr, [x1, thr_state]; str x1, [x3, 0x00000000]; THRSTATE_STORE(17, thr_state, 2)
  b complete_done

sched_out_in_unlock_and_restart:
  ldr x13, [x16, 0]; eor x13, x13, x17; cbnz x13, 999f; stlr xzr, [x16]; 999:
  ldr x13, [x15, 0]; eor x13, x13, x17; cbnz x13, 999f; stlr xzr, [x15]; 999:
  mov x0, xzr
  b complete_restart

.size sched_out_in, .-sched_out_in
