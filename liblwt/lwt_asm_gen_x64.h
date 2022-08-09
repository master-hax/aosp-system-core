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

// WARNING: do not edit, generated by lwt_genassym.c

// thrln_t
#define SIZEOF_thrln_t          0x00000010                      // 16
#define ln_next                 0x00000000
#define ln_prev                 0x00000008

#define LLLIST_GEN_SHIFT        0x00000000                      // 0
#define LLLIST_GEN_BITS         0x00000020                      // 32
#define LLLIST_COUNT_SHIFT      0x00000020                      // 32
#define LLLIST_COUNT_BITS       0x00000020                      // 32

#define STKCACHE_BUCKETS        0x00000006                      // 6

#define MTXID_NULL              0x0000000000000000uL            // 0
#define MTXID_DUMMY             0x0000000000000001uL            // 1

#define THRID_NULL              0x0000000000000000uL            // 0
#define THRIX_BITS              0x0000000f                      // 15
#define THRIX_BITS              0x0000000f                      // 15
#define THRIX_MASK              0x0000000000007fffuL            // 32767
#define THRIX_RESERVED_COUNT    0x00000100                      // 256
#define THRIX_MAX               0x0000000000007f00uL            // 32512
#define THRIX_RESERVED_THRLN    0x0000000000007fffuL            // 32767
#define THRIX_INVALID_1         0x0000000000007ffeuL            // 32766
#define THRIX_INVALID_2         0x0000000000007ffduL            // 32765

#define THRID_INDEX_SHIFT       0x00000000                      // 0
#define THRID_INDEX_BITS        0x0000000f                      // 15
#define THRID_REUSE_SHIFT       0x0000000f                      // 15
#define THRID_REUSE_BITS        0x00000031                      // 49

#define SCHEDQ_STATE_SHIFT      0x00000000                      // 0
#define SCHEDQ_STATE_BITS       0x00000004                      // 4
#define SCHEDQ_INS_SHIFT        0x00000004                      // 4
#define SCHEDQ_INS_BITS         0x0000000f                      // 15
#define SCHEDQ_INSPRV_SHIFT     0x00000013                      // 19
#define SCHEDQ_INSPRV_BITS      0x0000000f                      // 15
#define SCHEDQ_REMNXT_SHIFT     0x00000022                      // 34
#define SCHEDQ_REMNXT_BITS      0x0000000f                      // 15
#define SCHEDQ_REM_SHIFT        0x00000031                      // 49
#define SCHEDQ_REM_BITS         0x0000000f                      // 15
#define SCHEDQ_GEN_BITS         0x00000010                      // 16
#define SCHEDQ_RCNT_SHIFT       0x00000000                      // 0
#define SCHEDQ_RCNT_BITS        0x00000010                      // 16
#define SCHEDQ_RSER_SHIFT       0x00000010                      // 16
#define SCHEDQ_RSER_BITS        0x00000010                      // 16
#define SCHEDQ_ISER_SHIFT       0x00000020                      // 32
#define SCHEDQ_ISER_BITS        0x00000010                      // 16
#define SCHEDQ_ICNT_SHIFT       0x00000030                      // 48
#define SCHEDQ_ICNT_BITS        0x00000010                      // 16

#define SQ_PRIO_MAX             0x00000020                      // 32

#define THRLN_NEXT_BIT0_SHIFT   0x00000000                      // 0
#define THRLN_NEXT_BIT0_BITS    0x00000001                      // 1
#define THRLN_NEXT_TIX_SHIFT    0x00000001                      // 1
#define THRLN_NEXT_TIX_BITS     0x0000000f                      // 15
#define THRLN_NEXT_RSER_SHIFT   0x00000010                      // 16
#define THRLN_NEXT_RSER_BITS    0x00000010                      // 16
#define THRLN_NEXT_SQIX_SHIFT   0x00000020                      // 32
#define THRLN_NEXT_SQIX_BITS    0x00000010                      // 16
#define THRLN_NEXT_PAD_SHIFT    0x00000030                      // 48
#define THRLN_NEXT_PAD_BITS     0x0000000c                      // 12
#define THRLN_NEXT_HIGH_SHIFT   0x0000003c                      // 60
#define THRLN_NEXT_HIGH_BITS    0x00000004                      // 4

#define THRLN_PREV_BIT0_SHIFT   0x00000000                      // 0
#define THRLN_PREV_BIT0_BITS    0x00000001                      // 1
#define THRLN_PREV_TIX_SHIFT    0x00000001                      // 1
#define THRLN_PREV_TIX_BITS     0x0000000f                      // 15
#define THRLN_PREV_ISER_SHIFT   0x00000010                      // 16
#define THRLN_PREV_ISER_BITS    0x00000010                      // 16
#define THRLN_PREV_SQIX_SHIFT   0x00000020                      // 32
#define THRLN_PREV_SQIX_BITS    0x00000010                      // 16
#define THRLN_PREV_PAD_SHIFT    0x00000030                      // 48
#define THRLN_PREV_PAD_BITS     0x0000000c                      // 12
#define THRLN_PREV_HIGH_SHIFT   0x0000003c                      // 60
#define THRLN_PREV_HIGH_BITS    0x00000004                      // 4

#define THRLN_HIGH_VALUE        0x000000000000000auL            // 10

#define THRA_HOLD_SHIFT         0x00000000                      // 0
#define THRA_HOLD_BITS          0x00000010                      // 16
#define THRA_STATE_SHIFT        0x00000010                      // 16
#define THRA_STATE_BITS         0x00000003                      // 3
#define THRA_CANCEL_SHIFT       0x00000013                      // 19
#define THRA_CANCEL_BITS        0x00000001                      // 1
#define THRA_WAITTIMEDOUT_SHIFT 0x00000014                      // 20
#define THRA_WAITTIMEDOUT_BITS  0x00000001                      // 1
#define THRA_PAD_SHIFT          0x00000015                      // 21
#define THRA_PAD_BITS           0x0000001c                      // 28
#define THRA_LLASYNCNEXT_SHIFT  0x00000031                      // 49
#define THRA_LLASYNCNEXT_BITS   0x0000000f                      // 15
#define THRA_INDEX_SHIFT        0x00000000                      // 0
#define THRA_INDEX_BITS         0x0000000f                      // 15
#define THRA_REUSE_SHIFT        0x0000000f                      // 15
#define THRA_REUSE_BITS         0x00000031                      // 49

#define MTX_UNLOCKED            0x00000000                      // 0
#define MTX_LLLIST_EMPTY        0x00000000                      // 0

#define MTXA_LLWANT_SHIFT       0x00000000                      // 0
#define MTXA_LLWANT_BITS        0x0000000f                      // 15
#define MTXA_LLASYNC_SHIFT      0x0000000f                      // 15
#define MTXA_LLASYNC_BITS       0x0000000f                      // 15
#define MTXA_PADLO_BITS         0x00000012                      // 18
#define MTXA_RECCNT_SHIFT       0x00000030                      // 48
#define MTXA_RECCNT_BITS        0x00000010                      // 16
#define MTXA_OWNER_SHIFT        0x00000000                      // 0
#define MTXA_OWNER_BITS         0x0000000f                      // 15
#define MTXA_TYPE_SHIFT         0x0000000f                      // 15
#define MTXA_TYPE_BITS          0x00000002                      // 2
#define MTXA_PADHI_BITS         0x00000006                      // 6
#define MTXA_REUSE_SHIFT        0x00000017                      // 23
#define MTXA_REUSE_BITS         0x00000029                      // 41

// thrattr_t
#define SIZEOF_thrattr_t        0x00000020                      // 32

// thr_t
#define SIZEOF_thr_t            0x00000040                      // 64
#define thr_ln                  0x00000030
#define thr_core                0x00000018
#define thr_running             0x00000017

// cpu_t
#define SIZEOF_cpu_t            0x00000100                      // 256
#define cpu_running_thr         0x00000000
#define cpu_enabled             0x00000047
#define ENABLED_FROM_CPUCTX     -9
#define TRAMPOLINE_FROM_CPUCTX  -8

// ctx_t
#define ctx_fpctx               0x00000000
#define ctx_pc                  0x00000008
#define ctx_sp                  0x00000010
#define ctx_rbp                 0x00000018
#define ctx_r12                 0x00000028
#define ctx_r13                 0x00000030
#define ctx_r14                 0x00000038
#define ctx_r15                 0x00000040
#define ctx_rbx                 0x00000020
#define ctx_rax                 0x00000050
#define ctx_rcx                 0x00000058
#define ctx_rdx                 0x00000060
#define ctx_rdi                 0x00000068
#define ctx_rsi                 0x00000070
#define ctx_r8                  0x00000078
#define ctx_r9                  0x00000080
#define ctx_r10                 0x00000088
#define ctx_r11                 0x00000090
#define ctx_flags               0x00000048
