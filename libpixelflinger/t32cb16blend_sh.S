/* libs/pixelflinger/t32cb16blend_sh.S
**
** Copyright 2009, The Android Open Source Project
**
** Licensed under the Apache License, Version 2.0 (the "License");
** you may not use this file except in compliance with the License.
** You may obtain a copy of the License at
**
**     http://www.apache.org/licenses/LICENSE-2.0
**
** Unless required by applicable law or agreed to in writing, software
** distributed under the License is distributed on an "AS IS" BASIS,
** WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
** See the License for the specific language governing permissions and
** limitations under the License.
*/

    .text
    .align 4
    .global scanline_t32cb16blend_sh

// r0: rtn
// r1: work
// r2: work
// r3: work
// r4: dst ptr
// r5: src ptr
// r6: count
// r7: d
// r8: s
// r9: f
// r10: 100
// r11:
// r12:
// r13:
// r14:
// r15: sp

scanline_t32cb16blend_sh:
    mov.l   r8,@-r15
    mov.l   r9,@-r15
    mov.l   r10,@-r15
    mov.w   data,r10    // 100

    add     #-1,r6      // count--
    mov     r6,r0
    cmp/eq  #-1,r0
    bt.s    last

loop:
    mov.l   @r5+,r8     // (src)->r8
    tst     r8,r8       // (src)==0
    bt.s    continue

    mov.w   @r4,r0      // (dst)->r7
    mov     r8,r1
    extu.w  r0,r7
    shlr16  r1          // (src)>>16
    mov     r10,r9
    shlr8   r1          // (src)>>8 (>>24) -> f
    mov     #-7,r0
    sub     r1,r9       // 100-f
    shld    r0,r1       // f>>7
    mov     r7,r0
    sub     r1,r9       // 100- f - f>>7

    // Red
    mov     #-11,r1
    shld    r1,r0       // (dst)>>11
    mulu.w  r9,r0       // f*dR
    mov     #-3,r1
    sts     macl,r3
    mov     r8,r0
    shlr8   r3          // (f*dR)>>8
    shld    r1,r0       // (d>>3)
    and     #31,r0
    mov     #11,r1
    add     r0,r3       // sR+=(f*dR)>>8
    mov     r7,r0
    shld    r1, r3      // sR<<11

    // Green
    mov     #-5,r1
    shld    r1,r0       // (d>>5)
    and     #63,r0      // dG=(d>>5)&0x3F
    mulu.w  r9,r0       // f*dG
    mov     #-10,r1
    sts     macl,r2
    mov     r8,r0
    shlr8   r2          // (f*dG)>>8;
    shld    r1,r0       // (d>>10)
    and     #63,r0      // sG=(s>>10)&0x3F
    mov     #5,r1
    add     r0,r2       // sG+=(f*dG)>>8

    // Blue
    mov     r7,r0
    shld    r1, r2      // sG<<5
    and     #31,r0      // d&0x1F
    or      r2,r3       // (dst) |= (sG<<5)
    mulu.w  r9,r0       // f*dB
    mov     r8,r0
    sts     macl,r1
    mov     #-19,r7
    shlr8   r1          // (f*dB)>>8
    shld    r7,r0       // sB=(s>>19)
    and     #31,r0      // sB=(s>>19)&0x1F
    add     r0,r1       // sB+=(f*dB)>>8
    or      r1,r3       // (dst) |= sB

    mov.w   r3,@r4

continue:
    add     #-1,r6      // count--
    mov     r6,r0
    cmp/eq  #-1,r0
    bf.s    loop
    add     #2,r4       // dst++

last:
    mov.l   @r15+,r10
    mov.l   @r15+,r9
    mov.l   @r15+,r8
    rts
    nop

data:           .word 0x0100

