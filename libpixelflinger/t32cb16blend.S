/* libs/pixelflinger/t32cb16blend.S
**
** Copyright 2006, The Android Open Source Project
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
	.align
	
	.global scanline_t32cb16blend_arm

// uses r6, r7, lr

.macro pixel,   DREG, SRC, FB, OFFSET

    // SRC = AARRGGBB
    mov     r7, \SRC, lsr #24           // sA
    add     r7, r7, r7, lsr #7          // sA + (sA >> 7)
    rsb     r7, r7, #0x100              // sA = 0x100 - (sA+(sA>>7))

1:

.if \OFFSET

    // red
    mov     lr, \DREG, lsr #(\OFFSET + 6 + 5)
#ifndef __ARM_ARCH_4T__
    smulbb  lr, r7, lr
#else
    lsl     lr, lr, #16
    lsr     lr, lr, #16
    lsl     r6, r7, #16
    lsr     r6, r6, #16
    mul     lr, r6, lr
#endif
    mov     r6, \SRC, lsr #3
    and     r6, r6, #0x1F
    add     lr, r6, lr, lsr #8
    orr     \FB, lr, lsl #(\OFFSET + 11)

        // green
        and     r6, \DREG, #(0x3F<<(\OFFSET + 5))
#ifndef __ARM_ARCH_4T__
        smulbt  r6, r7, r6
#else
        lsr     r6, r6, #16
        lsl     lr, r7, #16
        lsr     lr, lr, #16
        mul     r6, lr, r6
#endif
        mov     lr, \SRC, lsr #(8+2)
        and     lr, lr, #0x3F
        add     r6, lr, r6, lsr #(5+8)
        orr     \FB, \FB, r6, lsl #(\OFFSET + 5)

            // blue
            and     lr, \DREG, #(0x1F << \OFFSET)
#ifndef __ARM_ARCH_4T__
            smulbt  lr, r7, lr
#else
            lsr     lr, lr, #16
            lsl     r6, r7, #16
            lsr     r6, r6, #16
            mul     lr, r6, lr
#endif
            mov     r6, \SRC, lsr #(8+8+3)
            and     r6, r6, #0x1F
            add     lr, r6, lr, lsr #8
            orr     \FB, \FB, lr, lsl #\OFFSET

.else

    // red
    mov     lr, \DREG, lsr #(6+5)
    and     lr, lr, #0x1F
#ifndef __ARM_ARCH_4T__
    smulbb  lr, r7, lr
#else
    lsl     lr, lr, #16
    lsr     lr, lr, #16
    lsl     r6, r7, #16
    lsr     r6, r6, #16
    mul     lr, r6, lr
#endif
    mov     r6, \SRC, lsr #3
    and     r6, r6, #0x1F
    add     lr, r6, lr, lsr #8
    mov     \FB, lr, lsl #11

        // green
        and     r6, \DREG, #(0x3F<<5)
#ifndef __ARM_ARCH_4T__
        smulbb  r6, r7, r6
#else
        lsl     r6, r6, #16
        lsr     r6, r6, #16
        lsl     lr, r7, #16
        lsr     lr, lr, #16
        mul     r6, lr, r6
#endif
        mov     lr, \SRC, lsr #(8+2)
        and     lr, lr, #0x3F
        add     r6, lr, r6, lsr #(5+8)
        orr     \FB, \FB, r6, lsl #5

            // blue
            and     lr, \DREG, #0x1F
#ifndef __ARM_ARCH_4T__
            smulbb  lr, r7, lr
#else
            lsl     lr, lr, #16
            lsr     lr, lr, #16
            lsl     r6, r7, #16
            lsr     r6, r6, #16
            mul     lr, r6, lr
#endif
            mov     r6, \SRC, lsr #(8+8+3)
            and     r6, r6, #0x1F
            add     lr, r6, lr, lsr #8
            orr     \FB, \FB, lr

.endif

    .endm
    

// r0:  dst ptr
// r1:  src ptr
// r2:  count
// r3:  d
// r4:  s0
// r5:  s1
// r6:  pixel
// r7:  pixel
// r8:  free
// r9:  free
// r10: free
// r11: free
// r12: scratch
// r14: pixel

scanline_t32cb16blend_arm:
    stmfd	sp!, {r4-r7, lr}

#ifndef __ARM_ARCH_4T__
    pld     [r0]
    pld     [r1]
#endif

    // align DST to 32 bits
    tst     r0, #0x3
    beq     aligned
    subs    r2, r2, #1
    ldmlofd	sp!, {r4-r7, lr}        // return
    bxlo    lr

last:
    ldr     r4, [r1], #4
    ldrh    r3, [r0]
    pixel   r3, r4, r12, 0
    strh    r12, [r0], #2

aligned:
    subs    r2, r2, #2
    blo     9f

    // The main loop is unrolled twice and process 4 pixels
8:  ldmia   r1!, {r4, r5}
    // stream the source
#ifndef __ARM_ARCH_4T__
    pld     [r1, #32]
#endif
    add     r0, r0, #4
    // it's all zero, skip this pixel
    orrs    r3, r4, r5
    beq     7f
    
    // load the destination
    ldr     r3, [r0, #-4]
    // stream the destination
#ifndef __ARM_ARCH_4T__
    pld     [r0, #32]
#endif
    pixel   r3, r4, r12, 0
    pixel   r3, r5, r12, 16
    // effectively, we're getting write-combining by virtue of the
    // cpu's write-back cache.
    str     r12, [r0, #-4]

    // 2nd iterration of the loop, don't stream anything
    subs    r2, r2, #2
    movlt   r4, r5
    blt     9f
    ldmia   r1!, {r4, r5}
    add     r0, r0, #4
    orrs    r3, r4, r5
    beq     7f
    ldr     r3, [r0, #-4]
    pixel   r3, r4, r12, 0
    pixel   r3, r5, r12, 16
    str     r12, [r0, #-4]

    
7:  subs    r2, r2, #2
    bhs     8b
    mov     r4, r5

9:  adds    r2, r2, #1
    ldmlofd sp!, {r4-r7, lr}        // return
    bxlo    lr
    b       last

