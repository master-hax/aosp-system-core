/*
 * Copyright (C) 2008 The Android Open Source Project
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
/*
 * The ARM architecture provides a number of different versions, each with 
 * a different set of capabilities. This file provides macros that enable
 * assembly source code to be more portable between versions. Each macro
 * matches the name of the asm instruction it conditionalises.
 *
 * Note: It is not feasible to provide macros to hide all differences, and
 * in these cases conditional compilation, or separate files should be used.
 */
#ifndef _ASM_MACROS_H
#define _ASM_MACROS_H

/*
 * The preload instruction is simply a hint to the cache infrastructure.
 * As it does not otherwise change the state of the processor it is safe
 * to simply ignore this instruction.
 */
#if defined(ARCH_ARM_HAVE_PLD)
#define PLD(x, y) pld x, y
#else
#define PLD(x, y)
#endif

/*
 * On architecture versions that do not support THUMB the branch and
 * exchange instruction does not exist, however the mov<cc> pc, <reg>
 * pattern is equivalent.
 */
#if defined(ARCH_ARM_HAVE_THUMB_SUPPORT)
#define BX(reg) bx reg
#define BXNE(reg) bxne reg
#define BXEQ(reg) bxeq reg
#define BXLS(reg) bxls reg
#define BXLE(reg) bxle reg
#define BXMI(reg) bxmi reg
#define BXPL(reg) bxpl reg
#else
#define BX(reg) mov pc, reg
#define BXNE(reg) movne pc, reg
#define BXEQ(reg) moveq pc, reg
#define BXLS(reg) movls pc, reg
#define BXLE(reg) movle pc, reg
#define BXMI(reg) movmi pc, reg
#define BXPL(reg) movpl pc, reg
#endif

#endif /* _ASM_MACROS_H */
