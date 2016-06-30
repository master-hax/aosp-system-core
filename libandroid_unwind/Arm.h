/*
 * Copyright (C) 2016 The Android Open Source Project
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

#ifndef _LIBANDROID_UNWIND_ARM_H
#define _LIBANDROID_UNWIND_ARM_H

typedef uint32_t arm_ptr_t;
typedef uint32_t arm_reg_t;

enum ArmRegs : size_t {
  ARM_SP = 13,
  ARM_LR = 14,
  ARM_PC = 15,
};

struct StateArm {
  arm_reg_t regs[16];
  arm_ptr_t cfa;
};

#endif  // _LIBANDROID_UNWIND_ARM_H
