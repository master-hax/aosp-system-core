/*
 * Copyright (C) 2024 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *        http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <stdio.h>

#define TO_STRING_EXP(DEF) #DEF
#define TO_STRING(DEF) TO_STRING_EXP(DEF)

void printArm32TargetFeatures() {
// Defines chosen from clang/test/Preprocessor/arm-target-features.c
#if defined(__ARM_ARCH)
    printf("%s=%s\n", TO_STRING_EXP(__ARM_ARCH), TO_STRING(__ARM_ARCH));
#else
    printf("%s not defined\n", TO_STRING_EXP(__ARM_ARCH));
#endif
#if defined(__ARM_ARCH_7A__)
    printf("%s=%s\n", TO_STRING_EXP(__ARM_ARCH_7A__), TO_STRING(__ARM_ARCH_7A__));
#else
    printf("%s not defined\n", TO_STRING_EXP(__ARM_ARCH_7A__));
#endif
#if defined(_ARM_ARCH_7S__)
    printf("%s=%s\n", TO_STRING_EXP(_ARM_ARCH_7S__), TO_STRING(_ARM_ARCH_7S__));
#else
    printf("%s not defined\n", TO_STRING_EXP(_ARM_ARCH_7S__));
#endif
#if defined(__ARM_ARCH_7VE__)
    printf("%s=%s\n", TO_STRING_EXP(__ARM_ARCH_7VE__), TO_STRING(__ARM_ARCH_7VE__));
#else
    printf("%s not defined\n", TO_STRING_EXP(__ARM_ARCH_7VE__));
#endif
#if defined(__ARM_ARCH_8_1A__)
    printf("%s=%s\n", TO_STRING_EXP(__ARM_ARCH_8_1A__), TO_STRING(__ARM_ARCH_8_1A__));
#else
    printf("%s not defined\n", TO_STRING_EXP(__ARM_ARCH_8_1A__));
#endif
#if defined(__ARM_ARCH_8_1M_MAIN__)
    printf("%s=%s\n", TO_STRING_EXP(__ARM_ARCH_8_1M_MAIN__), TO_STRING(__ARM_ARCH_8_1M_MAIN__));
#else
    printf("%s not defined\n", TO_STRING_EXP(__ARM_ARCH_8_1M_MAIN__));
#endif
#if defined(__ARM_ARCH_8_2A__)
    printf("%s=%s\n", TO_STRING_EXP(__ARM_ARCH_8_2A__), TO_STRING(__ARM_ARCH_8_2A__));
#else
    printf("%s not defined\n", TO_STRING_EXP(__ARM_ARCH_8_2A__));
#endif
#if defined(__ARM_ARCH_8_3A__)
    printf("%s=%s\n", TO_STRING_EXP(__ARM_ARCH_8_3A__), TO_STRING(__ARM_ARCH_8_3A__));
#else
    printf("%s not defined\n", TO_STRING_EXP(__ARM_ARCH_8_3A__));
#endif
#if defined(__ARM_ARCH_8_4A__)
    printf("%s=%s\n", TO_STRING_EXP(__ARM_ARCH_8_4A__), TO_STRING(__ARM_ARCH_8_4A__));
#else
    printf("%s not defined\n", TO_STRING_EXP(__ARM_ARCH_8_4A__));
#endif
#if defined(__ARM_ARCH_8_5A__)
    printf("%s=%s\n", TO_STRING_EXP(__ARM_ARCH_8_5A__), TO_STRING(__ARM_ARCH_8_5A__));
#else
    printf("%s not defined\n", TO_STRING_EXP(__ARM_ARCH_8_5A__));
#endif
#if defined(__ARM_ARCH_8_6A__)
    printf("%s=%s\n", TO_STRING_EXP(__ARM_ARCH_8_6A__), TO_STRING(__ARM_ARCH_8_6A__));
#else
    printf("%s not defined\n", TO_STRING_EXP(__ARM_ARCH_8_6A__));
#endif
#if defined(__ARM_ARCH_8_7A__)
    printf("%s=%s\n", TO_STRING_EXP(__ARM_ARCH_8_7A__), TO_STRING(__ARM_ARCH_8_7A__));
#else
    printf("%s not defined\n", TO_STRING_EXP(__ARM_ARCH_8_7A__));
#endif
#if defined(__ARM_ARCH_8_8A__)
    printf("%s=%s\n", TO_STRING_EXP(__ARM_ARCH_8_8A__), TO_STRING(__ARM_ARCH_8_8A__));
#else
    printf("%s not defined\n", TO_STRING_EXP(__ARM_ARCH_8_8A__));
#endif
#if defined(__ARM_ARCH_8_9A__)
    printf("%s=%s\n", TO_STRING_EXP(__ARM_ARCH_8_9A__), TO_STRING(__ARM_ARCH_8_9A__));
#else
    printf("%s not defined\n", TO_STRING_EXP(__ARM_ARCH_8_9A__));
#endif
#if defined(__ARM_ARCH_8A__)
    printf("%s=%s\n", TO_STRING_EXP(__ARM_ARCH_8A__), TO_STRING(__ARM_ARCH_8A__));
#else
    printf("%s not defined\n", TO_STRING_EXP(__ARM_ARCH_8A__));
#endif
#if defined(__ARM_ARCH_8M_BASE__)
    printf("%s=%s\n", TO_STRING_EXP(__ARM_ARCH_8M_BASE__), TO_STRING(__ARM_ARCH_8M_BASE__));
#else
    printf("%s not defined\n", TO_STRING_EXP(__ARM_ARCH_8M_BASE__));
#endif
#if defined(__ARM_ARCH_8M_MAIN__)
    printf("%s=%s\n", TO_STRING_EXP(__ARM_ARCH_8M_MAIN__), TO_STRING(__ARM_ARCH_8M_MAIN__));
#else
    printf("%s not defined\n", TO_STRING_EXP(__ARM_ARCH_8M_MAIN__));
#endif
#if defined(__ARM_ARCH_8R__)
    printf("%s=%s\n", TO_STRING_EXP(__ARM_ARCH_8R__), TO_STRING(__ARM_ARCH_8R__));
#else
    printf("%s not defined\n", TO_STRING_EXP(__ARM_ARCH_8R__));
#endif
#if defined(__ARM_ARCH_9_1A__)
    printf("%s=%s\n", TO_STRING_EXP(__ARM_ARCH_9_1A__), TO_STRING(__ARM_ARCH_9_1A__));
#else
    printf("%s not defined\n", TO_STRING_EXP(__ARM_ARCH_9_1A__));
#endif
#if defined(__ARM_ARCH_9_2A__)
    printf("%s=%s\n", TO_STRING_EXP(__ARM_ARCH_9_2A__), TO_STRING(__ARM_ARCH_9_2A__));
#else
    printf("%s not defined\n", TO_STRING_EXP(__ARM_ARCH_9_2A__));
#endif
#if defined(__ARM_ARCH_9_3A__)
    printf("%s=%s\n", TO_STRING_EXP(__ARM_ARCH_9_3A__), TO_STRING(__ARM_ARCH_9_3A__));
#else
    printf("%s not defined\n", TO_STRING_EXP(__ARM_ARCH_9_3A__));
#endif
#if defined(__ARM_ARCH_9_4A__)
    printf("%s=%s\n", TO_STRING_EXP(__ARM_ARCH_9_4A__), TO_STRING(__ARM_ARCH_9_4A__));
#else
    printf("%s not defined\n", TO_STRING_EXP(__ARM_ARCH_9_4A__));
#endif
#if defined(__ARM_ARCH_9_5A__)
    printf("%s=%s\n", TO_STRING_EXP(__ARM_ARCH_9_5A__), TO_STRING(__ARM_ARCH_9_5A__));
#else
    printf("%s not defined\n", TO_STRING_EXP(__ARM_ARCH_9_5A__));
#endif
#if defined(__ARM_ARCH_9A__)
    printf("%s=%s\n", TO_STRING_EXP(__ARM_ARCH_9A__), TO_STRING(__ARM_ARCH_9A__));
#else
    printf("%s not defined\n", TO_STRING_EXP(__ARM_ARCH_9A__));
#endif
#if defined(__ARM_ARCH_EXT_IDIV__)
    printf("%s=%s\n", TO_STRING_EXP(__ARM_ARCH_EXT_IDIV__), TO_STRING(__ARM_ARCH_EXT_IDIV__));
#else
    printf("%s not defined\n", TO_STRING_EXP(__ARM_ARCH_EXT_IDIV__));
#endif
#if defined(__ARM_ARCH_ISA_THUMB)
    printf("%s=%s\n", TO_STRING_EXP(__ARM_ARCH_ISA_THUMB), TO_STRING(__ARM_ARCH_ISA_THUMB));
#else
    printf("%s not defined\n", TO_STRING_EXP(__ARM_ARCH_ISA_THUMB));
#endif
#if defined(__ARM_BF16_FORMAT_ALTERNATIVE)
    printf("%s=%s\n", TO_STRING_EXP(__ARM_BF16_FORMAT_ALTERNATIVE),
           TO_STRING(__ARM_BF16_FORMAT_ALTERNATIVE));
#else
    printf("%s not defined\n", TO_STRING_EXP(__ARM_BF16_FORMAT_ALTERNATIVE));
#endif
#if defined(__ARM_DWARF_EH__)
    printf("%s=%s\n", TO_STRING_EXP(__ARM_DWARF_EH__), TO_STRING(__ARM_DWARF_EH__));
#else
    printf("%s not defined\n", TO_STRING_EXP(__ARM_DWARF_EH__));
#endif
#if defined(__ARMEL__)
    printf("%s=%s\n", TO_STRING_EXP(__ARMEL__), TO_STRING(__ARMEL__));
#else
    printf("%s not defined\n", TO_STRING_EXP(__ARMEL__));
#endif
#if defined(__ARM_FEATURE_AES)
    printf("%s=%s\n", TO_STRING_EXP(__ARM_FEATURE_AES), TO_STRING(__ARM_FEATURE_AES));
#else
    printf("%s not defined\n", TO_STRING_EXP(__ARM_FEATURE_AES));
#endif
#if defined(__ARM_FEATURE_BF16)
    printf("%s=%s\n", TO_STRING_EXP(__ARM_FEATURE_BF16), TO_STRING(__ARM_FEATURE_BF16));
#else
    printf("%s not defined\n", TO_STRING_EXP(__ARM_FEATURE_BF16));
#endif
#if defined(__ARM_FEATURE_BF16_VECTOR_ARITHMETIC)
    printf("%s=%s\n", TO_STRING_EXP(__ARM_FEATURE_BF16_VECTOR_ARITHMETIC),
           TO_STRING(__ARM_FEATURE_BF16_VECTOR_ARITHMETIC));
#else
    printf("%s not defined\n", TO_STRING_EXP(__ARM_FEATURE_BF16_VECTOR_ARITHMETIC));
#endif
#if defined(__ARM_FEATURE_BTI)
    printf("%s=%s\n", TO_STRING_EXP(__ARM_FEATURE_BTI), TO_STRING(__ARM_FEATURE_BTI));
#else
    printf("%s not defined\n", TO_STRING_EXP(__ARM_FEATURE_BTI));
#endif
#if defined(__ARM_FEATURE_BTI_DEFAULT)
    printf("%s=%s\n", TO_STRING_EXP(__ARM_FEATURE_BTI_DEFAULT),
           TO_STRING(__ARM_FEATURE_BTI_DEFAULT));
#else
    printf("%s not defined\n", TO_STRING_EXP(__ARM_FEATURE_BTI_DEFAULT));
#endif
#if defined(__ARM_FEATURE_CDE)
    printf("%s=%s\n", TO_STRING_EXP(__ARM_FEATURE_CDE), TO_STRING(__ARM_FEATURE_CDE));
#else
    printf("%s not defined\n", TO_STRING_EXP(__ARM_FEATURE_CDE));
#endif
#if defined(__ARM_FEATURE_CDE_COPROC)
    printf("%s=%s\n", TO_STRING_EXP(__ARM_FEATURE_CDE_COPROC), TO_STRING(__ARM_FEATURE_CDE_COPROC));
#else
    printf("%s not defined\n", TO_STRING_EXP(__ARM_FEATURE_CDE_COPROC));
#endif
#if defined(__ARM_FEATURE_CMSE)
    printf("%s=%s\n", TO_STRING_EXP(__ARM_FEATURE_CMSE), TO_STRING(__ARM_FEATURE_CMSE));
#else
    printf("%s not defined\n", TO_STRING_EXP(__ARM_FEATURE_CMSE));
#endif
#if defined(__ARM_FEATURE_COMPLEX)
    printf("%s=%s\n", TO_STRING_EXP(__ARM_FEATURE_COMPLEX), TO_STRING(__ARM_FEATURE_COMPLEX));
#else
    printf("%s not defined\n", TO_STRING_EXP(__ARM_FEATURE_COMPLEX));
#endif
#if defined(__ARM_FEATURE_CRC32)
    printf("%s=%s\n", TO_STRING_EXP(__ARM_FEATURE_CRC32), TO_STRING(__ARM_FEATURE_CRC32));
#else
    printf("%s not defined\n", TO_STRING_EXP(__ARM_FEATURE_CRC32));
#endif
#if defined(__ARM_FEATURE_CRYPTO)
    printf("%s=%s\n", TO_STRING_EXP(__ARM_FEATURE_CRYPTO), TO_STRING(__ARM_FEATURE_CRYPTO));
#else
    printf("%s not defined\n", TO_STRING_EXP(__ARM_FEATURE_CRYPTO));
#endif
#if defined(__ARM_FEATURE_DIRECTED_ROUNDING)
    printf("%s=%s\n", TO_STRING_EXP(__ARM_FEATURE_DIRECTED_ROUNDING),
           TO_STRING(__ARM_FEATURE_DIRECTED_ROUNDING));
#else
    printf("%s not defined\n", TO_STRING_EXP(__ARM_FEATURE_DIRECTED_ROUNDING));
#endif
#if defined(__ARM_FEATURE_DOTPROD)
    printf("%s=%s\n", TO_STRING_EXP(__ARM_FEATURE_DOTPROD), TO_STRING(__ARM_FEATURE_DOTPROD));
#else
    printf("%s not defined\n", TO_STRING_EXP(__ARM_FEATURE_DOTPROD));
#endif
#if defined(__ARM_FEATURE_DSP)
    printf("%s=%s\n", TO_STRING_EXP(__ARM_FEATURE_DSP), TO_STRING(__ARM_FEATURE_DSP));
#else
    printf("%s not defined\n", TO_STRING_EXP(__ARM_FEATURE_DSP));
#endif
#if defined(__ARM_FEATURE_FP16_SCALAR_ARITHMETIC)
    printf("%s=%s\n", TO_STRING_EXP(__ARM_FEATURE_FP16_SCALAR_ARITHMETIC),
           TO_STRING(__ARM_FEATURE_FP16_SCALAR_ARITHMETIC));
#else
    printf("%s not defined\n", TO_STRING_EXP(__ARM_FEATURE_FP16_SCALAR_ARITHMETIC));
#endif
#if defined(__ARM_FEATURE_FP16_VECTOR_ARITHMETIC)
    printf("%s=%s\n", TO_STRING_EXP(__ARM_FEATURE_FP16_VECTOR_ARITHMETIC),
           TO_STRING(__ARM_FEATURE_FP16_VECTOR_ARITHMETIC));
#else
    printf("%s not defined\n", TO_STRING_EXP(__ARM_FEATURE_FP16_VECTOR_ARITHMETIC));
#endif
#if defined(__ARM_FEATURE_MVE)
    printf("%s=%s\n", TO_STRING_EXP(__ARM_FEATURE_MVE), TO_STRING(__ARM_FEATURE_MVE));
#else
    printf("%s not defined\n", TO_STRING_EXP(__ARM_FEATURE_MVE));
#endif
#if defined(__ARM_FEATURE_NUMERIC_MAXMIN)
    printf("%s=%s\n", TO_STRING_EXP(__ARM_FEATURE_NUMERIC_MAXMIN),
           TO_STRING(__ARM_FEATURE_NUMERIC_MAXMIN));
#else
    printf("%s not defined\n", TO_STRING_EXP(__ARM_FEATURE_NUMERIC_MAXMIN));
#endif
#if defined(__ARM_FEATURE_PAC_DEFAULT)
    printf("%s=%s\n", TO_STRING_EXP(__ARM_FEATURE_PAC_DEFAULT),
           TO_STRING(__ARM_FEATURE_PAC_DEFAULT));
#else
    printf("%s not defined\n", TO_STRING_EXP(__ARM_FEATURE_PAC_DEFAULT));
#endif
#if defined(__ARM_FEATURE_PAUTH)
    printf("%s=%s\n", TO_STRING_EXP(__ARM_FEATURE_PAUTH), TO_STRING(__ARM_FEATURE_PAUTH));
#else
    printf("%s not defined\n", TO_STRING_EXP(__ARM_FEATURE_PAUTH));
#endif
#if defined(__ARM_FEATURE_QRDMX)
    printf("%s=%s\n", TO_STRING_EXP(__ARM_FEATURE_QRDMX), TO_STRING(__ARM_FEATURE_QRDMX));
#else
    printf("%s not defined\n", TO_STRING_EXP(__ARM_FEATURE_QRDMX));
#endif
#if defined(__ARM_FEATURE_SHA2)
    printf("%s=%s\n", TO_STRING_EXP(__ARM_FEATURE_SHA2), TO_STRING(__ARM_FEATURE_SHA2));
#else
    printf("%s not defined\n", TO_STRING_EXP(__ARM_FEATURE_SHA2));
#endif
#if defined(__ARM_FEATURE_SIMD32)
    printf("%s=%s\n", TO_STRING_EXP(__ARM_FEATURE_SIMD32), TO_STRING(__ARM_FEATURE_SIMD32));
#else
    printf("%s not defined\n", TO_STRING_EXP(__ARM_FEATURE_SIMD32));
#endif
#if defined(__ARM_FP)
    printf("%s=%s\n", TO_STRING_EXP(__ARM_FP), TO_STRING(__ARM_FP));
#else
    printf("%s not defined\n", TO_STRING_EXP(__ARM_FP));
#endif
#if defined(__ARM_FP16_ARGS)
    printf("%s=%s\n", TO_STRING_EXP(__ARM_FP16_ARGS), TO_STRING(__ARM_FP16_ARGS));
#else
    printf("%s not defined\n", TO_STRING_EXP(__ARM_FP16_ARGS));
#endif
#if defined(__ARM_FP16_FORMAT_IEEE)
    printf("%s=%s\n", TO_STRING_EXP(__ARM_FP16_FORMAT_IEEE), TO_STRING(__ARM_FP16_FORMAT_IEEE));
#else
    printf("%s not defined\n", TO_STRING_EXP(__ARM_FP16_FORMAT_IEEE));
#endif
#if defined(__ARM_FP_FAST)
    printf("%s=%s\n", TO_STRING_EXP(__ARM_FP_FAST), TO_STRING(__ARM_FP_FAST));
#else
    printf("%s not defined\n", TO_STRING_EXP(__ARM_FP_FAST));
#endif
#if defined(__ARM_FPV5__)
    printf("%s=%s\n", TO_STRING_EXP(__ARM_FPV5__), TO_STRING(__ARM_FPV5__));
#else
    printf("%s not defined\n", TO_STRING_EXP(__ARM_FPV5__));
#endif
#if defined(__ARM_NEON__)
    printf("%s=%s\n", TO_STRING_EXP(__ARM_NEON__), TO_STRING(__ARM_NEON__));
#else
    printf("%s not defined\n", TO_STRING_EXP(__ARM_NEON__));
#endif
#if defined(__ARM_PCS)
    printf("%s=%s\n", TO_STRING_EXP(__ARM_PCS), TO_STRING(__ARM_PCS));
#else
    printf("%s not defined\n", TO_STRING_EXP(__ARM_PCS));
#endif
#if defined(__ARM_PCS_VFP)
    printf("%s=%s\n", TO_STRING_EXP(__ARM_PCS_VFP), TO_STRING(__ARM_PCS_VFP));
#else
    printf("%s not defined\n", TO_STRING_EXP(__ARM_PCS_VFP));
#endif
#if defined(__ARM_SIZEOF_MINIMAL_ENUM)
    printf("%s=%s\n", TO_STRING_EXP(__ARM_SIZEOF_MINIMAL_ENUM),
           TO_STRING(__ARM_SIZEOF_MINIMAL_ENUM));
#else
    printf("%s not defined\n", TO_STRING_EXP(__ARM_SIZEOF_MINIMAL_ENUM));
#endif
#if defined(__ARM_SIZEOF_WCHAR_T)
    printf("%s=%s\n", TO_STRING_EXP(__ARM_SIZEOF_WCHAR_T), TO_STRING(__ARM_SIZEOF_WCHAR_T));
#else
    printf("%s not defined\n", TO_STRING_EXP(__ARM_SIZEOF_WCHAR_T));
#endif
#if defined(__ARM_VFPV4__)
    printf("%s=%s\n", TO_STRING_EXP(__ARM_VFPV4__), TO_STRING(__ARM_VFPV4__));
#else
    printf("%s not defined\n", TO_STRING_EXP(__ARM_VFPV4__));
#endif
#if defined(__GCC_HAVE_SYNC_COMPARE_AND_SWAP_1)
    printf("%s=%s\n", TO_STRING_EXP(__GCC_HAVE_SYNC_COMPARE_AND_SWAP_1),
           TO_STRING(__GCC_HAVE_SYNC_COMPARE_AND_SWAP_1));
#else
    printf("%s not defined\n", TO_STRING_EXP(__GCC_HAVE_SYNC_COMPARE_AND_SWAP_1));
#endif
#if defined(__VFP_FP__)
    printf("%s=%s\n", TO_STRING_EXP(__VFP_FP__), TO_STRING(__VFP_FP__));
#else
    printf("%s not defined\n", TO_STRING_EXP(__VFP_FP__));
#endif
}

void printAarch64TargetFeatures() {
// Defines chosen from clang/test/Preprocessor/aarch64-target-features.c
#if defined(__AARCH64EL__)
    printf("%s=%s\n", TO_STRING_EXP(__AARCH64EL__), TO_STRING(__AARCH64EL__));
#else
    printf("%s not defined\n", TO_STRING_EXP(__AARCH64EL__));
#endif
#if defined(__ARM_64BIT_STATE)
    printf("%s=%s\n", TO_STRING_EXP(__ARM_64BIT_STATE), TO_STRING(__ARM_64BIT_STATE));
#else
    printf("%s not defined\n", TO_STRING_EXP(__ARM_64BIT_STATE));
#endif
#if defined(__ARM_ACLE)
    printf("%s=%s\n", TO_STRING_EXP(__ARM_ACLE), TO_STRING(__ARM_ACLE));
#else
    printf("%s not defined\n", TO_STRING_EXP(__ARM_ACLE));
#endif
#if defined(__ARM_ALIGN_MAX_STACK_PWR)
    printf("%s=%s\n", TO_STRING_EXP(__ARM_ALIGN_MAX_STACK_PWR),
           TO_STRING(__ARM_ALIGN_MAX_STACK_PWR));
#else
    printf("%s not defined\n", TO_STRING_EXP(__ARM_ALIGN_MAX_STACK_PWR));
#endif
#if defined(__ARM_ARCH)
    printf("%s=%s\n", TO_STRING_EXP(__ARM_ARCH), TO_STRING(__ARM_ARCH));
#else
    printf("%s not defined\n", TO_STRING_EXP(__ARM_ARCH));
#endif
#if defined(__ARM_ARCH_ISA_A64)
    printf("%s=%s\n", TO_STRING_EXP(__ARM_ARCH_ISA_A64), TO_STRING(__ARM_ARCH_ISA_A64));
#else
    printf("%s not defined\n", TO_STRING_EXP(__ARM_ARCH_ISA_A64));
#endif
#if defined(__ARM_BF16_FORMAT_ALTERNATIVE)
    printf("%s=%s\n", TO_STRING_EXP(__ARM_BF16_FORMAT_ALTERNATIVE),
           TO_STRING(__ARM_BF16_FORMAT_ALTERNATIVE));
#else
    printf("%s not defined\n", TO_STRING_EXP(__ARM_BF16_FORMAT_ALTERNATIVE));
#endif
#if defined(__ARM_BIG_ENDIAN)
    printf("%s=%s\n", TO_STRING_EXP(__ARM_BIG_ENDIAN), TO_STRING(__ARM_BIG_ENDIAN));
#else
    printf("%s not defined\n", TO_STRING_EXP(__ARM_BIG_ENDIAN));
#endif
#if defined(__ARM_FEATURE_AES)
    printf("%s=%s\n", TO_STRING_EXP(__ARM_FEATURE_AES), TO_STRING(__ARM_FEATURE_AES));
#else
    printf("%s not defined\n", TO_STRING_EXP(__ARM_FEATURE_AES));
#endif
#if defined(__ARM_FEATURE_ATOMICS)
    printf("%s=%s\n", TO_STRING_EXP(__ARM_FEATURE_ATOMICS), TO_STRING(__ARM_FEATURE_ATOMICS));
#else
    printf("%s not defined\n", TO_STRING_EXP(__ARM_FEATURE_ATOMICS));
#endif
#if defined(__ARM_FEATURE_BF16)
    printf("%s=%s\n", TO_STRING_EXP(__ARM_FEATURE_BF16), TO_STRING(__ARM_FEATURE_BF16));
#else
    printf("%s not defined\n", TO_STRING_EXP(__ARM_FEATURE_BF16));
#endif
#if defined(__ARM_FEATURE_BF16_SCALAR_ARITHMETIC)
    printf("%s=%s\n", TO_STRING_EXP(__ARM_FEATURE_BF16_SCALAR_ARITHMETIC),
           TO_STRING(__ARM_FEATURE_BF16_SCALAR_ARITHMETIC));
#else
    printf("%s not defined\n", TO_STRING_EXP(__ARM_FEATURE_BF16_SCALAR_ARITHMETIC));
#endif
#if defined(__ARM_FEATURE_BF16_VECTOR_ARITHMETIC)
    printf("%s=%s\n", TO_STRING_EXP(__ARM_FEATURE_BF16_VECTOR_ARITHMETIC),
           TO_STRING(__ARM_FEATURE_BF16_VECTOR_ARITHMETIC));
#else
    printf("%s not defined\n", TO_STRING_EXP(__ARM_FEATURE_BF16_VECTOR_ARITHMETIC));
#endif
#if defined(__ARM_FEATURE_BTI)
    printf("%s=%s\n", TO_STRING_EXP(__ARM_FEATURE_BTI), TO_STRING(__ARM_FEATURE_BTI));
#else
    printf("%s not defined\n", TO_STRING_EXP(__ARM_FEATURE_BTI));
#endif
#if defined(__ARM_FEATURE_BTI_DEFAULT)
    printf("%s=%s\n", TO_STRING_EXP(__ARM_FEATURE_BTI_DEFAULT),
           TO_STRING(__ARM_FEATURE_BTI_DEFAULT));
#else
    printf("%s not defined\n", TO_STRING_EXP(__ARM_FEATURE_BTI_DEFAULT));
#endif
#if defined(__ARM_FEATURE_CLZ)
    printf("%s=%s\n", TO_STRING_EXP(__ARM_FEATURE_CLZ), TO_STRING(__ARM_FEATURE_CLZ));
#else
    printf("%s not defined\n", TO_STRING_EXP(__ARM_FEATURE_CLZ));
#endif
#if defined(__ARM_FEATURE_COMPLEX)
    printf("%s=%s\n", TO_STRING_EXP(__ARM_FEATURE_COMPLEX), TO_STRING(__ARM_FEATURE_COMPLEX));
#else
    printf("%s not defined\n", TO_STRING_EXP(__ARM_FEATURE_COMPLEX));
#endif
#if defined(__ARM_FEATURE_CRC32)
    printf("%s=%s\n", TO_STRING_EXP(__ARM_FEATURE_CRC32), TO_STRING(__ARM_FEATURE_CRC32));
#else
    printf("%s not defined\n", TO_STRING_EXP(__ARM_FEATURE_CRC32));
#endif
#if defined(__ARM_FEATURE_CRYPTO)
    printf("%s=%s\n", TO_STRING_EXP(__ARM_FEATURE_CRYPTO), TO_STRING(__ARM_FEATURE_CRYPTO));
#else
    printf("%s not defined\n", TO_STRING_EXP(__ARM_FEATURE_CRYPTO));
#endif
#if defined(__ARM_FEATURE_DIRECTED_ROUNDING)
    printf("%s=%s\n", TO_STRING_EXP(__ARM_FEATURE_DIRECTED_ROUNDING),
           TO_STRING(__ARM_FEATURE_DIRECTED_ROUNDING));
#else
    printf("%s not defined\n", TO_STRING_EXP(__ARM_FEATURE_DIRECTED_ROUNDING));
#endif
#if defined(__ARM_FEATURE_DIV)
    printf("%s=%s\n", TO_STRING_EXP(__ARM_FEATURE_DIV), TO_STRING(__ARM_FEATURE_DIV));
#else
    printf("%s not defined\n", TO_STRING_EXP(__ARM_FEATURE_DIV));
#endif
#if defined(__ARM_FEATURE_DOTPROD)
    printf("%s=%s\n", TO_STRING_EXP(__ARM_FEATURE_DOTPROD), TO_STRING(__ARM_FEATURE_DOTPROD));
#else
    printf("%s not defined\n", TO_STRING_EXP(__ARM_FEATURE_DOTPROD));
#endif
#if defined(__ARM_FEATURE_FMA)
    printf("%s=%s\n", TO_STRING_EXP(__ARM_FEATURE_FMA), TO_STRING(__ARM_FEATURE_FMA));
#else
    printf("%s not defined\n", TO_STRING_EXP(__ARM_FEATURE_FMA));
#endif
#if defined(__ARM_FEATURE_FP16_FML)
    printf("%s=%s\n", TO_STRING_EXP(__ARM_FEATURE_FP16_FML), TO_STRING(__ARM_FEATURE_FP16_FML));
#else
    printf("%s not defined\n", TO_STRING_EXP(__ARM_FEATURE_FP16_FML));
#endif
#if defined(__ARM_FEATURE_FP16_SCALAR_ARITHMETIC)
    printf("%s=%s\n", TO_STRING_EXP(__ARM_FEATURE_FP16_SCALAR_ARITHMETIC),
           TO_STRING(__ARM_FEATURE_FP16_SCALAR_ARITHMETIC));
#else
    printf("%s not defined\n", TO_STRING_EXP(__ARM_FEATURE_FP16_SCALAR_ARITHMETIC));
#endif
#if defined(__ARM_FEATURE_FP16_VECTOR_ARITHMETIC)
    printf("%s=%s\n", TO_STRING_EXP(__ARM_FEATURE_FP16_VECTOR_ARITHMETIC),
           TO_STRING(__ARM_FEATURE_FP16_VECTOR_ARITHMETIC));
#else
    printf("%s not defined\n", TO_STRING_EXP(__ARM_FEATURE_FP16_VECTOR_ARITHMETIC));
#endif
#if defined(__ARM_FEATURE_FRINT)
    printf("%s=%s\n", TO_STRING_EXP(__ARM_FEATURE_FRINT), TO_STRING(__ARM_FEATURE_FRINT));
#else
    printf("%s not defined\n", TO_STRING_EXP(__ARM_FEATURE_FRINT));
#endif
#if defined(__ARM_FEATURE_GCS)
    printf("%s=%s\n", TO_STRING_EXP(__ARM_FEATURE_GCS), TO_STRING(__ARM_FEATURE_GCS));
#else
    printf("%s not defined\n", TO_STRING_EXP(__ARM_FEATURE_GCS));
#endif
#if defined(__ARM_FEATURE_GCS_DEFAULT)
    printf("%s=%s\n", TO_STRING_EXP(__ARM_FEATURE_GCS_DEFAULT),
           TO_STRING(__ARM_FEATURE_GCS_DEFAULT));
#else
    printf("%s not defined\n", TO_STRING_EXP(__ARM_FEATURE_GCS_DEFAULT));
#endif
#if defined(__ARM_FEATURE_IDIV)
    printf("%s=%s\n", TO_STRING_EXP(__ARM_FEATURE_IDIV), TO_STRING(__ARM_FEATURE_IDIV));
#else
    printf("%s not defined\n", TO_STRING_EXP(__ARM_FEATURE_IDIV));
#endif
#if defined(__ARM_FEATURE_JCVT)
    printf("%s=%s\n", TO_STRING_EXP(__ARM_FEATURE_JCVT), TO_STRING(__ARM_FEATURE_JCVT));
#else
    printf("%s not defined\n", TO_STRING_EXP(__ARM_FEATURE_JCVT));
#endif
#if defined(__ARM_FEATURE_LDREX)
    printf("%s=%s\n", TO_STRING_EXP(__ARM_FEATURE_LDREX), TO_STRING(__ARM_FEATURE_LDREX));
#else
    printf("%s not defined\n", TO_STRING_EXP(__ARM_FEATURE_LDREX));
#endif
#if defined(__ARM_FEATURE_LOCALLY_STREAMING)
    printf("%s=%s\n", TO_STRING_EXP(__ARM_FEATURE_LOCALLY_STREAMING),
           TO_STRING(__ARM_FEATURE_LOCALLY_STREAMING));
#else
    printf("%s not defined\n", TO_STRING_EXP(__ARM_FEATURE_LOCALLY_STREAMING));
#endif
#if defined(__ARM_FEATURE_LS64)
    printf("%s=%s\n", TO_STRING_EXP(__ARM_FEATURE_LS64), TO_STRING(__ARM_FEATURE_LS64));
#else
    printf("%s not defined\n", TO_STRING_EXP(__ARM_FEATURE_LS64));
#endif
#if defined(__ARM_FEATURE_MATMUL_INT8)
    printf("%s=%s\n", TO_STRING_EXP(__ARM_FEATURE_MATMUL_INT8),
           TO_STRING(__ARM_FEATURE_MATMUL_INT8));
#else
    printf("%s not defined\n", TO_STRING_EXP(__ARM_FEATURE_MATMUL_INT8));
#endif
#if defined(__ARM_FEATURE_MEMORY_TAGGING)
    printf("%s=%s\n", TO_STRING_EXP(__ARM_FEATURE_MEMORY_TAGGING),
           TO_STRING(__ARM_FEATURE_MEMORY_TAGGING));
#else
    printf("%s not defined\n", TO_STRING_EXP(__ARM_FEATURE_MEMORY_TAGGING));
#endif
#if defined(__ARM_FEATURE_MOPS)
    printf("%s=%s\n", TO_STRING_EXP(__ARM_FEATURE_MOPS), TO_STRING(__ARM_FEATURE_MOPS));
#else
    printf("%s not defined\n", TO_STRING_EXP(__ARM_FEATURE_MOPS));
#endif
#if defined(__ARM_FEATURE_NUMERIC_MAXMIN)
    printf("%s=%s\n", TO_STRING_EXP(__ARM_FEATURE_NUMERIC_MAXMIN),
           TO_STRING(__ARM_FEATURE_NUMERIC_MAXMIN));
#else
    printf("%s not defined\n", TO_STRING_EXP(__ARM_FEATURE_NUMERIC_MAXMIN));
#endif
#if defined(__ARM_FEATURE_PAC_DEFAULT)
    printf("%s=%s\n", TO_STRING_EXP(__ARM_FEATURE_PAC_DEFAULT),
           TO_STRING(__ARM_FEATURE_PAC_DEFAULT));
#else
    printf("%s not defined\n", TO_STRING_EXP(__ARM_FEATURE_PAC_DEFAULT));
#endif
#if defined(__ARM_FEATURE_PAUTH)
    printf("%s=%s\n", TO_STRING_EXP(__ARM_FEATURE_PAUTH), TO_STRING(__ARM_FEATURE_PAUTH));
#else
    printf("%s not defined\n", TO_STRING_EXP(__ARM_FEATURE_PAUTH));
#endif
#if defined(__ARM_FEATURE_PAUTH_LR)
    printf("%s=%s\n", TO_STRING_EXP(__ARM_FEATURE_PAUTH_LR), TO_STRING(__ARM_FEATURE_PAUTH_LR));
#else
    printf("%s not defined\n", TO_STRING_EXP(__ARM_FEATURE_PAUTH_LR));
#endif
#if defined(__ARM_FEATURE_QRDMX)
    printf("%s=%s\n", TO_STRING_EXP(__ARM_FEATURE_QRDMX), TO_STRING(__ARM_FEATURE_QRDMX));
#else
    printf("%s not defined\n", TO_STRING_EXP(__ARM_FEATURE_QRDMX));
#endif
#if defined(__ARM_FEATURE_RCPC)
    printf("%s=%s\n", TO_STRING_EXP(__ARM_FEATURE_RCPC), TO_STRING(__ARM_FEATURE_RCPC));
#else
    printf("%s not defined\n", TO_STRING_EXP(__ARM_FEATURE_RCPC));
#endif
#if defined(__ARM_FEATURE_RNG)
    printf("%s=%s\n", TO_STRING_EXP(__ARM_FEATURE_RNG), TO_STRING(__ARM_FEATURE_RNG));
#else
    printf("%s not defined\n", TO_STRING_EXP(__ARM_FEATURE_RNG));
#endif
#if defined(__ARM_FEATURE_SHA2)
    printf("%s=%s\n", TO_STRING_EXP(__ARM_FEATURE_SHA2), TO_STRING(__ARM_FEATURE_SHA2));
#else
    printf("%s not defined\n", TO_STRING_EXP(__ARM_FEATURE_SHA2));
#endif
#if defined(__ARM_FEATURE_SHA3)
    printf("%s=%s\n", TO_STRING_EXP(__ARM_FEATURE_SHA3), TO_STRING(__ARM_FEATURE_SHA3));
#else
    printf("%s not defined\n", TO_STRING_EXP(__ARM_FEATURE_SHA3));
#endif
#if defined(__ARM_FEATURE_SHA512)
    printf("%s=%s\n", TO_STRING_EXP(__ARM_FEATURE_SHA512), TO_STRING(__ARM_FEATURE_SHA512));
#else
    printf("%s not defined\n", TO_STRING_EXP(__ARM_FEATURE_SHA512));
#endif
#if defined(__ARM_FEATURE_SM3)
    printf("%s=%s\n", TO_STRING_EXP(__ARM_FEATURE_SM3), TO_STRING(__ARM_FEATURE_SM3));
#else
    printf("%s not defined\n", TO_STRING_EXP(__ARM_FEATURE_SM3));
#endif
#if defined(__ARM_FEATURE_SM4)
    printf("%s=%s\n", TO_STRING_EXP(__ARM_FEATURE_SM4), TO_STRING(__ARM_FEATURE_SM4));
#else
    printf("%s not defined\n", TO_STRING_EXP(__ARM_FEATURE_SM4));
#endif
#if defined(__ARM_FEATURE_SME)
    printf("%s=%s\n", TO_STRING_EXP(__ARM_FEATURE_SME), TO_STRING(__ARM_FEATURE_SME));
#else
    printf("%s not defined\n", TO_STRING_EXP(__ARM_FEATURE_SME));
#endif
#if defined(__ARM_FEATURE_SME2)
    printf("%s=%s\n", TO_STRING_EXP(__ARM_FEATURE_SME2), TO_STRING(__ARM_FEATURE_SME2));
#else
    printf("%s not defined\n", TO_STRING_EXP(__ARM_FEATURE_SME2));
#endif
#if defined(__ARM_FEATURE_SME2p1)
    printf("%s=%s\n", TO_STRING_EXP(__ARM_FEATURE_SME2p1), TO_STRING(__ARM_FEATURE_SME2p1));
#else
    printf("%s not defined\n", TO_STRING_EXP(__ARM_FEATURE_SME2p1));
#endif
#if defined(__ARM_FEATURE_SVE)
    printf("%s=%s\n", TO_STRING_EXP(__ARM_FEATURE_SVE), TO_STRING(__ARM_FEATURE_SVE));
#else
    printf("%s not defined\n", TO_STRING_EXP(__ARM_FEATURE_SVE));
#endif
#if defined(__ARM_FEATURE_SVE2)
    printf("%s=%s\n", TO_STRING_EXP(__ARM_FEATURE_SVE2), TO_STRING(__ARM_FEATURE_SVE2));
#else
    printf("%s not defined\n", TO_STRING_EXP(__ARM_FEATURE_SVE2));
#endif
#if defined(__ARM_FEATURE_SVE2_AES)
    printf("%s=%s\n", TO_STRING_EXP(__ARM_FEATURE_SVE2_AES), TO_STRING(__ARM_FEATURE_SVE2_AES));
#else
    printf("%s not defined\n", TO_STRING_EXP(__ARM_FEATURE_SVE2_AES));
#endif
#if defined(__ARM_FEATURE_SVE2_BITPERM)
    printf("%s=%s\n", TO_STRING_EXP(__ARM_FEATURE_SVE2_BITPERM),
           TO_STRING(__ARM_FEATURE_SVE2_BITPERM));
#else
    printf("%s not defined\n", TO_STRING_EXP(__ARM_FEATURE_SVE2_BITPERM));
#endif
#if defined(__ARM_FEATURE_SVE2p1)
    printf("%s=%s\n", TO_STRING_EXP(__ARM_FEATURE_SVE2p1), TO_STRING(__ARM_FEATURE_SVE2p1));
#else
    printf("%s not defined\n", TO_STRING_EXP(__ARM_FEATURE_SVE2p1));
#endif
#if defined(__ARM_FEATURE_SVE2_SHA3)
    printf("%s=%s\n", TO_STRING_EXP(__ARM_FEATURE_SVE2_SHA3), TO_STRING(__ARM_FEATURE_SVE2_SHA3));
#else
    printf("%s not defined\n", TO_STRING_EXP(__ARM_FEATURE_SVE2_SHA3));
#endif
#if defined(__ARM_FEATURE_SVE2_SM4)
    printf("%s=%s\n", TO_STRING_EXP(__ARM_FEATURE_SVE2_SM4), TO_STRING(__ARM_FEATURE_SVE2_SM4));
#else
    printf("%s not defined\n", TO_STRING_EXP(__ARM_FEATURE_SVE2_SM4));
#endif
#if defined(__ARM_FEATURE_SVE_BF16)
    printf("%s=%s\n", TO_STRING_EXP(__ARM_FEATURE_SVE_BF16), TO_STRING(__ARM_FEATURE_SVE_BF16));
#else
    printf("%s not defined\n", TO_STRING_EXP(__ARM_FEATURE_SVE_BF16));
#endif
#if defined(__ARM_FEATURE_SVE_BITS)
    printf("%s=%s\n", TO_STRING_EXP(__ARM_FEATURE_SVE_BITS), TO_STRING(__ARM_FEATURE_SVE_BITS));
#else
    printf("%s not defined\n", TO_STRING_EXP(__ARM_FEATURE_SVE_BITS));
#endif
#if defined(__ARM_FEATURE_SVE_MATMUL_FP32)
    printf("%s=%s\n", TO_STRING_EXP(__ARM_FEATURE_SVE_MATMUL_FP32),
           TO_STRING(__ARM_FEATURE_SVE_MATMUL_FP32));
#else
    printf("%s not defined\n", TO_STRING_EXP(__ARM_FEATURE_SVE_MATMUL_FP32));
#endif
#if defined(__ARM_FEATURE_SVE_MATMUL_FP64)
    printf("%s=%s\n", TO_STRING_EXP(__ARM_FEATURE_SVE_MATMUL_FP64),
           TO_STRING(__ARM_FEATURE_SVE_MATMUL_FP64));
#else
    printf("%s not defined\n", TO_STRING_EXP(__ARM_FEATURE_SVE_MATMUL_FP64));
#endif
#if defined(__ARM_FEATURE_SVE_MATMUL_INT8)
    printf("%s=%s\n", TO_STRING_EXP(__ARM_FEATURE_SVE_MATMUL_INT8),
           TO_STRING(__ARM_FEATURE_SVE_MATMUL_INT8));
#else
    printf("%s not defined\n", TO_STRING_EXP(__ARM_FEATURE_SVE_MATMUL_INT8));
#endif
#if defined(__ARM_FEATURE_SVE_VECTOR_OPERATORS)
    printf("%s=%s\n", TO_STRING_EXP(__ARM_FEATURE_SVE_VECTOR_OPERATORS),
           TO_STRING(__ARM_FEATURE_SVE_VECTOR_OPERATORS));
#else
    printf("%s not defined\n", TO_STRING_EXP(__ARM_FEATURE_SVE_VECTOR_OPERATORS));
#endif
#if defined(__ARM_FEATURE_SYSREG128)
    printf("%s=%s\n", TO_STRING_EXP(__ARM_FEATURE_SYSREG128), TO_STRING(__ARM_FEATURE_SYSREG128));
#else
    printf("%s not defined\n", TO_STRING_EXP(__ARM_FEATURE_SYSREG128));
#endif
#if defined(__ARM_FEATURE_UNALIGNED)
    printf("%s=%s\n", TO_STRING_EXP(__ARM_FEATURE_UNALIGNED), TO_STRING(__ARM_FEATURE_UNALIGNED));
#else
    printf("%s not defined\n", TO_STRING_EXP(__ARM_FEATURE_UNALIGNED));
#endif
#if defined(__ARM_FP)
    printf("%s=%s\n", TO_STRING_EXP(__ARM_FP), TO_STRING(__ARM_FP));
#else
    printf("%s not defined\n", TO_STRING_EXP(__ARM_FP));
#endif
#if defined(__ARM_FP16_ARGS)
    printf("%s=%s\n", TO_STRING_EXP(__ARM_FP16_ARGS), TO_STRING(__ARM_FP16_ARGS));
#else
    printf("%s not defined\n", TO_STRING_EXP(__ARM_FP16_ARGS));
#endif
#if defined(__ARM_FP16_FORMAT_IEEE)
    printf("%s=%s\n", TO_STRING_EXP(__ARM_FP16_FORMAT_IEEE), TO_STRING(__ARM_FP16_FORMAT_IEEE));
#else
    printf("%s not defined\n", TO_STRING_EXP(__ARM_FP16_FORMAT_IEEE));
#endif
#if defined(__ARM_FP_FAST)
    printf("%s=%s\n", TO_STRING_EXP(__ARM_FP_FAST), TO_STRING(__ARM_FP_FAST));
#else
    printf("%s not defined\n", TO_STRING_EXP(__ARM_FP_FAST));
#endif
#if defined(__ARM_NEON)
    printf("%s=%s\n", TO_STRING_EXP(__ARM_NEON), TO_STRING(__ARM_NEON));
#else
    printf("%s not defined\n", TO_STRING_EXP(__ARM_NEON));
#endif
#if defined(__ARM_NEON_FP)
    printf("%s=%s\n", TO_STRING_EXP(__ARM_NEON_FP), TO_STRING(__ARM_NEON_FP));
#else
    printf("%s not defined\n", TO_STRING_EXP(__ARM_NEON_FP));
#endif
#if defined(__ARM_NEON_SVE_BRIDGE)
    printf("%s=%s\n", TO_STRING_EXP(__ARM_NEON_SVE_BRIDGE), TO_STRING(__ARM_NEON_SVE_BRIDGE));
#else
    printf("%s not defined\n", TO_STRING_EXP(__ARM_NEON_SVE_BRIDGE));
#endif
#if defined(__ARM_PCS)
    printf("%s=%s\n", TO_STRING_EXP(__ARM_PCS), TO_STRING(__ARM_PCS));
#else
    printf("%s not defined\n", TO_STRING_EXP(__ARM_PCS));
#endif
#if defined(__ARM_PCS_AAPCS64)
    printf("%s=%s\n", TO_STRING_EXP(__ARM_PCS_AAPCS64), TO_STRING(__ARM_PCS_AAPCS64));
#else
    printf("%s not defined\n", TO_STRING_EXP(__ARM_PCS_AAPCS64));
#endif
#if defined(__ARM_PCS_VFP)
    printf("%s=%s\n", TO_STRING_EXP(__ARM_PCS_VFP), TO_STRING(__ARM_PCS_VFP));
#else
    printf("%s not defined\n", TO_STRING_EXP(__ARM_PCS_VFP));
#endif
#if defined(__ARM_SIZEOF_MINIMAL_ENUM)
    printf("%s=%s\n", TO_STRING_EXP(__ARM_SIZEOF_MINIMAL_ENUM),
           TO_STRING(__ARM_SIZEOF_MINIMAL_ENUM));
#else
    printf("%s not defined\n", TO_STRING_EXP(__ARM_SIZEOF_MINIMAL_ENUM));
#endif
#if defined(__ARM_SIZEOF_WCHAR_T)
    printf("%s=%s\n", TO_STRING_EXP(__ARM_SIZEOF_WCHAR_T), TO_STRING(__ARM_SIZEOF_WCHAR_T));
#else
    printf("%s not defined\n", TO_STRING_EXP(__ARM_SIZEOF_WCHAR_T));
#endif
#if defined(__ARM_STATE_ZA)
    printf("%s=%s\n", TO_STRING_EXP(__ARM_STATE_ZA), TO_STRING(__ARM_STATE_ZA));
#else
    printf("%s not defined\n", TO_STRING_EXP(__ARM_STATE_ZA));
#endif
#if defined(__ARM_STATE_ZT0)
    printf("%s=%s\n", TO_STRING_EXP(__ARM_STATE_ZT0), TO_STRING(__ARM_STATE_ZT0));
#else
    printf("%s not defined\n", TO_STRING_EXP(__ARM_STATE_ZT0));
#endif
}

void printX86TargetFeatures() {
// Defines chosen from clang/test/Preprocessor/x86_target_features.c
#if defined(__3dNOW__)
    printf("%s=%s\n", TO_STRING_EXP(__3dNOW__), TO_STRING(__3dNOW__));
#else
    printf("%s not defined\n", TO_STRING_EXP(__3dNOW__));
#endif
#if defined(__ADX__)
    printf("%s=%s\n", TO_STRING_EXP(__ADX__), TO_STRING(__ADX__));
#else
    printf("%s not defined\n", TO_STRING_EXP(__ADX__));
#endif
#if defined(__AES__)
    printf("%s=%s\n", TO_STRING_EXP(__AES__), TO_STRING(__AES__));
#else
    printf("%s not defined\n", TO_STRING_EXP(__AES__));
#endif
#if defined(__AMX_COMPLEX__)
    printf("%s=%s\n", TO_STRING_EXP(__AMX_COMPLEX__), TO_STRING(__AMX_COMPLEX__));
#else
    printf("%s not defined\n", TO_STRING_EXP(__AMX_COMPLEX__));
#endif
#if defined(__AMX_FP16__)
    printf("%s=%s\n", TO_STRING_EXP(__AMX_FP16__), TO_STRING(__AMX_FP16__));
#else
    printf("%s not defined\n", TO_STRING_EXP(__AMX_FP16__));
#endif
#if defined(__AMX_TILE__)
    printf("%s=%s\n", TO_STRING_EXP(__AMX_TILE__), TO_STRING(__AMX_TILE__));
#else
    printf("%s not defined\n", TO_STRING_EXP(__AMX_TILE__));
#endif
#if defined(__APX_F__)
    printf("%s=%s\n", TO_STRING_EXP(__APX_F__), TO_STRING(__APX_F__));
#else
    printf("%s not defined\n", TO_STRING_EXP(__APX_F__));
#endif
#if defined(__APX_INLINE_ASM_USE_GPR32__)
    printf("%s=%s\n", TO_STRING_EXP(__APX_INLINE_ASM_USE_GPR32__),
           TO_STRING(__APX_INLINE_ASM_USE_GPR32__));
#else
    printf("%s not defined\n", TO_STRING_EXP(__APX_INLINE_ASM_USE_GPR32__));
#endif
#if defined(__AVX__)
    printf("%s=%s\n", TO_STRING_EXP(__AVX__), TO_STRING(__AVX__));
#else
    printf("%s not defined\n", TO_STRING_EXP(__AVX__));
#endif
#if defined(__AVX10_1__)
    printf("%s=%s\n", TO_STRING_EXP(__AVX10_1__), TO_STRING(__AVX10_1__));
#else
    printf("%s not defined\n", TO_STRING_EXP(__AVX10_1__));
#endif
#if defined(__AVX10_1_512__)
    printf("%s=%s\n", TO_STRING_EXP(__AVX10_1_512__), TO_STRING(__AVX10_1_512__));
#else
    printf("%s not defined\n", TO_STRING_EXP(__AVX10_1_512__));
#endif
#if defined(__AVX10_2__)
    printf("%s=%s\n", TO_STRING_EXP(__AVX10_2__), TO_STRING(__AVX10_2__));
#else
    printf("%s not defined\n", TO_STRING_EXP(__AVX10_2__));
#endif
#if defined(__AVX10_2_512__)
    printf("%s=%s\n", TO_STRING_EXP(__AVX10_2_512__), TO_STRING(__AVX10_2_512__));
#else
    printf("%s not defined\n", TO_STRING_EXP(__AVX10_2_512__));
#endif
#if defined(__AVX2__)
    printf("%s=%s\n", TO_STRING_EXP(__AVX2__), TO_STRING(__AVX2__));
#else
    printf("%s not defined\n", TO_STRING_EXP(__AVX2__));
#endif
#if defined(__AVX512BF16__)
    printf("%s=%s\n", TO_STRING_EXP(__AVX512BF16__), TO_STRING(__AVX512BF16__));
#else
    printf("%s not defined\n", TO_STRING_EXP(__AVX512BF16__));
#endif
#if defined(__AVX512BITALG__)
    printf("%s=%s\n", TO_STRING_EXP(__AVX512BITALG__), TO_STRING(__AVX512BITALG__));
#else
    printf("%s not defined\n", TO_STRING_EXP(__AVX512BITALG__));
#endif
#if defined(__AVX512BW__)
    printf("%s=%s\n", TO_STRING_EXP(__AVX512BW__), TO_STRING(__AVX512BW__));
#else
    printf("%s not defined\n", TO_STRING_EXP(__AVX512BW__));
#endif
#if defined(__AVX512CD__)
    printf("%s=%s\n", TO_STRING_EXP(__AVX512CD__), TO_STRING(__AVX512CD__));
#else
    printf("%s not defined\n", TO_STRING_EXP(__AVX512CD__));
#endif
#if defined(__AVX512DQ__)
    printf("%s=%s\n", TO_STRING_EXP(__AVX512DQ__), TO_STRING(__AVX512DQ__));
#else
    printf("%s not defined\n", TO_STRING_EXP(__AVX512DQ__));
#endif
#if defined(__AVX512F__)
    printf("%s=%s\n", TO_STRING_EXP(__AVX512F__), TO_STRING(__AVX512F__));
#else
    printf("%s not defined\n", TO_STRING_EXP(__AVX512F__));
#endif
#if defined(__AVX512FP16__)
    printf("%s=%s\n", TO_STRING_EXP(__AVX512FP16__), TO_STRING(__AVX512FP16__));
#else
    printf("%s not defined\n", TO_STRING_EXP(__AVX512FP16__));
#endif
#if defined(__AVX512IFMA__)
    printf("%s=%s\n", TO_STRING_EXP(__AVX512IFMA__), TO_STRING(__AVX512IFMA__));
#else
    printf("%s not defined\n", TO_STRING_EXP(__AVX512IFMA__));
#endif
#if defined(__AVX512VBMI__)
    printf("%s=%s\n", TO_STRING_EXP(__AVX512VBMI__), TO_STRING(__AVX512VBMI__));
#else
    printf("%s not defined\n", TO_STRING_EXP(__AVX512VBMI__));
#endif
#if defined(__AVX512VBMI2__)
    printf("%s=%s\n", TO_STRING_EXP(__AVX512VBMI2__), TO_STRING(__AVX512VBMI2__));
#else
    printf("%s not defined\n", TO_STRING_EXP(__AVX512VBMI2__));
#endif
#if defined(__AVX512VL__)
    printf("%s=%s\n", TO_STRING_EXP(__AVX512VL__), TO_STRING(__AVX512VL__));
#else
    printf("%s not defined\n", TO_STRING_EXP(__AVX512VL__));
#endif
#if defined(__AVX512VP2INTERSECT__)
    printf("%s=%s\n", TO_STRING_EXP(__AVX512VP2INTERSECT__), TO_STRING(__AVX512VP2INTERSECT__));
#else
    printf("%s not defined\n", TO_STRING_EXP(__AVX512VP2INTERSECT__));
#endif
#if defined(__AVXIFMA__)
    printf("%s=%s\n", TO_STRING_EXP(__AVXIFMA__), TO_STRING(__AVXIFMA__));
#else
    printf("%s not defined\n", TO_STRING_EXP(__AVXIFMA__));
#endif
#if defined(__AVXNECONVERT__)
    printf("%s=%s\n", TO_STRING_EXP(__AVXNECONVERT__), TO_STRING(__AVXNECONVERT__));
#else
    printf("%s not defined\n", TO_STRING_EXP(__AVXNECONVERT__));
#endif
#if defined(__AVXVNNI__)
    printf("%s=%s\n", TO_STRING_EXP(__AVXVNNI__), TO_STRING(__AVXVNNI__));
#else
    printf("%s not defined\n", TO_STRING_EXP(__AVXVNNI__));
#endif
#if defined(__AVXVNNIINT16__)
    printf("%s=%s\n", TO_STRING_EXP(__AVXVNNIINT16__), TO_STRING(__AVXVNNIINT16__));
#else
    printf("%s not defined\n", TO_STRING_EXP(__AVXVNNIINT16__));
#endif
#if defined(__AVXVNNIINT8__)
    printf("%s=%s\n", TO_STRING_EXP(__AVXVNNIINT8__), TO_STRING(__AVXVNNIINT8__));
#else
    printf("%s not defined\n", TO_STRING_EXP(__AVXVNNIINT8__));
#endif
#if defined(__CCMP__)
    printf("%s=%s\n", TO_STRING_EXP(__CCMP__), TO_STRING(__CCMP__));
#else
    printf("%s not defined\n", TO_STRING_EXP(__CCMP__));
#endif
#if defined(__CF__)
    printf("%s=%s\n", TO_STRING_EXP(__CF__), TO_STRING(__CF__));
#else
    printf("%s not defined\n", TO_STRING_EXP(__CF__));
#endif
#if defined(__CLFLUSHOPT__)
    printf("%s=%s\n", TO_STRING_EXP(__CLFLUSHOPT__), TO_STRING(__CLFLUSHOPT__));
#else
    printf("%s not defined\n", TO_STRING_EXP(__CLFLUSHOPT__));
#endif
#if defined(__CMPCCXADD__)
    printf("%s=%s\n", TO_STRING_EXP(__CMPCCXADD__), TO_STRING(__CMPCCXADD__));
#else
    printf("%s not defined\n", TO_STRING_EXP(__CMPCCXADD__));
#endif
#if defined(__CRC32__)
    printf("%s=%s\n", TO_STRING_EXP(__CRC32__), TO_STRING(__CRC32__));
#else
    printf("%s not defined\n", TO_STRING_EXP(__CRC32__));
#endif
#if defined(__EGPR__)
    printf("%s=%s\n", TO_STRING_EXP(__EGPR__), TO_STRING(__EGPR__));
#else
    printf("%s not defined\n", TO_STRING_EXP(__EGPR__));
#endif
#if defined(__ENQCMD__)
    printf("%s=%s\n", TO_STRING_EXP(__ENQCMD__), TO_STRING(__ENQCMD__));
#else
    printf("%s not defined\n", TO_STRING_EXP(__ENQCMD__));
#endif
#if defined(__EVEX256__)
    printf("%s=%s\n", TO_STRING_EXP(__EVEX256__), TO_STRING(__EVEX256__));
#else
    printf("%s not defined\n", TO_STRING_EXP(__EVEX256__));
#endif
#if defined(__EVEX512__)
    printf("%s=%s\n", TO_STRING_EXP(__EVEX512__), TO_STRING(__EVEX512__));
#else
    printf("%s not defined\n", TO_STRING_EXP(__EVEX512__));
#endif
#if defined(__F16C__)
    printf("%s=%s\n", TO_STRING_EXP(__F16C__), TO_STRING(__F16C__));
#else
    printf("%s not defined\n", TO_STRING_EXP(__F16C__));
#endif
#if defined(__GCC_HAVE_SYNC_COMPARE_AND_SWAP_16)
    printf("%s=%s\n", TO_STRING_EXP(__GCC_HAVE_SYNC_COMPARE_AND_SWAP_16),
           TO_STRING(__GCC_HAVE_SYNC_COMPARE_AND_SWAP_16));
#else
    printf("%s not defined\n", TO_STRING_EXP(__GCC_HAVE_SYNC_COMPARE_AND_SWAP_16));
#endif
#if defined(__GFNI__)
    printf("%s=%s\n", TO_STRING_EXP(__GFNI__), TO_STRING(__GFNI__));
#else
    printf("%s not defined\n", TO_STRING_EXP(__GFNI__));
#endif
#if defined(__HRESET__)
    printf("%s=%s\n", TO_STRING_EXP(__HRESET__), TO_STRING(__HRESET__));
#else
    printf("%s not defined\n", TO_STRING_EXP(__HRESET__));
#endif
#if defined(__KL__)
    printf("%s=%s\n", TO_STRING_EXP(__KL__), TO_STRING(__KL__));
#else
    printf("%s not defined\n", TO_STRING_EXP(__KL__));
#endif
#if defined(__LWP__)
    printf("%s=%s\n", TO_STRING_EXP(__LWP__), TO_STRING(__LWP__));
#else
    printf("%s not defined\n", TO_STRING_EXP(__LWP__));
#endif
#if defined(__MMX__)
    printf("%s=%s\n", TO_STRING_EXP(__MMX__), TO_STRING(__MMX__));
#else
    printf("%s not defined\n", TO_STRING_EXP(__MMX__));
#endif
#if defined(__NDD__)
    printf("%s=%s\n", TO_STRING_EXP(__NDD__), TO_STRING(__NDD__));
#else
    printf("%s not defined\n", TO_STRING_EXP(__NDD__));
#endif
#if defined(__NF__)
    printf("%s=%s\n", TO_STRING_EXP(__NF__), TO_STRING(__NF__));
#else
    printf("%s not defined\n", TO_STRING_EXP(__NF__));
#endif
#if defined(__PCLMUL__)
    printf("%s=%s\n", TO_STRING_EXP(__PCLMUL__), TO_STRING(__PCLMUL__));
#else
    printf("%s not defined\n", TO_STRING_EXP(__PCLMUL__));
#endif
#if defined(__POPCNT__)
    printf("%s=%s\n", TO_STRING_EXP(__POPCNT__), TO_STRING(__POPCNT__));
#else
    printf("%s not defined\n", TO_STRING_EXP(__POPCNT__));
#endif
#if defined(__PPX__)
    printf("%s=%s\n", TO_STRING_EXP(__PPX__), TO_STRING(__PPX__));
#else
    printf("%s not defined\n", TO_STRING_EXP(__PPX__));
#endif
#if defined(__PRFCHW__)
    printf("%s=%s\n", TO_STRING_EXP(__PRFCHW__), TO_STRING(__PRFCHW__));
#else
    printf("%s not defined\n", TO_STRING_EXP(__PRFCHW__));
#endif
#if defined(__PUSH2POP2__)
    printf("%s=%s\n", TO_STRING_EXP(__PUSH2POP2__), TO_STRING(__PUSH2POP2__));
#else
    printf("%s not defined\n", TO_STRING_EXP(__PUSH2POP2__));
#endif
#if defined(__RAOINT__)
    printf("%s=%s\n", TO_STRING_EXP(__RAOINT__), TO_STRING(__RAOINT__));
#else
    printf("%s not defined\n", TO_STRING_EXP(__RAOINT__));
#endif
#if defined(__RDPID__)
    printf("%s=%s\n", TO_STRING_EXP(__RDPID__), TO_STRING(__RDPID__));
#else
    printf("%s not defined\n", TO_STRING_EXP(__RDPID__));
#endif
#if defined(__RDPRU__)
    printf("%s=%s\n", TO_STRING_EXP(__RDPRU__), TO_STRING(__RDPRU__));
#else
    printf("%s not defined\n", TO_STRING_EXP(__RDPRU__));
#endif
#if defined(__RDSEED__)
    printf("%s=%s\n", TO_STRING_EXP(__RDSEED__), TO_STRING(__RDSEED__));
#else
    printf("%s not defined\n", TO_STRING_EXP(__RDSEED__));
#endif
#if defined(__SERIALIZE__)
    printf("%s=%s\n", TO_STRING_EXP(__SERIALIZE__), TO_STRING(__SERIALIZE__));
#else
    printf("%s not defined\n", TO_STRING_EXP(__SERIALIZE__));
#endif
#if defined(__SHA__)
    printf("%s=%s\n", TO_STRING_EXP(__SHA__), TO_STRING(__SHA__));
#else
    printf("%s not defined\n", TO_STRING_EXP(__SHA__));
#endif
#if defined(__SHA512__)
    printf("%s=%s\n", TO_STRING_EXP(__SHA512__), TO_STRING(__SHA512__));
#else
    printf("%s not defined\n", TO_STRING_EXP(__SHA512__));
#endif
#if defined(__SHSTK__)
    printf("%s=%s\n", TO_STRING_EXP(__SHSTK__), TO_STRING(__SHSTK__));
#else
    printf("%s not defined\n", TO_STRING_EXP(__SHSTK__));
#endif
#if defined(__SM3__)
    printf("%s=%s\n", TO_STRING_EXP(__SM3__), TO_STRING(__SM3__));
#else
    printf("%s not defined\n", TO_STRING_EXP(__SM3__));
#endif
#if defined(__SM4__)
    printf("%s=%s\n", TO_STRING_EXP(__SM4__), TO_STRING(__SM4__));
#else
    printf("%s not defined\n", TO_STRING_EXP(__SM4__));
#endif
#if defined(__SSE__)
    printf("%s=%s\n", TO_STRING_EXP(__SSE__), TO_STRING(__SSE__));
#else
    printf("%s not defined\n", TO_STRING_EXP(__SSE__));
#endif
#if defined(__SSE2__)
    printf("%s=%s\n", TO_STRING_EXP(__SSE2__), TO_STRING(__SSE2__));
#else
    printf("%s not defined\n", TO_STRING_EXP(__SSE2__));
#endif
#if defined(__SSE2_MATH__)
    printf("%s=%s\n", TO_STRING_EXP(__SSE2_MATH__), TO_STRING(__SSE2_MATH__));
#else
    printf("%s not defined\n", TO_STRING_EXP(__SSE2_MATH__));
#endif
#if defined(__SSE3__)
    printf("%s=%s\n", TO_STRING_EXP(__SSE3__), TO_STRING(__SSE3__));
#else
    printf("%s not defined\n", TO_STRING_EXP(__SSE3__));
#endif
#if defined(__SSE4_1__)
    printf("%s=%s\n", TO_STRING_EXP(__SSE4_1__), TO_STRING(__SSE4_1__));
#else
    printf("%s not defined\n", TO_STRING_EXP(__SSE4_1__));
#endif
#if defined(__SSE4_2__)
    printf("%s=%s\n", TO_STRING_EXP(__SSE4_2__), TO_STRING(__SSE4_2__));
#else
    printf("%s not defined\n", TO_STRING_EXP(__SSE4_2__));
#endif
#if defined(__SSE4A__)
    printf("%s=%s\n", TO_STRING_EXP(__SSE4A__), TO_STRING(__SSE4A__));
#else
    printf("%s not defined\n", TO_STRING_EXP(__SSE4A__));
#endif
#if defined(__SSE_MATH__)
    printf("%s=%s\n", TO_STRING_EXP(__SSE_MATH__), TO_STRING(__SSE_MATH__));
#else
    printf("%s not defined\n", TO_STRING_EXP(__SSE_MATH__));
#endif
#if defined(__SSSE3__)
    printf("%s=%s\n", TO_STRING_EXP(__SSSE3__), TO_STRING(__SSSE3__));
#else
    printf("%s not defined\n", TO_STRING_EXP(__SSSE3__));
#endif
#if defined(__TBM__)
    printf("%s=%s\n", TO_STRING_EXP(__TBM__), TO_STRING(__TBM__));
#else
    printf("%s not defined\n", TO_STRING_EXP(__TBM__));
#endif
#if defined(__TSXLDTRK__)
    printf("%s=%s\n", TO_STRING_EXP(__TSXLDTRK__), TO_STRING(__TSXLDTRK__));
#else
    printf("%s not defined\n", TO_STRING_EXP(__TSXLDTRK__));
#endif
#if defined(__UINTR__)
    printf("%s=%s\n", TO_STRING_EXP(__UINTR__), TO_STRING(__UINTR__));
#else
    printf("%s not defined\n", TO_STRING_EXP(__UINTR__));
#endif
#if defined(__USERMSR__)
    printf("%s=%s\n", TO_STRING_EXP(__USERMSR__), TO_STRING(__USERMSR__));
#else
    printf("%s not defined\n", TO_STRING_EXP(__USERMSR__));
#endif
#if defined(__VAES__)
    printf("%s=%s\n", TO_STRING_EXP(__VAES__), TO_STRING(__VAES__));
#else
    printf("%s not defined\n", TO_STRING_EXP(__VAES__));
#endif
#if defined(__VPCLMULQDQ__)
    printf("%s=%s\n", TO_STRING_EXP(__VPCLMULQDQ__), TO_STRING(__VPCLMULQDQ__));
#else
    printf("%s not defined\n", TO_STRING_EXP(__VPCLMULQDQ__));
#endif
#if defined(__WIDEKL__)
    printf("%s=%s\n", TO_STRING_EXP(__WIDEKL__), TO_STRING(__WIDEKL__));
#else
    printf("%s not defined\n", TO_STRING_EXP(__WIDEKL__));
#endif
#if defined(__XSAVE__)
    printf("%s=%s\n", TO_STRING_EXP(__XSAVE__), TO_STRING(__XSAVE__));
#else
    printf("%s not defined\n", TO_STRING_EXP(__XSAVE__));
#endif
#if defined(__XSAVEC__)
    printf("%s=%s\n", TO_STRING_EXP(__XSAVEC__), TO_STRING(__XSAVEC__));
#else
    printf("%s not defined\n", TO_STRING_EXP(__XSAVEC__));
#endif
#if defined(__XSAVEOPT__)
    printf("%s=%s\n", TO_STRING_EXP(__XSAVEOPT__), TO_STRING(__XSAVEOPT__));
#else
    printf("%s not defined\n", TO_STRING_EXP(__XSAVEOPT__));
#endif
#if defined(__XSAVES__)
    printf("%s=%s\n", TO_STRING_EXP(__XSAVES__), TO_STRING(__XSAVES__));
#else
    printf("%s not defined\n", TO_STRING_EXP(__XSAVES__));
#endif
#if defined(__ZU__)
    printf("%s=%s\n", TO_STRING_EXP(__ZU__), TO_STRING(__ZU__));
#else
    printf("%s not defined\n", TO_STRING_EXP(__ZU__));
#endif
}
