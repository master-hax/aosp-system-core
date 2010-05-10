/* libs/pixelflinger/codeflinger/SHAssembler.cpp
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

#define LOG_TAG "SHAssembler"

#include <stdio.h>
#include <stdlib.h>
#include <cutils/log.h>
#include <cutils/properties.h>

#if defined(WITH_LIB_HARDWARE)
#include <hardware_legacy/qemu_tracing.h>
#endif

#include <private/pixelflinger/ggl_context.h>

#include "codeflinger/SHAssembler.h"
#include "codeflinger/CodeCache.h"
#include "codeflinger/disassem.h"

// ----------------------------------------------------------------------------

namespace android {

// ----------------------------------------------------------------------------

#if 0
#pragma mark -
#pragma mark SHAssembler...
#endif

SHAssembler::SHAssembler(const sp<Assembly>& assembly)
    :   SHAssemblerInterface(),
        mAssembly(assembly)
{
    mBase = mPC = (uint16_t *)assembly->base();
    mDuration = ggl_system_time();
#if defined(WITH_LIB_HARDWARE)
    mQemuTracing = true;
#endif

    // initialize label generation
    gen_labels_count = 0;
    gen_label_strings = (char *)malloc(GENERATED_LABELS_MAX * 4);
    if (!gen_label_strings) {
        LOGE("Out of memory for lable generation.\n");
        return;
    }

    for (int i = 0; i < GENERATED_LABELS_MAX; i++) {
        gen_labels[i] = &gen_label_strings[i * 4];
        sprintf(gen_labels[i], "L%02d", i);
    }
}

SHAssembler::~SHAssembler()
{
    if (gen_label_strings)
        free(gen_label_strings);
}

uint16_t* SHAssembler::pc() const
{
    return mPC;
}

uint16_t* SHAssembler::base() const
{
    return mBase;
}

void SHAssembler::reset()
{
    mBase = mPC = (uint16_t *)mAssembly->base();
    mBranchTargets.clear();
    mLabels.clear();
    mLabelsInverseMapping.clear();
    mComments.clear();
    gen_labels_count = 0;
}

// ----------------------------------------------------------------------------

void SHAssembler::disassemble(const char* name)
{
    if (name)
        LOGD("%s:\n", name);

    size_t count = pc()-base();
    uint16_t* i = base();
    LOGD("count=%d, base=%p, pc=%p\n", count, i, pc());
    while (count--) {
        uint16_t* i_t = i;
        ssize_t label = mLabelsInverseMapping.indexOfKey(i_t);
        if (label >= 0) {
            LOGD("%s:\n", mLabelsInverseMapping.valueAt(label));
        }
        i_t = i;
        ssize_t comment = mComments.indexOfKey(i_t);
        if (comment >= 0) {
            LOGD("; %s\n", mComments.valueAt(comment));
        }
        i_t = i;
        disass_inst(i_t);
        i++;
    }
    LOGD("%s done.\n", __func__);
}

void SHAssembler::comment(const char* string)
{
    mComments.add(mPC, string);
}

void SHAssembler::label(const char* theLabel)
{
    mLabels.add(theLabel, mPC);
    mLabelsInverseMapping.add(mPC, theLabel);
}

const char* SHAssembler::genLabel(void)
{
    const char * ret = NULL;
    if (gen_labels_count < GENERATED_LABELS_MAX) {
        ret = gen_labels[gen_labels_count++];
    }
    return ret;
}

void SHAssembler::BRA(const char* label)
{
    mBranchTargets.add(branch_target_t(label, mPC));
    *mPC++ = (uint16_t) 0xa000 | 0; /* displacement will be set later */
}

void SHAssembler::BT(const char* label)
{
    mBranchTargets.add(branch_target_t(label, mPC));
    *mPC++ = (uint16_t)0x8900 | 0; /* displacement will be set later */
}

void SHAssembler::BF(const char* label)
{
    mBranchTargets.add(branch_target_t(label, mPC));
    *mPC++ = (uint16_t)0x8b00 | 0; /* displacement will be set later */
}

#if 0
#pragma mark -
#pragma mark Prolog/Epilog & Generate...
#endif


void SHAssembler::prolog()
{
    // write dummy prolog code
    uint32_t regs = LSAVED;
    mPrologPC = mPC;
    while (regs) {
        if (regs & 1)
            NOP();
        regs >>= 1;
    }
}

void SHAssembler::epilog(uint32_t touched)
{
    touched &= LSAVED;
    if (touched) {
        // write prolog code
        uint16_t* pc = mPC;
        mPC = mPrologPC;
        PUSH_REGS(touched); /* Note : We don't push PR. Then we can't call
                                      fuctions within generated code. */
        mPC = pc;
        // write epilog code
        POP_REGS(touched);
    }
    // finish writing epilog code
    RTS();
    NOP();  // Delay Slot
}

int SHAssembler::generate(const char* name)
{
    // fixup all the branches
    size_t count = mBranchTargets.size();
    while (count--) {
        const branch_target_t& bt = mBranchTargets[count];
        uint16_t* target_pc = mLabels.valueFor(bt.label);
        LOG_ALWAYS_FATAL_IF(!target_pc,
                "error resolving branch targets, target_pc is null");
        int32_t disp = int32_t(target_pc - (bt.pc+2));
        *bt.pc |= disp & 0xFFF; // bt and bf broken if disp > 0xFF
    }

    size_t size = pc()-base();
    mAssembly->resize(size*2);
    mBase = (uint16_t *)mAssembly->base();
    mPC = mBase + size;

    // the instruction cache is flushed by CodeCache
    const int64_t duration = ggl_system_time() - mDuration;
    const char * const format = "generated %s (%d ins) at [%p:%p] in %lld ns\n";

#if defined(WITH_LIB_HARDWARE)
    if (__builtin_expect(mQemuTracing, 0)) {
        int err = qemu_add_mapping(int(base()), name);
        mQemuTracing = (err >= 0);
    }
#endif

    char value[PROPERTY_VALUE_MAX];
    property_get("debug.pf.disasm", value, "0");
    if (atoi(value) != 0) {
        printf(format, name, int(pc()-base()), base(), pc(), duration);
        disassemble(name);
    }

    return NO_ERROR;
}

uint16_t* SHAssembler::pcForLabel(const char* label)
{
    return mLabels.valueFor(label);
}

// ----------------------------------------------------------------------------

#if 0
#pragma mark -
#pragma mark Arithmetic
#endif

void SHAssembler::ADD(int Rm, int Rn)
{
    *mPC++ = (uint16_t)0x300c | Rm << 4 | Rn << 8;
}

void SHAssembler::ADD_IMM(int32_t immed8, int Rn)
{
    LOG_ALWAYS_FATAL_IF(abs(immed8) >= 0x80,
                        "ADD_IMM immediate too big (%08x)", immed8);
    *mPC++ = (uint16_t)0x7000 | Rn << 8 | (immed8 & 0xFF);
}

void SHAssembler::DMULS(int Rm, int Rn)
{
    *mPC++ = (uint16_t)0x300d | Rm << 4 | Rn << 8;  // DMULS.L Rm,Rn -> MAC
}

void SHAssembler::DMULU(int Rm, int Rn)
{
    *mPC++ = (uint16_t)0x3005 | Rm << 4 | Rn << 8;  // DMULU.L Rm,Rn -> MAC
}

void SHAssembler::MULU(int Rm, int Rn)
{
    *mPC++ = (uint16_t)0x200e | Rm << 4 | Rn << 8;  // MULU.W  Rm,Rn -> MACL
}

void SHAssembler::MULS(int Rm, int Rn)
{
    *mPC++ = (uint16_t)0x200f | Rm << 4 | Rn << 8;  // MULS.W  Rm,Rn -> MACL
}

void SHAssembler::NEG(int Rm, int Rn)
{
    *mPC++ = (uint16_t)0x600b | Rm << 4 | Rn << 8;
}

void SHAssembler::SUB(int Rm, int Rn)
{
    *mPC++ = (uint16_t)0x3008 | Rm << 4 | Rn << 8;
}

void SHAssembler::DT(int Rn)
{
    *mPC++ = (uint16_t)0x4010 | Rn << 8;
}

void SHAssembler::CMP(int cond, int Rm, int Rn)
{
    *mPC++ = (uint16_t)0x3000 | Rn << 8 | Rm << 4 | cond;
}

void SHAssembler::CMP(int cond, int Rn)
{
    *mPC++ = (uint16_t)0x4010 | Rn << 8 | cond;
}

void SHAssembler::EXTU_B(int Rm, int Rn)
{
    *mPC++ = (uint16_t)0x600c | Rn << 8 | Rm << 4;
}

void SHAssembler::EXTU_W(int Rm, int Rn)
{
    *mPC++ = (uint16_t)0x600d | Rn << 8 | Rm << 4;
}

void SHAssembler::EXTS_B(int Rm, int Rn)
{
    *mPC++ = (uint16_t)0x600e | Rn << 8 | Rm << 4;
}

void SHAssembler::EXTS_W(int Rm, int Rn)
{
    *mPC++ = (uint16_t)0x600f | Rn << 8 | Rm << 4;
}

#if 0
#pragma mark -
#pragma mark Logic
#endif

void SHAssembler::AND(int Rm, int Rn)
{
    *mPC++ = (uint16_t)0x2009 | Rn << 8 | Rm << 4;
}

void SHAssembler::AND_IMM(uint32_t immed8)
{
    LOG_ALWAYS_FATAL_IF(immed8 > 0xFF,
                        "AND_IMM immediate too big (%08x)", immed8);
    *mPC++ = (uint16_t)0xc900 | (immed8 & 0xFF);
}

void SHAssembler::NOT(int Rm, int Rn)
{
    *mPC++ = (uint16_t)0x6007 | Rn << 8 | Rm << 4;
}

void SHAssembler::OR(int Rm, int Rn)
{
    *mPC++ = (uint16_t)0x200b | Rn << 8 | Rm << 4;
}

void SHAssembler::OR_IMM(uint32_t immed8)
{
    LOG_ALWAYS_FATAL_IF(immed8 > 0xFF,
                        "OR_IMM immediate too big (%08x)", immed8);
    *mPC++ = (uint16_t)0xcb00 | (immed8 & 0xFF);
}

void SHAssembler::XOR(int Rm, int Rn)
{
    *mPC++ = (uint16_t)0x200a | Rn << 8 | Rm << 4;
}

void SHAssembler::XOR_IMM(uint32_t immed8)
{
    LOG_ALWAYS_FATAL_IF(immed8 > 0xFF,
                        "XOR_IMM immediate too big (%08x)", immed8);
    *mPC++ = (uint16_t)0xca00 | (immed8 & 0xFF);
}

#if 0
#pragma mark -
#pragma mark Shift
#endif

void SHAssembler::ROTL(int bits, int Rn)
{
    while (bits-- > 0)
        *mPC++ = (uint16_t)0x4004 | Rn << 8;
}

void SHAssembler::ROTR(int bits, int Rn)
{
    while (bits-- > 0)
        *mPC++ = (uint16_t)0x4005 | Rn << 8;
}

void SHAssembler::SHAR(int bits, int Rn)
{
    while (bits-- > 0)
        *mPC++ = (uint16_t)0x4021 | Rn << 8;
}

void SHAssembler::SHLL(int bits, int Rn)
{
    switch(bits) {
        case 0: break;
        case 1: SHLL1(Rn); break;
        case 2: SHLL2(Rn); break;
        case 8: SHLL8(Rn); break;
        case 16: SHLL16(Rn); break;
        default:
            IMM(bits, R0);
            SHLD(R0, Rn);
            break;
    }
}

void SHAssembler::SHLR(int bits, int Rn)
{
    switch(bits) {
        case 0: break;
        case 1: SHLR1(Rn); break;
        case 2: SHLR2(Rn); break;
        case 8: SHLR8(Rn); break;
        case 16: SHLR16(Rn); break;
        default:
            IMM(-bits, R0);
            SHLD(R0, Rn);
            break;
    }
}

void SHAssembler::SHAD(int Rm, int Rn)
{
    *mPC++ = (uint16_t)0x400c | Rn << 8 | Rm << 4;
}
void SHAssembler::SHLD(int Rm, int Rn)
{
    *mPC++ = (uint16_t)0x400d | Rn << 8 | Rm << 4;
}
void SHAssembler::SHLL1(int Rn)
{
    *mPC++ = (uint16_t)0x4000 | Rn << 8;
}
void SHAssembler::SHLR1(int Rn)
{
    *mPC++ = (uint16_t)0x4001 | Rn << 8;
}
void SHAssembler::SHLL2(int Rn)
{
    *mPC++ = (uint16_t)0x4008 | Rn << 8;
}
void SHAssembler::SHLR2(int Rn)
{
    *mPC++ = (uint16_t)0x4009 | Rn << 8;
}
void SHAssembler::SHLL8(int Rn)
{
    *mPC++ = (uint16_t)0x4018 | Rn << 8;
}
void SHAssembler::SHLR8(int Rn)
{
    *mPC++ = (uint16_t)0x4019 | Rn << 8;
}
void SHAssembler::SHLL16(int Rn)
{
    *mPC++ = (uint16_t)0x4028 | Rn << 8;
}
void SHAssembler::SHLR16(int Rn)
{
    *mPC++ = (uint16_t)0x4029 | Rn << 8;
}

#if 0
#pragma mark -
#pragma mark Branches...
#endif

// branches...
void SHAssembler::BRA(uint16_t* pc)
{
    int32_t disp = int32_t(pc - (mPC+2));
    *mPC++ = (uint16_t)0xa000 | (disp & 0xFFF);
}
void SHAssembler::BRA(uint16_t disp)
{
    *mPC++ = (uint16_t)0xa000 | (disp & 0xFFF);
}
void SHAssembler::RTS(void)
{
    *mPC++ = 0x000b;
}

#if 0
#pragma mark -
#pragma mark Data Transfer...
#endif

// data transfert...
void SHAssembler::IMM(int32_t immed8, int Rn) {
    LOG_ALWAYS_FATAL_IF(abs(immed8) >= 0x80,
                        "IMM immediate too big (%08x)", immed8);
    *mPC++ = (uint16_t)0xe000 | Rn << 8 | (immed8 & 0xFF);
}

void SHAssembler::IMM16(int32_t immed16, int Rn) {
    LOG_ALWAYS_FATAL_IF(abs(immed16) >= 0x8000,
                        "IMM16 immediate too big (%08x)", immed16);
    IMM((immed16 >> 8) & 0xFF, R0);
    SHLL8(R0);
    OR_IMM(immed16 & 0xFF);
    if (Rn != R0)
        MOV(R0, Rn);
}

void SHAssembler::IMM32(uint32_t immed32, int Rn)
{
    uint32_t    imm;
    int32_t     shift;
    int err = buildImmediate(immed32, shift, imm);

    LOG_ALWAYS_FATAL_IF(err,
                        "IMM32 immediate too big (%08x)",
                        immed32);

    if (err) {
        shift = 24;
        imm = immed32 >> shift;
        IMM(imm, R0);
        while (shift) {
            shift -= 8;
            imm = (immed32 >> shift) & 0xFF;
            SHLL8(R0);
            if (imm)
                OR_IMM(imm);
        }
        MOV(R0, Rn);
    } else {
        IMM(imm, Rn);
        switch (shift) {
        case 0: break;
        case 1: SHLL1(Rn); break;
        case 2: SHLL2(Rn); break;
        case 8: SHLL8(Rn); break;
        case 16: SHLL16(Rn); break;
        default:
            IMM(shift, R0);
            SHLD(R0, Rn);
            break;
        }
    }
}

void SHAssembler::MOV(int Rm, int Rn) {
    *mPC++ = (uint16_t)0x6003 | Rn << 8 | Rm << 4;  // mov    Rm, Rn
}
void SHAssembler::MOV_PC_W(int disp, int Rn) {
    *mPC++ = (uint16_t)0x9000 | Rn << 8 | (disp & 0xFF);  // mov.w  @(disp8,PC), Rn
}
void SHAssembler::MOV_PC_L(int disp, int Rn) {
    *mPC++ = (uint16_t)0xd000 | Rn << 8 | (disp & 0xFF);  // mov.l  @(disp8,PC), Rn
}
void SHAssembler::MOVA(int disp) {
    *mPC++ = (uint16_t)0xc700 | (disp & 0xFF);  // mova  @(disp8,PC), R0
}
void SHAssembler::MOV_LD_B(int Rm, int Rn) {
    *mPC++ = (uint16_t)0x6000 | Rn << 8 | Rm << 4;  // mov.b  @Rm, Rn
}
void SHAssembler::MOV_LD_W(int Rm, int Rn) {
    *mPC++ = (uint16_t)0x6001 | Rn << 8 | Rm << 4;  // mov.w  @Rm, Rn
}
void SHAssembler::MOV_LD_L(int Rm, int Rn) {
    *mPC++ = (uint16_t)0x6002 | Rn << 8 | Rm << 4;  // mov.l  @Rm, Rn
}
void SHAssembler::MOV_LD_B_R0(int Rm, int Rn) {
    *mPC++ = (uint16_t)0x000c | Rn << 8 | Rm << 4;  // mov.b  @(R0,Rm), Rn
}
void SHAssembler::MOV_LD_W_R0(int Rm, int Rn) {
    *mPC++ = (uint16_t)0x000d | Rn << 8 | Rm << 4;  // mov.w  @(R0,Rm), Rn
}
void SHAssembler::MOV_LD_L_R0(int Rm, int Rn) {
    *mPC++ = (uint16_t)0x000e | Rn << 8 | Rm << 4;  // mov.l  @(R0,Rm), Rn
}
void SHAssembler::MOV_ST_B(int Rm, int Rn) {
    *mPC++ = (uint16_t)0x2000 | Rn << 8 | Rm << 4;  // mov.b  Rm, @Rn
}
void SHAssembler::MOV_ST_W(int Rm, int Rn) {
    *mPC++ = (uint16_t)0x2001 | Rn << 8 | Rm << 4;  // mov.w  Rm, @Rn
}
void SHAssembler::MOV_ST_L(int Rm, int Rn) {
    *mPC++ = (uint16_t)0x2002 | Rn << 8 | Rm << 4;  // mov.l  Rm, @Rn
}
void SHAssembler::MOV_ST_B_R0(int Rm, int Rn) {
    *mPC++ = (uint16_t)0x0004 | Rn << 8 | Rm << 4;  // mov.b  Rm, @(R0,Rn)
}
void SHAssembler::MOV_ST_W_R0(int Rm, int Rn) {
    *mPC++ = (uint16_t)0x0005 | Rn << 8 | Rm << 4;  // mov.w  Rm, @(R0,Rn)
}
void SHAssembler::MOV_ST_L_R0(int Rm, int Rn) {
    *mPC++ = (uint16_t)0x0006 | Rn << 8 | Rm << 4;  // mov.l  Rm, @(R0,Rn)
}
void SHAssembler::MOV_LD_B_POSTINC(int Rm, int Rn) {
    *mPC++ = (uint16_t)0x6004 | Rn << 8 | Rm << 4;  // mov.b  @Rm+, Rn
}
void SHAssembler::MOV_LD_W_POSTINC(int Rm, int Rn) {
    *mPC++ = (uint16_t)0x6005 | Rn << 8 | Rm << 4;  // mov.w  @Rm+, Rn
}
void SHAssembler::MOV_LD_L_POSTINC(int Rm, int Rn) {
    *mPC++ = (uint16_t)0x6006 | Rn << 8 | Rm << 4;  // mov.l  @Rm+, Rn
}
void SHAssembler::MOV_LD_B_PREDEC(int Rm, int Rn) {
    *mPC++ = (uint16_t)0x2004 | Rn << 8 | Rm << 4;  // mov.b  Rm, @-Rn
}
void SHAssembler::MOV_LD_W_PREDEC(int Rm, int Rn) {
    *mPC++ = (uint16_t)0x2005 | Rn << 8 | Rm << 4;  // mov.w  Rm, @-Rn
}
void SHAssembler::MOV_LD_L_PREDEC(int Rm, int Rn) {
    *mPC++ = (uint16_t)0x2006 | Rn << 8 | Rm << 4;  // mov.l  Rm, @-Rn
}
void SHAssembler::SWAP_B(int Rm, int Rn) {
    *mPC++ = (uint16_t)0x6008 | Rn << 8 | Rm << 4;  // swap.b  Rm, Rn
}
void SHAssembler::SWAP_W(int Rm, int Rn) {
    *mPC++ = (uint16_t)0x6009 | Rn << 8 | Rm << 4;  // swap.w  Rm, Rn
}

void SHAssembler::POP_REGS(uint32_t reglist)
{
    int Rn = R15;
    assert(sizeof(reglist) * 8 == 32);
    reglist <<= 16;
    while (reglist) {
        if (reglist & 0x80000000)
            MOV_LD_L_POSTINC(SP, Rn);  // mov.l @R15+,Rn
        reglist <<= 1; Rn--;
    }
}

void SHAssembler::PUSH_REGS(uint32_t reglist)
{
    int Rm = R0;
    while (reglist) {
        if (reglist & 1)
            MOV_LD_L_PREDEC(Rm, SP);  // mov.l Rm,@-R15
        reglist >>= 1; Rm++;
    }
}

#if 0
#pragma mark -
#pragma mark Special...
#endif

// special...
void SHAssembler::NOP(void) {
    *mPC++ = 0x0009;
}
void SHAssembler::OCBWB(int Rn) {
    *mPC++ = (uint16_t)0x0063 | Rn << 8;  // ocbwb  @Rn
}
void SHAssembler::PREF(int Rn) {
    *mPC++ = (uint16_t)0x0083 | Rn << 8;  // fref   @Rn
}
void SHAssembler::STS_MACH(int Rn) {
    *mPC++ = (uint16_t)0x000a | Rn << 8;  // sts  mach, Rn
}
void SHAssembler::STS_MACL(int Rn) {
    *mPC++ = (uint16_t)0x001a | Rn << 8;  // sts  macl, Rn
}

void SHAssembler::disass_inst(uint16_t *p)
{
    uint16_t inst = *p;
#define get_rM(_inst) (((_inst) >> 4) & 0xf)
#define get_rN(_inst) (((_inst) >> 8) & 0xf)
#define print_inst(fmt, ...) LOGI("%p : %04x : " fmt, p, inst, __VA_ARGS__)
    switch (inst) {
    case 0x000b:
        print_inst("rts %s", "");
        return;
    case 0x0009:
        print_inst("nop %s", "");
        return;
    }

    switch (inst & 0xf000) {
    case 0x7000:
        print_inst("add   #%x, R%d", inst & 0xff, get_rN(inst));
        return;
    case 0xe000:
        print_inst("mov   #%x, R%d", inst & 0xff, get_rN(inst));
        return;
    case 0x9000:
        print_inst("mov.w @(%x,PC), R%d", inst & 0xff, get_rN(inst));
        return;
    case 0xd000:
        print_inst("mov.l @(%x,PC), R%d", inst & 0xff, get_rN(inst));
        return;
    case 0xa000:
        print_inst("bra   #%x", inst & 0xfff);
        return;
    }

    switch (inst & 0xff00) {
    case 0xc700:
        print_inst("mova  @(%x,PC), R0", inst & 0xff);
        return;
    case 0x8900:
        print_inst("bt    #%x", inst & 0xff);
        return;
    case 0x8b00:
        print_inst("bf    #%x", inst & 0xff);
        return;
    case 0xc900:
        print_inst("and   #%x, R0", inst & 0xff);
        return;
    case 0xcb00:
        print_inst("or    #%x, R0", inst & 0xff);
        return;
    case 0xca00:
        print_inst("xor   #%x, R0", inst & 0xff);
        return;
    }

    switch (inst & 0xf00f) {
    // Arithmetic
    case 0x300c:
        print_inst("add     R%d, R%d", get_rM(inst), get_rN(inst));
        return;
    case 0x0007:
        print_inst("mul.l   R%d, R%d", get_rM(inst), get_rN(inst));
        return;
    case 0x300d:
        print_inst("dmuls.l R%d, R%d", get_rM(inst), get_rN(inst));
        return;
    case 0x3005:
        print_inst("dmulu.l R%d, R%d", get_rM(inst), get_rN(inst));
        return;
    case 0x200e:
        print_inst("mulu.w  R%d, R%d", get_rM(inst), get_rN(inst));
        return;
    case 0x200f:
        print_inst("muls.w  R%d, R%d", get_rM(inst), get_rN(inst));
        return;
    case 0x600b:
        print_inst("neg     R%d, R%d", get_rM(inst), get_rN(inst));
        return;
    case 0x3008:
        print_inst("sub     R%d, R%d", get_rM(inst), get_rN(inst));
        return;
    case 0x3000:
        print_inst("cmp/eq  R%d, R%d", get_rM(inst), get_rN(inst));
        return;
    case 0x3002:
        print_inst("cmp/hs  R%d, R%d", get_rM(inst), get_rN(inst));
        return;
    case 0x3003:
        print_inst("cmp/ge  R%d, R%d", get_rM(inst), get_rN(inst));
        return;
    case 0x3006:
        print_inst("cmp/hi  R%d, R%d", get_rM(inst), get_rN(inst));
        return;
    case 0x3007:
        print_inst("cmp/gt  R%d, R%d", get_rM(inst), get_rN(inst));
        return;
    case 0x600c:
        print_inst("extu.b  R%d, R%d", get_rM(inst), get_rN(inst));
        return;
    case 0x600d:
        print_inst("extu.w  R%d, R%d", get_rM(inst), get_rN(inst));
        return;
    case 0x600e:
        print_inst("exts.b  R%d, R%d", get_rM(inst), get_rN(inst));
        return;
    case 0x600f:
        print_inst("exts.w  R%d, R%d", get_rM(inst), get_rN(inst));
        return;
    // Logic
    case 0x2009:
        print_inst("and     R%d, R%d", get_rM(inst), get_rN(inst));
        return;
    case 0x6007:
        print_inst("not     R%d, R%d", get_rM(inst), get_rN(inst));
        return;
    case 0x200b:
        print_inst("or      R%d, R%d", get_rM(inst), get_rN(inst));
        return;
    case 0x200a:
        print_inst("xor     R%d, R%d", get_rM(inst), get_rN(inst));
        return;
    // Shift
    case 0x400c:
        print_inst("shad    R%d, R%d", get_rM(inst), get_rN(inst));
        return;
    case 0x400d:
        print_inst("shld    R%d, R%d", get_rM(inst), get_rN(inst));
        return;
    // data transfer
    case 0x6003:
        print_inst("mov     R%d, R%d", get_rM(inst), get_rN(inst));
        return;
    case 0x6000:
        print_inst("mov.b   @R%d, R%d", get_rM(inst), get_rN(inst));
        return;
    case 0x6001:
        print_inst("mov.w   @R%d, R%d", get_rM(inst), get_rN(inst));
        return;
    case 0x6002:
        print_inst("mov.l   @R%d, R%d", get_rM(inst), get_rN(inst));
        return;
    case 0x000c:
        print_inst("mov.b   @(R0,R%d), R%d", get_rM(inst), get_rN(inst));
        return;
    case 0x000d:
        print_inst("mov.w   @(R0,R%d), R%d", get_rM(inst), get_rN(inst));
        return;
    case 0x000e:
        print_inst("mov.l   @(R0,R%d), R%d", get_rM(inst), get_rN(inst));
        return;
    case 0x2000:
        print_inst("mov.b   R%d, @R%d", get_rM(inst), get_rN(inst));
        return;
    case 0x2001:
        print_inst("mov.w   R%d, @R%d", get_rM(inst), get_rN(inst));
        return;
    case 0x2002:
        print_inst("mov.l   R%d, @R%d", get_rM(inst), get_rN(inst));
        return;
    case 0x0004:
        print_inst("mov.b   R%d, @(R0,R%d)", get_rM(inst), get_rN(inst));
        return;
    case 0x0005:
        print_inst("mov.w   R%d, @(R0,R%d)", get_rM(inst), get_rN(inst));
        return;
    case 0x0006:
        print_inst("mov.l   R%d, @(R0,R%d)", get_rM(inst), get_rN(inst));
        return;
    case 0x6004:
        print_inst("mov.b   @R%d+, R%d", get_rM(inst), get_rN(inst));
        return;
    case 0x6005:
        print_inst("mov.w   @R%d+, R%d", get_rM(inst), get_rN(inst));
        return;
    case 0x6006:
        print_inst("mov.l   @R%d+, R%d", get_rM(inst), get_rN(inst));
        return;
    case 0x2004:
        print_inst("mov.b   R%d, @-R%d", get_rM(inst), get_rN(inst));
        return;
    case 0x2005:
        print_inst("mov.w   R%d, @-R%d", get_rM(inst), get_rN(inst));
        return;
    case 0x2006:
        print_inst("mov.l   R%d, @-R%d", get_rM(inst), get_rN(inst));
        return;
    case 0x6008:
        print_inst("swap.b   R%d, R%d", get_rM(inst), get_rN(inst));
        return;
    case 0x6009:
        print_inst("swap.w   R%d, R%d", get_rM(inst), get_rN(inst));
        return;
    }

    switch (inst & 0xf0ff) {
    case 0x0063:
        print_inst("ocbwb   @R%d", get_rN(inst));
        return;
    case 0x0083:
        print_inst("pref    @R%d", get_rN(inst));
        return;
    case 0x000a:
        print_inst("sts     mach, R%d", get_rN(inst));
        return;
    case 0x001a:
        print_inst("sts     macl, R%d", get_rN(inst));
        return;
    case 0x4010:
        print_inst("dt      R%d", get_rN(inst));
        return;
    case 0x4011:
        print_inst("cmp/pz  R%d", get_rN(inst));
        return;
    case 0x4015:
        print_inst("cmp/pl  R%d", get_rN(inst));
        return;
    case 0x4004:
        print_inst("rotl    R%d", get_rN(inst));
        return;
    case 0x4005:
        print_inst("rotr    R%d", get_rN(inst));
        return;
    case 0x4028:
        print_inst("shll16  R%d", get_rN(inst));
        return;
    case 0x4018:
        print_inst("shll8   R%d", get_rN(inst));
        return;
    case 0x4008:
        print_inst("shll2   R%d", get_rN(inst));
        return;
    case 0x4000:
        print_inst("shll    R%d", get_rN(inst));
        return;
    case 0x4029:
        print_inst("shlr16  R%d", get_rN(inst));
        return;
    case 0x4019:
        print_inst("shlr8   R%d", get_rN(inst));
        return;
    case 0x4009:
        print_inst("shlr2   R%d", get_rN(inst));
        return;
    case 0x4001:
        print_inst("shlr    R%d", get_rN(inst));
        return;
    case 0x4021:
        print_inst("shar    R%d", get_rN(inst));
        return;
    }
    print_inst("unknown inst=%x", inst);
}

}; // namespace android

