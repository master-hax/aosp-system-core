/* libs/pixelflinger/codeflinger/MIPS64Assembler.cpp
**
** Copyright 2015, The Android Open Source Project
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


/* MIPS64 assembler and ARM->MIPS64 assembly translator
**
** The approach is to leave the GGLAssembler and associated files largely
** un-changed, still utilizing all Arm instruction generation. Via the
** ArmToMips64Assembler (subclassed from ArmAssemblerInterface) each Arm
** instruction is translated to one or more Mips instructions as necessary. This
** is clearly less efficient than a direct implementation within the
** GGLAssembler, but is far cleaner, more maintainable, and has yielded very
** significant performance gains on Mips compared to the generic pixel pipeline.
**
**
** GGLAssembler changes
**
** - The register allocator has been modified to re-map Arm registers 0-15 to mips
** registers 2-17. Mips register 0 cannot be used as general-purpose register,
** and register 1 has traditional uses as a short-term temporary.
**
** - Added some early bailouts for OUT_OF_REGISTERS in texturing.cpp and
** GGLAssembler.cpp, since this is not fatal, and can be retried at lower
** optimization level.
**
**
** ARMAssembler and ARMAssemblerInterface changes
**
** Refactored ARM address-mode static functions (imm(), reg_imm(), imm12_pre(), etc.)
** to virtual, so they can be overridden in MIPS64Assembler. The implementation of these
** functions on ARM is moved from ARMAssemblerInterface.cpp to ARMAssembler.cpp, and
** is unchanged from the original. (This required duplicating 2 of these as static
** functions in ARMAssemblerInterface.cpp so they could be used as static initializers).
*/


#define LOG_TAG "MIPS64Assembler"

#include <stdio.h>
#include <stdlib.h>
#include <cutils/log.h>
#include <cutils/properties.h>

#if defined(WITH_LIB_HARDWARE)
#include <hardware_legacy/qemu_tracing.h>
#endif

#include <private/pixelflinger/ggl_context.h>

#include "MIPS64Assembler.h"
#include "CodeCache.h"
#include "mips64_disassem.h"


#define NOT_IMPLEMENTED()  LOG_ALWAYS_FATAL("Arm instruction %s not yet implemented\n", __func__)


// ----------------------------------------------------------------------------

namespace android {

// ----------------------------------------------------------------------------
#if 0
#pragma mark -
#pragma mark ArmToMips64Assembler...
#endif

ArmToMips64Assembler::ArmToMips64Assembler(const sp<Assembly>& assembly,
                                           char *abuf, int linesz, int instr_count)
    :   ARMAssemblerInterface(),
        mArmDisassemblyBuffer(abuf),
        mArmLineLength(linesz),
        mArmInstrCount(instr_count),
        mInum(0),
        mAssembly(assembly)
{
    mMips = new MIPS64Assembler(assembly, this);
    mArmPC = (uint32_t **) malloc(ARM_MAX_INSTUCTIONS * sizeof(uint32_t *));
    init_conditional_labels();
}

ArmToMips64Assembler::ArmToMips64Assembler(void* assembly)
    :   ARMAssemblerInterface(),
        mArmDisassemblyBuffer(NULL),
        mInum(0),
        mAssembly(NULL)
{
    mMips = new MIPS64Assembler(assembly, this);
    mArmPC = (uint32_t **) malloc(ARM_MAX_INSTUCTIONS * sizeof(uint32_t *));
    init_conditional_labels();
}

ArmToMips64Assembler::~ArmToMips64Assembler()
{
    delete mMips;
    free((void *) mArmPC);
}

uint32_t* ArmToMips64Assembler::pc() const
{
    return mMips->pc();
}

uint32_t* ArmToMips64Assembler::base() const
{
    return mMips->base();
}

void ArmToMips64Assembler::reset()
{
    cond.labelnum = 0;
    mInum = 0;
    mMips->reset();
}

int ArmToMips64Assembler::getCodegenArch()
{
    return CODEGEN_ARCH_MIPS64;
}

void ArmToMips64Assembler::comment(const char* string)
{
    mMips->comment(string);
}

void ArmToMips64Assembler::label(const char* theLabel)
{
    mMips->label(theLabel);
}

void ArmToMips64Assembler::disassemble(const char* name)
{
    mMips->disassemble(name);
}

void ArmToMips64Assembler::init_conditional_labels()
{
    int i;
    for (i=0;i<99; ++i) {
        sprintf(cond.label[i], "cond_%d", i);
    }
}



#if 0
#pragma mark -
#pragma mark Prolog/Epilog & Generate...
#endif

void ArmToMips64Assembler::prolog()
{
    mArmPC[mInum++] = pc();  // save starting PC for this instr

    mMips->DADDIU(R_sp, R_sp, -(5 * 8));
    mMips->SD(R_s0, R_sp, 0);
    mMips->SD(R_s1, R_sp, 8);
    mMips->SD(R_s2, R_sp, 16);
    mMips->SD(R_s3, R_sp, 24);
    mMips->SD(R_s4, R_sp, 32);
    mMips->MOVE(R_v0, R_a0);    // move context * passed in a0 to v0 (arm r0)
}

void ArmToMips64Assembler::epilog(uint32_t touched)
{
    mArmPC[mInum++] = pc();  // save starting PC for this instr

    mMips->LD(R_s0, R_sp, 0);
    mMips->LD(R_s1, R_sp, 8);
    mMips->LD(R_s2, R_sp, 16);
    mMips->LD(R_s3, R_sp, 24);
    mMips->LD(R_s4, R_sp, 32);
    mMips->DADDIU(R_sp, R_sp, (5 * 8));
    mMips->JR(R_ra);

}

int ArmToMips64Assembler::generate(const char* name)
{
    return mMips->generate(name);
}

void ArmToMips64Assembler::fix_branches()
{
    mMips->fix_branches();
}

uint32_t* ArmToMips64Assembler::pcForLabel(const char* label)
{
    return mMips->pcForLabel(label);
}

void ArmToMips64Assembler::set_condition(int mode, int R1, int R2) {
    if (mode == 2) {
        cond.type = SBIT_COND;
    } else {
        cond.type = CMP_COND;
    }
    cond.r1 = R1;
    cond.r2 = R2;
}

//----------------------------------------------------------

#if 0
#pragma mark -
#pragma mark Addressing modes & shifters...
#endif


// do not need this for MIPS, but it is in the Interface (virtual)
int ArmToMips64Assembler::buildImmediate(
        uint32_t immediate, uint32_t& rot, uint32_t& imm)
{
    // for MIPS, any 32-bit immediate is OK
    rot = 0;
    imm = immediate;
    return 0;
}

// shifters...

bool ArmToMips64Assembler::isValidImmediate(uint32_t immediate)
{
    // for MIPS, any 32-bit immediate is OK
    return true;
}

uint32_t ArmToMips64Assembler::imm(uint32_t immediate)
{
    amode.value = immediate;
    return AMODE_IMM;
}

uint32_t ArmToMips64Assembler::reg_imm(int Rm, int type, uint32_t shift)
{
    amode.reg = Rm;
    amode.stype = type;
    amode.value = shift;
    return AMODE_REG_IMM;
}

uint32_t ArmToMips64Assembler::reg_rrx(int Rm)
{
    // reg_rrx mode is not used in the GLLAssember code at this time
    return AMODE_UNSUPPORTED;
}

uint32_t ArmToMips64Assembler::reg_reg(int Rm, int type, int Rs)
{
    // reg_reg mode is not used in the GLLAssember code at this time
    return AMODE_UNSUPPORTED;
}


// addressing modes...
// LDR(B)/STR(B)/PLD (immediate and Rm can be negative, which indicate U=0)
uint32_t ArmToMips64Assembler::immed12_pre(int32_t immed12, int W)
{
    LOG_ALWAYS_FATAL_IF(abs(immed12) >= 0x800,
                        "LDR(B)/STR(B)/PLD immediate too big (%08x)",
                        immed12);
    amode.value = immed12;
    amode.writeback = W;
    return AMODE_IMM_12_PRE;
}

uint32_t ArmToMips64Assembler::immed12_post(int32_t immed12)
{
    LOG_ALWAYS_FATAL_IF(abs(immed12) >= 0x800,
                        "LDR(B)/STR(B)/PLD immediate too big (%08x)",
                        immed12);

    amode.value = immed12;
    return AMODE_IMM_12_POST;
}

uint32_t ArmToMips64Assembler::reg_scale_pre(int Rm, int type,
        uint32_t shift, int W)
{
    LOG_ALWAYS_FATAL_IF(W | type | shift, "reg_scale_pre adv modes not yet implemented");

    amode.reg = Rm;
    // amode.stype = type;      // more advanced modes not used in GGLAssembler yet
    // amode.value = shift;
    // amode.writeback = W;
    return AMODE_REG_SCALE_PRE;
}

uint32_t ArmToMips64Assembler::reg_scale_post(int Rm, int type, uint32_t shift)
{
    LOG_ALWAYS_FATAL("adr mode reg_scale_post not yet implemented\n");
    return AMODE_UNSUPPORTED;
}

// LDRH/LDRSB/LDRSH/STRH (immediate and Rm can be negative, which indicate U=0)
uint32_t ArmToMips64Assembler::immed8_pre(int32_t immed8, int W)
{
    LOG_ALWAYS_FATAL("adr mode immed8_pre not yet implemented\n");

    LOG_ALWAYS_FATAL_IF(abs(immed8) >= 0x100,
                        "LDRH/LDRSB/LDRSH/STRH immediate too big (%08x)",
                        immed8);
    return AMODE_IMM_8_PRE;
}

uint32_t ArmToMips64Assembler::immed8_post(int32_t immed8)
{
    LOG_ALWAYS_FATAL_IF(abs(immed8) >= 0x100,
                        "LDRH/LDRSB/LDRSH/STRH immediate too big (%08x)",
                        immed8);
    amode.value = immed8;
    return AMODE_IMM_8_POST;
}

uint32_t ArmToMips64Assembler::reg_pre(int Rm, int W)
{
    LOG_ALWAYS_FATAL_IF(W, "reg_pre writeback not yet implemented");
    amode.reg = Rm;
    return AMODE_REG_PRE;
}

uint32_t ArmToMips64Assembler::reg_post(int Rm)
{
    LOG_ALWAYS_FATAL("adr mode reg_post not yet implemented\n");
    return AMODE_UNSUPPORTED;
}



// ----------------------------------------------------------------------------

#if 0
#pragma mark -
#pragma mark Data Processing...
#endif


static const char * const dpOpNames[] = {
    "AND", "EOR", "SUB", "RSB", "ADD", "ADC", "SBC", "RSC",
    "TST", "TEQ", "CMP", "CMN", "ORR", "MOV", "BIC", "MVN"
};

// check if the operand registers from a previous CMP or S-bit instruction
// would be overwritten by this instruction. If so, move the value to a
// safe register.
// Note that we cannot tell at _this_ instruction time if a future (conditional)
// instruction will _also_ use this value (a defect of the simple 1-pass, one-
// instruction-at-a-time translation). Therefore we must be conservative and
// save the value before it is overwritten. This costs an extra MOVE instr.

void ArmToMips64Assembler::protectConditionalOperands(int Rd)
{
    if (Rd == cond.r1) {
        mMips->MOVE(R_cmp, cond.r1);
        cond.r1 = R_cmp;
    }
    if (cond.type == CMP_COND && Rd == cond.r2) {
        mMips->MOVE(R_cmp2, cond.r2);
        cond.r2 = R_cmp2;
    }
}


// interprets the addressing mode, and generates the common code
// used by the majority of data-processing ops. Many MIPS instructions
// have a register-based form and a different immediate form. See
// opAND below for an example. (this could be inlined)
//
// this works with the imm(), reg_imm() methods above, which are directly
// called by the GLLAssembler.
// note: _signed parameter defaults to false (un-signed)
// note: tmpReg parameter defaults to 1, MIPS register AT
int ArmToMips64Assembler::dataProcAdrModes(int op, int& source, bool _signed, int tmpReg)
{
    if (op < AMODE_REG) {
        source = op;
        return SRC_REG;
    } else if (op == AMODE_IMM) {
        if ((!_signed && amode.value > 0xffff)
                || (_signed && ((int)amode.value < -32768 || (int)amode.value > 32767) )) {
            mMips->LUI(tmpReg, (amode.value >> 16));
            if (amode.value & 0x0000ffff) {
                mMips->ORI(tmpReg, tmpReg, (amode.value & 0x0000ffff));
            }
            source = tmpReg;
            return SRC_REG;
        } else {
            source = amode.value;
            return SRC_IMM;
        }
    } else if (op == AMODE_REG_IMM) {
        switch (amode.stype) {
            case LSL: mMips->SLL(tmpReg, amode.reg, amode.value); break;
            case LSR: mMips->SRL(tmpReg, amode.reg, amode.value); break;
            case ASR: mMips->SRA(tmpReg, amode.reg, amode.value); break;
            case ROR: mMips->ROTR(tmpReg, amode.reg, amode.value); break;
        }
        source = tmpReg;
        return SRC_REG;
    } else {  // adr mode RRX is not used in GGL Assembler at this time
        // we are screwed, this should be exception, assert-fail or something
        LOG_ALWAYS_FATAL("adr mode reg_rrx not yet implemented\n");
        return SRC_ERROR;
    }
}


void ArmToMips64Assembler::dataProcessing(int opcode, int cc,
        int s, int Rd, int Rn, uint32_t Op2)
{
    int src;    // src is modified by dataProcAdrModes() - passed as int&

    if (cc != AL) {
        protectConditionalOperands(Rd);
        // the branch tests register(s) set by prev CMP or instr with 'S' bit set
        // inverse the condition to jump past this conditional instruction
        ArmToMips64Assembler::B(cc^1, cond.label[++cond.labelnum]);
    } else {
        mArmPC[mInum++] = pc();  // save starting PC for this instr
    }

    switch (opcode) {
    case opAND:
        if (dataProcAdrModes(Op2, src) == SRC_REG) {
            mMips->AND(Rd, Rn, src);
        } else {                        // adr mode was SRC_IMM
            mMips->ANDI(Rd, Rn, src);
        }
        break;

    case opADD:
        // set "signed" to true for adr modes
        if (dataProcAdrModes(Op2, src, true) == SRC_REG) {
            mMips->ADDU(Rd, Rn, src);
        } else {                        // adr mode was SRC_IMM
            mMips->ADDIU(Rd, Rn, src);
        }
        break;

    case opSUB:
        // set "signed" to true for adr modes
        if (dataProcAdrModes(Op2, src, true) == SRC_REG) {
            mMips->SUBU(Rd, Rn, src);
        } else {                        // adr mode was SRC_IMM
            mMips->SUBIU(Rd, Rn, src);
        }
        break;

    case opADD64:
        // set "signed" to true for adr modes
        if (dataProcAdrModes(Op2, src, true) == SRC_REG) {
            mMips->DADDU(Rd, Rn, src);
        } else {                        // adr mode was SRC_IMM
            mMips->DADDIU(Rd, Rn, src);
        }
        break;

    case opSUB64:
        // set "signed" to true for adr modes
        if (dataProcAdrModes(Op2, src, true) == SRC_REG) {
            mMips->DSUBU(Rd, Rn, src);
        } else {                        // adr mode was SRC_IMM
            mMips->DSUBIU(Rd, Rn, src);
        }
        break;

    case opEOR:
        if (dataProcAdrModes(Op2, src) == SRC_REG) {
            mMips->XOR(Rd, Rn, src);
        } else {                        // adr mode was SRC_IMM
            mMips->XORI(Rd, Rn, src);
        }
        break;

    case opORR:
        if (dataProcAdrModes(Op2, src) == SRC_REG) {
            mMips->OR(Rd, Rn, src);
        } else {                        // adr mode was SRC_IMM
            mMips->ORI(Rd, Rn, src);
        }
        break;

    case opBIC:
        if (dataProcAdrModes(Op2, src) == SRC_IMM) {
            // if we are 16-bit imnmediate, load to AT reg
            mMips->ORI(R_at, 0, src);
            src = R_at;
        }
        mMips->NOT(R_at, src);
        mMips->AND(Rd, Rn, R_at);
        break;

    case opRSB:
        if (dataProcAdrModes(Op2, src) == SRC_IMM) {
            // if we are 16-bit imnmediate, load to AT reg
            mMips->ORI(R_at, 0, src);
            src = R_at;
        }
        mMips->SUBU(Rd, src, Rn);   // subu with the parameters reversed
        break;

    case opMOV:
        if (Op2 < AMODE_REG) {  // op2 is reg # in this case
            mMips->MOVE(Rd, Op2);
        } else if (Op2 == AMODE_IMM) {
            if (amode.value > 0xffff) {
                mMips->LUI(Rd, (amode.value >> 16));
                if (amode.value & 0x0000ffff) {
                    mMips->ORI(Rd, Rd, (amode.value & 0x0000ffff));
                }
             } else {
                mMips->ORI(Rd, 0, amode.value);
            }
        } else if (Op2 == AMODE_REG_IMM) {
            switch (amode.stype) {
            case LSL: mMips->SLL(Rd, amode.reg, amode.value); break;
            case LSR: mMips->SRL(Rd, amode.reg, amode.value); break;
            case ASR: mMips->SRA(Rd, amode.reg, amode.value); break;
            case ROR: mMips->ROTR(Rd, amode.reg, amode.value); break;
            }
        }
        else {
            // adr mode RRX is not used in GGL Assembler at this time
            mMips->UNIMPL();
        }
        break;

    case opMVN:     // this is a 1's complement: NOT
        if (Op2 < AMODE_REG) {  // op2 is reg # in this case
            mMips->NOR(Rd, Op2, 0);     // NOT is NOR with 0
            break;
        } else if (Op2 == AMODE_IMM) {
            if (amode.value > 0xffff) {
                mMips->LUI(Rd, (amode.value >> 16));
                if (amode.value & 0x0000ffff) {
                    mMips->ORI(Rd, Rd, (amode.value & 0x0000ffff));
                }
             } else {
                mMips->ORI(Rd, 0, amode.value);
             }
        } else if (Op2 == AMODE_REG_IMM) {
            switch (amode.stype) {
            case LSL: mMips->SLL(Rd, amode.reg, amode.value); break;
            case LSR: mMips->SRL(Rd, amode.reg, amode.value); break;
            case ASR: mMips->SRA(Rd, amode.reg, amode.value); break;
            case ROR: mMips->ROTR(Rd, amode.reg, amode.value); break;
            }
        }
        else {
            // adr mode RRX is not used in GGL Assembler at this time
            mMips->UNIMPL();
        }
        mMips->NOR(Rd, Rd, 0);     // NOT is NOR with 0
        break;

    case opCMP:
        // Either operand of a CMP instr could get overwritten by a subsequent
        // conditional instruction, which is ok, _UNLESS_ there is a _second_
        // conditional instruction. Under MIPS, this requires doing the comparison
        // again (SLT), and the original operands must be available. (and this
        // pattern of multiple conditional instructions from same CMP _is_ used
        // in GGL-Assembler)
        //
        // For now, if a conditional instr overwrites the operands, we will
        // move them to dedicated temp regs. This is ugly, and inefficient,
        // and should be optimized.
        //
        // WARNING: making an _Assumption_ that CMP operand regs will NOT be
        // trashed by intervening NON-conditional instructions. In the general
        // case this is legal, but it is NOT currently done in GGL-Assembler.

        cond.type = CMP_COND;
        cond.r1 = Rn;
        if (dataProcAdrModes(Op2, src, false, R_cmp2) == SRC_REG) {
            cond.r2 = src;
        } else {                        // adr mode was SRC_IMM
            mMips->ORI(R_cmp2, R_zero, src);
            cond.r2 = R_cmp2;
        }

        break;


    case opTST:
    case opTEQ:
    case opCMN:
    case opADC:
    case opSBC:
    case opRSC:
        mMips->UNIMPL(); // currently unused in GGL Assembler code
        break;
    }

    if (cc != AL) {
        mMips->label(cond.label[cond.labelnum]);
    }
    if (s && opcode != opCMP) {
        cond.type = SBIT_COND;
        cond.r1 = Rd;
    }
}



#if 0
#pragma mark -
#pragma mark Multiply...
#endif

// multiply, accumulate
void ArmToMips64Assembler::MLA(int cc, int s,
        int Rd, int Rm, int Rs, int Rn) {

    //ALOGW("MLA");
    mArmPC[mInum++] = pc();  // save starting PC for this instr

    mMips->MUL(R_at, Rm, Rs);
    mMips->ADDU(Rd, R_at, Rn);
    if (s) {
        cond.type = SBIT_COND;
        cond.r1 = Rd;
    }
}

void ArmToMips64Assembler::MUL(int cc, int s,
        int Rd, int Rm, int Rs) {
    mArmPC[mInum++] = pc();
    mMips->MUL(Rd, Rm, Rs);
    if (s) {
        cond.type = SBIT_COND;
        cond.r1 = Rd;
    }
}

void ArmToMips64Assembler::UMULL(int cc, int s,
        int RdLo, int RdHi, int Rm, int Rs) {
    mArmPC[mInum++] = pc();
    mMips->MUH(RdHi, Rm, Rs);
    mMips->MUL(RdLo, Rm, Rs);

    if (s) {
        cond.type = SBIT_COND;
        cond.r1 = RdHi;     // BUG...
        LOG_ALWAYS_FATAL("Condition on UMULL must be on 64-bit result\n");
    }
}

void ArmToMips64Assembler::UMUAL(int cc, int s,
        int RdLo, int RdHi, int Rm, int Rs) {
    LOG_FATAL_IF(RdLo==Rm || RdHi==Rm || RdLo==RdHi,
                        "UMUAL(r%u,r%u,r%u,r%u)", RdLo,RdHi,Rm,Rs);
    // *mPC++ =    (cc<<28) | (1<<23) | (1<<21) | (s<<20) |
    //             (RdHi<<16) | (RdLo<<12) | (Rs<<8) | 0x90 | Rm;
    mArmPC[mInum++] = pc();
    mMips->NOP2();
    NOT_IMPLEMENTED();
    if (s) {
        cond.type = SBIT_COND;
        cond.r1 = RdHi;     // BUG...
        LOG_ALWAYS_FATAL("Condition on UMULL must be on 64-bit result\n");
    }
}

void ArmToMips64Assembler::SMULL(int cc, int s,
        int RdLo, int RdHi, int Rm, int Rs) {
    LOG_FATAL_IF(RdLo==Rm || RdHi==Rm || RdLo==RdHi,
                        "SMULL(r%u,r%u,r%u,r%u)", RdLo,RdHi,Rm,Rs);
    // *mPC++ =    (cc<<28) | (1<<23) | (1<<22) | (s<<20) |
    //             (RdHi<<16) | (RdLo<<12) | (Rs<<8) | 0x90 | Rm;
    mArmPC[mInum++] = pc();
    mMips->NOP2();
    NOT_IMPLEMENTED();
    if (s) {
        cond.type = SBIT_COND;
        cond.r1 = RdHi;     // BUG...
        LOG_ALWAYS_FATAL("Condition on SMULL must be on 64-bit result\n");
    }
}
void ArmToMips64Assembler::SMUAL(int cc, int s,
        int RdLo, int RdHi, int Rm, int Rs) {
    LOG_FATAL_IF(RdLo==Rm || RdHi==Rm || RdLo==RdHi,
                        "SMUAL(r%u,r%u,r%u,r%u)", RdLo,RdHi,Rm,Rs);
    // *mPC++ =    (cc<<28) | (1<<23) | (1<<22) | (1<<21) | (s<<20) |
    //             (RdHi<<16) | (RdLo<<12) | (Rs<<8) | 0x90 | Rm;
    mArmPC[mInum++] = pc();
    mMips->NOP2();
    NOT_IMPLEMENTED();
    if (s) {
        cond.type = SBIT_COND;
        cond.r1 = RdHi;     // BUG...
        LOG_ALWAYS_FATAL("Condition on SMUAL must be on 64-bit result\n");
    }
}



#if 0
#pragma mark -
#pragma mark Branches...
#endif

// branches...

void ArmToMips64Assembler::B(int cc, const char* label)
{
    mArmPC[mInum++] = pc();
    if (cond.type == SBIT_COND) { cond.r2 = R_zero; }

    switch(cc) {
        case EQ: mMips->BEQ(cond.r1, cond.r2, label); break;
        case NE: mMips->BNE(cond.r1, cond.r2, label); break;
        case HS: mMips->BGEU(cond.r1, cond.r2, label); break;
        case LO: mMips->BLTU(cond.r1, cond.r2, label); break;
        case MI: mMips->BLT(cond.r1, cond.r2, label); break;
        case PL: mMips->BGE(cond.r1, cond.r2, label); break;

        case HI: mMips->BGTU(cond.r1, cond.r2, label); break;
        case LS: mMips->BLEU(cond.r1, cond.r2, label); break;
        case GE: mMips->BGE(cond.r1, cond.r2, label); break;
        case LT: mMips->BLT(cond.r1, cond.r2, label); break;
        case GT: mMips->BGT(cond.r1, cond.r2, label); break;
        case LE: mMips->BLE(cond.r1, cond.r2, label); break;
        case AL: mMips->B(label); break;
        case NV: /* B Never - no instruction */ break;

        case VS:
        case VC:
        default:
            LOG_ALWAYS_FATAL("Unsupported cc: %02x\n", cc);
            break;
    }
}

void ArmToMips64Assembler::BL(int cc, const char* label)
{
    LOG_ALWAYS_FATAL("branch-and-link not supported yet\n");
    mArmPC[mInum++] = pc();
}

// no use for Branches with integer PC, but they're in the Interface class ....
void ArmToMips64Assembler::B(int cc, uint32_t* to_pc)
{
    LOG_ALWAYS_FATAL("branch to absolute PC not supported, use Label\n");
    mArmPC[mInum++] = pc();
}

void ArmToMips64Assembler::BL(int cc, uint32_t* to_pc)
{
    LOG_ALWAYS_FATAL("branch to absolute PC not supported, use Label\n");
    mArmPC[mInum++] = pc();
}

void ArmToMips64Assembler::BX(int cc, int Rn)
{
    LOG_ALWAYS_FATAL("branch to absolute PC not supported, use Label\n");
    mArmPC[mInum++] = pc();
}



#if 0
#pragma mark -
#pragma mark Data Transfer...
#endif

// data transfer...
void ArmToMips64Assembler::LDR(int cc, int Rd, int Rn, uint32_t offset)
{
    mArmPC[mInum++] = pc();
    // work-around for ARM default address mode of immed12_pre(0)
    if (offset > AMODE_UNSUPPORTED) offset = 0;
    switch (offset) {
        case 0:
            amode.value = 0;
            amode.writeback = 0;
            // fall thru to next case ....
        case AMODE_IMM_12_PRE:
            if (Rn == ARMAssemblerInterface::SP) {
                Rn = R_sp;      // convert LDR via Arm SP to LW via Mips SP
            }
            mMips->LW(Rd, Rn, amode.value);
            if (amode.writeback) {      // OPTIONAL writeback on pre-index mode
                mMips->DADDIU(Rn, Rn, amode.value);
            }
            break;
        case AMODE_IMM_12_POST:
            if (Rn == ARMAssemblerInterface::SP) {
                Rn = R_sp;      // convert STR thru Arm SP to STR thru Mips SP
            }
            mMips->LW(Rd, Rn, 0);
            mMips->DADDIU(Rn, Rn, amode.value);
            break;
        case AMODE_REG_SCALE_PRE:
            // we only support simple base + index, no advanced modes for this one yet
            mMips->DADDU(R_at, Rn, amode.reg);
            mMips->LW(Rd, R_at, 0);
            break;
    }
}

void ArmToMips64Assembler::LDRB(int cc, int Rd, int Rn, uint32_t offset)
{
    mArmPC[mInum++] = pc();
    // work-around for ARM default address mode of immed12_pre(0)
    if (offset > AMODE_UNSUPPORTED) offset = 0;
    switch (offset) {
        case 0:
            amode.value = 0;
            amode.writeback = 0;
            // fall thru to next case ....
        case AMODE_IMM_12_PRE:
            mMips->LBU(Rd, Rn, amode.value);
            if (amode.writeback) {      // OPTIONAL writeback on pre-index mode
                mMips->DADDIU(Rn, Rn, amode.value);
            }
            break;
        case AMODE_IMM_12_POST:
            mMips->LBU(Rd, Rn, 0);
            mMips->DADDIU(Rn, Rn, amode.value);
            break;
        case AMODE_REG_SCALE_PRE:
            // we only support simple base + index, no advanced modes for this one yet
            mMips->DADDU(R_at, Rn, amode.reg);
            mMips->LBU(Rd, R_at, 0);
            break;
    }

}

void ArmToMips64Assembler::STR(int cc, int Rd, int Rn, uint32_t offset)
{
    mArmPC[mInum++] = pc();
    // work-around for ARM default address mode of immed12_pre(0)
    if (offset > AMODE_UNSUPPORTED) offset = 0;
    switch (offset) {
        case 0:
            amode.value = 0;
            amode.writeback = 0;
            // fall thru to next case ....
        case AMODE_IMM_12_PRE:
            if (Rn == ARMAssemblerInterface::SP) {
                Rn = R_sp;  // convert STR thru Arm SP to SW thru Mips SP
            }
            if (amode.writeback) {      // OPTIONAL writeback on pre-index mode
                // If we will writeback, then update the index reg, then store.
                // This correctly handles stack-push case.
                mMips->DADDIU(Rn, Rn, amode.value);
                mMips->SW(Rd, Rn, 0);
            } else {
                // No writeback so store offset by value
                mMips->SW(Rd, Rn, amode.value);
            }
            break;
        case AMODE_IMM_12_POST:
            mMips->SW(Rd, Rn, 0);
            mMips->DADDIU(Rn, Rn, amode.value);  // post index always writes back
            break;
        case AMODE_REG_SCALE_PRE:
            // we only support simple base + index, no advanced modes for this one yet
            mMips->DADDU(R_at, Rn, amode.reg);
            mMips->SW(Rd, R_at, 0);
            break;
    }
}

void ArmToMips64Assembler::STRB(int cc, int Rd, int Rn, uint32_t offset)
{
    mArmPC[mInum++] = pc();
    // work-around for ARM default address mode of immed12_pre(0)
    if (offset > AMODE_UNSUPPORTED) offset = 0;
    switch (offset) {
        case 0:
            amode.value = 0;
            amode.writeback = 0;
            // fall thru to next case ....
        case AMODE_IMM_12_PRE:
            mMips->SB(Rd, Rn, amode.value);
            if (amode.writeback) {      // OPTIONAL writeback on pre-index mode
                mMips->DADDIU(Rn, Rn, amode.value);
            }
            break;
        case AMODE_IMM_12_POST:
            mMips->SB(Rd, Rn, 0);
            mMips->DADDIU(Rn, Rn, amode.value);
            break;
        case AMODE_REG_SCALE_PRE:
            // we only support simple base + index, no advanced modes for this one yet
            mMips->DADDU(R_at, Rn, amode.reg);
            mMips->SB(Rd, R_at, 0);
            break;
    }
}

void ArmToMips64Assembler::LDRH(int cc, int Rd, int Rn, uint32_t offset)
{
    mArmPC[mInum++] = pc();
    // work-around for ARM default address mode of immed8_pre(0)
    if (offset > AMODE_UNSUPPORTED) offset = 0;
    switch (offset) {
        case 0:
            amode.value = 0;
            // fall thru to next case ....
        case AMODE_IMM_8_PRE:      // no support yet for writeback
            mMips->LHU(Rd, Rn, amode.value);
            break;
        case AMODE_IMM_8_POST:
            mMips->LHU(Rd, Rn, 0);
            mMips->DADDIU(Rn, Rn, amode.value);
            break;
        case AMODE_REG_PRE:
            // we only support simple base +/- index
            if (amode.reg >= 0) {
                mMips->DADDU(R_at, Rn, amode.reg);
            } else {
                mMips->DSUBU(R_at, Rn, abs(amode.reg));
            }
            mMips->LHU(Rd, R_at, 0);
            break;
    }
}

void ArmToMips64Assembler::LDRSB(int cc, int Rd, int Rn, uint32_t offset)
{
    mArmPC[mInum++] = pc();
    mMips->NOP2();
    NOT_IMPLEMENTED();
}

void ArmToMips64Assembler::LDRSH(int cc, int Rd, int Rn, uint32_t offset)
{
    mArmPC[mInum++] = pc();
    mMips->NOP2();
    NOT_IMPLEMENTED();
}

void ArmToMips64Assembler::STRH(int cc, int Rd, int Rn, uint32_t offset)
{
    mArmPC[mInum++] = pc();
    // work-around for ARM default address mode of immed8_pre(0)
    if (offset > AMODE_UNSUPPORTED) offset = 0;
    switch (offset) {
        case 0:
            amode.value = 0;
            // fall thru to next case ....
        case AMODE_IMM_8_PRE:      // no support yet for writeback
            mMips->SH(Rd, Rn, amode.value);
            break;
        case AMODE_IMM_8_POST:
            mMips->SH(Rd, Rn, 0);
            mMips->DADDIU(Rn, Rn, amode.value);
            break;
        case AMODE_REG_PRE:
            // we only support simple base +/- index
            if (amode.reg >= 0) {
                mMips->DADDU(R_at, Rn, amode.reg);
            } else {
                mMips->DSUBU(R_at, Rn, abs(amode.reg));
            }
            mMips->SH(Rd, R_at, 0);
            break;
    }
}



#if 0
#pragma mark -
#pragma mark Block Data Transfer...
#endif

// block data transfer...
void ArmToMips64Assembler::LDM(int cc, int dir,
        int Rn, int W, uint32_t reg_list)
{   //                        ED FD EA FA      IB IA DB DA
    // const uint8_t P[8] = { 1, 0, 1, 0,      1, 0, 1, 0 };
    // const uint8_t U[8] = { 1, 1, 0, 0,      1, 1, 0, 0 };
    // *mPC++ = (cc<<28) | (4<<25) | (uint32_t(P[dir])<<24) |
    //         (uint32_t(U[dir])<<23) | (1<<20) | (W<<21) | (Rn<<16) | reg_list;
    mArmPC[mInum++] = pc();
    mMips->NOP2();
    NOT_IMPLEMENTED();
}

void ArmToMips64Assembler::STM(int cc, int dir,
        int Rn, int W, uint32_t reg_list)
{   //                        FA EA FD ED      IB IA DB DA
    // const uint8_t P[8] = { 0, 1, 0, 1,      1, 0, 1, 0 };
    // const uint8_t U[8] = { 0, 0, 1, 1,      1, 1, 0, 0 };
    // *mPC++ = (cc<<28) | (4<<25) | (uint32_t(P[dir])<<24) |
    //         (uint32_t(U[dir])<<23) | (0<<20) | (W<<21) | (Rn<<16) | reg_list;
    mArmPC[mInum++] = pc();
    mMips->NOP2();
    NOT_IMPLEMENTED();
}



#if 0
#pragma mark -
#pragma mark Special...
#endif

// special...
void ArmToMips64Assembler::SWP(int cc, int Rn, int Rd, int Rm) {
    // *mPC++ = (cc<<28) | (2<<23) | (Rn<<16) | (Rd << 12) | 0x90 | Rm;
    mArmPC[mInum++] = pc();
    mMips->NOP2();
    NOT_IMPLEMENTED();
}

void ArmToMips64Assembler::SWPB(int cc, int Rn, int Rd, int Rm) {
    // *mPC++ = (cc<<28) | (2<<23) | (1<<22) | (Rn<<16) | (Rd << 12) | 0x90 | Rm;
    mArmPC[mInum++] = pc();
    mMips->NOP2();
    NOT_IMPLEMENTED();
}

void ArmToMips64Assembler::SWI(int cc, uint32_t comment) {
    // *mPC++ = (cc<<28) | (0xF<<24) | comment;
    mArmPC[mInum++] = pc();
    mMips->NOP2();
    NOT_IMPLEMENTED();
}


#if 0
#pragma mark -
#pragma mark DSP instructions...
#endif

// DSP instructions...
void ArmToMips64Assembler::PLD(int Rn, uint32_t offset) {
    LOG_ALWAYS_FATAL_IF(!((offset&(1<<24)) && !(offset&(1<<21))),
                        "PLD only P=1, W=0");
    // *mPC++ = 0xF550F000 | (Rn<<16) | offset;
    mArmPC[mInum++] = pc();
    mMips->NOP2();
    NOT_IMPLEMENTED();
}

void ArmToMips64Assembler::CLZ(int cc, int Rd, int Rm)
{
    mArmPC[mInum++] = pc();
    mMips->CLZ(Rd, Rm);
}

void ArmToMips64Assembler::QADD(int cc,  int Rd, int Rm, int Rn)
{
    // *mPC++ = (cc<<28) | 0x1000050 | (Rn<<16) | (Rd<<12) | Rm;
    mArmPC[mInum++] = pc();
    mMips->NOP2();
    NOT_IMPLEMENTED();
}

void ArmToMips64Assembler::QDADD(int cc,  int Rd, int Rm, int Rn)
{
    // *mPC++ = (cc<<28) | 0x1400050 | (Rn<<16) | (Rd<<12) | Rm;
    mArmPC[mInum++] = pc();
    mMips->NOP2();
    NOT_IMPLEMENTED();
}

void ArmToMips64Assembler::QSUB(int cc,  int Rd, int Rm, int Rn)
{
    // *mPC++ = (cc<<28) | 0x1200050 | (Rn<<16) | (Rd<<12) | Rm;
    mArmPC[mInum++] = pc();
    mMips->NOP2();
    NOT_IMPLEMENTED();
}

void ArmToMips64Assembler::QDSUB(int cc,  int Rd, int Rm, int Rn)
{
    // *mPC++ = (cc<<28) | 0x1600050 | (Rn<<16) | (Rd<<12) | Rm;
    mArmPC[mInum++] = pc();
    mMips->NOP2();
    NOT_IMPLEMENTED();
}

// 16 x 16 signed multiply (like SMLAxx without the accumulate)
void ArmToMips64Assembler::SMUL(int cc, int xy,
                int Rd, int Rm, int Rs)
{
    mArmPC[mInum++] = pc();

    // the 16 bits may be in the top or bottom half of 32-bit source reg,
    // as defined by the codes BB, BT, TB, TT (compressed param xy)
    // where x corresponds to Rm and y to Rs

    // select half-reg for Rm
    if (xy & xyTB) {
        // use top 16-bits
        mMips->SRA(R_at, Rm, 16);
    } else {
        // use bottom 16, but sign-extend to 32
        mMips->SEH(R_at, Rm);
    }
    // select half-reg for Rs
    if (xy & xyBT) {
        // use top 16-bits
        mMips->SRA(R_at2, Rs, 16);
    } else {
        // use bottom 16, but sign-extend to 32
        mMips->SEH(R_at2, Rs);
    }
    mMips->MUL(Rd, R_at, R_at2);
}

// signed 32b x 16b multiple, save top 32-bits of 48-bit result
void ArmToMips64Assembler::SMULW(int cc, int y,
                int Rd, int Rm, int Rs)
{
    mArmPC[mInum++] = pc();

    // the selector yT or yB refers to reg Rs
    if (y & yT) {
        // zero the bottom 16-bits, with 2 shifts, it can affect result
        mMips->SRL(R_at, Rs, 16);
        mMips->SLL(R_at, R_at, 16);

    } else {
        // move low 16-bit half, to high half
        mMips->SLL(R_at, Rs, 16);
    }
    mMips->MUH(Rd, Rm, R_at);
}

// 16 x 16 signed multiply, accumulate: Rd = Rm{16} * Rs{16} + Rn
void ArmToMips64Assembler::SMLA(int cc, int xy,
                int Rd, int Rm, int Rs, int Rn)
{
    mArmPC[mInum++] = pc();

    // the 16 bits may be in the top or bottom half of 32-bit source reg,
    // as defined by the codes BB, BT, TB, TT (compressed param xy)
    // where x corresponds to Rm and y to Rs

    // select half-reg for Rm
    if (xy & xyTB) {
        // use top 16-bits
        mMips->SRA(R_at, Rm, 16);
    } else {
        // use bottom 16, but sign-extend to 32
        mMips->SEH(R_at, Rm);
    }
    // select half-reg for Rs
    if (xy & xyBT) {
        // use top 16-bits
        mMips->SRA(R_at2, Rs, 16);
    } else {
        // use bottom 16, but sign-extend to 32
        mMips->SEH(R_at2, Rs);
    }

    mMips->MUL(R_at, R_at, R_at2);
    mMips->ADDU(Rd, R_at, Rn);
}

void ArmToMips64Assembler::SMLAL(int cc, int xy,
                int RdHi, int RdLo, int Rs, int Rm)
{
    // *mPC++ = (cc<<28) | 0x1400080 | (RdHi<<16) | (RdLo<<12) | (Rs<<8) | (xy<<4) | Rm;
    mArmPC[mInum++] = pc();
    mMips->NOP2();
    NOT_IMPLEMENTED();
}

void ArmToMips64Assembler::SMLAW(int cc, int y,
                int Rd, int Rm, int Rs, int Rn)
{
    // *mPC++ = (cc<<28) | 0x1200080 | (Rd<<16) | (Rn<<12) | (Rs<<8) | (y<<4) | Rm;
    mArmPC[mInum++] = pc();
    mMips->NOP2();
    NOT_IMPLEMENTED();
}

// used by ARMv6 version of GGLAssembler::filter32
void ArmToMips64Assembler::UXTB16(int cc, int Rd, int Rm, int rotate)
{
    mArmPC[mInum++] = pc();

    //Rd[31:16] := ZeroExtend((Rm ROR (8 * sh))[23:16]),
    //Rd[15:0] := ZeroExtend((Rm ROR (8 * sh))[7:0]). sh 0-3.

    mMips->ROTR(R_at2, Rm, rotate * 8);
    mMips->LUI(R_at, 0xFF);
    mMips->ORI(R_at, R_at, 0xFF);
    mMips->AND(Rd, R_at2, R_at);
}

void ArmToMips64Assembler::UBFX(int cc, int Rd, int Rn, int lsb, int width)
{
     /* Placeholder for UBFX */
     mArmPC[mInum++] = pc();

     mMips->NOP2();
     NOT_IMPLEMENTED();
}

// ----------------------------------------------------------------------------
// Address Processing...
// ----------------------------------------------------------------------------

void ArmToMips64Assembler::ADDR_ADD(int cc,
        int s, int Rd, int Rn, uint32_t Op2)
{
//    if(cc != AL){ NOT_IMPLEMENTED(); return;} //Not required
//    if(s  != 0) { NOT_IMPLEMENTED(); return;} //Not required
    dataProcessing(opADD64, cc, s, Rd, Rn, Op2);
}

void ArmToMips64Assembler::ADDR_SUB(int cc,
        int s, int Rd, int Rn, uint32_t Op2)
{
//    if(cc != AL){ NOT_IMPLEMENTED(); return;} //Not required
//    if(s  != 0) { NOT_IMPLEMENTED(); return;} //Not required
    dataProcessing(opSUB64, cc, s, Rd, Rn, Op2);
}

void ArmToMips64Assembler::ADDR_LDR(int cc, int Rd, int Rn, uint32_t offset) {
    mArmPC[mInum++] = pc();
    // work-around for ARM default address mode of immed12_pre(0)
    if (offset > AMODE_UNSUPPORTED) offset = 0;
    switch (offset) {
        case 0:
            amode.value = 0;
            amode.writeback = 0;
            // fall thru to next case ....
        case AMODE_IMM_12_PRE:
            if (Rn == ARMAssemblerInterface::SP) {
                Rn = R_sp;      // convert LDR via Arm SP to LW via Mips SP
            }
            mMips->LD(Rd, Rn, amode.value);
            if (amode.writeback) {      // OPTIONAL writeback on pre-index mode
                mMips->DADDIU(Rn, Rn, amode.value);
            }
            break;
        case AMODE_IMM_12_POST:
            if (Rn == ARMAssemblerInterface::SP) {
                Rn = R_sp;      // convert STR thru Arm SP to STR thru Mips SP
            }
            mMips->LD(Rd, Rn, 0);
            mMips->DADDIU(Rn, Rn, amode.value);
            break;
        case AMODE_REG_SCALE_PRE:
            // we only support simple base + index, no advanced modes for this one yet
            mMips->DADDU(R_at, Rn, amode.reg);
            mMips->LD(Rd, R_at, 0);
            break;
    }
}

void ArmToMips64Assembler::ADDR_STR(int cc, int Rd, int Rn, uint32_t offset) {
    mArmPC[mInum++] = pc();
    // work-around for ARM default address mode of immed12_pre(0)
    if (offset > AMODE_UNSUPPORTED) offset = 0;
    switch (offset) {
        case 0:
            amode.value = 0;
            amode.writeback = 0;
            // fall thru to next case ....
        case AMODE_IMM_12_PRE:
            if (Rn == ARMAssemblerInterface::SP) {
                Rn = R_sp;  // convert STR thru Arm SP to SW thru Mips SP
            }
            if (amode.writeback) {      // OPTIONAL writeback on pre-index mode
                // If we will writeback, then update the index reg, then store.
                // This correctly handles stack-push case.
                mMips->DADDIU(Rn, Rn, amode.value);
                mMips->SD(Rd, Rn, 0);
            } else {
                // No writeback so store offset by value
                mMips->SD(Rd, Rn, amode.value);
            }
            break;
        case AMODE_IMM_12_POST:
            mMips->SD(Rd, Rn, 0);
            mMips->DADDIU(Rn, Rn, amode.value);  // post index always writes back
            break;
        case AMODE_REG_SCALE_PRE:
            // we only support simple base + index, no advanced modes for this one yet
            mMips->DADDU(R_at, Rn, amode.reg);
            mMips->SD(Rd, R_at, 0);
            break;
    }
}

#if 0
#pragma mark -
#pragma mark MIPS Assembler...
#endif


//**************************************************************************
//**************************************************************************
//**************************************************************************


/* mips assembler
** this is a subset of mips64r6, targeted specifically at ARM instruction
** replacement in the pixelflinger/codeflinger code.
**
** To that end, there is no need for floating point, or priviledged
** instructions. This all runs in user space, no float.
**
** The syntax makes no attempt to be as complete as the assember, with
** synthetic instructions, and automatic recognition of immedate operands
** (use the immediate form of the instruction), etc.
**
** We start with mips64r6, and may add r1/r2 support.
** Decision will be made at compile time, based on gcc options.
** (makes sense since android will be built for a a specific device)
*/

MIPS64Assembler::MIPS64Assembler(const sp<Assembly>& assembly, ArmToMips64Assembler *parent)
    : mParent(parent),
    mAssembly(assembly)
{
    mBase = mPC = (uint32_t *)assembly->base();
    mDuration = ggl_system_time();
}

MIPS64Assembler::MIPS64Assembler(void* assembly, ArmToMips64Assembler *parent)
    : mParent(parent),
    mAssembly(NULL)
{
    mBase = mPC = (uint32_t *)assembly;
}

MIPS64Assembler::~MIPS64Assembler()
{
}


uint32_t* MIPS64Assembler::pc() const
{
    return mPC;
}

uint32_t* MIPS64Assembler::base() const
{
    return mBase;
}

void MIPS64Assembler::reset()
{
    if (mAssembly != NULL) {
        mBase = mPC = (uint32_t *)mAssembly->base();
    } else {
        mPC = mBase = base();
    }
    mBranchTargets.clear();
    mLabels.clear();
    mLabelsInverseMapping.clear();
    mComments.clear();
}


// convert tabs to spaces, and remove any newline
// works with strings of limited size (makes a temp copy)
#define TABSTOP 8
void MIPS64Assembler::string_detab(char *s)
{
    char *os = s;
    char temp[100];
    char *t = temp;
    int len = 99;
    int i = TABSTOP;

    while (*s && len-- > 0) {
        if (*s == '\n') { s++; continue; }
        if (*s == '\t') {
            s++;
            for ( ; i>0; i--) {*t++ = ' '; len--; }
        } else {
            *t++ = *s++;
        }
        if (i <= 0) i = TABSTOP;
        i--;
    }
    *t = '\0';
    strcpy(os, temp);
}

void MIPS64Assembler::string_pad(char *s, int padded_len)
{
    int len = strlen(s);
    s += len;
    for (int i = padded_len - len; i > 0; --i) {
        *s++ = ' ';
    }
    *s = '\0';
}

// ----------------------------------------------------------------------------

void MIPS64Assembler::disassemble(const char* name)
{
    char di_buf[140];

    bool arm_disasm_fmt = (mParent->mArmDisassemblyBuffer == NULL) ? false : true;

    typedef char dstr[40];
    dstr *lines = (dstr *)mParent->mArmDisassemblyBuffer;

    if (mParent->mArmDisassemblyBuffer != NULL) {
        for (int i=0; i<mParent->mArmInstrCount; ++i) {
            string_detab(lines[i]);
        }
    }

    // iArm is an index to Arm instructions 1...n for this assembly sequence
    // mArmPC[iArm] holds the value of the Mips-PC for the first MIPS
    // instruction corresponding to that Arm instruction number

    int iArm = 0;
    size_t count = pc()-base();
    uint32_t* mipsPC = base();

    while (count--) {
        ssize_t label = mLabelsInverseMapping.indexOfKey(mipsPC);
        if (label >= 0) {
            ALOGW("%s:\n", mLabelsInverseMapping.valueAt(label));
        }
        ssize_t comment = mComments.indexOfKey(mipsPC);
        if (comment >= 0) {
            ALOGW("; %s\n", mComments.valueAt(comment));
        }
        ::mips_disassem(mipsPC, di_buf, arm_disasm_fmt);
        string_detab(di_buf);
        string_pad(di_buf, 30);
        ALOGW("%08lx:    %08x    %s", uint64_t(mipsPC), uint32_t(*mipsPC), di_buf);
        mipsPC++;
    }
}

void MIPS64Assembler::comment(const char* string)
{
    mComments.add(pc(), string);
}

void MIPS64Assembler::label(const char* theLabel)
{
    mLabels.add(theLabel, pc());
    mLabelsInverseMapping.add(pc(), theLabel);
}


void MIPS64Assembler::prolog()
{
    // empty - done in ArmToMips64Assembler
}

void MIPS64Assembler::epilog(uint32_t touched)
{
    // empty - done in ArmToMips64Assembler
}

int MIPS64Assembler::generate(const char* name)
{
    // fixup all the branches
    size_t count = mBranchTargets.size();
    while (count--) {
        const branch_target_t& bt = mBranchTargets[count];
        uint32_t* target_pc = mLabels.valueFor(bt.label);
        LOG_ALWAYS_FATAL_IF(!target_pc,
                "error resolving branch targets, target_pc is null");
        int32_t offset = int32_t(target_pc - (bt.pc+1));
        *bt.pc |= offset & 0x00FFFF;
    }

    mAssembly->resize( int(pc()-base())*4 );

    // the instruction & data caches are flushed by CodeCache
    const int64_t duration = ggl_system_time() - mDuration;
    const char * const format = "generated %s (%d ins) at [%p:%p] in %lld ns\n";
    ALOGI(format, name, int(pc()-base()), base(), pc(), duration);

#if defined(WITH_LIB_HARDWARE)
    if (__builtin_expect(mQemuTracing, 0)) {
        int err = qemu_add_mapping(int64_t(base()), name);
        mQemuTracing = (err >= 0);
    }
#endif

    char value[PROPERTY_VALUE_MAX];
    value[0] = '\0';

    property_get("debug.pf.disasm", value, "0");

    if (atoi(value) != 0) {
        disassemble(name);
    }

    return NO_ERROR;
}

void MIPS64Assembler::fix_branches()
{
    // fixup all the branches
    size_t count = mBranchTargets.size();
    while (count--) {
        const branch_target_t& bt = mBranchTargets[count];
        uint32_t* target_pc = mLabels.valueFor(bt.label);
        LOG_ALWAYS_FATAL_IF(!target_pc,
                "error resolving branch targets, target_pc is null");
        int32_t offset = int32_t(target_pc - (bt.pc+1));
        *bt.pc |= offset & 0x00FFFF;
    }
}

uint32_t* MIPS64Assembler::pcForLabel(const char* label)
{
    return mLabels.valueFor(label);
}



#if 0
#pragma mark -
#pragma mark Arithmetic...
#endif

void MIPS64Assembler::ADDU(int Rd, int Rs, int Rt)
{
    *mPC++ = (spec_op<<OP_SHF) | (addu_fn<<FUNC_SHF)
                    | (Rs<<RS_SHF) | (Rt<<RT_SHF) | (Rd<<RD_SHF);
}

// MD00086 pdf says this is: ADDIU rt, rs, imm -- they do not use Rd
void MIPS64Assembler::ADDIU(int Rt, int Rs, int16_t imm)
{
    *mPC++ = (addiu_op<<OP_SHF) | (Rt<<RT_SHF) | (Rs<<RS_SHF) | (imm & MSK_16);
}

void MIPS64Assembler::DADDU(int Rd, int Rs, int Rt)
{
    *mPC++ = (spec_op<<OP_SHF) | (daddu_fn<<FUNC_SHF)
                    | (Rs<<RS_SHF) | (Rt<<RT_SHF) | (Rd<<RD_SHF);
}

void MIPS64Assembler::DADDIU(int Rt, int Rs, int16_t imm)
{
    *mPC++ = (daddiu_op<<OP_SHF) | (Rt<<RT_SHF) | (Rs<<RS_SHF) | (imm & MSK_16);
}

void MIPS64Assembler::SUBU(int Rd, int Rs, int Rt)
{
    *mPC++ = (spec_op<<OP_SHF) | (subu_fn<<FUNC_SHF) |
                        (Rs<<RS_SHF) | (Rt<<RT_SHF) | (Rd<<RD_SHF) ;
}

void MIPS64Assembler::SUBIU(int Rt, int Rs, int16_t imm)   // really addiu(d, s, -j)
{
    *mPC++ = (addiu_op<<OP_SHF) | (Rt<<RT_SHF) | (Rs<<RS_SHF) | ((-imm) & MSK_16);
}

void MIPS64Assembler::DSUBU(int Rd, int Rs, int Rt)
{
    *mPC++ = (spec_op<<OP_SHF) | (dsubu_fn<<FUNC_SHF) |
                        (Rs<<RS_SHF) | (Rt<<RT_SHF) | (Rd<<RD_SHF) ;
}

void MIPS64Assembler::DSUBIU(int Rt, int Rs, int16_t imm)   // really addiu(d, s, -j)
{
    *mPC++ = (daddiu_op<<OP_SHF) | (Rt<<RT_SHF) | (Rs<<RS_SHF) | ((-imm) & MSK_16);
}

void MIPS64Assembler::NEGU(int Rd, int Rs)    // really subu(d, zero, s)
{
    MIPS64Assembler::SUBU(Rd, 0, Rs);
}

void MIPS64Assembler::MUL(int Rd, int Rs, int Rt)
{
    *mPC++ = (spec_op<<OP_SHF) | (mul_fn<<RE_SHF) | (sop30_fn<<FUNC_SHF) |
                        (Rs<<RS_SHF) | (Rt<<RT_SHF) | (Rd<<RD_SHF) ;
}

void MIPS64Assembler::MUH(int Rd, int Rs, int Rt)
{
    *mPC++ = (spec_op<<OP_SHF) | (muh_fn<<RE_SHF) | (sop30_fn<<FUNC_SHF) |
                        (Rs<<RS_SHF) | (Rt<<RT_SHF) | (Rd<<RD_SHF) ;
}

void MIPS64Assembler::SEB(int Rd, int Rt)    // sign-extend byte
{
    *mPC++ = (spec3_op<<OP_SHF) | (bshfl_fn<<FUNC_SHF) | (seb_fn << SA_SHF) |
                    (Rt<<RT_SHF) | (Rd<<RD_SHF);
}

void MIPS64Assembler::SEH(int Rd, int Rt)    // sign-extend half-word
{
    *mPC++ = (spec3_op<<OP_SHF) | (bshfl_fn<<FUNC_SHF) | (seh_fn << SA_SHF) |
                    (Rt<<RT_SHF) | (Rd<<RD_SHF);
}



#if 0
#pragma mark -
#pragma mark Comparisons...
#endif

void MIPS64Assembler::SLT(int Rd, int Rs, int Rt)
{
    *mPC++ = (spec_op<<OP_SHF) | (slt_fn<<FUNC_SHF) |
                        (Rd<<RD_SHF) | (Rs<<RS_SHF) | (Rt<<RT_SHF);
}

void MIPS64Assembler::SLTI(int Rt, int Rs, int16_t imm)
{
    *mPC++ = (slti_op<<OP_SHF) | (Rt<<RT_SHF) | (Rs<<RS_SHF) | (imm & MSK_16);
}

void MIPS64Assembler::SLTU(int Rd, int Rs, int Rt)
{
    *mPC++ = (spec_op<<OP_SHF) | (sltu_fn<<FUNC_SHF) |
                        (Rd<<RD_SHF) | (Rs<<RS_SHF) | (Rt<<RT_SHF);
}

void MIPS64Assembler::SLTIU(int Rt, int Rs, int16_t imm)
{
    *mPC++ = (sltiu_op<<OP_SHF) | (Rt<<RT_SHF) | (Rs<<RS_SHF) | (imm & MSK_16);
}



#if 0
#pragma mark -
#pragma mark Logical...
#endif

void MIPS64Assembler::AND(int Rd, int Rs, int Rt)
{
    *mPC++ = (spec_op<<OP_SHF) | (and_fn<<FUNC_SHF) |
                        (Rd<<RD_SHF) | (Rs<<RS_SHF) | (Rt<<RT_SHF);
}

void MIPS64Assembler::ANDI(int Rt, int Rs, uint16_t imm)      // todo: support larger immediate
{
    *mPC++ = (andi_op<<OP_SHF) | (Rt<<RT_SHF) | (Rs<<RS_SHF) | (imm & MSK_16);
}


void MIPS64Assembler::OR(int Rd, int Rs, int Rt)
{
    *mPC++ = (spec_op<<OP_SHF) | (or_fn<<FUNC_SHF) |
                        (Rd<<RD_SHF) | (Rs<<RS_SHF) | (Rt<<RT_SHF);
}

void MIPS64Assembler::ORI(int Rt, int Rs, uint16_t imm)
{
    *mPC++ = (ori_op<<OP_SHF) | (Rt<<RT_SHF) | (Rs<<RS_SHF) | (imm & MSK_16);
}

void MIPS64Assembler::NOR(int Rd, int Rs, int Rt)
{
    *mPC++ = (spec_op<<OP_SHF) | (nor_fn<<FUNC_SHF) |
                        (Rd<<RD_SHF) | (Rs<<RS_SHF) | (Rt<<RT_SHF);
}

void MIPS64Assembler::NOT(int Rd, int Rs)
{
    MIPS64Assembler::NOR(Rd, Rs, 0);  // NOT(d,s) = NOR(d,s,zero)
}

void MIPS64Assembler::XOR(int Rd, int Rs, int Rt)
{
    *mPC++ = (spec_op<<OP_SHF) | (xor_fn<<FUNC_SHF) |
                        (Rd<<RD_SHF) | (Rs<<RS_SHF) | (Rt<<RT_SHF);
}

void MIPS64Assembler::XORI(int Rt, int Rs, uint16_t imm)  // todo: support larger immediate
{
    *mPC++ = (xori_op<<OP_SHF) | (Rt<<RT_SHF) | (Rs<<RS_SHF) | (imm & MSK_16);
}

void MIPS64Assembler::SLL(int Rd, int Rt, int shft)
{
    *mPC++ = (spec_op<<OP_SHF) | (sll_fn<<FUNC_SHF) |
                        (Rd<<RD_SHF) | (Rt<<RT_SHF) | (shft<<RE_SHF);
}

void MIPS64Assembler::SLLV(int Rd, int Rt, int Rs)
{
    *mPC++ = (spec_op<<OP_SHF) | (sllv_fn<<FUNC_SHF) |
                        (Rd<<RD_SHF) | (Rs<<RS_SHF) | (Rt<<RT_SHF);
}

void MIPS64Assembler::SRL(int Rd, int Rt, int shft)
{
    *mPC++ = (spec_op<<OP_SHF) | (srl_fn<<FUNC_SHF) |
                        (Rd<<RD_SHF) | (Rt<<RT_SHF) | (shft<<RE_SHF);
}

void MIPS64Assembler::SRLV(int Rd, int Rt, int Rs)
{
    *mPC++ = (spec_op<<OP_SHF) | (srlv_fn<<FUNC_SHF) |
                        (Rd<<RD_SHF) | (Rs<<RS_SHF) | (Rt<<RT_SHF);
}

void MIPS64Assembler::SRA(int Rd, int Rt, int shft)
{
    *mPC++ = (spec_op<<OP_SHF) | (sra_fn<<FUNC_SHF) |
                        (Rd<<RD_SHF) | (Rt<<RT_SHF) | (shft<<RE_SHF);
}

void MIPS64Assembler::SRAV(int Rd, int Rt, int Rs)
{
    *mPC++ = (spec_op<<OP_SHF) | (srav_fn<<FUNC_SHF) |
                        (Rd<<RD_SHF) | (Rs<<RS_SHF) | (Rt<<RT_SHF);
}

void MIPS64Assembler::ROTR(int Rd, int Rt, int shft)
{
    // note weird encoding (SRL + 1)
    *mPC++ = (spec_op<<OP_SHF) | (srl_fn<<FUNC_SHF) |
                        (1<<RS_SHF) | (Rd<<RD_SHF) | (Rt<<RT_SHF) | (shft<<RE_SHF);
}

void MIPS64Assembler::ROTRV(int Rd, int Rt, int Rs)
{
    // note weird encoding (SRLV + 1)
    *mPC++ = (spec_op<<OP_SHF) | (srlv_fn<<FUNC_SHF) |
                        (Rd<<RD_SHF) | (Rs<<RS_SHF) | (Rt<<RT_SHF) | (1<<RE_SHF);
}

void MIPS64Assembler::CLO(int Rd, int Rs)
{
    *mPC++ = (spec_op<<OP_SHF) | (17<<FUNC_SHF) |
                        (Rd<<RD_SHF) | (Rs<<RS_SHF) | (1<<RE_SHF);
}

void MIPS64Assembler::CLZ(int Rd, int Rs)
{
    *mPC++ = (spec_op<<OP_SHF) | (16<<FUNC_SHF) |
                        (Rd<<RD_SHF) | (Rs<<RS_SHF) | (1<<RE_SHF);
}

void MIPS64Assembler::WSBH(int Rd, int Rt)
{
    *mPC++ = (spec3_op<<OP_SHF) | (bshfl_fn<<FUNC_SHF) | (wsbh_fn << SA_SHF) |
                        (Rt<<RT_SHF) | (Rd<<RD_SHF);
}



#if 0
#pragma mark -
#pragma mark Load/store...
#endif

void MIPS64Assembler::LW(int Rt, int Rbase, int16_t offset)
{
    *mPC++ = (lw_op<<OP_SHF) | (Rbase<<RS_SHF) | (Rt<<RT_SHF) | (offset & MSK_16);
}

void MIPS64Assembler::SW(int Rt, int Rbase, int16_t offset)
{
    *mPC++ = (sw_op<<OP_SHF) | (Rbase<<RS_SHF) | (Rt<<RT_SHF) | (offset & MSK_16);
}

// lb is sign-extended
void MIPS64Assembler::LB(int Rt, int Rbase, int16_t offset)
{
    *mPC++ = (lb_op<<OP_SHF) | (Rbase<<RS_SHF) | (Rt<<RT_SHF) | (offset & MSK_16);
}

void MIPS64Assembler::LBU(int Rt, int Rbase, int16_t offset)
{
    *mPC++ = (lbu_op<<OP_SHF) | (Rbase<<RS_SHF) | (Rt<<RT_SHF) | (offset & MSK_16);
}

void MIPS64Assembler::SB(int Rt, int Rbase, int16_t offset)
{
    *mPC++ = (sb_op<<OP_SHF) | (Rbase<<RS_SHF) | (Rt<<RT_SHF) | (offset & MSK_16);
}

// lh is sign-extended
void MIPS64Assembler::LH(int Rt, int Rbase, int16_t offset)
{
    *mPC++ = (lh_op<<OP_SHF) | (Rbase<<RS_SHF) | (Rt<<RT_SHF) | (offset & MSK_16);
}

void MIPS64Assembler::LHU(int Rt, int Rbase, int16_t offset)
{
    *mPC++ = (lhu_op<<OP_SHF) | (Rbase<<RS_SHF) | (Rt<<RT_SHF) | (offset & MSK_16);
}

void MIPS64Assembler::SH(int Rt, int Rbase, int16_t offset)
{
    *mPC++ = (sh_op<<OP_SHF) | (Rbase<<RS_SHF) | (Rt<<RT_SHF) | (offset & MSK_16);
}

void MIPS64Assembler::LD(int Rt, int Rbase, int16_t offset)
{
    *mPC++ = (ld_op<<OP_SHF) | (Rbase<<RS_SHF) | (Rt<<RT_SHF) | (offset & MSK_16);
}

void MIPS64Assembler::SD(int Rt, int Rbase, int16_t offset)
{
    *mPC++ = (sd_op<<OP_SHF) | (Rbase<<RS_SHF) | (Rt<<RT_SHF) | (offset & MSK_16);
}

void MIPS64Assembler::LUI(int Rt, int16_t offset)
{
    *mPC++ = (aui_op<<OP_SHF) | (Rt<<RT_SHF) | (offset & MSK_16);
}



#if 0
#pragma mark -
#pragma mark Register move...
#endif

void MIPS64Assembler::MOVE(int Rd, int Rs)
{
    // encoded as "or rd, rs, zero"
    *mPC++ = (spec_op<<OP_SHF) | (or_fn<<FUNC_SHF) |
                        (Rd<<RD_SHF) | (Rs<<RS_SHF) | (0<<RT_SHF);
}


#if 0
#pragma mark -
#pragma mark Branch...
#endif

// temporarily forcing a NOP into branch-delay slot, just to be safe
// todo: remove NOP, optimze use of delay slots
void MIPS64Assembler::B(const char* label)
{
    mBranchTargets.add(branch_target_t(label, mPC));

    // encoded as BEQ zero, zero, offset
    *mPC++ = (beq_op<<OP_SHF) | (0<<RT_SHF)
                        | (0<<RS_SHF) | 0;  // offset filled in later

    MIPS64Assembler::NOP();
}

void MIPS64Assembler::BEQ(int Rs, int Rt, const char* label)
{
    mBranchTargets.add(branch_target_t(label, mPC));
    *mPC++ = (beq_op<<OP_SHF) | (Rt<<RT_SHF) | (Rs<<RS_SHF) | 0;
    MIPS64Assembler::NOP();
}

void MIPS64Assembler::BNE(int Rs, int Rt, const char* label)
{
    mBranchTargets.add(branch_target_t(label, mPC));
    *mPC++ = (bne_op<<OP_SHF) | (Rt<<RT_SHF) | (Rs<<RS_SHF) | 0;
    MIPS64Assembler::NOP();
}

void MIPS64Assembler::BLEZ(int Rs, const char* label)
{
    mBranchTargets.add(branch_target_t(label, mPC));
    *mPC++ = (pop06_op<<OP_SHF) | (0<<RT_SHF) | (Rs<<RS_SHF) | 0;
    MIPS64Assembler::NOP();
}

void MIPS64Assembler::BLTZ(int Rs, const char* label)
{
    mBranchTargets.add(branch_target_t(label, mPC));
    *mPC++ = (regimm_op<<OP_SHF) | (bltz_fn<<RT_SHF) | (Rs<<RS_SHF) | 0;
    MIPS64Assembler::NOP();
}

void MIPS64Assembler::BGTZ(int Rs, const char* label)
{
    mBranchTargets.add(branch_target_t(label, mPC));
    *mPC++ = (pop07_op<<OP_SHF) | (0<<RT_SHF) | (Rs<<RS_SHF) | 0;
    MIPS64Assembler::NOP();
}


void MIPS64Assembler::BGEZ(int Rs, const char* label)
{
    mBranchTargets.add(branch_target_t(label, mPC));
    *mPC++ = (regimm_op<<OP_SHF) | (bgez_fn<<RT_SHF) | (Rs<<RS_SHF) | 0;
    MIPS64Assembler::NOP();
}

void MIPS64Assembler::JR(int Rs)
{
        *mPC++ = (spec_op<<OP_SHF) | (Rs<<RS_SHF) | (jalr_fn << FUNC_SHF);
        MIPS64Assembler::NOP();
}


#if 0
#pragma mark -
#pragma mark Synthesized Branch...
#endif

// synthetic variants of branches (using slt & friends)
void MIPS64Assembler::BEQZ(int Rs, const char* label)
{
    BEQ(Rs, R_zero, label);
}

void MIPS64Assembler::BNEZ(int Rs, const char* label)
{
    BNE(R_at, R_zero, label);
}

void MIPS64Assembler::BGE(int Rs, int Rt, const char* label)
{
    SLT(R_at, Rs, Rt);
    BEQ(R_at, R_zero, label);
}

void MIPS64Assembler::BGEU(int Rs, int Rt, const char* label)
{
    SLTU(R_at, Rs, Rt);
    BEQ(R_at, R_zero, label);
}

void MIPS64Assembler::BGT(int Rs, int Rt, const char* label)
{
    SLT(R_at, Rt, Rs);   // rev
    BNE(R_at, R_zero, label);
}

void MIPS64Assembler::BGTU(int Rs, int Rt, const char* label)
{
    SLTU(R_at, Rt, Rs);   // rev
    BNE(R_at, R_zero, label);
}

void MIPS64Assembler::BLE(int Rs, int Rt, const char* label)
{
    SLT(R_at, Rt, Rs);   // rev
    BEQ(R_at, R_zero, label);
}

void MIPS64Assembler::BLEU(int Rs, int Rt, const char* label)
{
    SLTU(R_at, Rt, Rs);  // rev
    BEQ(R_at, R_zero, label);
}

void MIPS64Assembler::BLT(int Rs, int Rt, const char* label)
{
    SLT(R_at, Rs, Rt);
    BNE(R_at, R_zero, label);
}

void MIPS64Assembler::BLTU(int Rs, int Rt, const char* label)
{
    SLTU(R_at, Rs, Rt);
    BNE(R_at, R_zero, label);
}




#if 0
#pragma mark -
#pragma mark Misc...
#endif

void MIPS64Assembler::NOP(void)
{
    // encoded as "sll zero, zero, 0", which is all zero
    *mPC++ = (spec_op<<OP_SHF) | (sll_fn<<FUNC_SHF);
}

// using this as special opcode for not-yet-implemented ARM instruction
void MIPS64Assembler::NOP2(void)
{
    // encoded as "sll zero, zero, 2", still a nop, but a unique code
    *mPC++ = (spec_op<<OP_SHF) | (sll_fn<<FUNC_SHF) | (2 << RE_SHF);
}

// using this as special opcode for purposefully NOT implemented ARM instruction
void MIPS64Assembler::UNIMPL(void)
{
    // encoded as "sll zero, zero, 3", still a nop, but a unique code
    *mPC++ = (spec_op<<OP_SHF) | (sll_fn<<FUNC_SHF) | (3 << RE_SHF);
}


}; // namespace android:


