/* libs/pixelflinger/codeflinger/SHAssemblerInterface.h
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


#ifndef ANDROID_SHASSEMBLER_INTERFACE_H
#define ANDROID_SHASSEMBLER_INTERFACE_H

#include <stdint.h>
#include <sys/types.h>

namespace android {

// ----------------------------------------------------------------------------

class SHAssemblerInterface
{
public:
    virtual ~SHAssemblerInterface();

    enum { /* single register comparisons */
        PZ = 1,
        PL = 5,
    };
    enum { /* comparisons between registers */
        NO_CMP = -1,
        EQ = 0,
        HS = 2,
        GE = 3,
        HI = 6,
        GT = 7,
    };
    enum {
        R0, R1, R2, R3, R4, R5, R6, R7, R8, R9, R10, R11, R12, R13, R14, R15,
        SP = R15,
    };
    enum {
        #define LIST(rr) L##rr=1<<rr
        LIST(R0), LIST(R1), LIST(R2), LIST(R3), LIST(R4), LIST(R5), LIST(R6),
        LIST(R7), LIST(R8), LIST(R9), LIST(R10), LIST(R11), LIST(R12),
        LIST(R13), LIST(R14), LIST(R15),
        LIST(SP),
        #undef LIST
        LSAVED = LR8|LR9|LR10|LR11|LR12|LR13|LR14
    };

    // -----------------------------------------------------------------------
    // shifters and addressing modes
    // -----------------------------------------------------------------------

#if 1 /* left to keep algorithm consistent with ARM inplementation. */
    // shifters...
    static bool        isValidImmediate(uint32_t immed32);
    static int         buildImmediate(uint32_t immed32, int32_t& shift, uint32_t& imm);
#endif

    // -----------------------------------------------------------------------
    // basic instructions & code generation
    // -----------------------------------------------------------------------

    // generate the code
    virtual void reset() = 0;
    virtual int  generate(const char* name) = 0;
    virtual void disassemble(const char* name) = 0;

    // construct prolog and epilog
    virtual void prolog() = 0;
    virtual void epilog(uint32_t touched) = 0;
    virtual void comment(const char* string) = 0;

    // Arithmetic
    virtual void ADD(int Rm, int Rn) = 0;
    virtual void ADD_IMM(int32_t immed8, int Rn) = 0;
    virtual void DMULS(int Rm, int Rn) = 0;
    virtual void DMULU(int Rm, int Rn) = 0;
    virtual void MULU(int Rm, int Rn) = 0;
    virtual void MULS(int Rm, int Rn) = 0;
    virtual void NEG(int Rm, int Rn) = 0;
    virtual void SUB(int Rm, int Rn) = 0;
    virtual void DT(int Rn) = 0;
    virtual void CMP(int cond, int Rm, int Rn) = 0;
    virtual void CMP(int cond, int Rn) = 0;
    virtual void EXTU_B(int Rm, int Rn) = 0;
    virtual void EXTU_W(int Rm, int Rn) = 0;
    virtual void EXTS_B(int Rm, int Rn) = 0;
    virtual void EXTS_W(int Rm, int Rn) = 0;

    // Logic
    virtual void AND(int Rm, int Rn) = 0;
    virtual void AND_IMM(uint32_t immed8) = 0;
    virtual void NOT(int Rm, int Rn) = 0;
    virtual void OR(int Rm, int Rn) = 0;
    virtual void OR_IMM(uint32_t immed8) = 0;
    virtual void XOR(int Rm, int Rn) = 0;
    virtual void XOR_IMM(uint32_t immed8) = 0;

    // Shift
    virtual void ROTL(int bits, int Rn) = 0;
    virtual void ROTR(int bits, int Rn) = 0;
    virtual void SHAR(int bits, int Rn) = 0;
    virtual void SHLL(int bits, int Rn) = 0;
    virtual void SHLR(int bits, int Rn) = 0;
    virtual void SHAD(int Rm, int Rn) = 0;
    virtual void SHLD(int Rm, int Rn) = 0;
    virtual void SHLL1(int Rn) = 0;
    virtual void SHLR1(int Rn) = 0;
    virtual void SHLL2(int Rn) = 0;
    virtual void SHLR2(int Rn) = 0;
    virtual void SHLL8(int Rn) = 0;
    virtual void SHLR8(int Rn) = 0;
    virtual void SHLL16(int Rn) = 0;
    virtual void SHLR16(int Rn) = 0;

    // branches...
    virtual void BRA(uint16_t* pc) = 0;
    virtual void BRA(uint16_t disp) = 0;
    virtual void RTS(void) = 0;

    virtual void label(const char* theLabel) = 0;
    virtual const char* genLabel(void) = 0;
    virtual void BRA(const char* label) = 0;
    virtual void BT(const char* label) = 0;
    virtual void BF(const char* label) = 0;

    // valid only after generate() has been called
    virtual uint16_t* pcForLabel(const char* label) = 0;

    // data transfer...
    virtual void IMM(int32_t immed8, int Rn) = 0;
    virtual void IMM16(int32_t immed16, int Rn) = 0;
    virtual void IMM32(uint32_t immed32, int Rn) = 0;
    virtual void MOV(int Rm, int Rn) = 0;
    virtual void MOVA(int disp) = 0;
    virtual void MOV_PC_W(int disp, int Rn) = 0;
    virtual void MOV_PC_L(int disp, int Rn) = 0;
    virtual void MOV_LD_B(int Rm, int Rn) = 0;
    virtual void MOV_LD_W(int Rm, int Rn) = 0;
    virtual void MOV_LD_L(int Rm, int Rn) = 0;
    virtual void MOV_LD_B_R0(int Rm, int Rn) = 0;
    virtual void MOV_LD_W_R0(int Rm, int Rn) = 0;
    virtual void MOV_LD_L_R0(int Rm, int Rn) = 0;
    virtual void MOV_ST_B(int Rm, int Rn) = 0;
    virtual void MOV_ST_W(int Rm, int Rn) = 0;
    virtual void MOV_ST_L(int Rm, int Rn) = 0;
    virtual void MOV_ST_B_R0(int Rm, int Rn) = 0;
    virtual void MOV_ST_W_R0(int Rm, int Rn) = 0;
    virtual void MOV_ST_L_R0(int Rm, int Rn) = 0;
    virtual void MOV_LD_B_POSTINC(int Rm, int Rn) = 0;
    virtual void MOV_LD_W_POSTINC(int Rm, int Rn) = 0;
    virtual void MOV_LD_L_POSTINC(int Rm, int Rn) = 0;
    virtual void MOV_LD_B_PREDEC(int Rm, int Rn) = 0;
    virtual void MOV_LD_W_PREDEC(int Rm, int Rn) = 0;
    virtual void MOV_LD_L_PREDEC(int Rm, int Rn) = 0;
    virtual void SWAP_B(int Rm, int Rn) = 0;
    virtual void SWAP_W(int Rm, int Rn) = 0;
    virtual void POP_REGS(uint32_t reglist) = 0;
    virtual void PUSH_REGS(uint32_t reglist) = 0;

    // special...
    virtual void NOP(void) = 0;
    virtual void OCBWB(int Rn) = 0;
    virtual void PREF(int Rn) = 0;
    virtual void STS_MACH(int Rn) = 0;
    virtual void STS_MACL(int Rn) = 0;

#if 1 /* left to keep algorithm consisten with ARM inplementation. */
    // DSP instructions...
    enum {
        // B=0, T=1
        //     yx
        xyBB = 0, // 0000,
        xyTB = 2, // 0010,
        xyBT = 4, // 0100,
        xyTT = 6, // 0110,
        yB   = 0, // 0000,
        yT   = 4, // 0100
    };
#endif

};

}; // namespace android

#endif //ANDROID_SHASSEMBLER_INTERFACE_H
