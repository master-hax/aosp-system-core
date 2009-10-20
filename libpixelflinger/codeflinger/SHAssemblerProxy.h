/* libs/pixelflinger/codeflinger/SHAssemblerProxy.h
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


#ifndef ANDROID_SHASSEMBLER_PROXY_H
#define ANDROID_SHASSEMBLER_PROXY_H

#include <stdint.h>
#include <sys/types.h>

#include "codeflinger/SHAssemblerInterface.h"

namespace android {

// ----------------------------------------------------------------------------

class SHAssemblerProxy : public SHAssemblerInterface
{
public:
    // SHAssemblerProxy take ownership of the target

                SHAssemblerProxy();
                SHAssemblerProxy(SHAssemblerInterface* target);
    virtual     ~SHAssemblerProxy();

    void setTarget(SHAssemblerInterface* target);

    virtual void    reset();
    virtual int     generate(const char* name);
    virtual void    disassemble(const char* name);

    virtual void    prolog();
    virtual void    epilog(uint32_t touched);
    virtual void    comment(const char* string);

    virtual void ADD(int Rm, int Rn);
    virtual void ADD_IMM(int32_t immed8, int Rn);
    virtual void DMULS(int Rm, int Rn);
    virtual void DMULU(int Rm, int Rn);
    virtual void MULU(int Rm, int Rn);
    virtual void MULS(int Rm, int Rn);
    virtual void NEG(int Rm, int Rn);
    virtual void SUB(int Rm, int Rn);
    virtual void DT(int Rn);
    virtual void CMP(int cond, int Rm, int Rn);
    virtual void CMP(int cond, int Rn);
    virtual void EXTU_B(int Rm, int Rn);
    virtual void EXTU_W(int Rm, int Rn);
    virtual void EXTS_B(int Rm, int Rn);
    virtual void EXTS_W(int Rm, int Rn);

    virtual void AND(int Rm, int Rn);
    virtual void AND_IMM(uint32_t immed8);
    virtual void NOT(int Rm, int Rn);
    virtual void OR(int Rm, int Rn);
    virtual void OR_IMM(uint32_t immed8);
    virtual void XOR(int Rm, int Rn);
    virtual void XOR_IMM(uint32_t immed8);

    virtual void ROTL(int bits, int Rn);
    virtual void ROTR(int bits, int Rn);
    virtual void SHAR(int bits, int Rn);
    virtual void SHLL(int bits, int Rn);
    virtual void SHLR(int bits, int Rn);
    virtual void SHAD(int Rm, int Rn);
    virtual void SHLD(int Rm, int Rn);
    virtual void SHLL1(int Rn);
    virtual void SHLR1(int Rn);
    virtual void SHLL2(int Rn);
    virtual void SHLR2(int Rn);
    virtual void SHLL8(int Rn);
    virtual void SHLR8(int Rn);
    virtual void SHLL16(int Rn);
    virtual void SHLR16(int Rn);

    virtual void BRA(uint16_t* pc);
    virtual void BRA(uint16_t disp);
    virtual void RTS(void);
    virtual void label(const char* theLabel);
    virtual const char* genLabel(void);
    virtual void BT(const char* label);
    virtual void BF(const char* label);
    virtual void BRA(const char* label);

    uint16_t* pcForLabel(const char* label);

    virtual void IMM(int32_t immed8, int Rn);
    virtual void IMM16(int32_t immed16, int Rn);
    virtual void IMM32(uint32_t immed32, int Rn);
    virtual void MOV(int Rm, int Rn);
    virtual void MOVA(int disp);
    virtual void MOV_PC_W(int disp, int Rn);
    virtual void MOV_PC_L(int disp, int Rn);
    virtual void MOV_LD_B(int Rm, int Rn);
    virtual void MOV_LD_W(int Rm, int Rn);
    virtual void MOV_LD_L(int Rm, int Rn);
    virtual void MOV_LD_B_R0(int Rm, int Rn);
    virtual void MOV_LD_W_R0(int Rm, int Rn);
    virtual void MOV_LD_L_R0(int Rm, int Rn);
    virtual void MOV_ST_B(int Rm, int Rn);
    virtual void MOV_ST_W(int Rm, int Rn);
    virtual void MOV_ST_L(int Rm, int Rn);
    virtual void MOV_ST_B_R0(int Rm, int Rn);
    virtual void MOV_ST_W_R0(int Rm, int Rn);
    virtual void MOV_ST_L_R0(int Rm, int Rn);
    virtual void MOV_LD_B_POSTINC(int Rm, int Rn);
    virtual void MOV_LD_W_POSTINC(int Rm, int Rn);
    virtual void MOV_LD_L_POSTINC(int Rm, int Rn);
    virtual void MOV_LD_B_PREDEC(int Rm, int Rn);
    virtual void MOV_LD_W_PREDEC(int Rm, int Rn);
    virtual void MOV_LD_L_PREDEC(int Rm, int Rn);
    virtual void SWAP_B(int Rm, int Rn);
    virtual void SWAP_W(int Rm, int Rn);
    virtual void POP_REGS(uint32_t reglist);
    virtual void PUSH_REGS(uint32_t reglist);

    virtual void NOP(void);
    virtual void OCBWB(int Rn);
    virtual void PREF(int Rn);
    virtual void STS_MACH(int Rn);
    virtual void STS_MACL(int Rn);

private:
    SHAssemblerInterface*  mTarget;
};

}; // namespace android

#endif //ANDROID_SHASSEMBLER_PROXY_H
