/* libs/pixelflinger/codeflinger/SHAssemblerProxy.cpp
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


#include <stdint.h>
#include <sys/types.h>

#include "codeflinger/SHAssemblerProxy.h"

namespace android {

// ----------------------------------------------------------------------------

SHAssemblerProxy::SHAssemblerProxy()
    : mTarget(0)
{
}

SHAssemblerProxy::SHAssemblerProxy(SHAssemblerInterface* target)
    : mTarget(target)
{
}

SHAssemblerProxy::~SHAssemblerProxy()
{
    delete mTarget;
}

void SHAssemblerProxy::setTarget(SHAssemblerInterface* target)
{
    delete mTarget;
    mTarget = target;
}

void SHAssemblerProxy::reset() {
    mTarget->reset();
}
int SHAssemblerProxy::generate(const char* name) {
    return mTarget->generate(name);
}
void SHAssemblerProxy::disassemble(const char* name) {
    return mTarget->disassemble(name);
}
void SHAssemblerProxy::prolog() {
    mTarget->prolog();
}
void SHAssemblerProxy::epilog(uint32_t touched) {
    mTarget->epilog(touched);
}
void SHAssemblerProxy::comment(const char* string) {
    mTarget->comment(string);
}

void SHAssemblerProxy::ADD(int Rm, int Rn)
{
    mTarget->ADD(Rm, Rn);
}
void SHAssemblerProxy::ADD_IMM(int32_t immed8, int Rn)
{
    mTarget->ADD_IMM(immed8, Rn);
}
void SHAssemblerProxy::DMULS(int Rm, int Rn)
{
    mTarget->DMULS(Rm, Rn);
}
void SHAssemblerProxy::DMULU(int Rm, int Rn)
{
    mTarget->DMULU(Rm, Rn);
}
void SHAssemblerProxy::MULU(int Rm, int Rn)
{
    mTarget->MULU(Rm, Rn);
}
void SHAssemblerProxy::MULS(int Rm, int Rn)
{
    mTarget->MULS(Rm, Rn);
}
void SHAssemblerProxy::NEG(int Rm, int Rn)
{
    mTarget->NEG(Rm, Rn);
}
void SHAssemblerProxy::SUB(int Rm, int Rn)
{
    mTarget->SUB(Rm, Rn);
}
void SHAssemblerProxy::DT(int Rn)
{
    mTarget->DT(Rn);
}
void SHAssemblerProxy::CMP(int cond, int Rm, int Rn)
{
    mTarget->CMP(cond, Rm, Rn);
}
void SHAssemblerProxy::CMP(int cond, int Rn)
{
    mTarget->CMP(cond, Rn);
}
void SHAssemblerProxy::EXTU_B(int Rm, int Rn) {
    mTarget->EXTU_B(Rm, Rn);
}
void SHAssemblerProxy::EXTU_W(int Rm, int Rn) {
    mTarget->EXTU_W(Rm, Rn);
}
void SHAssemblerProxy::EXTS_B(int Rm, int Rn) {
    mTarget->EXTS_B(Rm, Rn);
}
void SHAssemblerProxy::EXTS_W(int Rm, int Rn) {
    mTarget->EXTS_W(Rm, Rn);
}

void SHAssemblerProxy::AND(int Rm, int Rn)
{
    mTarget->AND(Rm, Rn);
}
void SHAssemblerProxy::AND_IMM(uint32_t immed8)
{
    mTarget->AND_IMM(immed8);
}
void SHAssemblerProxy::NOT(int Rm, int Rn)
{
    mTarget->NOT(Rm, Rn);
}
void SHAssemblerProxy::OR(int Rm, int Rn)
{
    mTarget->OR(Rm, Rn);
}
void SHAssemblerProxy::OR_IMM(uint32_t immed8)
{
    mTarget->OR_IMM(immed8);
}
void SHAssemblerProxy::XOR(int Rm, int Rn)
{
    mTarget->XOR(Rm, Rn);
}
void SHAssemblerProxy::XOR_IMM(uint32_t immed8)
{
    mTarget->XOR_IMM(immed8);
}

void SHAssemblerProxy::ROTL(int bits, int Rn)
{
    mTarget->ROTL(bits, Rn);
}
void SHAssemblerProxy::ROTR(int bits, int Rn)
{
    mTarget->ROTR(bits, Rn);
}
void SHAssemblerProxy::SHAR(int bits, int Rn)
{
    mTarget->SHAR(bits, Rn);
}
void SHAssemblerProxy::SHLL(int bits, int Rn)
{
    mTarget->SHLL(bits, Rn);
}
void SHAssemblerProxy::SHLR(int bits, int Rn)
{
    mTarget->SHLR(bits, Rn);
}
void SHAssemblerProxy::SHAD(int Rm, int Rn)
{
    mTarget->SHAD(Rm, Rn);
}
void SHAssemblerProxy::SHLD(int Rm, int Rn)
{
    mTarget->SHLD(Rm, Rn);
}
void SHAssemblerProxy::SHLL1(int Rn)
{
    mTarget->SHLL1(Rn);
}
void SHAssemblerProxy::SHLR1(int Rn)
{
    mTarget->SHLR1(Rn);
}
void SHAssemblerProxy::SHLL2(int Rn)
{
    mTarget->SHLL2(Rn);
}
void SHAssemblerProxy::SHLR2(int Rn)
{
    mTarget->SHLR2(Rn);
}
void SHAssemblerProxy::SHLL8(int Rn)
{
    mTarget->SHLL8(Rn);
}
void SHAssemblerProxy::SHLR8(int Rn)
{
    mTarget->SHLR8(Rn);
}
void SHAssemblerProxy::SHLL16(int Rn)
{
    mTarget->SHLL16(Rn);
}
void SHAssemblerProxy::SHLR16(int Rn)
{
    mTarget->SHLR16(Rn);
}

void SHAssemblerProxy::BRA(uint16_t* pc) {
    mTarget->BRA(pc);
}
void SHAssemblerProxy::BRA(uint16_t disp) {
    mTarget->BRA(disp);
}
void SHAssemblerProxy::RTS(void) {
    mTarget->RTS();
}
void SHAssemblerProxy::label(const char* theLabel) {
    mTarget->label(theLabel);
}
const char * SHAssemblerProxy::genLabel(void) {
    return mTarget->genLabel();
}
void SHAssemblerProxy::BT(const char* label) {
    mTarget->BT(label);
}
void SHAssemblerProxy::BF(const char* label) {
    mTarget->BF(label);
}
void SHAssemblerProxy::BRA(const char* label) {
    mTarget->BRA(label);
}

uint16_t* SHAssemblerProxy::pcForLabel(const char* label) {
    return mTarget->pcForLabel(label);
}


void SHAssemblerProxy::IMM(int32_t immed8, int Rn) {
    mTarget->IMM(immed8, Rn);
}
void SHAssemblerProxy::IMM16(int32_t immed16, int Rn)
{
    mTarget->IMM16(immed16, Rn);
}
void SHAssemblerProxy::IMM32(uint32_t immed32, int Rn)
{
    mTarget->IMM32(immed32, Rn);
}
void SHAssemblerProxy::MOV(int Rm, int Rn) {
    mTarget->MOV(Rm, Rn);
}
void SHAssemblerProxy::MOVA(int disp) {
    mTarget->MOVA(disp);
}
void SHAssemblerProxy::MOV_PC_W(int disp, int Rn) {
    mTarget->MOV_PC_W(disp, Rn);
}
void SHAssemblerProxy::MOV_PC_L(int disp, int Rn) {
    mTarget->MOV_PC_L(disp, Rn);
}
void SHAssemblerProxy::MOV_LD_B(int Rm, int Rn) {
    mTarget->MOV_LD_B(Rm, Rn);
}
void SHAssemblerProxy::MOV_LD_W(int Rm, int Rn) {
    mTarget->MOV_LD_W(Rm, Rn);
}
void SHAssemblerProxy::MOV_LD_L(int Rm, int Rn) {
    mTarget->MOV_LD_L(Rm, Rn);
}
void SHAssemblerProxy::MOV_LD_B_R0(int Rm, int Rn) {
    mTarget->MOV_LD_B_R0(Rm, Rn);
}
void SHAssemblerProxy::MOV_LD_W_R0(int Rm, int Rn) {
    mTarget->MOV_LD_W_R0(Rm, Rn);
}
void SHAssemblerProxy::MOV_LD_L_R0(int Rm, int Rn) {
    mTarget->MOV_LD_L_R0(Rm, Rn);
}
void SHAssemblerProxy::MOV_ST_B(int Rm, int Rn) {
    mTarget->MOV_ST_B(Rm, Rn);
}
void SHAssemblerProxy::MOV_ST_W(int Rm, int Rn) {
    mTarget->MOV_ST_W(Rm, Rn);
}
void SHAssemblerProxy::MOV_ST_L(int Rm, int Rn) {
    mTarget->MOV_ST_L(Rm, Rn);
}
void SHAssemblerProxy::MOV_ST_B_R0(int Rm, int Rn) {
    mTarget->MOV_ST_B_R0(Rm, Rn);
}
void SHAssemblerProxy::MOV_ST_W_R0(int Rm, int Rn) {
    mTarget->MOV_ST_W_R0(Rm, Rn);
}
void SHAssemblerProxy::MOV_ST_L_R0(int Rm, int Rn) {
    mTarget->MOV_ST_L_R0(Rm, Rn);
}
void SHAssemblerProxy::MOV_LD_B_POSTINC(int Rm, int Rn) {
    mTarget->MOV_LD_B_POSTINC(Rm, Rn);
}
void SHAssemblerProxy::MOV_LD_W_POSTINC(int Rm, int Rn) {
    mTarget->MOV_LD_W_POSTINC(Rm, Rn);
}
void SHAssemblerProxy::MOV_LD_L_POSTINC(int Rm, int Rn) {
    mTarget->MOV_LD_L_POSTINC(Rm, Rn);
}
void SHAssemblerProxy::MOV_LD_B_PREDEC(int Rm, int Rn) {
    mTarget->MOV_LD_B_PREDEC(Rm, Rn);
}
void SHAssemblerProxy::MOV_LD_W_PREDEC(int Rm, int Rn) {
    mTarget->MOV_LD_W_PREDEC(Rm, Rn);
}
void SHAssemblerProxy::MOV_LD_L_PREDEC(int Rm, int Rn) {
    mTarget->MOV_LD_L_PREDEC(Rm, Rn);
}
void SHAssemblerProxy::SWAP_B(int Rm, int Rn) {
    mTarget->SWAP_B(Rm, Rn);
}
void SHAssemblerProxy::SWAP_W(int Rm, int Rn) {
    mTarget->SWAP_W(Rm, Rn);
}
void SHAssemblerProxy::POP_REGS(uint32_t reglist) {
    mTarget->POP_REGS(reglist);
}
void SHAssemblerProxy::PUSH_REGS(uint32_t reglist) {
    mTarget->PUSH_REGS(reglist);
}


void SHAssemblerProxy::NOP(void) {
    mTarget->NOP();
}
void SHAssemblerProxy::OCBWB(int Rn) {
    mTarget->OCBWB(Rn);
}
void SHAssemblerProxy::PREF(int Rn) {
    mTarget->PREF(Rn);
}
void SHAssemblerProxy::STS_MACH(int Rn) {
    mTarget->STS_MACH(Rn);
}
void SHAssemblerProxy::STS_MACL(int Rn) {
    mTarget->STS_MACL(Rn);
}

}; // namespace android

