/* libs/pixelflinger/codeflinger/SHAssemblerInterface.cpp
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


#include <errno.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/types.h>

#include <cutils/log.h>
#include "codeflinger/SHAssemblerInterface.h"

namespace android {

// ----------------------------------------------------------------------------

SHAssemblerInterface::~SHAssemblerInterface()
{
}

int SHAssemblerInterface::buildImmediate(
        uint32_t immed32, int32_t& shift, uint32_t& imm)
{
    shift = 0;
    imm = immed32;
    if (immed32 == 0) return 0;

    if (imm > 0x7F) { // skip the easy cases
        while (!(imm & 1)) {
            if (imm < 0x80) {
                if (shift == 1 || shift == 2 || shift == 8 || shift == 16) {
                    break;  // skip the easy shift cases
                }
            }
            imm = imm >> 1;
            shift++;
            if (shift == 32) break;
        }
    }

    if (imm > 0x7F)
        return -1;

    if ((imm << shift) != immed32)
        return -1;

    return 0;
}

// shifters...

bool SHAssemblerInterface::isValidImmediate(uint32_t immed32)
{
    int32_t shift;
    uint32_t imm;
    return buildImmediate(immed32, shift, imm) == 0;
}

}; // namespace android

