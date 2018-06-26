/*
 * Copyright (C) 2008 The Android Open Source Project
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *  * Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *  * Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
 * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
 * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#pragma once

#include <inttypes.h>
#include <cstdlib>
#include <string>
#include <vector>
#include <queue>
#include <bootimg.h>
#include <android-base/logging.h>
#include <sparse/sparse.h>

#include "fastboot2.h"

class Transport;

class FastBootHLI : public FastBoot2 {

public:


  FastBootHLI(Transport &transport);

  std::string &Response();
  std::vector<std::string> &Info();

  RetCode GetVar(const std::string& key, std::string& val);
  RetCode GetVarAll(std::vector<std::string> &resp);

  RetCode Flash(const std::string &part, std::vector<char> &data);
  RetCode Flash(const std::string &part, int fd, uint32_t sz);
  RetCode FlashSparse(const std::string &part, sparse_file &s);

  RetCode Erase(const std::string &part);
  RetCode SetActive(const std::string &part);
  RetCode Reboot();

  RetCode Require(const std::string &var, const std::vector<std::string> &allowed, bool &reqmet, bool invert=false);



protected:
  RetCode GenericCommand(const std::string &val);

  std::string resp; // Stores the last response
  std::vector<std::string> info; // Info sent back from device
};
