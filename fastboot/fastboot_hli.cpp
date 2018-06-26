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

#include "fastboot_hli.h"

#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <memory>
#include <vector>

#include <android-base/stringprintf.h>

#include "transport.h"



FastBootHLI::FastBootHLI(Transport &transport)
: FastBoot2(transport) {
}

FastBootHLI::RetCode FastBootHLI::GenericCommand(const std::string& val) {
  info.clear();
  return RawCommand(val, resp, info);
}



FastBootHLI::RetCode FastBootHLI::GetVar(const std::string& key, std::string& val) {
  RetCode ret = GenericCommand("getvar:"+key);
  val = Response();
  return ret;
}

FastBootHLI::RetCode FastBootHLI::GetVarAll(std::vector<std::string> &resp) {
  RetCode ret = GenericCommand("getvar:all");
  resp = Info();
  return ret;
}



std::string &FastBootHLI::Response() {
  return resp;
}


std::vector<std::string> &FastBootHLI::Info() {
  return info;
}


FastBootHLI::RetCode FastBootHLI::Flash(const std::string &part, std::vector<char> &data) {
  RetCode ret;
  info.clear();
  if ((ret = Download(data, resp, info))) {
    return ret;
  }
  return RawCommand("flash:" + part, resp, info);
}


FastBootHLI::RetCode FastBootHLI::Flash(const std::string &part, int fd, uint32_t sz) {
  RetCode ret;
  info.clear();
  if ((ret = Download(fd, sz, resp, info))) {
    return ret;
  }
  return RawCommand("flash:" + part, resp, info);
}


FastBootHLI::RetCode FastBootHLI::FlashSparse(const std::string &part, sparse_file &s) {
  RetCode ret;
  info.clear();
  if ((ret = DownloadSparse(s, resp, info))) {
    return ret;
  }
  return RawCommand("flash:" + part, resp, info);
}


FastBootHLI::RetCode FastBootHLI::Erase(const std::string &part) {
  return GenericCommand("erase:" + part);
}

FastBootHLI::RetCode FastBootHLI::SetActive(const std::string &part) {
  return GenericCommand("set_active:" + part);
}


FastBootHLI::RetCode FastBootHLI::Reboot() {
  return GenericCommand("reboot");
}


FastBootHLI::RetCode FastBootHLI::Require(const std::string &var,
    const std::vector<std::string> &allowed,
    bool &reqmet, bool invert) {
  std::string resp;
  RetCode ret;
  reqmet = invert;

  if ((ret = GetVar(var, resp))) {
    return ret;
  }

  // Now check if we have a match
  for (auto s : allowed) {
    // If it ends in *, and starting substring match
    if (!resp.compare(s) ||
        (s.length() && s.back() == '*' &&
        !resp.compare(0, s.length()-1, s, 0, s.length()-1)))
    {
      reqmet = !invert;
      break;
    }
  }

  return ret;
}
