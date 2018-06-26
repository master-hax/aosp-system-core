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

#include "fastboot_api.h"

#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <iostream>

#include <memory>
#include <vector>
#include <regex>

#include <android-base/stringprintf.h>

#include "transport.h"



FastBootAPI::FastBootAPI(Transport &transport, std::function<void(std::string&)> info)
: driver(transport, info) {
}

bool FastBootAPI::GenericCommand(const std::string& val) {
  info.clear();
  return driver.RawCommand(val, resp, info) == driver.SUCCESS;
}


bool FastBootAPI::GenericCommand(const std::string& val, std::string &resp) {
  if (!GenericCommand(val)) {
    return false;
  }
  resp = Response();
  return true;
}



bool FastBootAPI::GetVar(const std::string& key, std::string& val) {
  return GenericCommand("getvar:"+key, val);
}

bool FastBootAPI::GetVarAll(std::vector<std::string> &resp) {
  bool ret = GenericCommand("getvar:all");
  resp = Info();
  return ret;
}



std::string FastBootAPI::Response() {
  return resp;
}


std::vector<std::string> FastBootAPI::Info() {
  return info;
}

std::string FastBootAPI::Error() {
  return driver.GetError();
}


FastBootDriver &FastBootAPI::Driver() {
  return driver;
}

void FastBootAPI::SetInfoCallback(std::function<void(std::string&)> info) {
  driver.SetInfoCallback(info);
}

void FastBootAPI::WaitForDisconnect() {
  driver.WaitForDisconnect();
}

bool FastBootAPI::Flash(const std::string &part, std::vector<char> &data) {
  info.clear();
  if (driver.Download(data, resp, info) != driver.SUCCESS) {
    return false;
  }
  return driver.RawCommand("flash:" + part, resp, info) == driver.SUCCESS;
}


bool FastBootAPI::Flash(const std::string &part, int fd, uint32_t sz) {
  info.clear();
  if (driver.Download(fd, sz, resp, info) != driver.SUCCESS) {
    return false;
  }
  return driver.RawCommand("flash:" + part, resp, info) == driver.SUCCESS;
}


bool FastBootAPI::FlashSparse(const std::string &part, sparse_file &s) {
  info.clear();
  if (driver.DownloadSparse(s, resp, info) != driver.SUCCESS) {
    return false;
  }
  return driver.RawCommand("flash:" + part, resp, info) == driver.SUCCESS;
}


bool FastBootAPI::Download(const std::vector<char> &buf) {
  return driver.Download(buf, resp, info) == driver.SUCCESS;
}


bool FastBootAPI::Download(int fd, size_t size) {
  return driver.Download(fd, size, resp, info) == driver.SUCCESS;
}


bool FastBootAPI::DownloadSparse(sparse_file &s) {
  return driver.DownloadSparse(s, resp, info) == driver.SUCCESS;
}

bool FastBootAPI::Upload(const std::string &outfile) {
  return driver.Upload(outfile, resp, info) == driver.SUCCESS;
}

bool FastBootAPI::Erase(const std::string &part) {
  return GenericCommand("erase:" + part);
}

bool FastBootAPI::SetActive(const std::string &part) {
  return GenericCommand("set_active:" + part);
}


bool FastBootAPI::Reboot() {
  return GenericCommand("reboot");
}


bool FastBootAPI::Partitions(std::vector<std::tuple<std::string,uint32_t>> &parts) {
  std::vector<std::string> all;
  if (!GetVarAll(all)) {
    return false;
  }

  std::regex reg("partition-size[[:s:]]*:[[:s:]]*([[:w:]]+)[[:s:]]*:[[:s:]]*0x([[:d:]]+)");
  std::smatch sm;

  for (auto s : all) {
    if (std::regex_match(s, sm, reg)) {
      std::string m1(sm[1]);
      std::string m2(sm[2]);
      uint32_t tmp = strtol(m2.c_str(), 0, 16);
      parts.push_back(std::make_tuple(m1, tmp));
    }
  }
  return true;
}



bool FastBootAPI::Require(const std::string &var,
    const std::vector<std::string> &allowed,
    bool &reqmet, bool invert) {
  std::string resp;

  reqmet = invert;

  if (!GetVar(var, resp)) {
    return false;
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

  return true;
}
