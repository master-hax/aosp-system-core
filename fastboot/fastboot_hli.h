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
#include <tuple>
#include <android-base/logging.h>
#include <sparse/sparse.h>

#include "fastboot_driver.h"

class Transport;

class FastBootHLI {

public:
  FastBootHLI(Transport &transport, std::function<void(std::string&)> info = [](std::string &tmp){(void)tmp;});

  std::string Response();
  std::vector<std::string> Info();

  bool GenericCommand(const std::string &val);
  bool GenericCommand(const std::string &val, std::string &resp);

  bool GetVarAll(std::vector<std::string> &resp);
  bool GetVar(const std::string& key, std::string& val);

  bool Flash(const std::string &part, std::vector<char> &data);
  bool Flash(const std::string &part, int fd, uint32_t sz);
  bool FlashSparse(const std::string &part, sparse_file &s);

  bool Download(const std::vector<char> &buf);
  bool Download(int fd, size_t size);
  bool DownloadSparse(sparse_file &s);

  bool Upload(const std::string &outfile);

  bool Erase(const std::string &part);
  bool SetActive(const std::string &part);
  bool Reboot();

  bool Partitions(std::vector<std::tuple<std::string,uint32_t>> &parts);

  bool Require(const std::string &var, const std::vector<std::string> &allowed, bool &reqmet, bool invert=false);

  std::string Error();
  void SetInfoCallback(std::function<void(std::string&)> info);
  void WaitForDisconnect();

  FastBootDriver &Driver();
protected:
  FastBootDriver driver;
  std::string resp; // Stores the last response
  std::vector<std::string> info; // Info sent back from device
};
