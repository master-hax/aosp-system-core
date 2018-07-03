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
#include <deque>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <bootimg.h>
#include <limits>
#include <android-base/logging.h>
#include <sparse/sparse.h>

class Transport;

class FastBootDriver {

public:
  static constexpr int FB_COMMAND_SZ = 64;
  static constexpr int FB_RESPONSE_SZ = 64;
  static constexpr int RESP_TIMEOUT = 10; // 10 seconds
  static constexpr int MAX_RESP_DATA_SIZE = std::numeric_limits<int32_t>::max();
  static constexpr size_t TRANSPORT_CHUNK_SIZE = 1024;

  static constexpr int SPARSE_QUEUE_MAX_SIZE = 100;

  enum RetCode : int {
    SUCCESS = 0,
    BAD_ARG,
    IO_ERROR,
    BAD_DEV_RESP,
    DEVICE_FAIL,
    TIMEOUT,
    INTERAL_ERROR,
  };

  static const std::string RCString(RetCode rc);


  FastBootDriver(Transport &transport, std::function<void(std::string&)> info = [](std::string &tmp){(void)tmp;});
  ~FastBootDriver();

  // The entire fastboot interface can be implemented with the following methods:
  RetCode Download(int fd, size_t size);
  RetCode Download(int fd, size_t size, std::string &response, std::vector<std::string> &info);

  RetCode Download(const std::vector<char> &buf);
  RetCode Download(const std::vector<char> &buf, std::string &response, std::vector<std::string> &info);

  RetCode DownloadSparse(sparse_file &s);
  RetCode DownloadSparse(sparse_file &s, std::string &response, std::vector<std::string> &info);

  RetCode Upload(const std::string &outfile, std::string &response, std::vector<std::string> &info);
  RetCode Upload(const std::string &outfile);

  RetCode RawCommand(const std::string& cmd);
  RetCode RawCommand(const std::string& cmd, std::string &response);
  RetCode RawCommand(const std::string& cmd, std::string &response, std::vector<std::string> &info, int *dsize=nullptr);

  RetCode WaitForDisconnect();

  std::string GetError();
  void SetInfoCallback(std::function<void(std::string&)> info);


  // You should never need these, and are only public for testing fastboot on devices
  RetCode SendBuffer(const std::vector<char> &buf);
  RetCode SendBuffer(const void *buf, size_t size);
  RetCode SendBuffer(int fd, size_t size);

  RetCode ReadBuffer(std::vector<char> &buf);
  RetCode ReadBuffer(void *buf, size_t size);
  RetCode HandleResponse(std::string &response, std::vector<std::string> &info, int *dsize=nullptr);

protected:

  // Error printing
  std::string ErrnoStr(const std::string &msg);

  Transport &transport;
  //bool singlethreaded;

private:
  // This is required to support the C sparse file library
  static int SparseWriteCallbackEntry(void* priv, const void* data, size_t len);
  int SparseWriteCallback(std::vector<char> &tpbuf, const char* data, size_t len);
  std::string g_error;
  std::function<void(std::string&)> info_cb;
};
