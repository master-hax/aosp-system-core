/*
 * Copyright (C) 2018 The Android Open Source Project
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

 #include <fcntl.h>
 #include <stdio.h>
 #include <stdlib.h>
 #include <string.h>
 #include <errno.h>

#include <chrono>
#include <algorithm>
#include <vector>

#include <android-base/file.h>
#include <android-base/stringprintf.h>
#include <android-base/unique_fd.h>
#include <utils/FileMap.h>

#include "fastboot2.h"
#include "transport.h"


FastBoot2::FastBoot2(Transport &transport)
: transport(transport)
{}


FastBoot2::~FastBoot2() {
  transport.Close();
}


std::string FastBoot2::ErrnoStr(const std::string &msg) {
  return android::base::StringPrintf("%s (%s)", msg.c_str(), strerror(errno));
}

const std::string FastBoot2::RCString(FastBoot2::RetCode rc) {
  switch (rc) {
    case SUCCESS:
      return std::string("Success");

    case BAD_ARG:
      return std::string("Invalid Argument");

    case IO_ERROR:
      return std::string("I/O Error");

    case BAD_DEV_RESP:
      return std::string("Invalid Device Response");

    case DEVICE_ERROR:
      return std::string("Device Error");

    case TIMEOUT:
      return std::string("Timeout");

    default:
      return std::string("Unknown Error");
  }
}



FastBoot2::RetCode FastBoot2::HandleResponse(std::string &response, std::vector<std::string> &info, int *dsize) {
  char status[FB_RESPONSE_SZ + 1];
  auto start = std::chrono::system_clock::now();
  // erase the response string
  response.erase();
  //info.clear();

  while ((std::chrono::system_clock::now() - start) < std::chrono::seconds(RESP_TIMEOUT))
  {
    memset(status, '\0', sizeof(status)); // Need the null terminator
    int r = transport.Read(status, FB_RESPONSE_SZ);
    if (r < 0) {
      g_error = ErrnoStr("Status read failed");
      return IO_ERROR;
    } else if (r < 4) {
      g_error = android::base::StringPrintf("status malformed (%d bytes)", r);
      return BAD_DEV_RESP;
    }

    if (!memcmp(status, "INFO", 4)) {
      info.push_back(status + 4);
    } else if (!memcmp(status, "OKAY", 4)) {
      response = status + 4;
      break;
    } else if (!memcmp(status, "FAIL", 4)) {
      g_error = android::base::StringPrintf("Device says: %s", status);
      response = status + 4;
      return DEVICE_ERROR;
    } else if (!memcmp(status, "DATA", 4)) {
      uint32_t num = strtol(status + 4, 0, 16);
      if (num > MAX_RESP_DATA_SIZE) {
        g_error = android::base::StringPrintf("Data size too large (%d)", num);
        return BAD_DEV_RESP;
      }
      if (dsize)
        *dsize = num;
      response = status + 4;
    } else {
      g_error = android::base::StringPrintf("Device sent unknown status code: %s", status);
      return BAD_DEV_RESP;
    }

  } // End of while loop

  return response.size() == 0 ? TIMEOUT : SUCCESS;
}


FastBoot2::RetCode FastBoot2::Download(int fd, size_t size, std::string &response, std::vector<std::string> &info) {
  RetCode ret;

  // Start by sending download command with # of bytes
  const std::string cmd = android::base::StringPrintf("download:%08zx", size);
  if((ret = RawCommand(cmd, response, info))) {
    return ret;
  }

  // Write the buffer
  if((ret = SendBuffer(fd, size))) {
    return ret;
  }

  // Wait for response
  return HandleResponse(response, info);
}


FastBoot2::RetCode FastBoot2::Download(int fd, size_t size) {
  std::string dummy;
  std::vector<std::string> dummy2;
  return Download(fd, size, dummy, dummy2);
}



FastBoot2::RetCode FastBoot2::Download(const std::vector<char> &buf, std::string &response, std::vector<std::string> &info) {
  RetCode ret;

  // Start by sending download command with # of bytes
  const std::string cmd = android::base::StringPrintf("download:%08zx", buf.size());
  if((ret = RawCommand(cmd, response, info))) {
    return ret;
  }

  // Write the buffer
  if((ret = SendBuffer(buf))) {
    return ret;
  }

  // Wait for response
  return HandleResponse(response, info);
}


FastBoot2::RetCode FastBoot2::Download(const std::vector<char> &buf) {
  std::string dummy;
  std::vector<std::string> dummy2;
  return Download(buf, dummy, dummy2);
}




FastBoot2::RetCode FastBoot2::DownloadSparse(sparse_file &s, std::string &response, std::vector<std::string> &info) {
  int64_t size = sparse_file_len(&s, true, false);
  if (size <= 0 || size > std::numeric_limits<uint32_t>::max()) {
    g_error = "Sparse file is too large";
    return BAD_ARG;
  }

  std::string cmd(android::base::StringPrintf("download:%08" PRIx64, size));
  RetCode ret;
  if ((ret = RawCommand(cmd, response, info))) {
    return ret;
  }

  // This is the transport buffer used in the callback
  std::vector<char> tpbuf;
  auto cb = [this, &tpbuf](std::vector<char> &towrite) { this->SparseWriteCallback(tpbuf, towrite); };


  if (sparse_file_callback(&s, true, false, SparseWriteCallbackEntry, &cb) < 0) {
    g_error = "Error reading sparse file";
    return IO_ERROR;
  }

  // Now flush
  if (tpbuf.size()) {
    if ((ret = SendBuffer(tpbuf))) {
      return ret;
    }
  }

  return HandleResponse(response, info);
}


FastBoot2::RetCode FastBoot2::DownloadSparse(sparse_file &s) {
  std::string dummy;
  std::vector<std::string> dummy2;
  return DownloadSparse(s, dummy, dummy2);
}


int FastBoot2::SparseWriteCallbackEntry(void* priv, const void* data, size_t len) {
  auto cb = *static_cast<std::function<int(std::vector<char>)>*>(priv);
  const char *buf = static_cast<const char*>(data);
  std::vector<char> tmp;
  tmp.assign(buf, buf + len);
  return cb(tmp);
}


int FastBoot2::SparseWriteCallback(std::vector<char> &tpbuf, std::vector<char> &towrite) {
  // Copy over the new stuff to write
  tpbuf.insert(tpbuf.end(), towrite.begin(), towrite.end());

  const int nchunks = tpbuf.size()/TRANSPORT_CHUNK_SIZE;
  for (int i=0; i < nchunks; i++)
  {
    // This is not the most efficient, can fix later
    std::vector<char> sub(tpbuf.begin() + i*TRANSPORT_CHUNK_SIZE, tpbuf.begin() + (i+1)*TRANSPORT_CHUNK_SIZE);
    if (SendBuffer(sub)) {
      g_error = ErrnoStr("Send failed in SparseWriteCallback()");
      return -1;
    }
  }

  if (nchunks) {
    towrite.erase(towrite.begin(), towrite.begin() + nchunks*(TRANSPORT_CHUNK_SIZE));
  }

  return 0;
}




FastBoot2::RetCode FastBoot2::Upload(const std::string &outfile, std::string &response, std::vector<std::string> &info) {
  RetCode ret;
  int dsize;
  if ((ret = RawCommand("upload", response, info, &dsize)) || dsize == 0) {
    g_error = "Upload request failed";
    return ret;
  }

  std::string data;
  data.resize(dsize);

  if ((ret = ReadBuffer(&data[0], data.size()))) {
    return ret;
  }

  if (!android::base::WriteStringToFile(data, outfile.c_str(), true)) {
    g_error =  android::base::StringPrintf("write to '%s' failed", outfile.c_str());
    return IO_ERROR;
  }

  return HandleResponse(response, info);
}

FastBoot2::RetCode FastBoot2::Upload(const std::string &outfile) {
  std::string dummy;
  std::vector<std::string> dummy2;
  return Upload(outfile, dummy, dummy2);
}

FastBoot2::RetCode FastBoot2::SendBuffer(int fd, size_t size) {
  static constexpr uint32_t MAX_MAP_SIZE = 512 * 1024 * 1024;
  off64_t offset = 0;
  uint32_t remaining = size;
  RetCode ret;

  while (remaining) {
    // Memory map the file
    android::FileMap filemap;
    size_t len = std::min(remaining, MAX_MAP_SIZE);

    if (!filemap.create(NULL, fd, offset, len, true)) {
      g_error = "Creating filemap failed";
      return IO_ERROR;
    }

    if ((ret = SendBuffer(filemap.getDataPtr(), len))) {
      return ret;
    }

    remaining -= len;
    offset += len;
  }

  return SUCCESS;
}


FastBoot2::RetCode FastBoot2::SendBuffer(const std::vector<char> &buf) {
  // Write the buffer
  return SendBuffer(&buf[0], buf.size());
}


FastBoot2::RetCode FastBoot2::SendBuffer(const void *buf, size_t size) {
  // Write the buffer
  ssize_t tmp = transport.Write(buf, size);

  if (tmp < 0) {
    g_error = ErrnoStr("Write to device failed in SendBuffer()");
    return IO_ERROR;
  } else if (static_cast<size_t>(tmp) != size) {
    g_error = android::base::StringPrintf("Failed to write all %zu bytes", size);

    return IO_ERROR;
  }

  return SUCCESS;
}



FastBoot2::RetCode FastBoot2::ReadBuffer(std::vector<char> &buf) {
  // Read the buffer
  return ReadBuffer(&buf[0], buf.size());
}


FastBoot2::RetCode FastBoot2::ReadBuffer(void *buf, size_t size) {
  // Read the buffer
  ssize_t tmp = transport.Read(buf, size);

  if (tmp < 0) {
    g_error = ErrnoStr("Read from device failed in ReadBuffer()");
    return IO_ERROR;
  } else if (static_cast<size_t>(tmp) != size) {
    g_error = android::base::StringPrintf("Failed to read all %zu bytes", size);
    return IO_ERROR;
  }

  return SUCCESS;
}



FastBoot2::RetCode FastBoot2::RawCommand(const std::string& cmd) {
  std::string dummy;
  std::vector<std::string> dummy2;
  return RawCommand(cmd, dummy, dummy2);
}



FastBoot2::RetCode FastBoot2::RawCommand(const std::string& cmd, std::string &response) {
  std::vector<std::string> dummy;
  return RawCommand(cmd, response, dummy);
}


FastBoot2::RetCode FastBoot2::RawCommand(
    const std::string& cmd, std::string &response,
    std::vector<std::string> &info, int *dsize) {

  if (cmd.size() > FB_COMMAND_SZ) {
      g_error = "Command length to RawCommand() is too long";
      return BAD_ARG;
  }

  if (transport.Write(cmd.c_str(), cmd.size()) != static_cast<int>(cmd.size())) {
    g_error = ErrnoStr("Write to device failed");
    return IO_ERROR;
  }

  // Read the response
  return HandleResponse(response, info, dsize);
}


std::string FastBoot2::GetError() {
  return g_error;
}


FastBoot2::RetCode FastBoot2::WaitForDisconnect() {
  return transport.WaitForDisconnect() ? IO_ERROR : SUCCESS;
}
