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

#include <android-base/logging.h>
#include <android-base/stringprintf.h>
#include <bootimg.h>
#include <inttypes.h>
#include <sparse/sparse.h>
#include <cstdlib>
#include <deque>
#include <limits>
#include <string>
#include <vector>

class Transport;

namespace fastboot {
class FastBootDriver;  // forward declare

static constexpr int FB_COMMAND_SZ = 64;
static constexpr int FB_RESPONSE_SZ = 64;
// I wish C++ had Java like enums...
namespace commands {

class Command {
    friend class fastboot::FastBootDriver;

  private:
    virtual bool Execute(std::function<bool(std::vector<char>&)>& recv,
                         std::function<bool(const std::vector<char>&)>& trans, std::string& err) = 0;
};

/************* Commands That Are Only Strings *******************/
class StrCommand : public Command {
  private:
    virtual bool Execute(std::function<bool(std::vector<char>&)>& recv,
                         std::function<bool(const std::vector<char>&)>& trans,
                         std::string& err) override;

    virtual const std::string Cmd() = 0;
};

class GetVar : public StrCommand {
  public:
    GetVar(std::string key);

  private:
    virtual const std::string Cmd() override final;

  protected:
    const std::string key;
};

class Download : public StrCommand {
  public:
    Download(uint32_t num);

  private:
    virtual const std::string Cmd() override final;

  protected:
    const uint32_t num;
};

class Upload : public StrCommand {
  private:
    virtual const std::string Cmd() override final;
};

class Verify : public StrCommand {
  public:
    Verify(uint32_t num);

  private:
    virtual const std::string Cmd() override final;

  protected:
    const uint32_t num;
};

class Flash : public StrCommand {
  public:
    Flash(std::string part);

  private:
    virtual const std::string Cmd() override final;

  protected:
    const std::string part;
};

class SetActive : public StrCommand {
  public:
    SetActive(std::string slot);

  private:
    virtual const std::string Cmd() override final;

  protected:
    const std::string slot;
};

class Erase : public StrCommand {
  public:
    Erase(std::string part);

  private:
    virtual const std::string Cmd() override final;

  protected:
    const std::string part;
};

class Boot : public StrCommand {
  private:
    virtual const std::string Cmd() override final;
};

class Continue : public StrCommand {
  private:
    virtual const std::string Cmd() override final;
};

class Reboot : public StrCommand {
  private:
    virtual const std::string Cmd() override final;
};

class RebootBootloader : public StrCommand {
  private:
    virtual const std::string Cmd() override final;
};

class Powerdown : public StrCommand {
  private:
    virtual const std::string Cmd() override final;
};

/************* Commands That Actually Transfer A Buffer *******************/
class Transfer : public Command {
  private:
    virtual bool Execute(std::function<bool(std::vector<char>&)>& recv,
                         std::function<bool(const std::vector<char>&)>& trans,
                         std::string& err) override;
    virtual bool Buf(std::function<bool(const std::vector<char>&)> transfer, std::string& err) = 0;
};

class BufTransfer : public Transfer {
  public:
    BufTransfer(const std::vector<char> buf);

  private:
    virtual bool Buf(std::function<bool(const std::vector<char>&)> transfer,
                     std::string& err) override final;

  protected:
    const std::vector<char> buf;
};

class FileTransfer : public Transfer {
  public:
    FileTransfer(int fd, size_t size);

  private:
    virtual bool Buf(std::function<bool(const std::vector<char>&)> transfer,
                     std::string& err) override final;

  protected:
    const int fd;
    const size_t size;
};

class SparseFileTransfer : public Transfer {
  public:
    static constexpr size_t TRANSPORT_CHUNK_SIZE = 1024;
    SparseFileTransfer(sparse_file& sf);

  private:
    virtual bool Buf(std::function<bool(const std::vector<char>&)> transfer,
                     std::string& err) override final;
    // This is required to support the C sparse file library
    static int SparseWriteCallbackEntry(void* priv, const void* data, size_t len);
    int SparseWriteCallback(std::function<bool(const std::vector<char>&)> trans,
                            std::vector<char>& tpbuf, const char* data, size_t len,
                            std::string& err);

  protected:
    struct sparse_file& sf;
};

// Read
class Read : public Command {
  public:
    Read(std::string outfile, size_t size);

  private:
    virtual bool Execute(std::function<bool(std::vector<char>&)>& recv,
                         std::function<bool(const std::vector<char>&)>& trans,
                         std::string& err) override;

  protected:
    const std::string outfile;
    const size_t size;
};

}  // namespace commands

class FastBootDriver {
  public:
    static constexpr int RESP_TIMEOUT = 10;  // 10 seconds
    static constexpr int MAX_RESP_DATA_SIZE = std::numeric_limits<int32_t>::max();

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

    FastBootDriver(Transport& transport,
                   std::function<void(std::string&)> info = [](std::string& tmp) { (void)tmp; });
    ~FastBootDriver();

    /* HIGHER LEVEL COMMANDS */
    RetCode GetVarAll(std::vector<std::string>& resp);
    RetCode GetVar(const std::string& key, std::string& val);
    RetCode Flash(const std::string& part, std::vector<char>& data);
    RetCode Flash(const std::string& part, int fd, uint32_t sz);
    RetCode Flash(const std::string& part, sparse_file& s);
    RetCode Download(int fd, size_t size);
    RetCode Download(const std::vector<char>& buf);
    RetCode Download(sparse_file& s);
    RetCode Upload(const std::string& outfile);
    RetCode Erase(const std::string& part);
    RetCode SetActive(const std::string& part);
    RetCode Reboot();
    RetCode Partitions(std::vector<std::tuple<std::string, uint32_t>>& parts);
    RetCode Require(const std::string& var, const std::vector<std::string>& allowed, bool& reqmet,
                    bool invert = false);

    /* LOWER LEVEL COMMAND INTERFACE */
    RetCode Command(commands::Command& cmd, bool clear = true, int* dsize = nullptr);
    RetCode Command(commands::Command& cmd, std::string& val, bool clear = true,
                    int* dsize = nullptr);

    std::string Response();
    std::vector<std::string> Info();
    std::string GetError();

    void SetInfoCallback(std::function<void(std::string&)> info);
    RetCode WaitForDisconnect();

    // TODO: these will be moved to protected after engine.cpp is updated to use Command()
    RetCode RawCommand(const std::string& cmd, bool clear = true, int* dsize = nullptr);
    RetCode RawCommand(const std::string& cmd, std::string& resp, bool clear = true,
                       int* dsize = nullptr);

  protected:
    RetCode HandleResponse(bool clear = true, int* dsize = nullptr);
    RetCode SendBuffer(const std::vector<char>& buf);
    RetCode ReadBuffer(std::vector<char>& buf);

    void DisableChecks();
    // Error printing
    std::string ErrnoStr(const std::string& msg);
    Transport& transport;

  private:
    std::string g_error;
    std::function<void(std::string&)> info_cb;
    bool disable_checks;

    std::string response;           // Stores the last response
    std::vector<std::string> info;  // Info sent back from device
};

}  // namespace fastboot
