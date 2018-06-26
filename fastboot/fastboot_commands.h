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

// I wish C++ had Java like enums...
namespace commands {

class Command {
    friend class fastboot::FastBootDriver;

  private:
    virtual bool Execute(std::function<bool(std::vector<char>&)>& recv,
                         std::function<bool(const std::vector<char>&)>& send, std::string& err) = 0;
};

/************* Commands That Are Only Strings *******************/
class StrCommand : public Command {
  private:
    virtual bool Execute(std::function<bool(std::vector<char>&)>& recv,
                         std::function<bool(const std::vector<char>&)>& send,
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
class Transfer : public Command {};

class BufTransfer : public Transfer {
  public:
    BufTransfer(const std::vector<char> buf);

  private:
    virtual bool Execute(std::function<bool(std::vector<char>&)>& recv,
                         std::function<bool(const std::vector<char>&)>& send,
                         std::string& err) override;

  protected:
    const std::vector<char> buf;
};

class FileTransfer : public Transfer {
  public:
    FileTransfer(int fd, size_t size);

  private:
    virtual bool Execute(std::function<bool(std::vector<char>&)>& recv,
                         std::function<bool(const std::vector<char>&)>& send,
                         std::string& err) override;

  protected:
    const int fd;
    const size_t size;
};

class SparseFileTransfer : public Transfer {
  public:
    static constexpr size_t TRANSPORT_CHUNK_SIZE = 1024;
    SparseFileTransfer(sparse_file& sf);

  private:
    virtual bool Execute(std::function<bool(std::vector<char>&)>& recv,
                         std::function<bool(const std::vector<char>&)>& send,
                         std::string& err) override;
    // This is required to support the C sparse file library
    static int SparseWriteCallbackEntry(void* priv, const void* data, size_t len);
    int SparseWriteCallback(std::function<bool(const std::vector<char>&)>& send,
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
                         std::function<bool(const std::vector<char>&)>& send,
                         std::string& err) override;

  protected:
    const std::string outfile;
    const size_t size;
};

}  // namespace commands
}  // namespace fastboot
