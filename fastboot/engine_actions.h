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
#pragma once

#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <deque>
#include <memory>
#include <string>
#include <vector>

#include <android-base/stringprintf.h>
#include "fastboot_driver.h"
#include "transport.h"

/******************************* ACTIONS *************************************/
struct Action {
    virtual ~Action() = default;
    virtual void Before() {}
    virtual fastboot::RetCode Execute(fastboot::FastBootDriver& fb) = 0;
    virtual bool After(double rt);
    virtual void Failure(std::string& err);
    void Print(const std::string& s);
    void PrintFirst(const std::string& s);
};

// Set Active
struct SetActive : public Action {
    SetActive(std::string slot) : slot(slot) {}
    virtual void Before() override;
    virtual fastboot::RetCode Execute(fastboot::FastBootDriver& fb) override;

  private:
    const std::string slot;
};

// Erase
struct Erase : public Action {
    Erase(std::string part) : part(part) {}
    virtual void Before() override;
    virtual fastboot::RetCode Execute(fastboot::FastBootDriver& fb) override;

  private:
    const std::string part;
};

// Flash
struct Flash : public Action {
    Flash(std::string part) : part(part) {}
    virtual void Before() override;
    virtual fastboot::RetCode Execute(fastboot::FastBootDriver& fb) override;

  private:
    const std::string part;
};

// Download buffer
struct Download : public Action {
    Download(const std::string name, const std::vector<char> buf) : name(name), buf(buf) {}

    virtual void Before() override;
    virtual fastboot::RetCode Execute(fastboot::FastBootDriver& fb) override;

  private:
    const std::string name;
    const std::vector<char> buf;
};

// Download FD
struct DownloadFD : public Action {
    DownloadFD(const std::string part, int fd, uint32_t sz) : part(part), fd(fd), size(sz) {}

    virtual void Before() override;
    virtual fastboot::RetCode Execute(fastboot::FastBootDriver& fb) override;

  private:
    const std::string part;
    const int fd;
    const uint32_t size;
};

// Download Sparse
struct DownloadSparse : public Action {
    DownloadSparse(const std::string part, sparse_file* sparse, uint32_t sz, size_t current,
                   size_t total)
        : part(part), sparse(sparse), size(sz), current(current), total(total) {}

    virtual void Before() override;
    virtual fastboot::RetCode Execute(fastboot::FastBootDriver& fb) override;

  private:
    const std::string part;
    sparse_file* const sparse;
    const uint32_t size;
    const size_t current;
    const size_t total;
};

// Require
struct Require : public Action {
    Require(const std::string prod, const std::string val, const std::vector<std::string> options,
            bool invert = false, const std::string* cur_prod = nullptr)
        : product(prod), val(val), options(options), invert(invert), cur_prod(cur_prod) {}

    virtual void Before() override;
    virtual fastboot::RetCode Execute(fastboot::FastBootDriver& fb) override;
    virtual bool After(double rt) override;

  private:
    const std::string product;
    const std::string val;
    const std::vector<std::string> options;
    const bool invert;
    const std::string* const cur_prod;
    // Will be set in Execute
    bool reqmet;
    std::string gvar;
};

// Getvar display
struct GetVarDisplay : public Action {
    GetVarDisplay(const std::string var, std::string msg) : var(var), msg(msg) {}
    virtual fastboot::RetCode Execute(fastboot::FastBootDriver& fb) override;
    virtual bool After(double) override;

  private:
    const std::string var;
    const std::string msg;
    std::string resp;
};

// GetVarStore
struct GetVarStore : public Action {
    GetVarStore(const std::string var, std::string* dest) : var(var), dest(dest) {}
    virtual fastboot::RetCode Execute(fastboot::FastBootDriver& fb) override;
    virtual bool After(double) override;

  private:
    const std::string var;
    std::string* const dest;
};

// Reboot
struct Reboot : public Action {
    virtual fastboot::RetCode Execute(fastboot::FastBootDriver& fb) override;
    virtual void Before() override;
    virtual bool After(double) override;
};

// Boot
struct Boot : public Action {
    Boot(const std::string msg) : msg(msg) {}
    virtual fastboot::RetCode Execute(fastboot::FastBootDriver& fb) override;
    virtual void Before() override;

  private:
    const std::string msg;
};

// Reboot Bootloader
struct RebootBootloader : public Action {
    RebootBootloader(const std::string msg) : msg(msg) {}
    virtual fastboot::RetCode Execute(fastboot::FastBootDriver& fb) override;
    virtual void Before() override;

  private:
    const std::string msg;
};

// Continue
struct Continue : public Action {
    virtual fastboot::RetCode Execute(fastboot::FastBootDriver& fb) override;
    virtual void Before() override;
};

// Notice
struct Notice : public Action {
    Notice(const std::string msg) : msg(msg) {}
    virtual fastboot::RetCode Execute(fastboot::FastBootDriver&) override;
    virtual bool After(double) override;

  private:
    const std::string msg;
};

// Upload
struct Upload : public Action {
    Upload(const std::string outfile) : outfile(outfile) {}

    virtual void Before() override;
    virtual fastboot::RetCode Execute(fastboot::FastBootDriver& fb);

  private:
    const std::string outfile;
};

// Upload
struct WaitForDisconnect : public Action {
    virtual fastboot::RetCode Execute(fastboot::FastBootDriver& fb);
};

// Raw command
struct Raw : public Action {
    Raw(const std::string cmd, const std::string msg) : cmd(cmd), msg(msg) {}

    virtual void Before() override;
    virtual fastboot::RetCode Execute(fastboot::FastBootDriver& fb) override;

  private:
    const std::string cmd;
    const std::string msg;
};
