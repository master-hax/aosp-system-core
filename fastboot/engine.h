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

#include <inttypes.h>
#include <stdlib.h>

#include <string>

#include <bootimg.h>
#include "engine_actions.h"
#include "fastboot_driver.h"
#include "util.h"

class Transport;
struct sparse_file;

class Engine {
  public:
    Engine(Transport* transport);
    ~Engine() = default;

    bool GetVar(const std::string& key, std::string* val);
    bool SetActive(const std::string& part);

    // Action Queue Interface
    // Run all the jobs in the queue
    bool ExecuteQueue();
    std::string FBError();

    // Note: no input args are passed by reference, use std::mov as neccesary
    void QueueFlash(const std::string part, std::vector<char> data);
    void QueueFlash(const std::string part, int fd, uint32_t sz);
    void QueueFlash(const std::string part, struct sparse_file* s, uint32_t sz, size_t current,
                    size_t total);
    void QueueBoot(std::string msg);
    void QueueContinue();
    void QueueErase(const std::string partition);
    void QueueRequire(const std::string prod, const std::string var,
                      const std::vector<std::string> options, bool invert = false,
                      const std::string* cur_prod = nullptr);
    void QueueDisplay(const std::string var, const std::string msg);
    void QueueSave(const std::string var, std::string* dest);
    void QueueReboot();
    void QueueRebootBootloader(std::string msg);
    void QueueDownload(const std::string part, std::vector<char> data);
    void QueueDownload(const std::string part, int fd, uint32_t sz);
    void QueueUpload(const std::string outfile);
    void QueueNotice(const std::string msg);
    void QueueSetActive(const std::string slot);
    void QueueWaitForDisconnect();
    // Use for non-standard commands like OEM
    void QueueRaw(const std::string cmd, const std::string msg);

  protected:
    fastboot::FastBootDriver fb;
    std::deque<std::unique_ptr<Action>> jobs;
};

class FastBootTool {
  public:
    int Main(int argc, char* argv[]);

    void ParseOsPatchLevel(boot_img_hdr_v1*, const char*);
    void ParseOsVersion(boot_img_hdr_v1*, const char*);
};
