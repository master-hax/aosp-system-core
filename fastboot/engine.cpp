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
#include "engine.h"

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

#include "transport.h"

/******************************* ENGINE *************************************/
bool Engine::GetVar(const std::string& key, std::string* val) {
    return !fb.GetVar(key, val);
}

bool Engine::SetActive(const std::string& part) {
    return !fb.SetActive(part);
}

std::string Engine::FBError() {
    return fb.Error();
}

void Engine::QueueWaitForDisconnect() {
    auto wait = std::unique_ptr<Action>(new WaitForDisconnect());
    jobs.push_back(std::move(wait));
}

void Engine::QueueFlash(const std::string part, std::vector<char> data) {
    QueueDownload(std::move(part), std::move(data));
    auto flash = std::unique_ptr<Action>(new Flash(part));
    jobs.push_back(std::move(flash));
}

void Engine::QueueFlash(const std::string part, int fd, uint32_t sz) {
    auto download = std::unique_ptr<Action>(new DownloadFD(part, fd, sz));
    auto flash = std::unique_ptr<Action>(new Flash(part));
    jobs.push_back(std::move(download));
    jobs.push_back(std::move(flash));
}

void Engine::QueueFlash(const std::string part, struct sparse_file* s, uint32_t sz, size_t current,
                        size_t total) {
    auto download = std::unique_ptr<Action>(new DownloadSparse(part, s, sz, current, total));
    auto flash = std::unique_ptr<Action>(new Flash(part));
    jobs.push_back(std::move(download));
    jobs.push_back(std::move(flash));
}

void Engine::QueueErase(const std::string part) {
    auto erase = std::unique_ptr<Action>(new Erase(part));
    jobs.push_back(std::move(erase));
}

void Engine::QueueRequire(const std::string prod, const std::string var,
                          const std::vector<std::string> options, bool invert,
                          const std::string* cur_prod) {
    auto req = std::unique_ptr<Action>(new Require(prod, var, options, invert, cur_prod));
    jobs.push_back(std::move(req));
}

void Engine::QueueDisplay(const std::string var, const std::string msg) {
    auto disp = std::unique_ptr<Action>(new GetVarDisplay(var, msg));
    jobs.push_back(std::move(disp));
}

void Engine::QueueSave(const std::string var, std::string* dest) {
    auto store = std::unique_ptr<Action>(new GetVarStore(var, dest));
    jobs.push_back(std::move(store));
}

void Engine::QueueReboot() {
    auto reboot = std::unique_ptr<Action>(new Reboot());
    jobs.push_back(std::move(reboot));
}

void Engine::QueueContinue() {
    auto cont = std::unique_ptr<Action>(new Continue());
    jobs.push_back(std::move(cont));
}

void Engine::QueueBoot(std::string msg) {
    auto boot = std::unique_ptr<Action>(new Boot(msg));
    jobs.push_back(std::move(boot));
}

void Engine::QueueRebootBootloader(std::string msg) {
    auto boot = std::unique_ptr<Action>(new RebootBootloader(msg));
    jobs.push_back(std::move(boot));
}

void Engine::QueueDownload(const std::string part, std::vector<char> data) {
    auto download = std::unique_ptr<Action>(new Download(part, data));
    jobs.push_back(std::move(download));
}

void Engine::QueueDownload(const std::string part, int fd, uint32_t sz) {
    auto download = std::unique_ptr<Action>(new DownloadFD(part, fd, sz));
    jobs.push_back(std::move(download));
}

void Engine::QueueUpload(const std::string outfile) {
    auto upload = std::unique_ptr<Action>(new Upload(outfile));
    jobs.push_back(std::move(upload));
}

void Engine::QueueNotice(const std::string msg) {
    auto notice = std::unique_ptr<Action>(new Notice(msg));
    jobs.push_back(std::move(notice));
}

void Engine::QueueSetActive(const std::string slot) {
    auto active = std::unique_ptr<Action>(new struct SetActive(slot));
    jobs.push_back(std::move(active));
}

void Engine::QueueRaw(const std::string cmd, const std::string msg) {
    auto raw = std::unique_ptr<Raw>(new Raw(cmd, msg));
    jobs.push_back(std::move(raw));
}

bool Engine::ExecuteQueue() {
    while (!jobs.empty()) {
        std::unique_ptr<Action> next = std::move(jobs.front());
        jobs.pop_front();
        double start = now();
        next->Before();
        if (next->Execute(fb)) {
            // there was a fastboot driver error
            std::string err = fb.Error();
            next->Failure(err);
            return false;
        }
        if (!next->After(now() - start)) {  // The after action failed
            return false;
        }
    }
    return true;
}
