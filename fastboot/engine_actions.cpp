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

#include "engine_actions.h"
#include "transport.h"

/******************************* ACTIONS *************************************/
bool Action::After(double rt) {
    std::string tmp = android::base::StringPrintf("OKAY [%7.3fs]\n", rt);
    Print(tmp);
    return true;
}

void Action::Failure(std::string& err) {
    std::string tmp = android::base::StringPrintf("FAILED (%s)\n", err.c_str());
    Print(tmp);
}

void Action::Print(const std::string& s) {
    fprintf(stderr, "%s", s.c_str());
}

// Print with the trailing whitespace fixed offset
void Action::PrintFirst(const std::string& s) {
    fprintf(stderr, "%-50s ", s.c_str());
}

// Set Active
void SetActive::Before() {
    std::string tmp("Setting current slot to '" + slot + "'");
    PrintFirst(tmp);
}

fastboot::RetCode SetActive::Execute(fastboot::FastBootDriver& fb) {
    return fb.SetActive(slot);
}

// Erase
void Erase::Before() {
    std::string tmp("Erasing '" + part + "'");
    PrintFirst(tmp);
}

fastboot::RetCode Erase::Execute(fastboot::FastBootDriver& fb) {
    return fb.Erase(part);
}

// Flash
void Flash::Before() {
    std::string tmp("Writing '" + part + "'");
    PrintFirst(tmp);
}

fastboot::RetCode Flash::Execute(fastboot::FastBootDriver& fb) {
    return fb.Flash(part);
}

// Download buffer
void Download::Before() {
    std::string tmp("Downloading '" + name + "'");
    PrintFirst(tmp);
}

fastboot::RetCode Download::Execute(fastboot::FastBootDriver& fb) {
    return fb.Download(buf);
}

// Download FD
void DownloadFD::Before() {
    std::string tmp(android::base::StringPrintf("Sending '%s' (%u KB)", part.c_str(), size / 1024));
    PrintFirst(tmp);
}

fastboot::RetCode DownloadFD::Execute(fastboot::FastBootDriver& fb) {
    return fb.Download(fd, size);
}

// Download Sparse
void DownloadSparse::Before() {
    std::string tmp = android::base::StringPrintf("Sending sparse '%s' %zu/%zu (%u KB)",
                                                  part.c_str(), current, total, size / 1024);
    PrintFirst(tmp);
}

fastboot::RetCode DownloadSparse::Execute(fastboot::FastBootDriver& fb) {
    return fb.Download(sparse);
}

// Require
void Require::Before() {
    std::string tmp("Checking " + val);
    PrintFirst(tmp);
}

fastboot::RetCode Require::Execute(fastboot::FastBootDriver& fb) {
    fastboot::RetCode ret = fb.Require(val, options, &reqmet, invert);
    if (ret) {
        return ret;
    }
    return fb.GetVar(val, &gvar);
}

bool Require::After(double rt) {
    std::string tmp;
    // Magic short-circuit semantics
    if (!product.empty() && cur_prod != nullptr && product != *cur_prod) {
        tmp = android::base::StringPrintf("IGNORE, product is %s required only for %s [%7.3fs]\n",
                                          cur_prod->c_str(), product.c_str(), rt);
        Print(tmp);
        return true;
    }

    if (reqmet) {  // Success
        tmp = android::base::StringPrintf("OKAY [%7.3fs]\n", rt);
        Print(tmp);
        return true;
    } else {
        std::string tmp("FAILED\n\n");
        Print(tmp);
        tmp = android::base::StringPrintf("Device %s is '%s'.\n", val.c_str(), gvar.c_str());
        Print(tmp);
        if (options.size()) {
            tmp = android::base::StringPrintf("Update %s '%s'", invert ? "rejects" : "requires",
                                              options[0].c_str());
            Print(tmp);
            for (auto s = options.begin() + 1; s < options.end(); s++) {
                tmp = android::base::StringPrintf(" or '%s'", s->c_str());
                Print(tmp);
            }
        }
        tmp = ".\n\n";
        Print(tmp);
        return false;
    }
}

// Getvar display
fastboot::RetCode GetVarDisplay::Execute(fastboot::FastBootDriver& fb) {
    return fb.GetVar(var, &resp);
}

bool GetVarDisplay::After(double) {
    std::string tmp(android::base::StringPrintf("%s: %s\n", msg.c_str(), resp.c_str()));
    Print(tmp);
    return true;
}

// GetVarStore
fastboot::RetCode GetVarStore::Execute(fastboot::FastBootDriver& fb) {
    return fb.GetVar(var, dest);
}

bool GetVarStore::After(double) {
    return true;
}

// Reboot
fastboot::RetCode Reboot::Execute(fastboot::FastBootDriver& fb) {
    return fb.Reboot();
}

void Reboot::Before() {
    PrintFirst("Rebooting");
}

bool Reboot::After(double) {
    return true;
}

// Continue
fastboot::RetCode Continue::Execute(fastboot::FastBootDriver& fb) {
    return fb.Continue();
}

void Continue::Before() {
    PrintFirst("resuming boot");
}

// Boot
fastboot::RetCode Boot::Execute(fastboot::FastBootDriver& fb) {
    return fb.Boot();
}

void Boot::Before() {
    PrintFirst(msg);
}

// Reboot Bootlaoder
fastboot::RetCode RebootBootloader::Execute(fastboot::FastBootDriver& fb) {
    return fb.RebootBootloader();
}

void RebootBootloader::Before() {
    PrintFirst(msg);
}

// Notice
fastboot::RetCode Notice::Execute(fastboot::FastBootDriver&) {
    return fastboot::SUCCESS;
}

bool Notice::After(double) {
    Print(msg + '\n');
    return true;
}

// Upload
void Upload::Before() {
    PrintFirst("Uploading '" + outfile + "'");
}

fastboot::RetCode Upload::Execute(fastboot::FastBootDriver& fb) {
    return fb.Upload(outfile);
}

// Raw command
void Raw::Before() {
    PrintFirst(msg);
}

fastboot::RetCode Raw::Execute(fastboot::FastBootDriver& fb) {
    return fb.RawCommand(cmd);
}

fastboot::RetCode WaitForDisconnect::Execute(fastboot::FastBootDriver& fb) {
    return fb.WaitForDisconnect();
}
