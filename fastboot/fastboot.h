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
#include "filesystem.h"
#include "task.h"

#include <bootimg.h>
#include <string>
#include "fastboot_driver.h"
#include "super_flash_helper.h"
#include "util.h"

#include "result.h"
#include "socket.h"
#include "util.h"

class FastBootTool {
  public:
    int Main(int argc, char* argv[]);

    void ParseOsPatchLevel(boot_img_hdr_v1*, const char*);
    void ParseOsVersion(boot_img_hdr_v1*, const char*);
    unsigned ParseFsOption(const char*);
};

enum fb_buffer_type {
    FB_BUFFER_FD,
    FB_BUFFER_SPARSE,
};

struct fastboot_buffer {
    enum fb_buffer_type type;
    std::vector<SparsePtr> files;
    int64_t sz;
    unique_fd fd;
    int64_t image_size;
};

class FlashAllTool {
  public:
    FlashAllTool(FlashingPlan* fp);

    void Flash();

  private:
    void CheckRequirements();
    void DetermineSlot();
    void CollectImages();
    void FlashImages(const std::vector<std::pair<const Image*, std::string>>& images);
    void FlashImage(const Image& image, const std::string& slot, fastboot_buffer* buf);
    void HardcodedFlash();

    std::vector<ImageEntry> boot_images_;
    std::vector<ImageEntry> os_images_;
    FlashingPlan* fp_;
};

bool should_flash_in_userspace(const std::string& partition_name);
bool is_userspace_fastboot();
void do_flash(const char* pname, const char* fname, const bool apply_vbmeta);
void do_for_partitions(const std::string& part, const std::string& slot,
                       const std::function<void(const std::string&)>& func, bool force_slot);
std::string find_item(const std::string& item);
void reboot_to_userspace_fastboot();
void syntax_error(const char* fmt, ...);
std::string get_current_slot();

// Code for Parsing fastboot-info.txt
std::unique_ptr<FlashTask> ParseFlashCommand(FlashingPlan* fp, std::vector<std::string> parts);
std::unique_ptr<RebootTask> ParseRebootCommand(FlashingPlan* fp,
                                               const std::vector<std::string>& parts);
std::unique_ptr<WipeTask> ParseWipeCommand(FlashingPlan* fp, const std::vector<std::string>& parts);
std::unique_ptr<Task> ParseFastbootInfoLine(FlashingPlan* fp,
                                            const std::vector<std::string>& command);
void AddResizeTasks(FlashingPlan* fp, std::vector<std::unique_ptr<Task>>& tasks);
std::vector<std::unique_ptr<Task>> ParseFastbootInfo(FlashingPlan* fp, std::ifstream& fs);

struct NetworkSerial {
    Socket::Protocol protocol;
    std::string address;
    int port;
};

Result<NetworkSerial, FastbootError> ParseNetworkSerial(const std::string& serial);
bool supports_AB();
std::string GetPartitionName(const ImageEntry& entry);
void flash_partition_files(const std::string& partition, const std::vector<SparsePtr>& files);
int64_t get_sparse_limit(int64_t size);
std::vector<SparsePtr> resparse_file(sparse_file* s, int64_t max_size);

bool is_retrofit_device();
bool is_logical(const std::string& partition);
void fb_perform_format(const std::string& partition, int skip_if_not_supported,
                       const std::string& type_override, const std::string& size_override,
                       const unsigned fs_options);
