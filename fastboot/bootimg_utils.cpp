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

#include "bootimg_utils.h"

#include "util.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <android-base/file.h>

static void bootimg_set_cmdline_v3(boot_img_hdr_v3* h, const std::string& cmdline) {
    if (cmdline.size() >= sizeof(h->cmdline)) die("command line too large: %zu", cmdline.size());
    strcpy(reinterpret_cast<char*>(h->cmdline), cmdline.c_str());
}

void bootimg_set_cmdline(boot_img_hdr_v2* h, const std::string& cmdline) {
    if (h->header_version == 3) {
        return bootimg_set_cmdline_v3(reinterpret_cast<boot_img_hdr_v3*>(h), cmdline);
    }
    if (cmdline.size() >= sizeof(h->cmdline)) die("command line too large: %zu", cmdline.size());
    strcpy(reinterpret_cast<char*>(h->cmdline), cmdline.c_str());
}

static boot_img_hdr_v3* mkbootimg_v3(const std::vector<char>& kernel,
                                     const std::vector<char>& ramdisk, const boot_img_hdr_v2& src,
                                     std::vector<char>* out) {
#define V3_PAGE_SIZE 4096
    const size_t page_mask = V3_PAGE_SIZE - 1;
    int64_t kernel_actual = (kernel.size() + page_mask) & (~page_mask);
    int64_t ramdisk_actual = (ramdisk.size() + page_mask) & (~page_mask);

    int64_t bootimg_size = V3_PAGE_SIZE + kernel_actual + ramdisk_actual;
    out->resize(bootimg_size);

    boot_img_hdr_v3* hdr = reinterpret_cast<boot_img_hdr_v3*>(out->data());

    memcpy(hdr->magic, BOOT_MAGIC, BOOT_MAGIC_SIZE);
    hdr->kernel_size = kernel.size();
    hdr->ramdisk_size = ramdisk.size();
    hdr->os_version = src.os_version;
    hdr->header_size = sizeof(boot_img_hdr_v3);
    hdr->header_version = 3;

    memcpy(hdr->magic + V3_PAGE_SIZE, kernel.data(), kernel.size());
    memcpy(hdr->magic + V3_PAGE_SIZE + kernel_actual, ramdisk.data(), ramdisk.size());

    return hdr;
}

boot_img_hdr_v2* mkbootimg(const std::vector<char>& kernel, const std::vector<char>& ramdisk,
                           const std::vector<char>& second, const std::vector<char>& dtb,
                           size_t base, const boot_img_hdr_v2& src, std::vector<char>* out) {
    if (src.header_version == 3) {
        if (!second.empty() || !dtb.empty()) {
            die("Second stage bootloader and dtb not supported in v3 boot image\n");
        }
        return reinterpret_cast<boot_img_hdr_v2*>(mkbootimg_v3(kernel, ramdisk, src, out));
    }
    const size_t page_mask = src.page_size - 1;

    int64_t header_actual = (sizeof(boot_img_hdr_v1) + page_mask) & (~page_mask);
    int64_t kernel_actual = (kernel.size() + page_mask) & (~page_mask);
    int64_t ramdisk_actual = (ramdisk.size() + page_mask) & (~page_mask);
    int64_t second_actual = (second.size() + page_mask) & (~page_mask);
    int64_t dtb_actual = (dtb.size() + page_mask) & (~page_mask);

    int64_t bootimg_size =
            header_actual + kernel_actual + ramdisk_actual + second_actual + dtb_actual;
    out->resize(bootimg_size);

    boot_img_hdr_v2* hdr = reinterpret_cast<boot_img_hdr_v2*>(out->data());

    *hdr = src;
    memcpy(hdr->magic, BOOT_MAGIC, BOOT_MAGIC_SIZE);

    hdr->kernel_size = kernel.size();
    hdr->ramdisk_size = ramdisk.size();
    hdr->second_size = second.size();

    hdr->kernel_addr += base;
    hdr->ramdisk_addr += base;
    hdr->second_addr += base;
    hdr->tags_addr += base;

    if (hdr->header_version == 1) {
        hdr->header_size = sizeof(boot_img_hdr_v1);
    } else if (hdr->header_version == 2) {
        hdr->header_size = sizeof(boot_img_hdr_v2);
        hdr->dtb_size = dtb.size();
        hdr->dtb_addr += base;
    }

    memcpy(hdr->magic + hdr->page_size, kernel.data(), kernel.size());
    memcpy(hdr->magic + hdr->page_size + kernel_actual, ramdisk.data(), ramdisk.size());
    memcpy(hdr->magic + hdr->page_size + kernel_actual + ramdisk_actual, second.data(),
           second.size());
    memcpy(hdr->magic + hdr->page_size + kernel_actual + ramdisk_actual + second_actual, dtb.data(),
           dtb.size());
    return hdr;
}

namespace {
// Helpers for replace_vendor_ramdisk.

// Updates a given buffer by creating a new one.
class DataUpdater {
  public:
    DataUpdater(const std::string& old_data) : old_data_(&old_data) {
        old_data_ptr_ = old_data_->data();
        new_data_.resize(old_data_->size(), '\0');
        new_data_ptr_ = new_data_.data();
    }
    // Copy |num_bytes| from src to dst.
    void Copy(uint32_t num_bytes) {
        if (num_bytes == 0) return;
        CheckAdvance(old_data_ptr_, old_end(), num_bytes, "copy");
        CheckAdvance(new_data_ptr_, new_end(), num_bytes, "copy");
        memcpy(new_data_ptr_, old_data_ptr_, num_bytes);
        old_data_ptr_ += num_bytes;
        new_data_ptr_ += num_bytes;
    }
    // Replace |old_num_bytes| from src with new data.
    void Replace(uint32_t old_num_bytes, const std::string& new_data) {
        Replace(old_num_bytes, new_data.data(), new_data.size());
    }
    void Replace(uint32_t old_num_bytes, const void* new_data, uint32_t new_data_size) {
        CheckAdvance(old_data_ptr_, old_end(), old_num_bytes, "replace");
        old_data_ptr_ += old_num_bytes;

        if (new_data_size == 0) return;
        CheckAdvance(new_data_ptr_, new_end(), new_data_size, "replace");
        memcpy(new_data_ptr_, new_data, new_data_size);
        new_data_ptr_ += new_data_size;
    }
    // Skip |old_skip| from src and |new_skip| from dst, respectively.
    void Skip(uint32_t old_skip, uint32_t new_skip) {
        CheckAdvance(old_data_ptr_, old_end(), old_skip, "skip");
        old_data_ptr_ += old_skip;
        CheckAdvance(new_data_ptr_, new_end(), new_skip, "skip");
        new_data_ptr_ += new_skip;
    }
    const char* old_begin() const { return old_data_->data(); }
    const char* old_cur() { return old_data_ptr_; }
    const char* old_end() const { return old_data_->data() + old_data_->size(); }
    char* new_begin() { return new_data_.data(); }
    char* new_cur() { return new_data_ptr_; }
    char* new_end() { return new_data_.data() + new_data_.size(); }

    std::string Finish() {
        new_data_ptr_ = nullptr;
        return std::move(new_data_);
    }

  private:
    uint64_t size() const { return old_data_->size(); }
    // Check if it is okay to advance |num_bytes| from |current|.
    void CheckAdvance(const char* current, const char* end, uint32_t num_bytes, const char* op) {
        auto new_end = current + num_bytes;
        if (new_end < current /* add overflow */)
            die("%s: Addition verflow when advancing 0x%" PRIx32 " bytes", op, num_bytes);
        if (new_end > end) die("%s: Overflow when advancing 0x%" PRIx32 " bytes", op, num_bytes);
    }
    const std::string* old_data_;
    std::string new_data_;
    const char* old_data_ptr_;
    char* new_data_ptr_;
};

void check_vendor_boot_hdr(const vendor_boot_img_hdr_v3* hdr, uint32_t version) {
    if (memcmp(hdr->magic, VENDOR_BOOT_MAGIC, VENDOR_BOOT_MAGIC_SIZE) != 0) {
        die("Vendor boot image magic mismatch");
    }
    if (hdr->header_version < version) {
        die("Require vendor boot header %" PRIx32 " but is %" PRId32, version, hdr->header_version);
    }
}

uint32_t get_vendor_boot_header_size(const vendor_boot_img_hdr_v3* hdr) {
    if (hdr->header_version == 3) {
        return sizeof(vendor_boot_img_hdr_v3);
    } else if (hdr->header_version == 4) {
        return sizeof(vendor_boot_img_hdr_v4);
    }
    die("Unrecognized vendor boot header version %" PRId32, hdr->header_version);
}

// Wrapper of ReadFdToString. Seek to the beginning and read the whole file to string.
std::string load_file(android::base::borrowed_fd fd, uint64_t expected_size, const char* what) {
    if (lseek(fd.get(), 0, SEEK_SET) != 0) {
        int saved_errno = errno;
        die("Can't seek to the beginning of %s image: %s", what, strerror(saved_errno));
    }
    std::string content;
    if (!android::base::ReadFdToString(fd, &content)) {
        int saved_errno = errno;
        die("Cannot read %s to string: %s", what, strerror(saved_errno));
    }
    if (content.size() != expected_size) {
        die("Size of %s does not match, expected 0x%" PRIx64 ", read 0x%zx", what, expected_size,
            content.size());
    }
    return content;
}

// Wrapper of WriteStringToFd. Seek to the beginning and write the whole file to string.
void store_file(android::base::borrowed_fd fd, const std::string& data, const char* what) {
    if (lseek(fd.get(), 0, SEEK_SET) != 0) {
        int saved_errno = errno;
        die("Cannot seek to beginning of %s before writing: %s", what, strerror(saved_errno));
    }
    if (!android::base::WriteStringToFd(data, fd)) {
        int saved_errno = errno;
        die("Cannot write new content to %s: %s", what, strerror(saved_errno));
    }
    if (TEMP_FAILURE_RETRY(ftruncate64(fd.get(), data.size())) == -1) {
        int saved_errno = errno;
        die("Truncating new vendor boot image to 0x%zx fails: %s", data.size(),
            strerror(saved_errno));
    }
}

std::string replace_default_vendor_ramdisk(const std::string& vendor_boot,
                                           const std::string& new_ramdisk) {
    auto hdr = reinterpret_cast<const vendor_boot_img_hdr_v3*>(vendor_boot.data());
    // Refer to bootimg.h for details. Numbers are in bytes.
    const uint32_t o = (get_vendor_boot_header_size(hdr) + hdr->page_size - 1) / hdr->page_size *
                       hdr->page_size;
    const uint32_t p =
            (hdr->vendor_ramdisk_size + hdr->page_size - 1) / hdr->page_size * hdr->page_size;
    const uint32_t q = (hdr->dtb_size + hdr->page_size - 1) / hdr->page_size * hdr->page_size;

    DataUpdater updater(vendor_boot);

    // Copy header (O bytes), then update fields in header.
    updater.Copy(o);
    auto new_hdr = reinterpret_cast<vendor_boot_img_hdr_v3*>(updater.new_begin());
    new_hdr->vendor_ramdisk_size = new_ramdisk.size();
    // Clear vendor ramdisk table.
    if (new_hdr->header_version >= 4) {
        auto new_hdr_v4 = static_cast<vendor_boot_img_hdr_v4*>(new_hdr);
        new_hdr_v4->vendor_ramdisk_table_size = 0;
        new_hdr_v4->vendor_ramdisk_table_entry_size = 0;
        new_hdr_v4->vendor_ramdisk_table_entry_size = 0;
    }

    // Copy the new ramdisk.
    updater.Replace(hdr->vendor_ramdisk_size, new_ramdisk);
    const uint32_t new_p = (new_hdr->vendor_ramdisk_size + new_hdr->page_size - 1) /
                           new_hdr->page_size * new_hdr->page_size;
    updater.Skip(p - hdr->vendor_ramdisk_size, new_p - new_hdr->vendor_ramdisk_size);
    if (updater.old_begin() + o + p != updater.old_cur()) die("Offset mismatch");
    if (updater.new_begin() + o + new_p != updater.new_cur()) die("Offset mismatch");

    // Copy DTB (Q bytes).
    updater.Copy(q);
    // Leave vendor ramdisk table empty.

    return updater.Finish();
}

static const vendor_ramdisk_table_entry_v4* find_unique_ramdisk(
        const std::string& ramdisk_name, const vendor_ramdisk_table_entry_v4* table,
        uint32_t size) {
    const vendor_ramdisk_table_entry_v4* ret = nullptr;
    uint32_t idx = 0;
    const vendor_ramdisk_table_entry_v4* entry = table;
    for (; idx < size; idx++, entry++) {
        auto entry_name_c_str = reinterpret_cast<const char*>(entry->ramdisk_name);
        auto entry_name_len = strnlen(entry_name_c_str, VENDOR_RAMDISK_NAME_SIZE);
        std::string_view entry_name(entry_name_c_str, entry_name_len);
        if (entry_name == ramdisk_name) {
            if (ret != nullptr) {
                die("Multiple vendor ramdisk '%s' found, name should be unique",
                    ramdisk_name.c_str());
            }
            ret = entry;
        }
    }
    if (ret == nullptr) {
        die("Vendor ramdisk '%s' not found", ramdisk_name.c_str());
    }
    return ret;
}

std::string replace_vendor_ramdisk_fragment(const std::string& ramdisk_name,
                                            const std::string& vendor_boot,
                                            const std::string& new_ramdisk) {
    auto hdr = reinterpret_cast<const vendor_boot_img_hdr_v4*>(vendor_boot.data());
    // Refer to bootimg.h for details. Numbers are in bytes.
    const uint32_t o = (get_vendor_boot_header_size(hdr) + hdr->page_size - 1) / hdr->page_size *
                       hdr->page_size;
    const uint32_t p =
            (hdr->vendor_ramdisk_size + hdr->page_size - 1) / hdr->page_size * hdr->page_size;
    const uint32_t q = (hdr->dtb_size + hdr->page_size - 1) / hdr->page_size * hdr->page_size;
    const uint32_t r =
            (hdr->vendor_ramdisk_table_size + hdr->page_size - 1) / hdr->page_size * hdr->page_size;

    if (hdr->vendor_ramdisk_table_entry_num == std::numeric_limits<uint32_t>::max()) {
        die("Too many vendor ramdisk entries in table, overflow");
    }

    // Find entry with name |ramdisk_name|.
    auto old_table_start =
            reinterpret_cast<const vendor_ramdisk_table_entry_v4*>(vendor_boot.data() + o + p + q);
    const vendor_ramdisk_table_entry_v4* replace_entry =
            find_unique_ramdisk(ramdisk_name, old_table_start, hdr->vendor_ramdisk_table_entry_num);
    uint32_t replace_idx = replace_entry - old_table_start;

    // Now reconstruct.
    DataUpdater updater(vendor_boot);

    // Copy header (O bytes), then update fields in header.
    updater.Copy(o);
    auto new_hdr = reinterpret_cast<vendor_boot_img_hdr_v4*>(updater.new_begin());

    // Copy ramdisk fragments, replace for the matching index.
    {
        auto old_ramdisk_entry = reinterpret_cast<const vendor_ramdisk_table_entry_v4*>(
                vendor_boot.data() + o + p + q);
        uint32_t new_total_ramdisk_size = 0;
        for (uint32_t new_ramdisk_idx = 0; new_ramdisk_idx < hdr->vendor_ramdisk_table_entry_num;
             new_ramdisk_idx++, old_ramdisk_entry++) {
            if (new_ramdisk_idx == replace_idx) {
                updater.Replace(replace_entry->ramdisk_size, new_ramdisk);
                new_total_ramdisk_size += new_ramdisk.size();
            } else {
                updater.Copy(old_ramdisk_entry->ramdisk_size);
                new_total_ramdisk_size += old_ramdisk_entry->ramdisk_size;
            }
        }
        new_hdr->vendor_ramdisk_size = new_total_ramdisk_size;
    }

    // Pad ramdisk to page boundary.
    const uint32_t new_p = (new_hdr->vendor_ramdisk_size + new_hdr->page_size - 1) /
                           new_hdr->page_size * new_hdr->page_size;
    updater.Skip(p - hdr->vendor_ramdisk_size, new_p - new_hdr->vendor_ramdisk_size);
    if (updater.old_begin() + o + p != updater.old_cur()) die("Offset mismatch");
    if (updater.new_begin() + o + new_p != updater.new_cur()) die("Offset mismatch");

    // Copy DTB (Q bytes).
    updater.Copy(q);

    // Copy table, but with corresponding entries modified, including:
    // - ramdisk_size of the entry replaced
    // - ramdisk_offset of subsequent entries.
    for (uint32_t new_total_ramdisk_size = 0, new_entry_idx = 0;
         new_entry_idx < hdr->vendor_ramdisk_table_entry_num; new_entry_idx++) {
        auto new_entry = reinterpret_cast<vendor_ramdisk_table_entry_v4*>(updater.new_cur());
        updater.Copy(hdr->vendor_ramdisk_table_entry_size);
        new_entry->ramdisk_offset = new_total_ramdisk_size;

        if (new_entry_idx == replace_idx) {
            new_entry->ramdisk_size = new_ramdisk.size();
        }
        new_total_ramdisk_size += new_entry->ramdisk_size;
    }

    // Copy padding of R pages; this is okay because table size is not changed.
    updater.Copy(r - hdr->vendor_ramdisk_table_entry_num * hdr->vendor_ramdisk_table_entry_size);
    if (updater.old_begin() + o + p + q + r != updater.old_cur()) die("Offset mismatch");
    if (updater.new_begin() + o + new_p + q + r != updater.new_cur()) die("Offset mismatch");

    return updater.Finish();
}

}  // namespace

void replace_vendor_ramdisk(android::base::borrowed_fd vendor_boot_fd, uint64_t vendor_boot_size,
                            const std::string& ramdisk_name,
                            android::base::borrowed_fd new_ramdisk_fd, uint64_t new_ramdisk_size) {
    if (vendor_boot_size < sizeof(vendor_boot_img_hdr_v4)) {
        die("Size of vendor boot is 0x%" PRIx64 ", less than size of V4 header: 0x%zx",
            vendor_boot_size, sizeof(vendor_boot_img_hdr_v4));
    }
    if (new_ramdisk_size > std::numeric_limits<uint32_t>::max()) {
        die("New vendor ramdisk is too big");
    }

    std::string vendor_boot = load_file(vendor_boot_fd, vendor_boot_size, "vendor boot");
    std::string new_ramdisk = load_file(new_ramdisk_fd, new_ramdisk_size, "new vendor ramdisk");

    std::string new_vendor_boot;
    if (ramdisk_name == "default") {
        new_vendor_boot = replace_default_vendor_ramdisk(vendor_boot, new_ramdisk);
    } else {
        check_vendor_boot_hdr(reinterpret_cast<vendor_boot_img_hdr_v4*>(vendor_boot.data()), 4);
        new_vendor_boot = replace_vendor_ramdisk_fragment(ramdisk_name, vendor_boot, new_ramdisk);
    }

    store_file(vendor_boot_fd, new_vendor_boot, "new vendor boot image");
}
