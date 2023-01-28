//
// Copyright (C) 2023 The Android Open Source Project
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions
// are met:
//  * Redistributions of source code must retain the above copyright
//    notice, this list of conditions and the following disclaimer.
//  * Redistributions in binary form must reproduce the above copyright
//    notice, this list of conditions and the following disclaimer in
//    the documentation and/or other materials provided with the
//    distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
// FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
// COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
// INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
// BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
// OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
// AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
// OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
// OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
// SUCH DAMAGE.
//

#pragma once

#include <memory>
#include <string>
#include <unordered_map>
#include <unordered_set>

#include <android-base/unique_fd.h>
#include <liblp/liblp.h>
#include <liblp/super_layout_builder.h>

#include "util.h"

class SuperFlashHelper final {
  public:
    explicit SuperFlashHelper(const ImageSource& source);

    bool Open(android::base::borrowed_fd fd);
    bool IncludeInSuper(const std::string& partition);
    bool AddPartition(const std::string& partition, const std::string& image_name, bool optional);

    // Note: the SparsePtr if non-null should not outlive SuperFlashHelper, since
    // it depends on open fds and data pointers.
    SparsePtr GetSparseLayout();

    bool WillFlash(const std::string& partition) const {
        return will_flash_.find(partition) != will_flash_.end();
    }

  private:
    const ImageSource& source_;
    android::fs_mgr::SuperLayoutBuilder builder_;
    std::unique_ptr<android::fs_mgr::LpMetadata> base_metadata_;
    std::vector<android::fs_mgr::SuperImageExtent> extents_;

    // Cache open image fds. This keeps them alive while we flash the sparse
    // file.
    std::unordered_map<std::string, android::base::unique_fd> image_fds_;
    std::unordered_set<std::string> will_flash_;
};
