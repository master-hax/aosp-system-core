// Copyright (C) 2019 The Android Open Source Project
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include <fs_mgr/file_wait.h>

#include <limits.h>
#include <poll.h>
#include <sys/inotify.h>
#include <unistd.h>

#include <functional>

#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/unique_fd.h>

namespace android {
namespace fs_mgr {

using android::base::unique_fd;

class OneShotInotify {
  public:
    OneShotInotify(const std::string& path, uint32_t mask,
                   const std::chrono::milliseconds relative_timeout);

    bool Wait();

  private:
    bool CheckCompleted();
    int64_t RemainingMs() const;
    bool ConsumeEvents();

    unique_fd inotify_fd_;
    std::string path_;
    uint32_t mask_;
    std::chrono::time_point<std::chrono::steady_clock> start_time_;
    std::chrono::milliseconds relative_timeout_;
    bool finished_;
};

OneShotInotify::OneShotInotify(const std::string& path, uint32_t mask,
                               const std::chrono::milliseconds relative_timeout)
    : path_(path),
      mask_(mask),
      start_time_(std::chrono::steady_clock::now()),
      relative_timeout_(relative_timeout),
      finished_(false) {
    // If the condition is already met, don't bother creating an inotify.
    if (CheckCompleted()) return;

    unique_fd inotify_fd(inotify_init1(IN_CLOEXEC | IN_NONBLOCK));
    if (inotify_fd < 0) {
        PLOG(ERROR) << "inotify_init1 failed";
        return;
    }

    std::string watch_path;
    if (mask == IN_CREATE) {
        watch_path = android::base::Dirname(path);
    } else {
        watch_path = path;
    }
    if (inotify_add_watch(inotify_fd, watch_path.c_str(), mask) < 0) {
        PLOG(ERROR) << "inotify_add_watch failed";
        return;
    }

    // It's possible the condition was met before the add_watch. Check for
    // this and abort early if so.
    if (CheckCompleted()) return;

    inotify_fd_ = std::move(inotify_fd);
}

bool OneShotInotify::Wait() {
    // If the operation completed super early, we'll never have created an
    // inotify instance.
    if (finished_) return true;
    if (inotify_fd_ < 0) return false;

    do {
        auto remaining_ms = RemainingMs();
        if (remaining_ms <= 0) return false;

        struct pollfd event = {
                .fd = inotify_fd_,
                .events = POLLIN,
                .revents = 0,
        };
        int rv = poll(&event, 1, static_cast<int>(remaining_ms));
        if (rv <= 0) {
            if (rv == 0 || errno == EINTR) {
                continue;
            }
            PLOG(ERROR) << "poll for inotify failed";
            return false;
        }
        if (event.revents & POLLERR) {
            LOG(ERROR) << "error reading inotify for " << path_;
            return false;
        }

        // Note that we don't bother checking what kind of event it is, since
        // it's cheap enough to just see if the initial condition is satisified.
        // If it's not, we consume all the events available and continue.
        if (CheckCompleted()) return true;
        if (!ConsumeEvents()) return false;
    } while (true);
}

bool OneShotInotify::CheckCompleted() {
    if (mask_ == IN_CREATE) {
        finished_ = !access(path_.c_str(), F_OK) || errno != ENOENT;
    } else if (mask_ == IN_DELETE_SELF) {
        finished_ = access(path_.c_str(), F_OK) && errno == ENOENT;
    } else {
        LOG(ERROR) << "Unexpected mask: " << mask_;
    }
    return finished_;
}

bool OneShotInotify::ConsumeEvents() {
    // According to the manpage, this is enough to read at least one event.
    static constexpr size_t kBufferSize = sizeof(struct inotify_event) + NAME_MAX + 1;
    char buffer[kBufferSize];

    do {
        ssize_t rv = TEMP_FAILURE_RETRY(read(inotify_fd_, buffer, sizeof(buffer)));
        if (rv <= 0) {
            if (rv == 0 || errno == EAGAIN) {
                return true;
            }
            PLOG(ERROR) << "read inotify failed";
            return false;
        }
    } while (true);
}

int64_t OneShotInotify::RemainingMs() const {
    auto remaining = (std::chrono::steady_clock::now() - start_time_);
    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(remaining);
    return (relative_timeout_ - elapsed).count();
}

// Wait at most |relative_timeout| milliseconds for |path| to exist. dirname(path)
// must already exist. For example, to wait on /dev/block/dm-6, /dev/block must
// be a valid directory.
bool WaitForFile(const std::string& path, const std::chrono::milliseconds relative_timeout) {
    OneShotInotify inotify(path, IN_CREATE, relative_timeout);
    return inotify.Wait();
}

// Wait at most |relative_timeout| milliseconds for |path| to stop existing.
bool WaitForFileDeleted(const std::string& path, const std::chrono::milliseconds relative_timeout) {
    OneShotInotify inotify(path, IN_DELETE_SELF, relative_timeout);
    return inotify.Wait();
}

}  // namespace fs_mgr
}  // namespace android
