/*
 * Copyright (C) 2018 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <stdint.h>

#include <deque>
#include <mutex>
#include <string>
#include <thread>

#include <android-base/logging.h>
#include <android-base/stringprintf.h>
#include <android-base/thread_annotations.h>

#include "adb_unique_fd.h"
#include "sysdeps.h"
#include "sysdeps/memory.h"
#include "transport.h"
#include "types.h"

static void CreateWakeFds(unique_fd* read, unique_fd* write) {
    // TODO: eventfd on linux?
    int wake_fds[2];
    int rc = adb_socketpair(wake_fds);
    CHECK_EQ(0, rc);
    *read = unique_fd(wake_fds[0]);
    *write = unique_fd(wake_fds[1]);
}

struct NonblockingFdConnection : public Connection {
    NonblockingFdConnection(unique_fd fd) : fd_(std::move(fd)) {
        CreateWakeFds(&wake_fd_read_, &wake_fd_write_);
    }

    void HandleInput() {}

    void Run(std::string* error) {
        running_ = true;
        while (running_) {
            adb_pollfd pfds[2] = {
                {.fd = fd_.get(), .events = POLLIN},
                {.fd = wake_fd_read_.get(), .events = POLLIN},
            };

            {
                std::lock_guard<std::mutex> lock(this->write_mutex_);
                if (!writable_) {
                    pfds[0].events |= POLLOUT;
                }
            }

            int rc = adb_poll(pfds, 2, -1);
            if (rc == -1) {
                *error = android::base::StringPrintf("poll failed: %s", strerror(errno));
                return;
            } else if (rc == 0) {
                LOG(FATAL) << "poll timed out with an infinite timeout?";
            }

            if (pfds[0].revents) {
                if ((pfds[0].revents & POLLOUT)) {
                    std::lock_guard<std::mutex> lock(this->write_mutex_);
                    WriteResult result = DispatchWrites();
                    switch (result) {
                        case WriteResult::Error:
                            *error = "write failed";
                            return;

                        case WriteResult::Completed:
                            writable_ = true;
                            break;

                        case WriteResult::TryAgain:
                            break;
                    }
                }

                if (pfds[0].revents & POLLIN) {
                    auto block = BlockChain::AcquireBlock();
                    rc = adb_read(fd_.get(), &(*block)[0], block->size());
                    if (rc == -1) {
                        *error = std::string("read failed: ") + strerror(errno);
                        return;
                    } else if (rc == 0) {
                        *error = "read failed: EOF";
                        return;
                    }
                    block->resize(rc);
                    read_buffer_.append(std::move(block));

                    if (!read_header_ && read_buffer_.size() >= sizeof(amessage)) {
                        auto header_buf = read_buffer_.take_front(sizeof(amessage)).coalesce();
                        CHECK_EQ(sizeof(amessage), header_buf.size());
                        read_header_ = std::make_unique<amessage>();
                        memcpy(read_header_.get(), header_buf.data(), sizeof(amessage));
                    }

                    if (read_header_ && read_buffer_.size() >= read_header_->data_length) {
                        auto data_chain = read_buffer_.take_front(read_header_->data_length);

                        // TODO: Make apacket carry around a BlockChain instead of coalescing.
                        auto payload = data_chain.coalesce<std::string>();
                        auto packet = std::make_unique<apacket>();
                        packet->msg = *read_header_;
                        packet->payload = std::move(payload);
                        read_header_ = nullptr;
                        read_callback_(this, std::move(packet));
                    }
                }
            }

            if (pfds[1].revents) {
                uint64_t buf;
                rc = adb_read(wake_fd_read_.get(), &buf, sizeof(buf));
                CHECK_EQ(static_cast<int>(sizeof(buf)), rc);

                // Do nothing (we were woken up to add POLLOUT to our events).
            }
        }
    }

    void Start() override final {
        if (running_) {
            LOG(FATAL) << "Connection started multiple times?";
        }

        thread_ = std::thread([this]() {
            std::string error = "connection closed";
            Run(&error);
            this->error_callback_(this, error);
        });
    }

    void Stop() override final {
        running_ = false;
        WakeThread();
        thread_.join();
    }

    void WakeThread() {
        uint64_t buf = 0;
        if (TEMP_FAILURE_RETRY(adb_write(wake_fd_write_.get(), &buf, sizeof(buf))) != sizeof(buf)) {
            LOG(FATAL) << "failed to wake up thread";
        }
    }

    enum class WriteResult {
        Error,
        Completed,
        TryAgain,
    };

    WriteResult DispatchWrites() REQUIRES(write_mutex_) {
#if defined(_WIN32)
        // TODO: adb_writev, using WSASend
        abort();
#else
        CHECK(!write_buffer_.empty());
        if (!writable_) {
            return WriteResult::TryAgain;
        }

        std::vector<struct iovec> iovs = write_buffer_.iovecs();
        ssize_t rc = writev(fd_.get(), iovs.data(), iovs.size());
        if (rc == -1) {
            return WriteResult::Error;
        } else if (rc == 0) {
            errno = 0;
            return WriteResult::Error;
        }

        // TODO: Implement a more efficient drop_front?
        write_buffer_.take_front(rc);
        if (write_buffer_.empty()) {
            return WriteResult::Completed;
        }

        // There's data left in the range, which means our write returned early.
        return WriteResult::TryAgain;
#endif
    }

    bool Write(std::unique_ptr<apacket> packet) final {
        std::lock_guard<std::mutex> lock(write_mutex_);
        const char* header_begin = reinterpret_cast<const char*>(&packet->msg);
        const char* header_end = header_begin + sizeof(packet->msg);
        auto header_block = std::make_unique<BlockChain::block_type>(header_begin, header_end);
        write_buffer_.append(std::move(header_block));
        if (!packet->payload.empty()) {
            write_buffer_.append(std::move(packet->payload));
        }
        return DispatchWrites() != WriteResult::Error;
    }

    std::thread thread_;
    std::atomic<bool> running_;

    std::unique_ptr<amessage> read_header_;
    BlockChain read_buffer_;

    unique_fd fd_;
    unique_fd wake_fd_read_;
    unique_fd wake_fd_write_;

    std::mutex write_mutex_;
    bool writable_ GUARDED_BY(write_mutex_) = true;
    BlockChain write_buffer_ GUARDED_BY(write_mutex_);

    std::vector<Range> incoming_queue_;
};

std::unique_ptr<Connection> Connection::FromFd(unique_fd fd) {
    return std::make_unique<NonblockingFdConnection>(std::move(fd));
}
