/*
 * Copyright (C) 2012-2013 The Android Open Source Project
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

#include <ctype.h>
#include <inttypes.h>
#include <poll.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/types.h>

#include <chrono>

#include <android-base/stringprintf.h>
#include <cutils/sockets.h>
#include <private/android_filesystem_config.h>
#include <private/android_logger.h>

#include "LogBuffer.h"
#include "LogBufferElement.h"
#include "LogReader.h"
#include "LogUtils.h"
#include "LogWriter.h"

static bool CanReadSecurityLogs(SocketClient* client) {
    return client->getUid() == AID_SYSTEM || client->getGid() == AID_SYSTEM;
}

static std::string SocketClientToName(SocketClient* client) {
    return android::base::StringPrintf("pid %d, fd %d", client->getPid(), client->getSocket());
}

class SocketLogWriter : public LogWriter {
  public:
    SocketLogWriter(LogReader* reader, SocketClient* client, bool privileged,
                    bool can_read_security_logs)
        : LogWriter(client->getUid(), privileged, can_read_security_logs),
          reader_(reader),
          client_(client) {}

    bool Write(const void* entry, const char* msg) override {
        struct iovec iovec[2];
        auto logger_entry = reinterpret_cast<const struct logger_entry*>(entry);
        iovec[0].iov_base = const_cast<void*>(entry);
        iovec[0].iov_len = logger_entry->hdr_size;
        iovec[1].iov_base = const_cast<char*>(msg);
        iovec[1].iov_len = logger_entry->len;

        return client_->sendDatav(iovec, 1 + (logger_entry->len != 0)) == 0;
    }

    void Release() override {
        reader_->release(client_);
        client_->decRef();
    }

    void Shutdown() override { shutdown(client_->getSocket(), SHUT_RDWR); }

    std::string name() const override { return SocketClientToName(client_); }

  private:
    LogReader* reader_;
    SocketClient* client_;
};

LogReader::LogReader(LogBuffer* logbuf, LogReaderList* reader_list)
    : SocketListener(getLogSocket(), true), log_buffer_(logbuf), reader_list_(reader_list) {}

// Note returning false will release the SocketClient instance.
bool LogReader::onDataAvailable(SocketClient* cli) {
    static bool name_set;
    if (!name_set) {
        prctl(PR_SET_NAME, "logd.reader");
        name_set = true;
    }

    char buffer[255];

    int len = read(cli->getSocket(), buffer, sizeof(buffer) - 1);
    if (len <= 0) {
        DoSocketDelete(cli);
        return false;
    }
    buffer[len] = '\0';

    // Clients are only allowed to send one command, disconnect them if they send another.
    if (DoSocketDelete(cli)) {
        return false;
    }

    android::prdebug("Reader connected from pid=%d, requesting '%s'.", cli->getPid(), buffer);

    unsigned long tail = 0;
    static const char _tail[] = " tail=";
    char* cp = strstr(buffer, _tail);
    if (cp) {
        tail = atol(cp + sizeof(_tail) - 1);
    }

    log_time start(log_time::EPOCH);
    static const char _start[] = " start=";
    cp = strstr(buffer, _start);
    if (cp) {
        // Parse errors will result in current time
        start.strptime(cp + sizeof(_start) - 1, "%s.%q");
    }

    log_time monotonic_start(log_time::EPOCH);
    static const char _monotonic_start[] = " monotonic_start=";
    cp = strstr(buffer, _monotonic_start);
    if (cp) {
        if (start != log_time::EPOCH) {
            android::prdebug(
                    "Ignoring reader from pid=%d that specified both 'start=' and "
                    "'monotonic_start=' values.",
                    cli->getPid());
            return false;
        }
        // Format should be sec.nsec
        uint32_t monotonic_sec = 0;
        uint32_t monotonic_nsec = 0;
        if (sscanf(cp + sizeof(_monotonic_start) - 1, "%" PRIu32 ".%" PRIu32, &monotonic_sec,
                   &monotonic_nsec) != 2) {
            android::prdebug(
                    "Ignoring reader from pid=%d that specified and invalid 'monotonic_start=' "
                    "value.",
                    cli->getPid());
            return false;
        }
        monotonic_start.tv_sec = monotonic_sec;
        monotonic_start.tv_nsec = monotonic_nsec;
    }

    std::chrono::steady_clock::time_point deadline = {};
    static const char _timeout[] = " timeout=";
    cp = strstr(buffer, _timeout);
    if (cp) {
        long timeout_seconds = atol(cp + sizeof(_timeout) - 1);
        deadline = std::chrono::steady_clock::now() + std::chrono::seconds(timeout_seconds);
    }

    unsigned int logMask = -1;
    static const char _logIds[] = " lids=";
    cp = strstr(buffer, _logIds);
    if (cp) {
        logMask = 0;
        cp += sizeof(_logIds) - 1;
        while (*cp && *cp != '\0') {
            int val = 0;
            while (isdigit(*cp)) {
                val = val * 10 + *cp - '0';
                ++cp;
            }
            logMask |= 1 << val;
            if (*cp != ',') {
                break;
            }
            ++cp;
        }
    }

    pid_t pid = 0;
    static const char _pid[] = " pid=";
    cp = strstr(buffer, _pid);
    if (cp) {
        pid = atol(cp + sizeof(_pid) - 1);
    }

    bool nonBlock = false;
    if (!fastcmp<strncmp>(buffer, "dumpAndClose", 12)) {
        // Allow writer to get some cycles, and wait for pending notifications
        sched_yield();
        reader_list_->reader_threads_lock().lock();
        reader_list_->reader_threads_lock().unlock();
        sched_yield();
        nonBlock = true;
    }

    bool privileged = clientHasLogCredentials(cli);
    bool can_read_security = CanReadSecurityLogs(cli);

    std::unique_ptr<LogWriter> socket_log_writer(
            new SocketLogWriter(this, cli, privileged, can_read_security));

    uint64_t monotonic_time = 1;
    // Find the monotonic timestamp for the entry that matches the input realtime timestamp.
    if (start != log_time::EPOCH) {
        bool start_time_set = false;
        uint64_t last = monotonic_time;
        auto log_find_start = [pid, logMask, start, &monotonic_time, &start_time_set,
                               &last](const LogBufferElement* element) -> FlushToResult {
            if (pid && pid != element->getPid()) {
                return FlushToResult::kSkip;
            }
            if ((logMask & (1 << element->getLogId())) == 0) {
                return FlushToResult::kSkip;
            }
            if (start == element->getRealTime()) {
                monotonic_time = element->getMonotonicTime();
                start_time_set = true;
                return FlushToResult::kStop;
            } else {
                if (start < element->getRealTime()) {
                    monotonic_time = last;
                    start_time_set = true;
                    return FlushToResult::kStop;
                }
                last = element->getMonotonicTime();
            }
            return FlushToResult::kSkip;
        };

        log_buffer_->FlushTo(socket_log_writer.get(), monotonic_time, nullptr, log_find_start);

        if (!start_time_set) {
            if (nonBlock) {
                android::prdebug(
                        "Ignoring non-blocking reader from pid=%d, did not find start time.",
                        cli->getPid());
                return false;
            }
            monotonic_time = LogBufferElement::getLatestMonotonicTime();
        }
    }

    if (monotonic_start != log_time::EPOCH) {
        monotonic_time = monotonic_start.nsec();
    }

    android::prdebug(
            "logdr: UID=%d GID=%d PID=%d %c tail=%lu logMask=%x pid=%d "
            "start=%" PRIu64 "ns monotonic_time=%" PRIu64 "ns deadline=%" PRIi64 "ns\n",
            cli->getUid(), cli->getGid(), cli->getPid(), nonBlock ? 'n' : 'b', tail, logMask,
            (int)pid, start.nsec(), monotonic_time,
            static_cast<int64_t>(deadline.time_since_epoch().count()));

    if (start == log_time::EPOCH) {
        deadline = {};
    }

    auto lock = std::lock_guard{reader_list_->reader_threads_lock()};
    auto entry = std::make_unique<LogReaderThread>(log_buffer_, reader_list_,
                                                   std::move(socket_log_writer), nonBlock, tail,
                                                   logMask, pid, start, monotonic_time, deadline);
    // release client and entry reference counts once done
    cli->incRef();
    reader_list_->reader_threads().emplace_front(std::move(entry));

    // Set acceptable upper limit to wait for slow reader processing b/27242723
    struct timeval t = { LOGD_SNDTIMEO, 0 };
    setsockopt(cli->getSocket(), SOL_SOCKET, SO_SNDTIMEO, (const char*)&t,
               sizeof(t));

    return true;
}

bool LogReader::DoSocketDelete(SocketClient* cli) {
    auto cli_name = SocketClientToName(cli);
    auto lock = std::lock_guard{reader_list_->reader_threads_lock()};
    for (const auto& reader : reader_list_->reader_threads()) {
        if (reader->name() == cli_name) {
            reader->release_Locked();
            return true;
        }
    }
    return false;
}

int LogReader::getLogSocket() {
    static const char socketName[] = "logdr";
    int sock = android_get_control_socket(socketName);

    if (sock < 0) {
        sock = socket_local_server(
            socketName, ANDROID_SOCKET_NAMESPACE_RESERVED, SOCK_SEQPACKET);
    }

    return sock;
}
