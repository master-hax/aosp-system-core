/*
 * Copyright (C) 2020 The Android Open Source Project
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

#include <inttypes.h>

#include <android-base/file.h>
#include <log/log_time.h>
#include <log/logprint.h>

#include "LogBuffer.h"
#include "SimpleLogBuffer.h"

#ifndef __ANDROID__
unsigned long __android_logger_get_buffer_size(log_id_t) {
    return 1024 * 1024;
}

bool __android_logger_valid_buffer_size(unsigned long) {
    return true;
}
#endif

char* android::uidToName(uid_t) {
    return nullptr;
}

static AndroidLogFormat* GetLogFormat() {
    static AndroidLogFormat* format = [] {
        auto* format = android_log_format_new();
        android_log_setPrintFormat(format, android_log_formatFromString("threadtime"));
        return format;
    }();
    return format;
}

static void PrintMessage(struct log_msg* buf) {
    bool is_binary =
            buf->id() == LOG_ID_EVENTS || buf->id() == LOG_ID_STATS || buf->id() == LOG_ID_SECURITY;

    AndroidLogEntry entry;
    int err;
    if (is_binary) {
        char binaryMsgBuf[1024];
        err = android_log_processBinaryLogBuffer(&buf->entry, &entry, nullptr, binaryMsgBuf,
                                                 sizeof(binaryMsgBuf));
    } else {
        err = android_log_processLogBuffer(&buf->entry, &entry);
    }
    if (err < 0) {
        fprintf(stderr, "Error parsing log message\n");
    }

    android_log_printLogLine(GetLogFormat(), STDOUT_FILENO, &entry);
}

struct __attribute__((packed)) RecordedLogMessage {
    uint32_t uid;
    uint32_t pid;
    uint32_t tid;
    log_time realtime;
    uint16_t msg_len;
    uint8_t log_id;
};

class StdoutWriter : public LogWriter {
  public:
    StdoutWriter() : LogWriter(0, true) {}
    bool Write(const logger_entry& entry, const char* message) override {
        struct log_msg log_msg;
        log_msg.entry = entry;
        if (log_msg.entry.len > LOGGER_ENTRY_MAX_PAYLOAD) {
            fprintf(stderr, "payload too large %" PRIu16, log_msg.entry.len);
            exit(1);
        }
        memcpy(log_msg.msg(), message, log_msg.entry.len);

        PrintMessage(&log_msg);

        return true;
    }

    std::string name() const override { return "stdout writer"; }
};

int main(int argc, char** argv) {
    if (argc != 2) {
        fprintf(stderr, "Expected filename\n");
        return 1;
    }

    std::string recorded_messages;
    if (!android::base::ReadFileToString(argv[1], &recorded_messages)) {
        fprintf(stderr, "Couldn't read input file\n");
        return 1;
    }

    // SimpleLogBuffer::Log() won't log without this.
    __android_log_set_minimum_priority(ANDROID_LOG_VERBOSE);

    LogReaderList reader_list;
    LogTags tags;
    LogStatistics stats{false};
    std::unique_ptr<LogBuffer> buffer(new SimpleLogBuffer(&reader_list, &tags, &stats));

    uint64_t read_position = 0;
    while (read_position + sizeof(RecordedLogMessage) < recorded_messages.size()) {
        auto* meta =
                reinterpret_cast<RecordedLogMessage*>(recorded_messages.data() + read_position);
        if (read_position + sizeof(RecordedLogMessage) + meta->msg_len >=
            recorded_messages.size()) {
            break;
        }
        char* msg = recorded_messages.data() + read_position + sizeof(RecordedLogMessage);
        read_position += sizeof(RecordedLogMessage) + meta->msg_len;

        buffer->Log(static_cast<log_id_t>(meta->log_id), meta->realtime, meta->uid, meta->pid,
                    meta->tid, msg, meta->msg_len);
    }

    std::unique_ptr<LogWriter> test_writer(new StdoutWriter());
    std::unique_ptr<FlushToState> flush_to_state = buffer->CreateFlushToState(1, kLogMaskAll);
    buffer->FlushTo(test_writer.get(), *flush_to_state, nullptr);

    auto stats_string = stats.Format(0, 0, kLogMaskAll);
    printf("%s\n", stats_string.c_str());

    return 0;
}
