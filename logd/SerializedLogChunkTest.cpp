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

#include "SerializedLogChunk.h"

#include <limits>

#include <android-base/stringprintf.h>
#include <gtest/gtest.h>

using android::base::StringPrintf;

TEST(SerializedLogChunk, smoke) {
    size_t chunk_size = 10 * 4096;
    auto chunk = SerializedLogChunk{chunk_size};
    EXPECT_EQ(chunk_size, chunk.PruneSize());

    static const char log_message[] = "log message";
    size_t expected_total_len = sizeof(SerializedLogEntry) + sizeof(log_message);
    ASSERT_TRUE(chunk.CanLog(expected_total_len));
    EXPECT_TRUE(chunk.CanLog(chunk_size));
    EXPECT_FALSE(chunk.CanLog(chunk_size + 1));

    log_time time(CLOCK_REALTIME);
    auto* message = chunk.Log(1234, time, 0, 1, 2, log_message, sizeof(log_message));
    ASSERT_NE(nullptr, message);

    EXPECT_EQ(1234U, message->sequence());
    EXPECT_EQ(time, message->realtime());
    EXPECT_EQ(0U, message->uid());
    EXPECT_EQ(1, message->pid());
    EXPECT_EQ(2, message->tid());
    EXPECT_EQ(sizeof(log_message), message->msg_len());
    EXPECT_STREQ(log_message, message->msg());
    EXPECT_EQ(expected_total_len, message->total_len());

    EXPECT_FALSE(chunk.CanLog(chunk_size));
    EXPECT_EQ(static_cast<int>(expected_total_len), chunk.write_position());
    EXPECT_EQ(1234U, chunk.highest_sequence_number());
}

TEST(SerializedLogChunk, fill_log_exactly) {
    static const char log_message[] = "this is a log message";
    size_t individual_message_size = sizeof(SerializedLogEntry) + sizeof(log_message);
    size_t chunk_size = individual_message_size * 3;
    auto chunk = SerializedLogChunk{chunk_size};
    EXPECT_EQ(chunk_size, chunk.PruneSize());

    ASSERT_TRUE(chunk.CanLog(individual_message_size));
    EXPECT_NE(nullptr, chunk.Log(1, log_time(), 1000, 1, 1, log_message, sizeof(log_message)));

    ASSERT_TRUE(chunk.CanLog(individual_message_size));
    EXPECT_NE(nullptr, chunk.Log(2, log_time(), 1000, 2, 1, log_message, sizeof(log_message)));

    ASSERT_TRUE(chunk.CanLog(individual_message_size));
    EXPECT_NE(nullptr, chunk.Log(3, log_time(), 1000, 3, 1, log_message, sizeof(log_message)));

    EXPECT_FALSE(chunk.CanLog(1));
}

TEST(SerializedLogChunk, three_logs) {
    size_t chunk_size = 10 * 4096;
    auto chunk = SerializedLogChunk{chunk_size};

    chunk.Log(2, log_time(0x1234, 0x5678), 0x111, 0x222, 0x333, "initial message",
              strlen("initial message"));
    chunk.Log(3, log_time(0x2345, 0x6789), 0x444, 0x555, 0x666, "second message",
              strlen("second message"));
    auto uint64_t_max = std::numeric_limits<uint64_t>::max();
    auto uint32_t_max = std::numeric_limits<uint32_t>::max();
    chunk.Log(uint64_t_max, log_time(uint32_t_max, uint32_t_max), uint32_t_max, uint32_t_max,
              uint32_t_max, "last message", strlen("last message"));

    static const char expected_buffer_data[] =
            "\x11\x01\x00\x00\x22\x02\x00\x00\x33\x03\x00\x00"  // UID PID TID
            "\x02\x00\x00\x00\x00\x00\x00\x00"                  // Sequence
            "\x34\x12\x00\x00\x78\x56\x00\x00"                  // Timestamp
            "\x0F\x00initial message"                           // msg_len + message
            "\x44\x04\x00\x00\x55\x05\x00\x00\x66\x06\x00\x00"  // UID PID TID
            "\x03\x00\x00\x00\x00\x00\x00\x00"                  // Sequence
            "\x45\x23\x00\x00\x89\x67\x00\x00"                  // Timestamp
            "\x0E\x00second message"                            // msg_len + message
            "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF"  // UID PID TID
            "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF"                  // Sequence
            "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF"                  // Timestamp
            "\x0C\x00last message";                             // msg_len + message

    for (size_t i = 0; i < chunk_size; ++i) {
        if (i < sizeof(expected_buffer_data)) {
            EXPECT_EQ(static_cast<uint8_t>(expected_buffer_data[i]), chunk.data()[i])
                    << "position: " << i;
        } else {
            EXPECT_EQ(0, chunk.data()[i]) << "position: " << i;
        }
    }
}

// Check that the CHECK() in DecDecompressedRef() if the ref count goes bad is caught.
TEST(SerializedLogChunk, catch_DecCompressedRef_CHECK) {
    size_t chunk_size = 10 * 4096;
    auto chunk = SerializedLogChunk{chunk_size};
    chunk.DecDecompressedRef();
    EXPECT_DEATH({ chunk.DecDecompressedRef(); }, "");
}

// Check that the CHECK() in ClearUidLogs() if the ref count is greater than 0 is caught.
TEST(SerializedLogChunk, catch_ClearUidLogs_CHECK) {
    size_t chunk_size = 10 * 4096;
    auto chunk = SerializedLogChunk{chunk_size};
    EXPECT_DEATH({ chunk.ClearUidLogs(1000); }, "");
}

// Test that ClearUidLogs() is a no-op if there are no logs of that UID in the buffer.
TEST(SerializedLogChunk, uid_clear_nothing) {
    size_t chunk_size = 10 * 4096;
    auto chunk = SerializedLogChunk{chunk_size};
    static const char msg[] = "this is a log message";
    chunk.Log(1, log_time(), 0, 1, 2, msg, sizeof(msg));

    chunk.DecDecompressedRef();
    EXPECT_FALSE(chunk.ClearUidLogs(1000));
    chunk.IncDecompressedRef();

    auto* log_message = reinterpret_cast<const SerializedLogEntry*>(chunk.data());
    EXPECT_STREQ(msg, log_message->msg());
}

// Test that ClearUidLogs() returns true if all logs in a given buffer correspond to the given UID.
TEST(SerializedLogChunk, uid_clear_all_single) {
    size_t chunk_size = 10 * 4096;
    auto chunk = SerializedLogChunk{chunk_size};
    uid_t uid_to_clear = 1234;
    static const char msg[] = "this is a log message";
    chunk.Log(1, log_time(), uid_to_clear, 1, 2, msg, sizeof(msg));

    chunk.DecDecompressedRef();
    EXPECT_TRUE(chunk.ClearUidLogs(uid_to_clear));
}

// Test that ClearUidLogs() returns true if all logs in a given buffer correspond to the given UID.
TEST(SerializedLogChunk, uid_clear_all_multiple) {
    size_t chunk_size = 10 * 4096;
    auto chunk = SerializedLogChunk{chunk_size};
    uid_t uid_to_clear = 1234;
    static const char msg[] = "this is a log message";
    chunk.Log(2, log_time(), uid_to_clear, 1, 2, msg, sizeof(msg));
    chunk.Log(3, log_time(), uid_to_clear, 1, 2, msg, sizeof(msg));
    chunk.Log(4, log_time(), uid_to_clear, 1, 2, msg, sizeof(msg));

    chunk.DecDecompressedRef();
    EXPECT_TRUE(chunk.ClearUidLogs(uid_to_clear));
}

static std::string MakePrintable(const uint8_t* in, size_t length) {
    std::string result;
    for (size_t i = 0; i < length; ++i) {
        uint8_t c = in[i];
        if (isprint(c)) {
            result.push_back(c);
        } else {
            result.append(StringPrintf("\\%02x", static_cast<int>(c) & 0xFF));
        }
    }
    return result;
}

// This test clears UID logs at the beginning and end of the buffer, as well as two back to back
// logs in the interior.
TEST(SerializedLogChunk, uid_clear_beginning_and_end) {
    size_t chunk_size = 10 * 4096;
    auto chunk = SerializedLogChunk{chunk_size};
    uid_t uid_to_clear = 0;
    uid_t other_uid = 1000;
    static const char msg1[] = "this is a log message";
    ASSERT_NE(nullptr, chunk.Log(1, log_time(), uid_to_clear, 1, 2, msg1, sizeof(msg1)));
    static const char msg2[] = "non-cleared message";
    ASSERT_NE(nullptr, chunk.Log(2, log_time(), other_uid, 1, 2, msg2, sizeof(msg2)));
    static const char msg3[] = "back to back cleared messages";
    ASSERT_NE(nullptr, chunk.Log(3, log_time(), uid_to_clear, 1, 2, msg3, sizeof(msg3)));
    static const char msg4[] = "second in a row gone";
    ASSERT_NE(nullptr, chunk.Log(4, log_time(), uid_to_clear, 1, 2, msg4, sizeof(msg4)));
    static const char msg5[] = "but we save this one";
    ASSERT_NE(nullptr, chunk.Log(5, log_time(), other_uid, 1, 2, msg5, sizeof(msg5)));
    static const char msg6[] = "and this 1!";
    ASSERT_NE(nullptr, chunk.Log(6, log_time(), other_uid, 1, 2, msg6, sizeof(msg6)));
    static const char msg7[] = "the last one goes too";
    ASSERT_NE(nullptr, chunk.Log(7, log_time(), uid_to_clear, 1, 2, msg7, sizeof(msg7)));

    // ClearUidLogs requires there to be no references to the logs, since it would invalidate the
    // pointers, so we must decrease our ref count before calling it.
    chunk.DecDecompressedRef();
    EXPECT_FALSE(chunk.ClearUidLogs(uid_to_clear));
    chunk.IncDecompressedRef();

    size_t read_position = 0;
    auto* log_message = reinterpret_cast<const SerializedLogEntry*>(chunk.data());
    EXPECT_STREQ(msg2, log_message->msg());
    read_position += log_message->total_len();

    log_message = reinterpret_cast<const SerializedLogEntry*>(chunk.data() + read_position);
    EXPECT_STREQ(msg5, log_message->msg());
    read_position += log_message->total_len();

    log_message = reinterpret_cast<const SerializedLogEntry*>(chunk.data() + read_position);
    EXPECT_STREQ(msg6, log_message->msg()) << MakePrintable(chunk.data(), chunk.write_position());
    read_position += log_message->total_len();

    EXPECT_EQ(static_cast<int>(read_position), chunk.write_position());
}

// This tests the opposite case of uid_clear_beginning_and_end, in which we don't clear the
// beginning or end logs.  There is a single log pruned in the middle instead of back to back logs.
TEST(SerializedLogChunk, uid_clear_save_beginning_and_end) {
    size_t chunk_size = 10 * 4096;
    auto chunk = SerializedLogChunk{chunk_size};
    uid_t uid_to_clear = 0;
    uid_t other_uid = 1000;
    static const char msg1[] = "saved first message";
    ASSERT_NE(nullptr, chunk.Log(1, log_time(), other_uid, 1, 2, msg1, sizeof(msg1)));
    static const char msg2[] = "cleared interior message";
    ASSERT_NE(nullptr, chunk.Log(2, log_time(), uid_to_clear, 1, 2, msg2, sizeof(msg2)));
    static const char msg3[] = "last message stays";
    ASSERT_NE(nullptr, chunk.Log(3, log_time(), other_uid, 1, 2, msg3, sizeof(msg3)));

    chunk.DecDecompressedRef();
    EXPECT_FALSE(chunk.ClearUidLogs(uid_to_clear));
    chunk.IncDecompressedRef();

    size_t read_position = 0;
    auto* log_message = reinterpret_cast<const SerializedLogEntry*>(chunk.data());
    EXPECT_STREQ(msg1, log_message->msg());
    read_position += log_message->total_len();

    log_message = reinterpret_cast<const SerializedLogEntry*>(chunk.data() + read_position);
    EXPECT_STREQ(msg3, log_message->msg());
    read_position += log_message->total_len();

    EXPECT_EQ(static_cast<int>(read_position), chunk.write_position());
}
