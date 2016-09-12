/*
 * Copyright (C) 2005-2016 The Android Open Source Project
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

#ifndef _LIBS_LOG_EVENT_LIST_H
#define _LIBS_LOG_EVENT_LIST_H

#if (defined(__cplusplus) && defined(_USING_LIBCXX))
extern "C++" {
#include <string>
}
#endif

#include <log/log.h>

#ifdef __cplusplus
extern "C" {
#endif

#if  __ANDROID_USE_LIBLOG_EVENT_INTERFACE

#ifdef __cplusplus
#ifndef __class_android_log_event_context_defined
#define __class_android_log_event_context_defined
/* android_log_context C++ helpers */
extern "C++" {
class android_log_event_context {
friend class __android_log_event_context;

private:
    android_log_context ctx;
    int ret;

    android_log_event_context(const android_log_event_context&) = delete;
    void operator =(const android_log_event_context&) = delete;

public:
    explicit android_log_event_context(int tag) : ret(0) {
        ctx = create_android_logger(static_cast<uint32_t>(tag));
    }
    explicit android_log_event_context(log_msg& log_msg) : ret(0) {
        ctx = create_android_log_parser(log_msg.msg() + sizeof(uint32_t),
                                        log_msg.entry.len - sizeof(uint32_t));
    }
    ~android_log_event_context() { android_log_destroy(&ctx); }

    int close() {
        int retval = android_log_destroy(&ctx);
        if (retval < 0) ret = retval;
        return retval;
    }

    /* To allow above C calls to use this class as parameter */
    operator android_log_context() const { return ctx; }

    int status() const { return ret; }

    int begin() {
        int retval = android_log_write_list_begin(ctx);
        if (retval < 0) ret = retval;
        return ret;
    }
    int end() {
        int retval = android_log_write_list_end(ctx);
        if (retval < 0) ret = retval;
        return ret;
    }

    android_log_event_context& operator <<(int32_t value) {
        int retval = android_log_write_int32(ctx, value);
        if (retval < 0) ret = retval;
        return *this;
    }
    android_log_event_context& operator <<(uint32_t value) {
        int retval = android_log_write_int32(ctx, static_cast<int32_t>(value));
        if (retval < 0) ret = retval;
        return *this;
    }
    android_log_event_context& operator <<(int64_t value) {
        int retval = android_log_write_int64(ctx, value);
        if (retval < 0) ret = retval;
        return *this;
    }
    android_log_event_context& operator <<(uint64_t value) {
        int retval = android_log_write_int64(ctx, static_cast<int64_t>(value));
        if (retval < 0) ret = retval;
        return *this;
    }
    android_log_event_context& operator <<(const char* value) {
        int retval = android_log_write_string8(ctx, value);
        if (retval < 0) ret = retval;
        return *this;
    }
#if defined(_USING_LIBCXX)
    android_log_event_context& operator <<(const std::string& value) {
        int retval = android_log_write_string8_len(ctx,
                                                   value.data(),
                                                   value.length());
        if (retval < 0) ret = retval;
        return *this;
    }
#endif
    android_log_event_context& operator <<(float value) {
        int retval = android_log_write_float32(ctx, value);
        if (retval < 0) ret = retval;
        return *this;
    }

    int write(log_id_t id = LOG_ID_EVENTS) {
        int retval = android_log_write_list(ctx, id);
        if (retval < 0) ret = retval;
        return ret;
    }

    int operator <<(log_id_t id) {
        int retval = android_log_write_list(ctx, id);
        if (retval < 0) ret = retval;
        android_log_destroy(&ctx);
        return ret;
    }

    /*
     * Append should be a lesser-used interface, but adds
     * access to string with length. So we offer all types.
     */
    template <typename Tvalue>
    bool Append(Tvalue value) { *this << value; return ret >= 0; }

    bool Append(const char* value, size_t len) {
        int retval = android_log_write_string8_len(ctx, value, len);
        if (retval < 0) ret = retval;
        return ret >= 0;
    }

    android_log_list_element read() { return android_log_read_next(ctx); }
    android_log_list_element peek() { return android_log_peek_next(ctx); }

};
}
#endif
#endif

#endif /* __ANDROID_USE_LIBLOG_EVENT_INTERFACE */

#ifdef __cplusplus
}
#endif

#endif /* _LIBS_LOG_EVENT_LIST_H */
