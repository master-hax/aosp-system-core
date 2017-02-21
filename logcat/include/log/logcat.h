/*
 * Copyright (C) 2005-2017 The Android Open Source Project
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

#ifndef _LIBS_LOGCAT_H /* header boilerplate */
#define _LIBS_LOGCAT_H

#ifndef __ANDROID_USE_LIBLOG_LOGCAT_INTERFACE
#ifndef __ANDROID_API__
#define __ANDROID_USE_LIBLOG_LOGCAT_INTERFACE 1
#elif __ANDROID_API__ > 24 /* > Nougat */
#define __ANDROID_USE_LIBLOG_LOGCAT_INTERFACE 1
#else
#define __ANDROID_USE_LIBLOG_LOGCAT_INTERFACE 0
#endif
#endif

#if __ANDROID_USE_LIBLOG_LOGCAT_INTERFACE

#include <stdio.h>

#if (defined(__cplusplus) && defined(_USING_LIBCXX))
extern "C++" {
#include <errno.h>

#include <string>
}
#endif

#ifdef __cplusplus
extern "C" {
#endif

/* For managing an in-process logcat function, rather than forking/execing
 *
 * It also serves as the basis for the logcat command.
 *
 * The following C API allows a logcat instance to be created, run
 * to completion, and then release all the associated resources.
 */

/*
 * The opaque context
 */
#ifndef __android_logcat_context_defined /* typedef boilerplate */
#define __android_logcat_context_defined
typedef struct android_logcat_context_internal* android_logcat_context;
#endif

/* Creates a context associated with this logcat instance
 *
 * Returns a pointer to the context, or a NULL on error.
 */
android_logcat_context create_android_logcat(void);

/* Collects and outputs the logcat data to output and error file descriptors
 *
 * Will block, performed in-thread and in-process
 *
 * The output file descriptor variable, if greater than or equal to 0, is
 * where the output (ie: stdout) will be sent. The file descriptor is closed
 * on android_logcat_destroy which terminates the instance, or when an -f flag
 * (output redirect to a file) is present in the command.  The error file
 * descriptor variable, if greater than or equal to 0, is where the error
 * stream (ie: stderr) will be sent, also closed on android_logcat_destroy.
 * The error file descriptor can be set to equal to the output file descriptor,
 * which will mix output and error stream content, and will defer closure of
 * the file descriptor on -f flag redirection.  Negative values for the file
 * descriptors will use stdout and stderr FILE references respectively
 * internally, and will not close the references as noted above.
 *
 * Return value is 0 for success, non-zero for errors.
 */
int android_logcat_run_command(android_logcat_context ctx, int output, int error,
                               int argc, char* const* argv, char* const* envp);

/* Will not block, performed in-process
 *
 * Starts a thread, opens a pipe, returns reading end fd, saves off argv.
 * The command supports 2>&1 (mix content) and 2>/dev/null (drop content) for
 * scripted error (stderr) redirection.
 */
int android_logcat_run_command_thread(android_logcat_context ctx, int argc,
                                      char* const* argv, char* const* envp);
int android_logcat_run_command_thread_running(android_logcat_context ctx);

/* Finished with context
 *
 * Kill the command thread ASAP (if any), and free up all associated resources.
 *
 * Return value is the result of the android_logcat_run_command, or
 * non-zero for any errors.
 */
int android_logcat_destroy(android_logcat_context* ctx);

/* derived helpers */

/*
 * In-process thread that acts like somewhat like libc-like system and popen
 * respectively.  Can not handle shell scripting, only pure calls to the
 * logcat operations. The android_logcat_system is a wrapper for the
 * create_android_logcat, android_logcat_run_command and android_logcat_destroy
 * API above.  The android_logcat_popen is a wrapper for the
 * android_logcat_run_command_thread API above.  The android_logcat_pclose is
 * a wrapper for a reasonable wait until output has subsided for command
 * completion, fclose on the FILE pointer and the android_logcat_destroy API.
 */
int android_logcat_system(const char* command);
/* ctx is assumed uninitialized and completely managed by the following calls */
FILE* android_logcat_popen(android_logcat_context* ctx, const char* command);
int android_logcat_pclose(android_logcat_context* ctx, FILE* output);

#if (defined(__cplusplus) && defined(_USING_LIBCXX))
extern "C++" {

class AndroidLogcat {
   private:
    std::string command_;         // command to execute (cleared after execute).
    android_logcat_context ctx_;  // popen context.
    FILE* fp_;                    // popen file descriptor.
    int ret_;                     // if non-zero (failure) ret is assumed valid.
    bool run_;                    // ret valid (for cases where ret == 0).

   public:
    AndroidLogcat() : ctx_(nullptr), fp_(nullptr), ret_(-EINVAL), run_(false) {
    }

    explicit AndroidLogcat(const std::string& command)
        : command_(command),
          ctx_(nullptr),
          fp_(nullptr),
          ret_(command.empty() ? -EINVAL : 0),
          run_(false) {
    }

    // copy constructors lead to api confusion about
    // state expectations, let's not go there.
    AndroidLogcat(const AndroidLogcat&) = delete;
    void operator=(const AndroidLogcat&) = delete;

    ~AndroidLogcat() {
        if (fp_) {
            android_logcat_pclose(&ctx_, fp_);
        } else if (!command_.empty()) {
            android_logcat_system(command_.c_str());
        }
    }

    // Can only be called after void constructor, or after getInt() completion.
    AndroidLogcat& reset(const std::string& command) {
        if (!command_.empty() || fp_) {
            ret_ = -EBUSY;
            return *this;
        }
        if (command.empty()) {
            ret_ = -EINVAL;
            return *this;
        }
        command_ = command;
        ret_ = 0;
        run_ = false;
        return *this;
    }

    AndroidLogcat& operator=(const std::string& command) {
        return reset(command);
    }

    // Start thread (popen)
    FILE* getFp() {
        if (run_ || ret_ || fp_) return fp_;
        if (command_.empty()) return nullptr;
        fp_ = android_logcat_popen(&ctx_, command_.c_str());
        command_.erase();
        return fp_;
    }

    // Finish thread (popen) or process (system)
    int getRet() {
        if (run_ || ret_) return ret_;
        if (fp_) {
            ret_ = android_logcat_pclose(&ctx_, fp_);
            fp_ = nullptr;
        } else if (command_.empty()) {
            ret_ = -EINVAL;
            return ret_;
        } else {
            ret_ = android_logcat_system(command_.c_str());
            command_.erase();
        }
        run_ = true;
        return ret_;
    }
};

// Android coding standard requires headers to be in alphabetical order,
// as such we can assume if #include <android-base/file.h> preceeds
// #include <log/logcat.h> then we can add ReadLogcatToString helpers.
#ifdef ANDROID_BASE_FILE_H
namespace android {
namespace base {

bool ReadLogcatToString(const char* command, std::string* content) {
    AndroidLogcat logcat(command);
    FILE* fp = logcat.getFp();
    if (fp == nullptr) return false;
    auto ret = ReadFdToString(fileno(fp), content);
    return (logcat.getRet() == 0) && ret;
}

bool ReadLogcatToString(const std::string& command, std::string* content) {
    AndroidLogcat logcat(command);
    FILE* fp = logcat.getFp();
    if (fp == nullptr) return false;
    auto ret = ReadFdToString(fileno(fp), content);
    return (logcat.getRet() == 0) && ret;
}

bool ReadLogcatToString(std::string&& command, std::string* content) {
    AndroidLogcat logcat(std::move(command));
    FILE* fp = logcat.getFp();
    if (fp == nullptr) return false;
    auto ret = ReadFdToString(fileno(fp), content);
    return (logcat.getRet() == 0) && ret;
}

}  // namespace base
}  // namespace android
#endif  // ANDROID_BASE_FILE_H
}
#endif /* __cplusplus && _UISNG_LIBCXX */

#ifdef __cplusplus
}
#endif

#endif /* __ANDROID_USE_LIBLOG_LOGCAT_INTERFACE */

#endif /* _LIBS_LOGCAT_H */
