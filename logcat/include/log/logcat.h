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

#ifndef _LIBS_LOGCAT_H
#define _LIBS_LOGCAT_H

#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

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

/* For managing an in-process logcat */

/*
 * The opaque context
 */
#ifndef __android_logcat_context_defined
#define __android_logcat_context_defined
typedef struct android_logcat_context_internal* android_logcat_context;
#endif

/* Creates a context associated with this logcat instance */
android_logcat_context create_android_logcat();

/* Will block, performed in-thread and in-process
 *
 * The output file descriptor variable if greater than or equal to 0 is where
 * the stdout will be sent, closed on destroy, or when an -f flag is present
 * in the command.  A value of 0, 1 or 2 are admittedly troublesome but
 * correct as it could represents the environmental stdio stdin, stdout and
 * stderr; accept the consequences that it will be closed on destroy or
 * -f flag.  The error variable if greater than or equal to 0 is where the
 * stderr stream will be sent, closed on destroy.  Also beware closure risk
 * of stdio.  The error can be set to equal to output and will mix content
 * and will not close the file descriptor reference on -f flag and will defer
 * it to the destroy call.  Negative values will use stdout and stderr
 * respectively and not close.
 */
int android_logcat_run_command(android_logcat_context ctx,
                               int output, int error,
                               int argc, char* const* argv);
/* Will not block, performed in-process
 *
 * Starts a thread, opens a pipe, returns reading end fd, saves off argv.
 * The command supports 2>&1 (mix content) and 2>/dev/null (drop content) for
 * scripted error (stderr) redirection.
 */
int android_logcat_run_command_thread(android_logcat_context ctx,
                                      int argc, char* const* argv);
int android_logcat_run_command_thread_running(android_logcat_context ctx);

/* Finished with context
 *
 * Kill the thread ASAP, and free up all associated resources.
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
 * fruition, fclose on the FILE pointer and the android_logcat_destroy API.
 */
int android_logcat_system(const char* command);
FILE* android_logcat_popen(android_logcat_context* ctx, const char* command);
int android_logcat_pclose(android_logcat_context* ctx, FILE* output);

#endif /* __ANDROID_USE_LIBLOG_LOGCAT_INTERFACE */

#ifdef __cplusplus
}
#endif

#endif /* _LIBS_LOGCAT_H */
