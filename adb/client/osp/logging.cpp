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

#include <platform/api/logging.h>

#include <android-base/logging.h>

namespace openscreen {

// Returns true if |level| is at or above the level where the embedder will
// record/emit log entries from the code in |file|.
bool IsLoggingOn(LogLevel level, const char* file) {
    return true;
}

// Record a log entry, consisting of its logging level, location and message.
// The embedder may filter-out entries according to its own policy, but this
// function will not be called if IsLoggingOn(level, file) returns false.
// Whenever |level| is kFatal, Open Screen will call Break() immediately after
// this returns.
//
// |message| is passed as a string stream to avoid unnecessary string copies.
// Embedders can call its rdbuf() or str() methods to access the log message.
void LogWithLevel(LogLevel level, const char* file, int line, std::stringstream message) {
    LOG(INFO) << message.str();
}

// Breaks into the debugger, if one is present. Otherwise, aborts the current
// process (i.e., this function should not return). In production builds, an
// embedder could invoke its infrastructure for performing "dumps," consisting
// of thread stack traces and other relevant process state information, before
// aborting the process.
void Break() {}

}  // namespace openscreen
