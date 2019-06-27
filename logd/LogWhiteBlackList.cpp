/*
 * Copyright (C) 2014 The Android Open Source Project
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

#include <android-base/stringprintf.h>
#include <cutils/properties.h>

#include "LogWhiteBlackList.h"

// White and Black list

Prune::Prune(uid_t uid, pid_t pid) : mUid(uid), mPid(pid) {
}

int Prune::cmp(uid_t uid, pid_t pid) const {
    if ((mUid == uid_all) || (mUid == uid)) {
        if (mPid == pid_all) {
            return 0;
        }
        return pid - mPid;
    }
    return uid - mUid;
}

std::string Prune::format() {
    if (mUid != uid_all) {
        if (mPid != pid_all) {
            return android::base::StringPrintf("%u/%u", mUid, mPid);
        }
        return android::base::StringPrintf("%u", mUid);
    }
    if (mPid != pid_all) {
        return android::base::StringPrintf("/%u", mPid);
    }
    // NB: mPid == pid_all can not happen if mUid == uid_all
    return std::string("/");
}

PruneList::PruneList() {
    init(nullptr);
}

PruneList::~PruneList() {
    PruneCollection::iterator it;
    for (it = mNice.begin(); it != mNice.end();) {
        it = mNice.erase(it);
    }
    for (it = mNaughty.begin(); it != mNaughty.end();) {
        it = mNaughty.erase(it);
    }
}

int PruneList::init(const char* /*str*/) {
    return 0;
}

std::string PruneList::format() {
    static const char nice_format[] = " %s";
    const char* fmt = nice_format + 1;

    std::string string;

    if (mWorstUidEnabled) {
        string = "~!";
        fmt = nice_format;
        if (mWorstPidOfSystemEnabled) {
            string += " ~1000/!";
        }
    }

    PruneCollection::iterator it;

    for (it = mNice.begin(); it != mNice.end(); ++it) {
        string += android::base::StringPrintf(fmt, (*it).format().c_str());
        fmt = nice_format;
    }

    static const char naughty_format[] = " ~%s";
    fmt = naughty_format + (*fmt != ' ');
    for (it = mNaughty.begin(); it != mNaughty.end(); ++it) {
        string += android::base::StringPrintf(fmt, (*it).format().c_str());
        fmt = naughty_format;
    }

    return string;
}

// ToDo: Lists are in sorted order, Prune->cmp() returns + or -
// If there is scaling issues, resort to a better algorithm than linear
// based on these assumptions.

bool PruneList::naughty(LogBufferElement* element) {
    PruneCollection::iterator it;
    for (it = mNaughty.begin(); it != mNaughty.end(); ++it) {
        if (!(*it).cmp(element)) {
            return true;
        }
    }
    return false;
}

bool PruneList::nice(LogBufferElement* element) {
    PruneCollection::iterator it;
    for (it = mNice.begin(); it != mNice.end(); ++it) {
        if (!(*it).cmp(element)) {
            return true;
        }
    }
    return false;
}
