/*
 * Copyright (C) 2016 The Android Open Source Project
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

#ifndef _LOGD_LOG_TAGS_H__
#define _LOGD_LOG_TAGS_H__

#include <unordered_map>
#include <string>

#include <utils/RWLock.h>

class LogTags {
    android::RWLock rwlock;

    // key is Name + "+" + Format
    std::unordered_map<std::string, uint32_t> key2tag;
    typedef std::unordered_map<std::string, uint32_t>::const_iterator key2tag_const_iterator;

    // Allows us to filter tags that this uid knows as noise-mitigation measure
    // Everyone can see AID_ROOT (clear) entries though.
    std::unordered_map<uint32_t, uid_t> tag2uid;
    typedef std::unordered_map<uint32_t, uid_t>::const_iterator tag2uid_const_iterator;

    std::unordered_map<uint32_t, std::string> tag2name;
    typedef std::unordered_map<uint32_t, std::string>::const_iterator tag2name_const_iterator;

    std::unordered_map<uint32_t, std::string> tag2format;
    typedef std::unordered_map<uint32_t, std::string>::const_iterator tag2format_const_iterator;

    std::unordered_map<uid_t, size_t> uid2count;
    typedef std::unordered_map<uid_t, size_t>::const_iterator uid2count_const_iterator;

    // Dynamic entries are assigned
    std::unordered_map<uint32_t, size_t> tag2total;
    typedef std::unordered_map<uint32_t, size_t>::const_iterator tag2total_const_iterator;

    // emplace unique tag
    uint32_t nameToTag(uid_t uid, const char* name, const char* format);
    // find unique or associated tag
    uint32_t nameToTag_unlocked(const std::string& name, const char* format, bool &unique);

    // Record expected file watermarks to detect corruption.
    std::unordered_map<std::string, size_t> file2watermark;
    typedef std::unordered_map<std::string, size_t>::const_iterator file2watermark_const_iterator;

    void ReadPmsgEventLogTags();

    static std::string formatEntry(uint32_t tag, uid_t uid,
                                   const char* name, const char* format);
    std::string formatEntry(uint32_t tag, uid_t uid);
    bool RestoreFileEventLogTags(const char* filename, bool warn = true);

public:
    static const uint32_t emptyTag = uint32_t(-1);

    LogTags();

    static const char system_event_log_tags[];
    static const char dynamic_event_log_tags[];
    // Only for debug
    static const char debug_event_log_tags[];

    void ReadFileEventLogTags(const char* filename, bool warn = true);

    // push tag details to pmsg.
    void WritePmsgEventLogTags(uint32_t tag, const char* source = NULL);
    // reverse lookup from tag
    const char* tagToName(uint32_t tag) const;
    const char* tagToFormat(uint32_t tag) const;
    // find associated tag
    uint32_t nameToTag(const char* name) const;

    // emplace tag if necessary, provide event-log-tag formated output in string
    std::string formatGetEventTag(uid_t uid, const char *name, const char *format);
};

#endif // _LOGD_LOG_TAGS_H__
