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

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <string>

#include <android-base/file.h>
#include <android-base/macros.h>
#include <android-base/stringprintf.h>
#include <log/log_event_list.h>
#include <private/android_filesystem_config.h>
#include <private/android_logger.h>

#include "LogTags.h"
#include "LogUtils.h"

static LogTags* logtags;

const char LogTags::system_event_log_tags[] = "/system/etc/event-log-tags";
const char LogTags::dynamic_event_log_tags[] = "/dev/event-log-tags";
// Only for debug
const char LogTags::debug_event_log_tags[] = "/data/misc/logd/event-log-tags";

// Look for first uid=%d in comment
static uid_t sniffUid(const char* comment, const char* endp) {
    if (!comment) return AID_ROOT;

    if (*comment == '#') ++comment;
    while ((comment < endp) && (*comment != '\n') && isspace(*comment)) ++comment;
    if (((comment + 4) >= endp) ||
            (comment[0] != 'u') ||
            (comment[1] != 'i') ||
            (comment[2] != 'd') ||
            (comment[3] != '=') ||
            !isdigit(comment[4])) return AID_ROOT;
    char *cp;
    unsigned long Uid = strtoul(comment + 4, &cp, 10);
    if ((cp > endp) || (Uid >= INT_MAX)) return AID_ROOT;

    return Uid;
}

bool LogTags::RestoreFileEventLogTags(const char* filename, bool warn) {
    int fd;

    {
        android::RWLock::AutoWLock writeLock(rwlock);

        if (tag2total.begin() == tag2total.end()) {
            return false;
        }

        file2watermark_const_iterator iwater = file2watermark.find(filename);
        if (iwater == file2watermark.end()) {
            return false;
        }

        struct stat sb;
        if (!stat(filename, &sb) && ((size_t)sb.st_size >= iwater->second)) {
            return false;
        }

        // dump what we already know back into the file?
        fd = TEMP_FAILURE_RETRY(open(filename,
                                     O_WRONLY | O_TRUNC | O_CLOEXEC |
                                     O_NOFOLLOW | O_BINARY));
        if (fd >= 0) {
            time_t now = time(NULL);
            struct tm tm;
            localtime_r(&now, &tm);
            char timebuf[20];
            size_t len = strftime(timebuf, sizeof(timebuf),
                                  "%Y-%m-%d %H:%M:%S", &tm);
            android::base::WriteStringToFd(
                android::base::StringPrintf(
                    "# Rebuilt %.20s, content owned by logd\n", timebuf),
                fd);
            for (const auto& it : tag2total) {
                android::base::WriteStringToFd(formatEntry(it.first, AID_ROOT),
                                               fd);
            }
            TEMP_FAILURE_RETRY(close(fd));
        }
    }

    if (warn) {
        android::prdebug(((fd < 0) ?
                              "%s failed to rebuild" :
                              "%s missing, damaged or truncated; rebuilt"),
                         filename);
    }
    return true;
}

void LogTags::ReadFileEventLogTags(const char* filename, bool warn) {
    bool etc = strcmp(filename, system_event_log_tags) == 0;

    if (!etc) {
        RestoreFileEventLogTags(filename, warn);
    }
    std::string content;
    if (android::base::ReadFileToString(filename, &content)) {
        char* cp = (char*) content.c_str();
        char* endp = cp + content.length();

        {
            android::RWLock::AutoRLock readLock(rwlock);

            file2watermark[filename] = content.length();
        }

        char *lineStart = cp;
        while (cp < endp) {
            if (*cp == '\n') {
                lineStart = cp;
            } else if (lineStart) {
                if (*cp == '#') {
                    /* comment; just scan to end */
                    lineStart = NULL;
                } else if (isdigit(*cp)) {
                    unsigned long Tag = strtoul(cp, &cp, 10);
                    if (warn && (Tag > emptyTag)) {
                        android::prdebug("tag too large %lu", Tag);
                    }
                    while ((cp < endp) && (*cp != '\n') && isspace(*cp)) ++cp;
                    if (cp >= endp) break;
                    if (*cp == '\n') continue;
                    const char *name = cp;
                    /* Determine whether it is a valid tag name [a-zA-Z0-9_] */
                    bool hasAlpha = false;
                    while ((cp < endp) && (isalnum(*cp) || (*cp == '_'))) {
                        if (!isdigit(*cp)) hasAlpha = true;
                        ++cp;
                    }
                    std::string Name(name, cp - name);
#ifdef ALLOW_NOISY_LOGGING_OF_PROBLEM_WITH_LOTS_OF_TECHNICAL_DEBT
                    // tag names longer than 24 are not officially supported
                    if (warn && (Name.length() > 24)) {
                       android::prdebug("tag name too long %s", Name.c_str());
                    }
#endif
                    if (hasAlpha && ((cp >= endp) || (*cp == '#') || isspace(*cp))) {
                        if (Tag > emptyTag) {
                            if (*cp != '\n') lineStart = NULL;
                            continue;
                        }
                        while ((cp < endp) && (*cp != '\n') && isspace(*cp)) ++cp;
                        const char *format = cp;
                        uid_t uid = AID_ROOT;
                        while ((cp < endp) && (*cp != '\n')) {
                            if (*cp == '#') {
                                uid = sniffUid(cp, endp);
                                lineStart = NULL;
                                break;
                            }
                            ++cp;
                        }
                        while ((cp > format) && isspace(cp[-1])) {
                            --cp;
                            lineStart = NULL;
                        }
                        std::string Format(format, cp - format);
                        std::string Key = Name;
                        if (Format.length()) Key += "+" + Format;

                        uint32_t tag = Tag;
                        bool updatePmsg = false;

                        {
                            android::RWLock::AutoWLock writeLock(rwlock);

                            if (!etc) {
                                tag2total_const_iterator itot;

                                itot = tag2total.find(tag);
                                // likely except for dupes
                                if (itot == tag2total.end()) {
                                    tag2total[tag] = 0;
                                    updatePmsg = true;
                                }
                            }
                            bool newOne = tag2name.find(tag) == tag2name.end();
                            if (warn && !newOne) {
                                // For the files, we want to report dupes.
                                android::prdebug("Multiple tag %lu %s %s", Tag,
                                                 Name.c_str(), Format.c_str());
                            }
                            key2tag[Key] = tag;
                            if (Format.length()) {
                                if (key2tag.find(Name) == key2tag.end()) {
                                    key2tag[Name] = tag;
                                }
                                tag2format[tag] = Format;
                            }
                            tag2name[tag] = Name;
                            tag2uid_const_iterator iu = tag2uid.find(tag);
                            if (iu != tag2uid.end()) {
                                if ((uid == AID_ROOT) || (uid != iu->second)) {
                                    tag2uid.erase(iu);
                                }
                            } else if (newOne) {
                                tag2uid[tag] = uid;
                            }
                        }
                        if (updatePmsg) WritePmsgEventLogTags(tag, filename);
                    } else {
                        if (warn) {
                            android::prdebug("tag name invalid %.*s",
                                             (int)(cp - name + 1), name);
                        }
                        lineStart = NULL;
                    }
                } else if (!isspace(*cp)) break;
            }
            cp++;
        }
    } else if (warn) {
        android::prdebug("Cannot read %s", filename);
    }
}

/*
 * Extract a 4-byte value from a byte stream.
 */
static inline uint32_t get4LE(const char* msg)
{
    const uint8_t* src = reinterpret_cast<const uint8_t *>(msg);
    return src[0] | (src[1] << 8) | (src[2] << 16) | (src[3] << 24);
}

void LogTags::ReadPmsgEventLogTags() {
    struct logger_list *logger_list = android_logger_list_alloc(
        ANDROID_LOG_RDONLY | ANDROID_LOG_PSTORE | ANDROID_LOG_NONBLOCK,
        0, (pid_t)0);
    if (!logger_list) return;

    struct logger *e = android_logger_open(logger_list, LOG_ID_EVENTS);
    struct logger *s = android_logger_open(logger_list, LOG_ID_SECURITY);
    if (!e && !s) {
        android_logger_list_free(logger_list);
        return;
    }

    for (;;) {
        struct log_msg log_msg;
        int ret = android_logger_list_read(logger_list, &log_msg);
        if (ret <= 0) break;

        const char *msg = log_msg.msg();
        if (!msg) continue;
        if (log_msg.entry.len <= sizeof(uint32_t)) continue;
        uint32_t Tag = get4LE(msg);
        if (Tag != TAG_DEF_LOG_TAG) continue;
        uid_t uid = (log_msg.entry.hdr_size >= sizeof(logger_entry_v4)) ?
            log_msg.entry.uid : AID_ROOT;

        std::string Name;
        std::string Format;
        android_log_list_element elem;
        {
            android_log_event_list ctx(log_msg);
            elem = ctx.read();
            if (elem.type != EVENT_TYPE_LIST) {
                continue;
            }
            elem = ctx.read();
            if (elem.type != EVENT_TYPE_INT) {
                continue;
            }
            Tag = elem.data.int32;
            elem = ctx.read();
            if (elem.type != EVENT_TYPE_STRING) {
                continue;
            }
            Name = std::string(elem.data.string, elem.len);
            elem = ctx.read();
            if (elem.type != EVENT_TYPE_STRING) {
                continue;
            }
            Format = std::string(elem.data.string, elem.len);
            elem = ctx.read();
        }
        if ((elem.type != EVENT_TYPE_LIST_STOP) || !elem.complete) continue;

        std::string Key = Name;
        if (Format.length()) Key += "+" + Format;

        android::RWLock::AutoWLock writeLock(rwlock);

        if (key2tag.find(Key) == key2tag.end()) {
            // set means dynamic allocation
            tag2total_const_iterator itot = tag2total.find(Tag);
            if (itot == tag2total.end()) tag2total[Tag] = 0; // likely

            key2tag[Key] = Tag;
            if (Format.length()) {
                if (key2tag.find(Name) == key2tag.end()) {
                    key2tag[Name] = Tag;
                }
                tag2format[Tag] = Format;
            }
            tag2name[Tag] = Name;
            if (uid != AID_ROOT) tag2uid[Tag] = uid;
        } else {
            tag2uid_const_iterator ut = tag2uid.find(Tag);
            if ((ut != tag2uid.end()) &&
                    ((uid == AID_ROOT) || (uid != ut->second))) {
                tag2uid.erase(ut);
            }
        }
    }
    android_logger_list_free(logger_list);
}

LogTags::LogTags() {
    ReadFileEventLogTags(system_event_log_tags);
    // Following will likely fail on boot, but is required if logd restarts
    ReadFileEventLogTags(dynamic_event_log_tags, false);
    if (__android_log_is_debuggable()) {
        ReadFileEventLogTags(debug_event_log_tags, false);
    }
    ReadPmsgEventLogTags();

    logtags = this;
}

// tagToName converts an events tag into a name
const char* LogTags::tagToName(uint32_t tag) const {
    tag2name_const_iterator it;
    {
        android::RWLock::AutoRLock readLock(const_cast<android::RWLock&>(rwlock));

        it = tag2name.find(tag);
    }

    if ((it == tag2name.end()) || (it->second.length() == 0)) return NULL;

    return it->second.c_str();
}

const char* android::tagToName(uint32_t tag) {
    LogTags* me = logtags;

    if (!me) return NULL;
    me->WritePmsgEventLogTags(tag);
    return me->tagToName(tag);
}

void android::ReReadEventLogTags() {
    LogTags* me = logtags;

    if (me && __android_log_is_debuggable()) {
        me->ReadFileEventLogTags(me->debug_event_log_tags);
    }
}

// tagToName converts an events tag into a name
const char* LogTags::tagToFormat(uint32_t tag) const {
    tag2format_const_iterator iform;
    {
        android::RWLock::AutoRLock readLock(const_cast<android::RWLock&>(rwlock));

        iform = tag2format.find(tag);
    }

    if (iform == tag2format.end()) return NULL;

    return iform->second.c_str();
}

// converts a name into an event tag
uint32_t LogTags::nameToTag(const char *name) const {
    uint32_t ret = emptyTag;

    // Bug: Only works for a single entry, we can have multiple entries,
    // one for each format, so we find first entry recorded, or entry with
    // no format associated with it.

    {
        android::RWLock::AutoRLock readLock(const_cast<android::RWLock&>(rwlock));

        key2tag_const_iterator ik = key2tag.find(std::string(name));
        if (ik != key2tag.end()) ret = ik->second;
    }

    return ret;
}

// Caller must peform locks, can be under reader (for pre-check) or writer lock
// We use this call to invent a new deterministically random tag, unique is
// cleared if no conflicts. if format is NULL, we are in readonly mode.
uint32_t LogTags::nameToTag_unlocked(const std::string& name,
                                     const char* format,
                                     bool& unique) {
    key2tag_const_iterator ik;

    bool write = format != NULL;
    unique = write;

    if (!write) {
        // Bug: Only works for a single entry, we can have multiple entries,
        // one for each format, so we find first entry recorded, or entry with
        // no format associated with it.
        ik = key2tag.find(name);
        if (ik == key2tag.end()) return emptyTag;
        return ik->second;
    }

    std::string Key(name);
    if (*format) Key += std::string("+") + format;

    ik = key2tag.find(Key);
    if (ik != key2tag.end()) {
        unique = false;
        return ik->second;
    }

    size_t Hash = key2tag.hash_function()(Key);
    uint32_t Tag = Hash;
    // This sets an upper limit on the conflics we are allowed to deal with.
    for (unsigned i = 0; i < 256; ) {
        tag2name_const_iterator it = tag2name.find(Tag);
        if (it == tag2name.end()) return Tag;
        std::string localKey(it->second);
        tag2format_const_iterator iform = tag2format.find(Tag);
        if ((iform == tag2format.end()) && iform->second.length()) {
            localKey += "+" + iform->second;
        }
        unique = !!it->second.compare(localKey);
        if (!unique) return Tag; // unlikely except in a race

        ++i;
        // Algorithm to convert hash to next tag
        if (i < 32) {
            Tag = (Hash >> i);
            // size_t is 32 bits, or upper word zero, rotate
            if ((sizeof(Hash) <= 4) ||
                    ((Hash & (uint64_t(-1LL) << 32)) == 0)) {
                Tag |= Hash << (32 - i);
            }
        } else {
            Tag = Hash + i - 31;
        }
    }
    return emptyTag;
}

// because logd starts before there is a decryption context,
// for the processes, transitory failures result from ext4
// file encryption. Start with append without create as it has
// a higher chance of succeeding in this condition.
static int openFile(const char* name, int mode, bool warning) {
    int fd = TEMP_FAILURE_RETRY(open(name, mode));
    if ((fd < 0) && warning) {
        android::prdebug("Failed open %s (%d)", name, errno);
    }
    return fd;
}

void LogTags::WritePmsgEventLogTags(uint32_t tag, const char* source) {
    // very unlikely
    bool etc = source && !strcmp(source, system_event_log_tags);
    if (etc) return;

    bool dynamic = source && !strcmp(source, dynamic_event_log_tags);
    bool debug = (!dynamic &&
                  source &&
                  !strcmp(source, debug_event_log_tags)) ||
                 !__android_log_is_debuggable();
    size_t lastTotal;

    __android_log_event_list ctx(TAG_DEF_LOG_TAG);
    android::RWLock::AutoWLock writeLock(rwlock);

    tag2total_const_iterator itot = tag2total.find(tag);
    etc = (itot == tag2total.end());
    if (etc) { // very unlikely
        return;
    }
    lastTotal = itot->second;

    // Every 16K (half the smallest configurable pmsg buffer size) record
    if (lastTotal && ((android::sizesTotal() - lastTotal) < (16 * 1024))) {
        return;
    }
    std::string Name = tag2name[tag];
    tag2format_const_iterator iform = tag2format.find(tag);
    tag2uid_const_iterator ut = tag2uid.find(tag);
    uid_t uid = (ut != tag2uid.end()) ? uid = ut->second : AID_ROOT;

    std::string Format = (iform != tag2format.end()) ? iform->second : "";

    static int pmsg_fd = -1;
    if (pmsg_fd < 0) {
        pmsg_fd = TEMP_FAILURE_RETRY(open("/dev/pmsg0", O_WRONLY | O_CLOEXEC));
    }

    if (pmsg_fd >= 0) { // likely, but deal with partners with borken pmsg
        ctx << tag << Name << Format;
        std::string buffer(ctx);

        if (buffer.length() > 0) { // likely
            /*
             *  struct {
             *      // what we provide to pstore
             *      android_pmsg_log_header_t pmsgHeader;
             *      // what we provide to file
             *      android_log_header_t header;
             *      // caller provides
             *      union {
             *          struct {
             *              char     prio;
             *              char     payload[];
             *          } string;
             *          struct {
             *              uint32_t tag
             *              char     payload[];
             *          } binary;
             *      };
             *  };
             */

            struct timespec ts;
            clock_gettime(android_log_clockid(), &ts);

            android_log_header_t header = {
                .id = LOG_ID_EVENTS,
                .tid = (uint16_t)gettid(),
                .realtime.tv_sec = (uint32_t)ts.tv_sec,
                .realtime.tv_nsec = (uint32_t)ts.tv_nsec,
            };

            uint32_t outTag = TAG_DEF_LOG_TAG;
            outTag = get4LE((const char*)&outTag);

            android_pmsg_log_header_t pmsgHeader = {
                .magic = LOGGER_MAGIC,
                .len = (uint16_t)(sizeof(pmsgHeader) + sizeof(header) +
                                  sizeof(outTag) + buffer.length()),
                .uid = (uint16_t)uid,
                .pid = (uint16_t)getpid(),
            };

            struct iovec Vec[] = {
                { (unsigned char*)&pmsgHeader, sizeof(pmsgHeader) },
                { (unsigned char*)&header, sizeof(header) },
                { (unsigned char*)&outTag, sizeof(outTag) },
                { (unsigned char*)const_cast<char*>(buffer.data()), buffer.length() }
            };

            TEMP_FAILURE_RETRY(writev(pmsg_fd, Vec, arraysize(Vec)));
        }
    }

    ctx.close();

    if (lastTotal == 0) {
        static const int mode = O_WRONLY | O_APPEND |
                                O_CLOEXEC | O_NOFOLLOW | O_BINARY;
        if (!dynamic || !RestoreFileEventLogTags(dynamic_event_log_tags)) {
            int fd = openFile(dynamic_event_log_tags, mode, true);
            if (fd >= 0) {
                std::string ret = formatEntry(tag, uid,
                                              Name.c_str(), Format.c_str());
                android::base::WriteStringToFd(ret, fd);
                TEMP_FAILURE_RETRY(close(fd));

                file2watermark_const_iterator iwater = file2watermark.find(
                        dynamic_event_log_tags);
                size_t size = (iwater != file2watermark.end()) ? iwater->second : 0;
                file2watermark[dynamic_event_log_tags] = size + ret.length();
            }
        }

        if (!debug && !RestoreFileEventLogTags(debug_event_log_tags)) {
            // Store all new dynamic tags to propagate into bugreports
            static bool one = true;

            int fd = openFile(debug_event_log_tags, mode, one);
            one = fd >= 0;
            if (one) {
                std::string ret = formatEntry(tag, uid,
                                              Name.c_str(), Format.c_str());
                android::base::WriteStringToFd(ret, fd);
                TEMP_FAILURE_RETRY(close(fd));

                file2watermark_const_iterator iwater = file2watermark.find(
                        debug_event_log_tags);
                size_t size = (iwater != file2watermark.end()) ? iwater->second : 0;
                file2watermark[debug_event_log_tags] = size + ret.length();
            }
        }
    }

    // record totals for next watermark.
    lastTotal = android::sizesTotal();
    if (!lastTotal) ++lastTotal;
    tag2total[tag] = lastTotal;
}

// nameToTag converts a name into an event tag. If format is NULL, then we
// are in readonly mode.
uint32_t LogTags::nameToTag(uid_t uid, const char *name, const char *format) {
    std::string Name = std::string(name);
    bool write = format != NULL;
    bool updateUid = uid != AID_ROOT;
    bool updateFormat = format && *format;
    bool unique;
    uint32_t Tag;

    {
        android::RWLock::AutoRLock readLock(rwlock);

        Tag = nameToTag_unlocked(Name, format, unique);
        if (updateUid && (Tag != emptyTag) && !unique) {
            tag2uid_const_iterator ut = tag2uid.find(Tag);
            // Multiple identical registrants for different uids, permit wider
            // audience, assumption now it must be common knowledge, so we need
            // to write an update to the database. if from another uid, then
            // unique.
            if ((ut != tag2uid.end()) && (uid != ut->second)) {
                unique = write; // write passthrough to update uid counts
                if (!write) Tag = emptyTag; // deny read access
            }
        }
    }

    if (Tag == emptyTag) return Tag;
    WritePmsgEventLogTags(Tag);
    if (!unique) return Tag;

    bool updateTag;

    {
        android::RWLock::AutoWLock writeLock(rwlock);

        // double check after switch from read lock to write lock for Tag
        updateTag = tag2name.find(Tag) == tag2name.end();
        // unlikely, either update, race inviting conflict or multiple uids
        if (!updateTag) {
            Tag = nameToTag_unlocked(Name, format, unique);
            // is it multiple uid's setting this value
            if (Tag == emptyTag) {
                return Tag;
            }
            if (!unique) {
                if (updateUid) {
                    tag2uid_const_iterator ut = tag2uid.find(Tag);
                    if ((ut != tag2uid.end()) && (uid != ut->second)) {
                        tag2uid.erase(ut);
                        --uid2count[uid];
                    }
                }
                return Tag;
            }
            if (updateUid) {
                tag2uid_const_iterator ut = tag2uid.find(Tag);
                updateUid = (ut == tag2uid.end()) || (uid != ut->second);
            }
        }

        // Update section
        size_t count;
        if (updateUid) {
            count = 0;
            uid2count_const_iterator ci = uid2count.find(uid);
            if (ci != uid2count.end()) {
                count = ci->second;
                if (count >= 256) {
                    return emptyTag;
                }
            }
        }

        if (updateTag) {
            tag2total_const_iterator itot = tag2total.find(Tag);
            if (itot == tag2total.end()) tag2total[Tag] = 0; // likely

            if (*format) {
                key2tag[Name + "+" + format] = Tag;
                if (key2tag.find(Name) == key2tag.end()) key2tag[Name] = Tag;
            } else {
                key2tag[Name] = Tag;
            }
            tag2name[Tag] = Name;
        }
        if (updateFormat) {
            tag2format[Tag] = format;
        }

        if (updateUid) {
            tag2uid[Tag] = uid;
            uid2count[uid] = count + 1;
        }
    }

    if (updateTag || updateFormat) WritePmsgEventLogTags(Tag);

    return Tag;
}

std::string LogTags::formatEntry(uint32_t tag, uid_t uid, const char* name, const char* format) {
    if (!format || !format[0]) {
        return android::base::StringPrintf("%" PRIu32 "\t%s\n", tag, name);
    }
    size_t len = (strlen(name) + 7) / 8;
    static const char tabs[] = "\t\t\t";
    if (len > strlen(tabs)) len = strlen(tabs);
    std::string Uid = (uid == AID_ROOT) ?
        "" :
        android::base::StringPrintf(" # uid=%u", uid);
    return android::base::StringPrintf("%" PRIu32 "\t%s%s\t%s%s\n",
                                       tag, name, &tabs[len], format, Uid.c_str());
}

std::string LogTags::formatEntry(uint32_t tag, uid_t uid) {
    // Access permission test, do not report dynamic entries
    // that do not belong to us. Not a security test, more
    // like a space optimization.
    tag2uid_const_iterator ut = tag2uid.find(tag);
    uid_t Uid = (ut != tag2uid.end()) ? ut->second : AID_ROOT;
    if ((uid != AID_ROOT) && (Uid != AID_ROOT) && (uid != Uid)) return std::string("");
    return formatEntry(tag, Uid, tag2name[tag].c_str(), tag2format[tag].c_str());
}

std::string LogTags::formatGetEventTag(uid_t uid,
                                       const char *name, const char *format) {
    bool all = name && (name[0] == '*') && !name[1];
    bool list = !name || all;

    if (!list) {
        // switch to read entry only if format == "*"
        if (format && (format[0] == '*') && !format[1]) format = NULL;

        // Bug: for null format, only works for a single entry, we can have
        // multiple entries, one for each format, so we find first entry
        // recorded, or entry with no format associated with it.
        // We may desire to print all that match the name, but we did not
        // add a mapping table for that.
        uint32_t tag = nameToTag(uid, name, format);
        if (tag == emptyTag) return std::string("-1 ESRCH");
        return formatEntry(tag, uid, name, format ?: tagToFormat(tag));
    }

    std::string ret;

    android::RWLock::AutoRLock readLock(rwlock);
    if (all) {
        // everything under the sun
        for (const auto& it : tag2name) {
            ret += formatEntry(it.first, uid);
        }
    } else {
        // set entries are dynamic
        for (const auto& it : tag2total) {
            ret += formatEntry(it.first, uid);
        }
    }
    return ret;
}
