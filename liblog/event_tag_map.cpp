/*
 * Copyright (C) 2007-2016 The Android Open Source Project
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

#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>

#include <experimental/string_view>
#include <functional>
#include <string>
#include <unordered_map>

#include <log/event_tag_map.h>
#include <utils/FastStrcmp.h>
#include <utils/RWLock.h>
#include <private/android_logger.h>

#include "log_portability.h"
#include "logd_reader.h"

#define OUT_TAG "EventTagMap"

class MapString {
private:
    const std::string* alloc; // HAS-AN
    const std::experimental::string_view str; // HAS-A

public:
    operator const std::experimental::string_view() const { return str; }

    const char* data() const { return str.data(); }
    size_t length() const { return str.length(); }

    bool operator== (const MapString& rval) const {
        if (length() != rval.length()) return false;
        if (length() == 0) return true;
        return fastcmp<strncmp>(data(), rval.data(), length()) == 0;
    }
    bool operator!= (const MapString& rval) const {
        return !(*this == rval);
    }

    MapString(const char* str, size_t len) : alloc(NULL), str(str, len) { }
    explicit MapString(const std::string& str) :
            alloc(new std::string(str)),
            str(alloc->data(), alloc->length()) { }
    MapString(MapString &&rval) :
            alloc(rval.alloc),
            str(rval.data(), rval.length()) {
        rval.alloc = NULL;
    }
    explicit MapString(const MapString &rval) :
            alloc(rval.alloc ? new std::string(*rval.alloc) : NULL),
            str(alloc ? alloc->data() : rval.data(), rval.length()) { }

    ~MapString() { if (alloc) delete alloc; }
};

// Hash for MapString
template <> struct _LIBCPP_TYPE_VIS_ONLY std::hash<MapString>
        : public std::unary_function<const MapString&, size_t> {
    _LIBCPP_INLINE_VISIBILITY
    size_t operator()(const MapString& __t) const _NOEXCEPT {
        if (!__t.length()) return 0;
        return std::hash<std::experimental::string_view>()(std::experimental::string_view(__t));
    }
};

class TagFmt : public std::pair<MapString, MapString> {
public:
    bool operator== (const TagFmt& rval) const {
        if (first != rval.first) return false;
        return second == rval.second;
    }

    TagFmt(const char* tag, size_t tagLen, const char* fmt, size_t fmtLen) :
        std::pair<MapString, MapString>(std::make_pair(
            MapString(tag, tagLen), MapString(fmt, fmtLen))) { }
    TagFmt(const std::string&& tag, const std::string&& fmt) :
        std::pair<MapString, MapString>(std::make_pair(
            MapString(tag), MapString(fmt))) { }
};

template <> struct _LIBCPP_TYPE_VIS_ONLY std::hash<TagFmt>
        : public std::unary_function<const TagFmt&, size_t> {
    _LIBCPP_INLINE_VISIBILITY
    size_t operator()(const TagFmt& __t) const _NOEXCEPT {
        // Tag is typically unique.  Will cost us an extra 100ns for the
        // unordered_map lookup if we instead did a hash that combined
        // both of tag and fmt members, e.g.:
        //
        // return std::hash<MapString>()(__t.first) ^
        //        std::hash<MapString>()(__t.second);
        return std::hash<MapString>()(__t.first);
    }
};

// Map
struct EventTagMap {
    // memory-mapped source file; we get strings from here
    void*  mapAddr;
    size_t mapLen;

private:
    std::unordered_map<uint32_t, TagFmt> Idx2TagFmt;
    std::unordered_map<TagFmt, uint32_t> TagFmt2Idx;
    std::unordered_map<MapString, uint32_t> Tag2Idx;
    // protect unordered sets
    android::RWLock rwlock;

public:
    EventTagMap() : mapAddr(NULL), mapLen(0) { }

    ~EventTagMap() {
        Idx2TagFmt.clear();
        TagFmt2Idx.clear();
        Tag2Idx.clear();
        if (mapAddr) {
            munmap(mapAddr, mapLen);
            mapAddr = 0;
        }
    }

    bool emplaceUnique(uint32_t tag, const TagFmt& tagfmt, bool verbose = false);
    const TagFmt* find(uint32_t tag) const;
    int find(TagFmt&& tagfmt) const;
    int find(MapString&& tag) const;
};

bool EventTagMap::emplaceUnique(uint32_t tag, const TagFmt& tagfmt, bool verbose) {
    bool ret = true;
    static const char errorFormat[] = OUT_TAG ": duplicate tag entries %" PRIu32
                                      ":%.*s:%.*s and %" PRIu32
                                      ":%.*s:%.*s)\n";
    android::RWLock::AutoWLock writeLock(rwlock);
    {
        std::unordered_map<uint32_t, TagFmt>::const_iterator it;
        it = Idx2TagFmt.find(tag);
        if (it != Idx2TagFmt.end()) {
            if (verbose) {
                fprintf(stderr, errorFormat,
                        it->first,
                        (int)it->second.first.length(), it->second.first.data(),
                        (int)it->second.second.length(), it->second.second.data(),
                        tag,
                        (int)tagfmt.first.length(), tagfmt.first.data(),
                        (int)tagfmt.second.length(), tagfmt.second.data());
            }
            ret = false;
        } else {
            Idx2TagFmt.emplace(std::make_pair(tag, tagfmt));
        }
    }

    {
        std::unordered_map<TagFmt, uint32_t>::const_iterator it;
        it = TagFmt2Idx.find(tagfmt);
        if (it != TagFmt2Idx.end()) {
            if (verbose) {
                fprintf(stderr, errorFormat,
                        it->second,
                        (int)it->first.first.length(), it->first.first.data(),
                        (int)it->first.second.length(), it->first.second.data(),
                        tag,
                        (int)tagfmt.first.length(), tagfmt.first.data(),
                        (int)tagfmt.second.length(), tagfmt.second.data());
            }
            ret = false;
        } else {
            TagFmt2Idx.emplace(std::make_pair(tagfmt, tag));
        }
    }

    {
        std::unordered_map<MapString, uint32_t>::const_iterator it;
        it = Tag2Idx.find(tagfmt.first);
        if (!tagfmt.second.length() && (it != Tag2Idx.end())) {
            Tag2Idx.erase(it);
            it = Tag2Idx.end();
        }
        if (it == Tag2Idx.end()) {
            Tag2Idx.emplace(std::make_pair(tagfmt.first, tag));
        }
    }

    return ret;
}

const TagFmt* EventTagMap::find(uint32_t tag) const {
    std::unordered_map<uint32_t, TagFmt>::const_iterator it;
    android::RWLock::AutoRLock readLock(const_cast<android::RWLock&>(rwlock));
    it = Idx2TagFmt.find(tag);
    if (it == Idx2TagFmt.end()) return NULL;
    return &(it->second);
}

int EventTagMap::find(TagFmt&& tagfmt) const {
    std::unordered_map<TagFmt, uint32_t>::const_iterator it;
    android::RWLock::AutoRLock readLock(const_cast<android::RWLock&>(rwlock));
    it = TagFmt2Idx.find(std::move(tagfmt));
    if (it == TagFmt2Idx.end()) return -1;
    return it->second;
}

int EventTagMap::find(MapString&& tag) const {
    std::unordered_map<MapString, uint32_t>::const_iterator it;
    android::RWLock::AutoRLock readLock(const_cast<android::RWLock&>(rwlock));
    it = Tag2Idx.find(std::move(tag));
    if (it == Tag2Idx.end()) return -1;
    return it->second;
}

// Scan one tag line.
//
// "*pData" should be pointing to the first digit in the tag number.  On
// successful return, it will be pointing to the last character in the
// tag line (i.e. the character before the start of the next line).
//
// Returns 0 on success, nonzero on failure.
static int scanTagLine(EventTagMap* map, char** pData, int lineNum) {
    char* cp;
    unsigned long val = strtoul(*pData, &cp, 10);
    if (cp == *pData) {
        fprintf(stderr, OUT_TAG ": malformed tag number on line %d\n", lineNum);
        errno = EINVAL;
        return -1;
    }

    uint32_t tagIndex = val;
    if (tagIndex != val) {
        fprintf(stderr, OUT_TAG ": tag number too large on line %d\n", lineNum);
        errno = ERANGE;
        return -1;
    }

    while ((*++cp != '\n') && isspace(*cp)) {
    }

    if (*cp == '\n') {
        fprintf(stderr, OUT_TAG ": missing tag string on line %d\n", lineNum);
        errno = EINVAL;
        return -1;
    }

    const char* tag = cp;
    // Determine whether "c" is a valid tag char.
    while (isalnum(*++cp) || (*cp == '_')) { }
    size_t tagLen = cp - tag;

    if (!isspace(*cp)) {
        fprintf(stderr, OUT_TAG ": invalid tag chars on line %d\n", lineNum);
        errno = EINVAL;
        return -1;
    }

    while (isspace(*cp) && (*cp != '\n')) ++cp;
    const char* fmt = NULL;
    size_t fmtLen = 0;
    if (*cp != '#') {
        fmt = cp;
        while ((*cp != '\n') && (*cp != '#')) ++cp;
        while ((cp > fmt) && isspace(*(cp - 1))) --cp;
        fmtLen = cp - fmt;
    }

    while (*cp != '\n') ++cp;
#ifdef DEBUG
    fprintf(stderr, "%d: %p: %.*s\n", lineNum, tag, (int)(cp - *pData), *pData);
#endif
    *pData = cp;

    if (map->emplaceUnique(tagIndex, TagFmt(tag, tagLen, fmt, fmtLen), true)) {
        return 0;
    }
    errno = EMLINK;
    return -1;
}

// Parse the tags out of the file.
static int parseMapLines(EventTagMap* map) {
    char* cp = static_cast<char*>(map->mapAddr);
    size_t len = map->mapLen;
    char* endp = cp + len;

    // insist on EOL at EOF; simplifies parsing and null-termination
    if (!len || (*(endp - 1) != '\n')) {
#ifdef DEBUG
        fprintf(stderr, OUT_TAG ": map file missing EOL on last line\n");
#endif
        errno = EINVAL;
        return -1;
    }

    bool lineStart = true;
    int lineNum = 1;
    while (cp < endp) {
        if (*cp == '\n') {
            lineStart = true;
            lineNum++;
        } else if (lineStart) {
            if (*cp == '#') {
                // comment; just scan to end
                lineStart = false;
            } else if (isdigit(*cp)) {
                // looks like a tag; scan it out
                if (scanTagLine(map, &cp, lineNum) != 0) {
                    return -1;
                }
                lineNum++;      // we eat the '\n'
                // leave lineStart==true
            } else if (isspace(*cp)) {
                // looks like leading whitespace; keep scanning
            } else {
                fprintf(stderr,
                        OUT_TAG ": unexpected chars (0x%02x) in tag number on line %d\n",
                        *cp, lineNum);
                errno = EINVAL;
                return -1;
            }
        } else {
            // this is a blank or comment line
        }
        cp++;
    }

    return 0;
}

// Open the map file and allocate a structure to manage it.
//
// We create a private mapping because we want to terminate the log tag
// strings with '\0'.
LIBLOG_ABI_PUBLIC EventTagMap* android_openEventTagMap(const char* fileName) {
    int save_errno;

    const char* tagfile = fileName ? fileName : EVENT_TAG_MAP_FILE;
    int fd = open(tagfile, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        save_errno = errno;
        fprintf(stderr, OUT_TAG ": unable to open map '%s': %s\n",
                tagfile, strerror(save_errno));
        errno = save_errno;
        return NULL;
    }
    off_t end = lseek(fd, 0L, SEEK_END);
    save_errno = errno;
    (void)lseek(fd, 0L, SEEK_SET);
    if (end < 0) {
        fprintf(stderr, OUT_TAG ": unable to seek map '%s' %s\n",
                tagfile, strerror(save_errno));
        close(fd);
        errno = save_errno;
        return NULL;
    }

    EventTagMap* newTagMap = new EventTagMap;
    if (newTagMap == NULL) {
        save_errno = errno;
        close(fd);
        errno = save_errno;
        return NULL;
    }

    newTagMap->mapAddr = mmap(NULL, end, PROT_READ | PROT_WRITE,
                              MAP_PRIVATE, fd, 0);
    save_errno = errno;
    close(fd);
    fd = -1;
    if ((newTagMap->mapAddr == MAP_FAILED) || (newTagMap->mapAddr == NULL)) {
        fprintf(stderr, OUT_TAG ": mmap(%s) failed: %s\n",
                tagfile, strerror(save_errno));
        delete newTagMap;
        errno = save_errno;
        return NULL;
    }

    newTagMap->mapLen = end;

    if (parseMapLines(newTagMap) != 0) {
        delete newTagMap;
        return NULL;
    }

    return newTagMap;
}

// Close the map.
LIBLOG_ABI_PUBLIC void android_closeEventTagMap(EventTagMap* map) {
    if (map) delete map;
}

// Look up an entry in the map.
LIBLOG_ABI_PUBLIC const char* android_lookupEventTag_len(const EventTagMap* map,
                                                         size_t *len,
                                                         unsigned int tag) {
    if (len) *len = 0;
    const TagFmt* str = map->find(tag);
    if (!str) return NULL;
    if (len) *len = str->first.length();
    return str->first.data();
}

// Look up an entry in the map.
LIBLOG_ABI_PUBLIC const char* android_lookupEventFormat_len(
        const EventTagMap* map, size_t *len, unsigned int tag) {
    if (len) *len = 0;
    const TagFmt* str = map->find(tag);
    if (!str) return NULL;
    if (len) *len = str->second.length();
    return str->second.data();
}

// This function is deprecated and replaced with android_lookupEventTag_len
// since it will cause the map to change from Shared and backed by a file,
// to Private Dirty and backed up by swap, albeit highly compressible. By
// deprecating this function everywhere, we save 100s of MB of memory space.
LIBLOG_ABI_PUBLIC const char* android_lookupEventTag(const EventTagMap* map,
                                                     unsigned int tag) {
    size_t len;
    const char* tagStr = android_lookupEventTag_len(map, &len, tag);

    if (!tagStr) return tagStr;
    char* cp = const_cast<char*>(tagStr);
    cp += len;
    if (*cp) *cp = '\0'; // Trigger copy on write :-( and why deprecated.
    return tagStr;
}

// Look up tagname, generate one if necessary, and return a tag
LIBLOG_ABI_PUBLIC int android_lookupEventTagNum(EventTagMap* map,
                                                const char* tagname,
                                                const char* format,
                                                int prio) {
    size_t len = strlen(tagname);
    if (!len) {
        errno = EINVAL;
        return -1;
    }

    if ((prio != ANDROID_LOG_UNKNOWN) && (prio < ANDROID_LOG_SILENT) &&
            !__android_log_is_loggable_len(prio, tagname, len,
                                           __android_log_is_debuggable() ?
                                             ANDROID_LOG_VERBOSE :
                                             ANDROID_LOG_DEBUG)) {
        errno = EPERM;
        return -1;
    }

    if (!format) format="";
    ssize_t fmtLen = strlen(format);
    int ret = map->find(TagFmt(tagname, len, format, fmtLen));
    if (ret != -1) return ret;

    // call event tag service to arrange for a new tag
    char *buf = NULL;
    // Can not use android::base::StringPrintf, asprintf + free instead.
    static const char command_template[] = "getEventTag name=%s format=\"%s\"";
    ret = asprintf(&buf, command_template, tagname, format);
    if (ret > 0) {
        // Add some buffer margin for an estimate of the full return content.
        char *cp;
        size_t size = ret - strlen(command_template) +
            strlen("65535\n4294967295\t?\t\t\t?\t# uid=32767\n\n\f?success?");
        if (size > (size_t)ret) {
            cp = static_cast<char*>(realloc(buf, size));
            if (cp) {
                buf = cp;
            } else {
                size = ret;
            }
        } else {
            size = ret;
        }
        // Ask event log tag service for an allocation
        if (__send_log_msg(buf, size) >= 0) {
            buf[size - 1] = '\0';
            unsigned long val = strtoul(buf, &cp, 10); // return size
            if ((buf != cp) && (val > 0) && (*cp == '\n')) { // truncation OK
                val = strtoul(cp + 1, &cp, 10); // allocated tag number
                if ((val > 0) && (val < UINT32_MAX) && (*cp == '\t')) {
                    free(buf);
                    ret = val;
                    // cache
                    map->emplaceUnique(ret,
                                       TagFmt(std::string(tagname, len),
                                              std::string(format, fmtLen)));
                    return ret;
                }
            }
        }
        free(buf);
    }

    // Hail Mary
    ret = map->find(MapString(tagname, len));
    if (ret == -1) errno = ESRCH;
    return ret;
}
