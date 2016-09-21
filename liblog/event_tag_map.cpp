/*
 * Copyright (C) 2007 The Android Open Source Project
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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>

#include <functional>
#include <string>
#include <unordered_map>

#include <log/event_tag_map.h>

#include "log_portability.h"

#define OUT_TAG "EventTagMap"

class MapString {
private:
    const char*  _str;
    const size_t _len;

public:
    const char* str() const { return _str; }
    size_t len() const { return _len; }

    bool operator== (const MapString& rval) const {
        if (len() != rval.len()) return false;
        if (len() == 0) return true;
        if (*str() != *rval.str()) return false;
        if (len() == 1) return true;
        return strncmp(str() + 1, rval.str() + 1, len() - 1) == 0;
    }
    bool operator!= (const MapString& rval) const {
        return !(*this == rval);
    }

    MapString(const char* str, size_t len) : _str(str), _len(len) { }
    MapString(const MapString &&rval) : _str(rval._str), _len(rval._len) { }
    MapString(const MapString &rval) : _str(rval._str), _len(rval._len) { }
};

// Hash for MapString borrows from internal knowledge of std::string
template <> struct _LIBCPP_TYPE_VIS_ONLY std::hash<MapString>
        : public std::unary_function<const MapString, size_t> {
    _LIBCPP_INLINE_VISIBILITY
    size_t operator()(const MapString __t) const _NOEXCEPT {
        if (!__t.len()) return 0;
        return __do_string_hash(__t.str(), __t.str() + __t.len());
    }
};

class TagFmt {
public:
    const MapString tag;
    const MapString fmt;

    bool operator== (const TagFmt& rval) const {
        if (tag != rval.tag) return false;
        return fmt == rval.fmt;
    }

    TagFmt(const char* tag, size_t tagLen, const char* fmt, size_t fmtLen) :
        tag(tag, tagLen), fmt(fmt, fmtLen) { }
};

template <> struct _LIBCPP_TYPE_VIS_ONLY std::hash<TagFmt>
        : public std::unary_function<const TagFmt, size_t> {
    _LIBCPP_INLINE_VISIBILITY
    size_t operator()(const TagFmt __t) const _NOEXCEPT {
        // Tag is typically unique.  Cost us an extra 100ns for the lookup if:
        // return std::hash<MapString>()(__t.tag) ^
        //        std::hash<MapString>()(__t.fmt);
        return std::hash<MapString>()(__t.tag);
    }
};

// Map
struct EventTagMap {
    // memory-mapped source file; we get strings from here
    void*  mapAddr;
    size_t mapLen;

    std::unordered_map<uint32_t, TagFmt> Idx2TagFmt;

    EventTagMap() : mapAddr(NULL), mapLen(0) { }

    ~EventTagMap() {
        Idx2TagFmt.clear();
        if (mapAddr) {
            munmap(mapAddr, mapLen);
            mapAddr = 0;
        }
    }
};

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

    int save_errno = 0;

    std::unordered_map<uint32_t, TagFmt>::const_iterator it;
    it = map->Idx2TagFmt.find(tagIndex);
    if (it != map->Idx2TagFmt.end()) {
        fprintf(stderr,
                OUT_TAG ": duplicate tag entries %" PRIu32
                    ":%.*s:%.*s and %" PRIu32 ":%.*s:%.*s)\n",
                it->first,
                (int)it->second.tag.len(), it->second.tag.str(),
                (int)it->second.fmt.len(), it->second.fmt.str(),
                tagIndex, (int)tagLen, tag, (int)fmtLen, fmt);
        errno = EMLINK;
        return -1;
    }

    map->Idx2TagFmt.emplace(std::make_pair(tagIndex,
                                           TagFmt(tag, tagLen, fmt, fmtLen)));
    return 0;
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

    int lineStart = 1;
    int lineNum = 1;
    while (cp < endp) {
        if (*cp == '\n') {
            lineStart = 1;
            lineNum++;
        } else if (lineStart) {
            if (*cp == '#') {
                // comment; just scan to end
                lineStart = 0;
            } else if (isdigit(*cp)) {
                // looks like a tag; scan it out
                if (scanTagLine(map, &cp, lineNum) != 0) {
                    return -1;
                }
                lineNum++;      // we eat the '\n'
                // leave lineStart==1
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
    EventTagMap* newTagMap;
    off_t end = 0;
    int save_errno, fd = -1;

    const char* tagfile = fileName ? fileName : EVENT_TAG_MAP_FILE;

    fd = open(tagfile, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        save_errno = errno;
        fprintf(stderr, OUT_TAG ": unable to open map '%s': %s\n",
                tagfile, strerror(save_errno));
        goto fail_errno;
    }
    end = lseek(fd, 0L, SEEK_END);
    save_errno = errno;
    (void)lseek(fd, 0L, SEEK_SET);
    if (end < 0) {
        fprintf(stderr, OUT_TAG ": unable to seek map '%s' %s\n",
                tagfile, strerror(save_errno));
        goto fail_close;
    }

    newTagMap = new EventTagMap;
    if (newTagMap == NULL) {
        save_errno = errno;
        goto fail_close;
    }

    if (fd >= 0) {
        newTagMap->mapAddr = mmap(NULL, end, PROT_READ | PROT_WRITE,
                                  MAP_PRIVATE, fd, 0);
        save_errno = errno;
        close(fd);
        fd = -1;
        if ((newTagMap->mapAddr != MAP_FAILED) &&
            (newTagMap->mapAddr != NULL)) {
            newTagMap->mapLen = end;
        } else {
            fprintf(stderr, OUT_TAG ": mmap(%s) failed: %s\n",
                    tagfile, strerror(save_errno));
            goto fail_unmap;
        }
    }

    if (parseMapLines(newTagMap) != 0) goto fail_unmap;

    return newTagMap;

fail_unmap:
    save_errno = EINVAL;
    delete newTagMap;
fail_close:
    close(fd);
fail_errno:
    errno = save_errno;
    return NULL;
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

    std::unordered_map<uint32_t, TagFmt>::const_iterator it;
    uint32_t tagIndex = tag;
    it = map->Idx2TagFmt.find(tagIndex);
    if (it == map->Idx2TagFmt.end()) return NULL;

    const TagFmt& str = it->second;
    if (len) *len = str.tag.len();
    return str.tag.str();
}

// Look up an entry in the map.
LIBLOG_ABI_PUBLIC const char* android_lookupEventFormat_len(
        const EventTagMap* map, size_t *len, unsigned int tag) {
    if (len) *len = 0;

    std::unordered_map<uint32_t, TagFmt>::const_iterator it;
    uint32_t tagIndex = tag;
    it = map->Idx2TagFmt.find(tagIndex);
    if (it == map->Idx2TagFmt.end()) return NULL;

    const TagFmt& str = it->second;
    if (len) *len = str.fmt.len();
    return str.fmt.str();
}

LIBLOG_ABI_PUBLIC const char* android_lookupEventTag(const EventTagMap* map,
                                                     unsigned int tag) {
    size_t len;
    const char* tagStr = android_lookupEventTag_len(map, &len, tag);

    if (!tagStr) return tagStr;
    char* cp = const_cast<char*>(tagStr);
    cp += len;
    if (*cp) *cp = '\0'; // Trigger copy on write :-( causes b/31456426
    return tagStr;
}
