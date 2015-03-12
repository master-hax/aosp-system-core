/*
** Copyright 2014, The Android Open Source Project
**
** Licensed under the Apache License, Version 2.0 (the "License");
** you may not use this file except in compliance with the License.
** You may obtain a copy of the License at
**
**     http://www.apache.org/licenses/LICENSE-2.0
**
** Unless required by applicable law or agreed to in writing, software
** distributed under the License is distributed on an "AS IS" BASIS,
** WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
** See the License for the specific language governing permissions and
** limitations under the License.
*/

#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#define _REALLY_INCLUDE_SYS__SYSTEM_PROPERTIES_H_
#include <sys/_system_properties.h>

#include <android/log.h>

static int __android_log_level(const char *tag, int def)
{
    static const char log_namespace[] = "persist.log.tag.";
    const size_t taglen = (tag && *tag) ? strlen(tag) : 0;
    char key[sizeof(log_namespace) + taglen];
    static char *last_tag;
    size_t i;
    char c = 0;
    /*
     * Single cache of four properties. Priorities are:
     *    log.tag.<tag>
     *    persist.log.tag.<tag>
     *    log.tag
     *    persist.log.tag
     * Where the missing tag matches all tags and becomes the
     * system global default.
     *
     * The cache only speeds up reading an existing entry and
     * subsequent tracking of changes. ToDo: skip N searches
     * if not found to gain some speedup by being sloppy?
     */
    static struct {
        const prop_info *pinfo;
        uint32_t serial;
        char c;
    } cache[4] = {
        { NULL, -1, 0 },
        { NULL, -1, 0 },
        { NULL, -1, 0 },
        { NULL, -1, 0 }
    };

    strcpy(key, log_namespace);

    if (taglen) {
        if (!last_tag || strcmp(last_tag, tag)) {
            /* invalidate log.tag.<tag> cache */
            for(i = 0; i < 2; ++i) {
                cache[i].pinfo = NULL;
                cache[i].serial = -1;
                cache[i].c = '\0';
            }
            free(last_tag);
            last_tag = NULL;
        }
        if (!last_tag) {
            last_tag = strdup(tag);
        }
        strcpy(key + sizeof(log_namespace) - 1, tag);
    }

    for(i = taglen ? 0 : 2; i < (sizeof(cache) / sizeof(cache[0])); ++i) {
        char buf[PROP_VALUE_MAX];

        if (i == 2) {
            /* clear '.' after log.tag */
            key[sizeof(log_namespace) - 2] = '\0';
        }

        if (!cache[i].pinfo) {
            cache[i].pinfo = __system_property_find((i & 1) ? key : (key + 8));
        }
        if (cache[i].pinfo) {
            uint32_t serial = __system_property_serial(cache[i].pinfo);
            if (serial != cache[i].serial) {
                cache[i].serial = serial;
                __system_property_read(cache[i].pinfo, 0, buf);
                cache[i].c = buf[0];
            }
        }
        if (cache[i].c) {
            c = cache[i].c;
            break;
        }
    }

    switch (toupper(c)) {
        case 'V': return ANDROID_LOG_VERBOSE;
        case 'D': return ANDROID_LOG_DEBUG;
        case 'I': return ANDROID_LOG_INFO;
        case 'W': return ANDROID_LOG_WARN;
        case 'E': return ANDROID_LOG_ERROR;
        case 'F': /* FALLTHRU */ /* Not officially supported */
        case 'A': return ANDROID_LOG_FATAL;
        case 'S': return -1; /* ANDROID_LOG_SUPPRESS */
    }
    return def;
}

int __android_log_is_loggable(int prio, const char *tag, int def)
{
    int logLevel = __android_log_level(tag, def);
    return logLevel >= 0 && prio >= logLevel;
}
