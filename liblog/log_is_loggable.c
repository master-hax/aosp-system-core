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
    char buf[PROP_VALUE_MAX];
    static const char log_namespace[] = "persist.log.tag.";
    const size_t taglen = (tag && *tag) ? strlen(tag) : 0;
    char key[sizeof(log_namespace) + taglen];
#   define runtime_key (key + 8)

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
    static const prop_info* all_persist_pinfo, *all_runtime_pinfo;
    static uint32_t all_persist_serial = -1;
    static uint32_t all_runtime_serial = -1;
    static char all_persist_c, all_runtime_c;
    char persist_c = 0;
    char runtime_c = 0;
    uint32_t serial;

    strcpy(key, log_namespace);

    if (taglen) {
        static char *last_tag;
        static const prop_info* persist_pinfo, *runtime_pinfo;
        static uint32_t persist_serial = -1;
        static uint32_t runtime_serial = -1;
        static char tag_persist_c, tag_runtime_c;

        if (!last_tag || strcmp(last_tag, tag)) {
            persist_pinfo = runtime_pinfo = NULL;
            persist_serial = runtime_serial = -1;
            tag_persist_c = tag_runtime_c = '\0';
            free(last_tag);
            last_tag = NULL;
        }
        if (!last_tag) {
            last_tag = strdup(tag);
        }

        strcpy(key + sizeof(log_namespace) - 1, tag);

        if (!runtime_pinfo) {
            runtime_pinfo = __system_property_find(runtime_key);
        }
        if (runtime_pinfo) {
            serial = __system_property_serial(runtime_pinfo);
            if (serial != runtime_serial) {
                runtime_serial = serial;
                __system_property_read(runtime_pinfo, 0, buf);
                tag_runtime_c = buf[0];
            }
        }
        if (!tag_runtime_c && !persist_pinfo) {
            persist_pinfo = __system_property_find(key);
        }
        if (persist_pinfo) {
            serial = __system_property_serial(persist_pinfo);
            if (serial != persist_serial) {
                persist_serial = serial;
                __system_property_read(persist_pinfo, 0, buf);
                tag_persist_c = buf[0];
            }
        }

        runtime_c = tag_runtime_c;
        persist_c = tag_persist_c;
    }

    if (!runtime_c && !persist_c) {
        key[sizeof(log_namespace) - 2] = '\0';
        if (!all_runtime_pinfo) {
            all_runtime_pinfo = __system_property_find(runtime_key);
        }
        if (all_runtime_pinfo) {
            serial = __system_property_serial(all_runtime_pinfo);
            if (serial != all_runtime_serial) {
                all_runtime_serial = serial;
                __system_property_read(all_runtime_pinfo, 0, buf);
                all_runtime_c = buf[0];
            }
        }

        if (!all_runtime_c) {
            if (!all_persist_pinfo) {
                all_persist_pinfo = __system_property_find(key);
            }
            if (all_persist_pinfo) {
                serial = __system_property_serial(all_persist_pinfo);
                if (serial != all_persist_serial) {
                    all_persist_serial = serial;
                    __system_property_read(all_persist_pinfo, 0, buf);
                    all_persist_c = buf[0];
                }
            }
        }
    }
#   undef runtime_key

    buf[0] = '\0';
    if (all_persist_c) {
        buf[0] = all_persist_c;
    }
    if (all_runtime_c) {
        buf[0] = all_runtime_c;
    }
    if (persist_c) {
        buf[0] = persist_c;
    }
    if (runtime_c) {
        buf[0] = runtime_c;
    }

    switch (toupper(buf[0])) {
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
