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
#include <string.h>

#include <android/log.h>
#include <cutils/properties.h>

#define WEAK __attribute__((weak))

/* Private copy portions of ../libcutils/properties.c prevent library loops */

#include <sys/system_properties.h>

int WEAK property_get(const char *key, char *value, const char *default_value)
{
    int len;

    len = __system_property_get(key, value);
    if (len > 0) {
        return len;
    }
    if (default_value) {
        len = strlen(default_value);
        if (len >= PROPERTY_VALUE_MAX) {
            len = PROPERTY_VALUE_MAX - 1;
        }
        memcpy(value, default_value, len);
        value[len] = '\0';
    }
    return len;
}

/* End of ../libcutils/properties.c */

static int __android_log_level(const char *tag, int def)
{
    char buf[PROPERTY_VALUE_MAX];

    if (!tag || !*tag) {
        return def;
    }
    {
        static const char log_namespace[] = "persist.log.tag.";
        char key[sizeof(log_namespace) + strlen(tag)];

        strcpy(key, log_namespace);
        strcpy(key + sizeof(log_namespace) - 1, tag);

        if (property_get(key + 8, buf, "") <= 0) {
            buf[0] = '\0';
        }
        if (!buf[0] && property_get(key, buf, "") <= 0) {
            buf[0] = '\0';
        }
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
