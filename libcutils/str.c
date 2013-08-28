/*
 * Copyright (C) 2013 Tresys Technologies LLC
 * Author: William Roberts <w.roberts@tresys.com>
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

#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdbool.h>

static char *_replace(char *str, char *old, char *new, bool global) {

    int err;
    size_t size;
    char *location;
    size_t index = 0;
    char *tmp = NULL;
    char *new_str = NULL;

    /* arguments must be sane pointers */
    if (!(str && old && new)) {
        errno = EINVAL;
        return NULL;
    }

    size = strlen(new);
    /*
     * if we are replacing with "" or attempting to replace "" just
     * return a copy of itself.
     */
    if (!size || old[0] == '\0') {
        /* errno set by strdup */
        return strdup(str);
    }

    /*
     * always alloc the original string so we don't have to worry about
     * overlapping memory and when to free or not to free.
     */
    tmp = strdup(str);
    if (!tmp) {
        /* errno set by strdup */
        return NULL;
    }

    do {

        location = strstr(&tmp[index], old);
        if (!location) {
            /* return path on global replace or no occurrence*/
            return tmp;
        }

        size += strlen(tmp) - strlen(old) + 1;

        new_str = calloc(sizeof(*tmp), size);
        if (!new_str) {
            /* errno should be set by calloc, back it up due to the free */
            err = errno;
            free(tmp);
            errno = err;
            return NULL;
        }

        /* copy the string that is to the left of the old text */
        strncat(new_str, tmp, ((location - tmp) * sizeof(*tmp)));

        /* jam in the new text we're replacing old with */
        strcat(new_str, new);

        /* record the index for global replacements */
        index = strlen(new_str);

        /* append the text that is PAST the old */
        strcat(new_str, &location[strlen(old)]);

        free(tmp);
        tmp = new_str;

    } while (global);

    /* return path on non-global replacements with occurrence*/
    return tmp;
}

char *replace(char *str, char *old, char *new) {
    return _replace(str, old, new, false);
}

char *replace_all(char *str, char *old, char *new) {
    return _replace(str, old, new, true);
}
