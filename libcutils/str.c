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

char *replace(char *str, char *old, char *new) {

    int err;
    size_t size;
    char *new_str;
    char *location;

    if(!(str && old && new)) {
	errno = EINVAL;
        return NULL;
    }

    size = strlen(new);
    if(!size) {
        /* errno set by strdup */
        return strdup(old);
    }

    location = strstr(str, old);
    if(!location) {
	errno = ENOENT;
        return NULL;
    }

    size += strlen(str) + 1;
    new_str = calloc(sizeof(*str), size);
    if(!new_str) {
        /* errno should be set by calloc */
        return NULL;
    }

    /* Copy the string that is to the left of the old text */
    strncat(new_str, str, ((location - str) * sizeof(*str)));

    /* Jam in the new text we're replacing old with */
    strcat(new_str, new);

    /* Append the text that is PAST the old */
    strcat(new_str, &location[strlen(old)]);

    return new_str;
}


char *replace_all(char *str, char *old, char *new) {

    char *last;
    char *new_str;
    last = new_str = replace(str, old, new);
    while(new_str) {
        new_str = replace(new_str, old, new);
        if(!new_str) {
            if(errno == ENOENT) {
                errno = 0;
            }
            else {
                free(last);
                last = NULL;
            }
            break;
        }

        free(last);
        last = new_str;
    }

    return last;
}
