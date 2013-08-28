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

#ifndef _CUTILS_STR_H
#define _CUTILS_STR_H

#ifdef __cplusplus
extern "C" {
#endif

/** Replace first occurence of text in string
 * Replaces the first occurence, from the left, of old in string.
 *
 * @param str
 *     The string to search for occurences of old. This string stays
 *     unmodified.
 * @param old
 *     The text to replace with new.
 * @param new
 *     The text to replace old with.
 * @return
 *     The string with the first occurence of old replaced with new. If
 *     old is an empty string, it returns a copy of the sting. The sring
 *     returned was aquired via calloc and must be freed. NULL is returned
 *     with errno set to indicate the error.
 *     Possible Errors:
 *     ENOENT
 *         Old is not found in string
 *     EINVAL
 *         Arguments are invalid
 *     or Any of the errors found in man calloc(3)
 */
char *replace(char *str, char *old, char *new);

/** Replaces all occurences of text in string
 * @param str
 *     The string to search for occurences of old. This string stays
 *     unmodified.
 * @param old
 *     The text to replace with new.
 * @param new
 *     The text to replace old with.
 * @return
 *     The string with all occurences of old replaced with new.
 *     The same error's as replace()
 */
char *replace_all(char *str, char *old, char *new);

#ifdef __cplusplus
}
#endif

#endif /* __CUTILS_STR_H */

