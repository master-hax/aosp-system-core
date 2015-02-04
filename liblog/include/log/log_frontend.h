/*
**
** Copyright 2007-2014, The Android Open Source Project
**
** This file is dual licensed.  It may be redistributed and/or modified
** under the terms of the Apache 2.0 License OR version 2 of the GNU
** General Public License.
*/

#ifndef _LIBS_LOG_FRONTEND_H
#define _LIBS_LOG_FRONTEND_H

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Logging frontends, bit mask to select features. Function returns selection.
 */
#define LOGGER_NORMAL 0x0
#define LOGGER_KERNEL 0x1 /* Reserved/Deprecated */
#define LOGGER_NULL   0x2 /* Does not release resources of other selections */

int android_set_log_frontend(int frontend_flag);
int android_get_log_frontend();

#ifdef __cplusplus
}
#endif

#endif /* _LIBS_LOG_FRONTEND_H */
