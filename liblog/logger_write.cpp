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

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>

#ifdef __BIONIC__
#include <android/set_abort_message.h>
#endif

#include <private/android_filesystem_config.h>
#include <private/android_logger.h>

#include "log_portability.h"
#include "logger.h"
#include "uio.h"

#if (FAKE_LOG_DEVICE == 0)
#include "logd_writer.h"
#include "pmsg_writer.h"
#else
#include "fake_log_device.h"
#endif

#define LOG_BUF_SIZE 1024

class ErrnoRestorer {
 public:
  ErrnoRestorer() : saved_errno_(errno) {}
  ~ErrnoRestorer() { errno = saved_errno_; }

 private:
  const int saved_errno_;
};

#if defined(__ANDROID__)
static int check_log_uid_permissions() {
  uid_t uid = getuid();

  /* Matches clientHasLogCredentials() in logd */
  if ((uid != AID_SYSTEM) && (uid != AID_ROOT) && (uid != AID_LOG)) {
    uid = geteuid();
    if ((uid != AID_SYSTEM) && (uid != AID_ROOT) && (uid != AID_LOG)) {
      gid_t gid = getgid();
      if ((gid != AID_SYSTEM) && (gid != AID_ROOT) && (gid != AID_LOG)) {
        gid = getegid();
        if ((gid != AID_SYSTEM) && (gid != AID_ROOT) && (gid != AID_LOG)) {
          int num_groups;
          gid_t* groups;

          num_groups = getgroups(0, NULL);
          if (num_groups <= 0) {
            return -EPERM;
          }
          groups = static_cast<gid_t*>(calloc(num_groups, sizeof(gid_t)));
          if (!groups) {
            return -ENOMEM;
          }
          num_groups = getgroups(num_groups, groups);
          while (num_groups > 0) {
            if (groups[num_groups - 1] == AID_LOG) {
              break;
            }
            --num_groups;
          }
          free(groups);
          if (num_groups <= 0) {
            return -EPERM;
          }
        }
      }
    }
  }
  return 0;
}
#endif

/*
 * Release any logger resources. A new log write will immediately re-acquire.
 */
void __android_log_close() {
#if (FAKE_LOG_DEVICE == 0)
  LogdClose();
  PmsgClose();
#else
  FakeClose();
#endif
}

static void GetTimestamp(struct timespec* ts) {
#if defined(__ANDROID__)
  clock_gettime(android_log_clockid(), ts);
#else
  ts->tv_sec = 0;
  ts->tv_nsec = 0;
  // Host ignores the timestamp, so no need to provide it.
#endif
}

static bool CanLogSecurity() {
#if defined(__ANDROID__)
  int ret = check_log_uid_permissions();
  if (ret < 0) {
    return false;
  }
  if (!__android_log_security()) {
    return false;
  }
  return true;
#endif
  return false;
}

static int WriteToLog(log_id_t log_id, struct iovec* vec, size_t nr, const struct timespec& ts) {
  if (log_id == LOG_ID_KERNEL) {
    return -EINVAL;
  }

#if (FAKE_LOG_DEVICE == 0)
  int ret = LogdWrite(log_id, ts, vec, nr);
  PmsgWrite(log_id, ts, vec, nr);
#else
  int ret = FakeWrite(log_id, ts, vec, nr);
#endif

  return ret;
}

int WriteTextToLog(int bufID, int prio, const char* tag, const char* msg,
                   const struct timespec& ts) {
  if (!tag) tag = "";

#if __BIONIC__
  if (prio == ANDROID_LOG_FATAL) {
    android_set_abort_message(msg);
  }
#endif

  struct iovec vec[3];
  vec[0].iov_base = (unsigned char*)&prio;
  vec[0].iov_len = 1;
  vec[1].iov_base = (void*)tag;
  vec[1].iov_len = strlen(tag) + 1;
  vec[2].iov_base = (void*)msg;
  vec[2].iov_len = strlen(msg) + 1;

  return WriteToLog(static_cast<log_id_t>(bufID), vec, 3, ts);
}

int __android_log_write(int prio, const char* tag, const char* msg) {
  return __android_log_buf_write(LOG_ID_MAIN, prio, tag, msg);
}

#define TEXT_PREAMBLE                                               \
  ErrnoRestorer errno_restorer;                                     \
                                                                    \
  struct timespec ts;                                               \
  GetTimestamp(&ts);                                                \
                                                                    \
  if (!__android_log_is_loggable(prio, tag, ANDROID_LOG_VERBOSE)) { \
    return -EPERM;                                                  \
  }

int __android_log_buf_write(int bufID, int prio, const char* tag, const char* msg) {
  TEXT_PREAMBLE

  return WriteTextToLog(bufID, prio, tag, msg, ts);
}

int __android_log_vprint(int prio, const char* tag, const char* fmt, va_list ap) {
  TEXT_PREAMBLE

  char buf[LOG_BUF_SIZE];

  vsnprintf(buf, LOG_BUF_SIZE, fmt, ap);

  return WriteTextToLog(LOG_ID_MAIN, prio, tag, buf, ts);
}

int __android_log_print(int prio, const char* tag, const char* fmt, ...) {
  TEXT_PREAMBLE

  va_list ap;
  char buf[LOG_BUF_SIZE];

  va_start(ap, fmt);
  vsnprintf(buf, LOG_BUF_SIZE, fmt, ap);
  va_end(ap);

  return WriteTextToLog(LOG_ID_MAIN, prio, tag, buf, ts);
}

int __android_log_buf_print(int bufID, int prio, const char* tag, const char* fmt, ...) {
  TEXT_PREAMBLE

  va_list ap;
  char buf[LOG_BUF_SIZE];

  va_start(ap, fmt);
  vsnprintf(buf, LOG_BUF_SIZE, fmt, ap);
  va_end(ap);

  return WriteTextToLog(bufID, prio, tag, buf, ts);
}

#undef TEXT_PREABMLE

void __android_log_assert(const char* cond, const char* tag, const char* fmt, ...) {
  char buf[LOG_BUF_SIZE];

  if (fmt) {
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, LOG_BUF_SIZE, fmt, ap);
    va_end(ap);
  } else {
    /* Msg not provided, log condition.  N.B. Do not use cond directly as
     * format string as it could contain spurious '%' syntax (e.g.
     * "%d" in "blocks%devs == 0").
     */
    if (cond)
      snprintf(buf, LOG_BUF_SIZE, "Assertion failed: %s", cond);
    else
      strcpy(buf, "Unspecified assertion failed");
  }

  // Log assertion failures to stderr for the benefit of "adb shell" users
  // and gtests (http://b/23675822).
  TEMP_FAILURE_RETRY(write(2, buf, strlen(buf)));
  TEMP_FAILURE_RETRY(write(2, "\n", 1));

  __android_log_write(ANDROID_LOG_FATAL, tag, buf);
  abort(); /* abort so we have a chance to debug the situation */
           /* NOTREACHED */
}

int __android_log_bwrite(int32_t tag, const void* payload, size_t len) {
  ErrnoRestorer errno_restorer;

  struct timespec ts;
  GetTimestamp(&ts);

  struct iovec vec[2];

  vec[0].iov_base = &tag;
  vec[0].iov_len = sizeof(tag);
  vec[1].iov_base = (void*)payload;
  vec[1].iov_len = len;

  return WriteToLog(LOG_ID_EVENTS, vec, 2, ts);
}

int __android_log_stats_bwrite(int32_t tag, const void* payload, size_t len) {
  ErrnoRestorer errno_restorer;

  struct timespec ts;
  GetTimestamp(&ts);

  struct iovec vec[2];

  vec[0].iov_base = &tag;
  vec[0].iov_len = sizeof(tag);
  vec[1].iov_base = (void*)payload;
  vec[1].iov_len = len;

  return WriteToLog(LOG_ID_STATS, vec, 2, ts);
}

int __android_log_security_bwrite(int32_t tag, const void* payload, size_t len) {
  ErrnoRestorer errno_restorer;

  struct timespec ts;
  GetTimestamp(&ts);

  if (!CanLogSecurity()) {
    return -EPERM;
  }

  struct iovec vec[2];

  vec[0].iov_base = &tag;
  vec[0].iov_len = sizeof(tag);
  vec[1].iov_base = (void*)payload;
  vec[1].iov_len = len;

  return WriteToLog(LOG_ID_SECURITY, vec, 2, ts);
}

/*
 * Like __android_log_bwrite, but takes the type as well.  Doesn't work
 * for the general case where we're generating lists of stuff, but very
 * handy if we just want to dump an integer into the log.
 */
int __android_log_btwrite(int32_t tag, char type, const void* payload, size_t len) {
  ErrnoRestorer errno_restorer;

  struct timespec ts;
  GetTimestamp(&ts);

  struct iovec vec[3];

  vec[0].iov_base = &tag;
  vec[0].iov_len = sizeof(tag);
  vec[1].iov_base = &type;
  vec[1].iov_len = sizeof(type);
  vec[2].iov_base = (void*)payload;
  vec[2].iov_len = len;

  return WriteToLog(LOG_ID_EVENTS, vec, 3, ts);
}

/*
 * Like __android_log_bwrite, but used for writing strings to the
 * event log.
 */
int __android_log_bswrite(int32_t tag, const char* payload) {
  ErrnoRestorer errno_restorer;

  struct timespec ts;
  GetTimestamp(&ts);

  struct iovec vec[4];
  char type = EVENT_TYPE_STRING;
  uint32_t len = strlen(payload);

  vec[0].iov_base = &tag;
  vec[0].iov_len = sizeof(tag);
  vec[1].iov_base = &type;
  vec[1].iov_len = sizeof(type);
  vec[2].iov_base = &len;
  vec[2].iov_len = sizeof(len);
  vec[3].iov_base = (void*)payload;
  vec[3].iov_len = len;

  return WriteToLog(LOG_ID_EVENTS, vec, 4, ts);
}

/*
 * Like __android_log_security_bwrite, but used for writing strings to the
 * security log.
 */
int __android_log_security_bswrite(int32_t tag, const char* payload) {
  ErrnoRestorer errno_restorer;

  struct timespec ts;
  GetTimestamp(&ts);

  if (!CanLogSecurity()) {
    return -EPERM;
  }

  struct iovec vec[4];
  char type = EVENT_TYPE_STRING;
  uint32_t len = strlen(payload);

  vec[0].iov_base = &tag;
  vec[0].iov_len = sizeof(tag);
  vec[1].iov_base = &type;
  vec[1].iov_len = sizeof(type);
  vec[2].iov_base = &len;
  vec[2].iov_len = sizeof(len);
  vec[3].iov_base = (void*)payload;
  vec[3].iov_len = len;

  return WriteToLog(LOG_ID_SECURITY, vec, 4, ts);
}
