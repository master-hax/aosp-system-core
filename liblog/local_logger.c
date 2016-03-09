/*
 * Copyright (C) 2016 The Android Open Source Project
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

/*
 * local log buffer, with binder transport mechanism to debuggerd and
 * logd for content propagation.
 *
 * NB: liblog stands alone and we can not take lightly circular
 *     or additional dependencies to higher level libraries.
 */
#if defined(_WIN32)
#error "This can only compile on Android"
#endif

#include <errno.h>
#include <fcntl.h>
#include <linux/ashmem.h>
#include <pthread.h>
#include <pwd.h>
#include <sched.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/types.h>
#include <sys/uio.h>

#include <binder.h>
#include <cutils/list.h> /* template, no library dependency */
#include <private/android_filesystem_config.h>
#include <private/android_logger.h>
#include <system/thread_defs.h>

#include "config_read.h"
#include "config_write.h"
#include "log_portability.h"
#include "logger.h"

static const char baseServiceName[] = "android.logd";
static const char ashmemDevice[] = "/dev/ashmem";
static const uint32_t LOGD_DATA = 0x42;

static int writeToLocalInit();
static int writeToLocalAvailable(log_id_t logId);
static void writeToLocalReset();
static int writeToLocal(log_id_t logId, struct timespec *ts,
                        struct iovec *vec, size_t nr);

LIBLOG_HIDDEN struct android_log_transport_write localLoggerWrite = {
    .node = { &localLoggerWrite.node, &localLoggerWrite.node },
    .context.private = NULL,
    .name = "local",
    .available = writeToLocalAvailable,
    .open = writeToLocalInit,
    .close = writeToLocalReset,
    .write = writeToLocal,
};

static int writeToLocalVersion(struct android_log_logger *logger,
                               struct android_log_transport_context *transp);
static int writeToLocalRead(struct android_log_logger_list *logger_list,
                            struct android_log_transport_context *transp,
                            struct log_msg *log_msg);
static int writeToLocalPoll(struct android_log_logger_list *logger_list,
                            struct android_log_transport_context *transp);
static void writeToLocalClose(struct android_log_logger_list *logger_list,
                              struct android_log_transport_context *transp);
static int writeToLocalClear(struct android_log_logger *logger,
                             struct android_log_transport_context *transp);
static ssize_t writeToLocalGetSize(
        struct android_log_logger *logger,
        struct android_log_transport_context *transp);
static ssize_t writeToLocalSetSize(
        struct android_log_logger *logger,
        struct android_log_transport_context *transp __unused,
        size_t size);
static ssize_t writeToLocalGetReadbleSize(
        struct android_log_logger *logger,
        struct android_log_transport_context *transp);

struct android_log_transport_read localLoggerRead = {
    .node = { &localLoggerRead.node, &localLoggerRead.node },
    .name = "local",
    .available = writeToLocalAvailable,
    .version = writeToLocalVersion,
    .read = writeToLocalRead,
    .poll = writeToLocalPoll,
    .close = writeToLocalClose,
    .clear = writeToLocalClear,
    .getSize = writeToLocalGetSize,
    .setSize = writeToLocalSetSize,
    .getReadableSize = writeToLocalGetReadbleSize,
    .getPrune = NULL,
    .setPrune = NULL,
    .getStats = NULL,
};

/* binder calls */

static uint32_t svcmgrLookup(struct binder_state *bs,
                             uint32_t target, const char *name) {
  uint32_t handle;
  unsigned iodata[512/sizeof(unsigned)];
  struct binder_io msg, reply;

  bio_init(&msg, iodata, sizeof(iodata), 4);
  bio_put_uint32(&msg, 0);  /* strict mode header */
  bio_put_string16_x(&msg, SVC_MGR_NAME);
  bio_put_string16_x(&msg, name);

  if (binder_call(bs, &msg, &reply, target, SVC_MGR_CHECK_SERVICE)) {
    return 0;
  }

  handle = bio_get_ref(&reply);

  if (handle) {
    binder_acquire(bs, handle);
  }

  binder_done(bs, &msg, &reply);

  return handle;
}

static int logdPublish(struct binder_state *bs,
                       uint32_t target, const char *name, void *ptr) {
  int status;
  unsigned iodata[512/sizeof(unsigned)];
  struct binder_io msg, reply;

  bio_init(&msg, iodata, sizeof(iodata), 4);
  bio_put_uint32(&msg, 0); /* strict mode header */
  bio_put_string16_x(&msg, baseServiceName);
  bio_put_string16_x(&msg, name);
  bio_put_obj(&msg, ptr);

  /* borrowing SVC_MGR_ADD_SERVICE registration */
  if (binder_call(bs, &msg, &reply, target, SVC_MGR_ADD_SERVICE)) {
    return -1;
  }

  status = bio_get_uint32(&reply);

  binder_done(bs, &msg, &reply);

  return status;
}

static int logdPush(struct binder_state *bs, uint32_t target, uint32_t fd) {
  int status;
  unsigned iodata[512/sizeof(unsigned)];
  struct binder_io msg, reply;

  bio_init(&msg, iodata, sizeof(iodata), 4);
  bio_put_uint32(&msg, 0); /* strict mode header */
  bio_put_fd(&msg, fd);

  if (binder_call(bs, &msg, &reply, target, LOGD_DATA)) {
    return -1;
  }

  status = bio_get_uint32(&reply);

  binder_done(bs, &msg, &reply);

  return status;
}

struct LogBufferElement {
  struct listnode node;
  log_id_t logId;
  pid_t tid;
  log_time timestamp;
  unsigned short len;
  char msg[];
};

static const size_t MAX_SIZE_DEFAULT = 32768;

static struct LogBuffer {
  struct listnode head;
  pthread_rwlock_t listLock;
  char *serviceName; /* Also indicates ready by having a value */
  uint32_t logdHandle;
  struct binder_state *bs;
  pthread_t thread;
  /* Order and proximity important for memset */
  size_t number[LOG_ID_SECURITY];         /* clear memset          */
  size_t size[LOG_ID_SECURITY];           /* clear memset          */
  size_t totalSize[LOG_ID_SECURITY];      /* init memset           */
  size_t maxSize[LOG_ID_SECURITY];        /* init MAX_SIZE_DEFAULT */
  struct listnode *last[LOG_ID_SECURITY]; /* init &head            */
} logbuf = {
  .head = { &logbuf.head, &logbuf.head },
  .listLock = PTHREAD_RWLOCK_INITIALIZER,
};

static void LogBufferInit(struct LogBuffer *log) {
  size_t i;

  /* pthread_rwlock_init(&log->listLock, NULL); */
  pthread_rwlock_wrlock(&log->listLock);
  list_init(&log->head);
  memset(log->number, 0,
    sizeof(log->number) + sizeof(log->size) + sizeof(log->totalSize));
  for (i = 0; i < LOG_ID_SECURITY; ++i) {
    log->maxSize[i] = MAX_SIZE_DEFAULT;
    log->last[i] = &log->head;
  }
  asprintf(&log->serviceName, "%s@%d:%d", baseServiceName,
           __android_log_uid(), __android_log_pid());
  if (log->serviceName) {
    log->bs = binder_open(8192);
    if (log->bs) {
      log->logdHandle = svcmgrLookup(log->bs, (uint32_t)BINDER_SERVICE_MANAGER,
                                     baseServiceName);
    }
  }
  pthread_rwlock_unlock(&log->listLock);
}

static void LogBufferClear(struct LogBuffer *log) {
  size_t i;
  struct listnode *node;

  pthread_rwlock_wrlock(&log->listLock);
  memset(log->number, 0, sizeof(log->number) + sizeof(log->size));
  for (i = 0; i < LOG_ID_SECURITY; ++i) {
    log->last[i] = &log->head;
  }
  while ((node = list_head(&log->head)) != &log->head) {
    struct LogBufferElement *element;

    element = node_to_item(node, struct LogBufferElement, node);
    list_remove(node);
    free(element);
  }
  pthread_rwlock_unlock(&log->listLock);
}

static inline void LogBufferFree(struct LogBuffer *log) {
  pthread_rwlock_wrlock(&log->listLock);
  free(log->serviceName);
  log->serviceName = NULL;
  /* ToDo: wake up all readers */
  if (log->bs) {
    binder_close(log->bs);
    log->bs = NULL;
    sched_yield();
  }
  pthread_rwlock_unlock(&log->listLock);
  LogBufferClear(log);
}

static int writeAshmem(struct LogBuffer *log) {
  size_t len;
  struct listnode *node;
  int fd, result;
  void *ptr, *data;
  uid_t uid;
  pid_t pid;

  uid = __android_log_uid();
  if (uid == AID_ROOT) {
    return -EPERM;
  }
  pid = __android_log_pid();
  if (!pid) {
    return -EPERM;
  }

  result = -ENOMEM;
  fd = TEMP_FAILURE_RETRY(open(ashmemDevice, O_RDWR | O_CLOEXEC));
  if (fd < 0) {
    return errno ? -errno : result;
  }

  pthread_rwlock_rdlock(&log->listLock);

  if (!log->serviceName) {
    result = -ENODEV;
    pthread_rwlock_unlock(&log->listLock);
    close(fd);
    return result;
  }

  result = TEMP_FAILURE_RETRY(ioctl(fd, ASHMEM_SET_NAME, log->serviceName));
  if (result < 0) {
    result = errno ? -errno : -EPERM;
    pthread_rwlock_unlock(&log->listLock);
    close(fd);
    return result;
  }

  len = 0;

  list_for_each(node, &log->head) {
    struct LogBufferElement *element;

    element = node_to_item(node, struct LogBufferElement, node);
    len += sizeof(android_pmsg_log_header_t) + sizeof(android_log_header_t) + element->len;
  }

  result = TEMP_FAILURE_RETRY(ioctl(fd, ASHMEM_SET_SIZE, len));
  if (result < 0) {
    result = errno ? -errno : -EPERM;
    pthread_rwlock_unlock(&log->listLock);
    close(fd);
    return result;
  }
  result = TEMP_FAILURE_RETRY(ioctl(fd, ASHMEM_SET_PROT_MASK,
                                        PROT_READ | PROT_WRITE));
  if (result < 0) {
    result = errno ? -errno : -EPERM;
    pthread_rwlock_unlock(&log->listLock);
    close(fd);
    return result;
  }

  ptr = mmap(NULL, len, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
  if (ptr == MAP_FAILED) {
    result = errno ? -errno : -EPERM;
    pthread_rwlock_unlock(&log->listLock);
    close(fd);
    return result;
  }
  data = ptr;
  list_for_each(node, &log->head) {
    android_pmsg_log_header_t *pmsgHeader = (android_pmsg_log_header_t *)data;
    android_log_header_t *header = (android_log_header_t *)(pmsgHeader + 1);
    void *data = header + 1;
    struct LogBufferElement *element;

    pmsgHeader->magic = LOGGER_MAGIC;
    pmsgHeader->len = sizeof(*pmsgHeader) + sizeof(*header) + len;
    pmsgHeader->uid = uid;
    pmsgHeader->pid = pid;

    element = node_to_item(node, struct LogBufferElement, node);

    header->id = element->logId;
    header->tid = element->tid;
    header->realtime.tv_sec = element->timestamp.tv_sec;
    header->realtime.tv_nsec = element->timestamp.tv_nsec;

    if (len) {
      memcpy(data, element->msg, len);
      data = (void *)((uintptr_t)data + len);
    }
  }
  pthread_rwlock_unlock(&log->listLock);
  munmap(ptr, len);
  return fd;
}

static int LogBufferLog(struct LogBuffer *log,
                        struct LogBufferElement *element) {
  log_id_t logId = element->logId;

  pthread_rwlock_wrlock(&log->listLock);
  log->number[logId]++;
  log->size[logId] += element->len;
  log->totalSize[logId] += element->len;
  /* prune entry(s) until enough space is available */
  if (log->last[logId] == &log->head) {
    log->last[logId] = list_tail(&log->head);
  }
  while (log->size[logId] > log->maxSize[logId]) {
    struct listnode *node = log->last[logId];
    struct LogBufferElement *e;
    struct android_log_logger_list *logger_list;

    e = node_to_item(node, struct LogBufferElement, node);
    log->number[logId]--;
    log->size[logId] -= e->len;
    logger_list_rdlock();
    logger_list_for_each(logger_list) {
      struct android_log_transport_context *transp;

      transport_context_for_each(transp, logger_list) {
        if ((transp->transport == &localLoggerRead) &&
            (transp->context.node == node)) {
          if (node == &log->head) {
            transp->context.node = &log->head;
          } else {
            transp->context.node = node->next;
          }
        }
      }
    }
    logger_list_unlock();
    if (node != &log->head) {
      log->last[logId] = node->prev;
    }
    list_remove(node);
    free(e);
  }
  /* add entry to list */
  list_add_head(&log->head, &element->node);
  /* ToDo: wake up all readers */
  pthread_rwlock_unlock(&log->listLock);
  if ((logId != LOG_ID_EVENTS) && (logId != LOG_ID_SECURITY)) {
    unsigned char prio = element->msg[0];
    if (prio == ANDROID_LOG_FATAL) { /* ToDo wot about to crash buffer? */
      /* push content to logd */
      if (log->logdHandle) {
        int fd = writeAshmem(log);
        if (fd >= 0) {
          logdPush(log->bs, log->logdHandle, fd);
        }
      }
    }
  }
  return element->len;
}

static int logdHandler(struct binder_state *bs,
                       struct binder_transaction_data *txn,
                       struct binder_io *msg,
                       struct binder_io *reply) {
  uint16_t *s;
  size_t len;
  uint32_t strictPolicy;
  int fd;

  if (txn->code == PING_TRANSACTION) {
    return 0;
  }

  if (bs != logbuf.bs) {
    return -1;
  }

  strictPolicy = bio_get_uint32(msg);
  s = bio_get_string16(msg, &len);
  if (s == NULL) {
    return -1;
  }
  if (txn->sender_euid != AID_LOGD) {
    uid_t uid = __android_log_uid();
    if ((uid == AID_ROOT) || (txn->sender_euid != uid)) {
      return -1;
    }
  }

  switch(txn->code) {
  case LOGD_DATA:
    fd = writeAshmem(&logbuf);
    if (fd < 0) {
      return -1;
    }
    bio_put_fd(reply, (uint32_t)fd);
    return 0;
  default:
    return -1;
  }
  /* NOTREACH */

  bio_put_uint32(reply, 0);
  return 0;
}

static void *logdThreadStart(void *obj) {
  struct LogBuffer *log = (struct LogBuffer *)obj;

  pthread_rwlock_rdlock(&log->listLock);

  if (!log->serviceName) {
    pthread_rwlock_unlock(&log->listLock);
    return NULL;
  }

  prctl(PR_SET_NAME, log->serviceName);
  /* can't have libcutils dependency for set_sched_policy(0, SP_BACKGROUND); */
  setpriority(PRIO_PROCESS, 0, ANDROID_PRIORITY_BACKGROUND);

  pthread_rwlock_unlock(&log->listLock);

  binder_loop(log->bs, logdHandler);
  return NULL;
}

/*
 * return zero if permitted to log directly to logd,
 * return 1 if binder server started and
 * return negative error number if failed to start binder server.
 */
static int writeToLocalInit() {
  pthread_attr_t attr;
  struct LogBuffer *log;
  uid_t uid = __android_log_uid();

  if (writeToLocalAvailable(LOG_ID_MAIN) < 0) {
    return -EPERM;
  }

  log = &logbuf;
  if (log->serviceName) {
    return -EBUSY;
  }

  LogBufferInit(log);
  /*
   *  We do not require binder interface, local reader interface still works
   *    if (!log->serviceName || !log->bs || !log->logdHandle) {
   */
  if (!log->serviceName) {
    LogBufferFree(log);
    return -ENOMEM;
  }

  if (!log->bs) {
    return ENOMEM; /* no binder :-(, successful local-only logging */
  }

  if (!log->logdHandle) {
    return ESRCH; /* Could not find logd :-(, successful local-only logging */
  }

  /* inform logd of our existence, and bind our service receiver */
  if (logdPublish(log->bs, log->logdHandle, log->serviceName, log)) {
    return EPERM; /* logd misbehavior :-(, successful local-only logging */
  }

  /* start a single thread to take incoming binder transactions */
  if (!pthread_attr_init(&attr)) {
    struct sched_param param;

    memset(&param, 0, sizeof(param));
    pthread_attr_setschedparam(&attr, &param);
    pthread_attr_setschedpolicy(&attr, SCHED_BATCH);
    if (!pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED)) {
      if (pthread_create(&log->thread, &attr, logdThreadStart, log)) {
        return ECHILD; /* could not start thread :-(, local-only logging */
      }
    }
    pthread_attr_destroy(&attr);
  }

  return 0;
}

static void writeToLocalReset() {
  LogBufferFree(&logbuf);
}

static int writeToLocalAvailable(log_id_t logId) {
  uid_t uid;
  size_t i;

  if (logId >= LOG_ID_SECURITY) {
    return -EINVAL;
  }

  /* Android hard coded permitted */
  uid = __android_log_uid();
  if ((uid < AID_APP) && (getpwuid(uid) != NULL)) {
    return -EPERM;
  }

  /* Ask package manager for LOGD permissions */
  /* ToDo: Assume we do _not_ have permissions to go to LOGD */
  return 0;
}

static int writeToLocal(log_id_t logId, struct timespec *ts,
                        struct iovec *vec, size_t nr) {
  size_t len, i;
  struct LogBufferElement *element;

  if (logId >= LOG_ID_SECURITY) {
    return -EINVAL;
  }

  len = 0;
  for (i = 0; i < nr; ++i) {
    len += vec[i].iov_len;
  }

  if (len > LOGGER_ENTRY_MAX_PAYLOAD) {
    len = LOGGER_ENTRY_MAX_PAYLOAD;
  }
  element = (struct LogBufferElement *)calloc(1,
      sizeof(struct LogBufferElement) + len);
  if (!element) {
    return errno ? -errno : -ENOMEM;
  }
  element->timestamp.tv_sec = ts->tv_sec;
  element->timestamp.tv_nsec = ts->tv_nsec;
  element->tid = gettid();
  element->logId = logId;
  element->len = len;

  char *cp = element->msg;
  for (i = 0; i < nr; ++i) {
    size_t iov_len = vec[i].iov_len;
    if (iov_len > len) {
      iov_len = len;
    }
    memcpy(cp, vec[i].iov_base, iov_len);
    len -= iov_len;
    if (len == 0) {
      break;
    }
    cp += iov_len;
  }

  return LogBufferLog(&logbuf, element);
}

static int writeToLocalVersion(
        struct android_log_logger *logger __unused,
        struct android_log_transport_context *transp __unused) {
  return 3;
}

/* within reader lock, serviceName already validated */
static struct listnode *writeToLocalNode(
        struct android_log_logger_list *logger_list,
        struct android_log_transport_context *transp) {
  struct listnode *node;
  unsigned logMask;
  unsigned int tail;

  node = transp->context.node;
  if (node) {
    return node;
  }

  if (!logger_list->tail) {
    return transp->context.node = &logbuf.head;
  }

  logMask = transp->logMask;
  tail = logger_list->tail;

  for (node = list_head(&logbuf.head); node != &logbuf.head; node = node->next) {
    struct LogBufferElement *element;
    log_id_t logId;

    element = node_to_item(node, struct LogBufferElement, node);
    logId = element->logId;

    if ((logMask & (1 << logId)) && !--tail) {
      node = node->next;
      break;
    }
  }
  return transp->context.node = node;
}

static int writeToLocalRead(
        struct android_log_logger_list *logger_list,
        struct android_log_transport_context *transp,
        struct log_msg *log_msg) {
  int ret;
  struct listnode *node;
  unsigned logMask;

  pthread_rwlock_rdlock(&logbuf.listLock);
  if (!logbuf.serviceName) {
    pthread_rwlock_unlock(&logbuf.listLock);
    return (logger_list->mode & ANDROID_LOG_NONBLOCK) ? -ENODEV : 0;
  }

  logMask = transp->logMask;

  node = writeToLocalNode(logger_list, transp);

  ret = 0;

  while (node != list_head(&logbuf.head)) {
    struct LogBufferElement *element;
    log_id_t logId;

    node = node->prev;
    element = node_to_item(node, struct LogBufferElement, node);
    logId = element->logId;

    if (logMask & (1 << logId)) {
      ret = log_msg->entry_v3.len = element->len;
      log_msg->entry_v3.hdr_size = sizeof(log_msg->entry_v3);
      log_msg->entry_v3.pid = __android_log_pid();
      log_msg->entry_v3.tid = element->tid;
      log_msg->entry_v3.sec = element->timestamp.tv_sec;
      log_msg->entry_v3.nsec = element->timestamp.tv_nsec;
      log_msg->entry_v3.lid = logId;
      memcpy(log_msg->entry_v3.msg, element->msg, ret);
      break;
    }
  }

  transp->context.node = node;

  /* ToDo: if blocking, and no entry, put reader to sleep */
  pthread_rwlock_unlock(&logbuf.listLock);
  return ret;
}

static int writeToLocalPoll(
        struct android_log_logger_list *logger_list,
        struct android_log_transport_context *transp) {
  int ret = (logger_list->mode & ANDROID_LOG_NONBLOCK) ? -ENODEV : 0;

  pthread_rwlock_rdlock(&logbuf.listLock);

  if (logbuf.serviceName) {
    unsigned logMask = transp->logMask;
    struct listnode *node = writeToLocalNode(logger_list, transp);

    ret = (node != list_head(&logbuf.head));
    if (ret) {
      do {
        ret = !!(logMask & (1 << (node_to_item(node->prev,
                                               struct LogBufferElement,
                                               node))->logId));
      } while (!ret && ((node = node->prev) != list_head(&logbuf.head)));
    }

    transp->context.node = node;
  }

  pthread_rwlock_unlock(&logbuf.listLock);

  return ret;
}

static void writeToLocalClose(
        struct android_log_logger_list *logger_list __unused,
        struct android_log_transport_context *transp) {
  pthread_rwlock_wrlock(&logbuf.listLock);
  transp->context.node = list_head(&logbuf.head);
  pthread_rwlock_unlock(&logbuf.listLock);
}

static int writeToLocalClear(
        struct android_log_logger *logger,
        struct android_log_transport_context *unused __unused) {
  log_id_t logId = logger->logId;
  struct listnode *node, *n;

  if (logId >= LOG_ID_SECURITY) {
    return -EINVAL;
  }

  pthread_rwlock_wrlock(&logbuf.listLock);
  logbuf.number[logId] = 0;
  logbuf.last[logId] = &logbuf.head;
  list_for_each_safe(node, n, &logbuf.head) {
    struct LogBufferElement *element;
    element = node_to_item(node, struct LogBufferElement, node);

    if (logId == element->logId) {
      struct android_log_logger_list *logger_list;

      logger_list_rdlock();
      logger_list_for_each(logger_list) {
        struct android_log_transport_context *transp;

        transport_context_for_each(transp, logger_list) {
          if ((transp->transport == &localLoggerRead) &&
              (transp->context.node == node)) {
            transp->context.node = node->next;
          }
        }
      }
      logger_list_unlock();
      list_remove(node);
      free(element);
    }
  }

  pthread_rwlock_unlock(&logbuf.listLock);

  return 0;
}

static ssize_t writeToLocalGetSize(
        struct android_log_logger *logger,
        struct android_log_transport_context *transp __unused) {
  ssize_t ret = -EINVAL;
  log_id_t logId = logger->logId;

  if (logId < LOG_ID_SECURITY) {
    pthread_rwlock_rdlock(&logbuf.listLock);
    ret = logbuf.maxSize[logId];
    pthread_rwlock_unlock(&logbuf.listLock);
  }

  return ret;
}

static ssize_t writeToLocalSetSize(
        struct android_log_logger *logger,
        struct android_log_transport_context *transp __unused,
        size_t size) {
  ssize_t ret = -EINVAL;

  if ((size > LOGGER_ENTRY_MAX_LEN) || (size < (4 * 1024 * 1024))) {
    log_id_t logId = logger->logId;
    if (logId < LOG_ID_SECURITY) {
      pthread_rwlock_wrlock(&logbuf.listLock);
      ret = logbuf.maxSize[logId] = size;
      pthread_rwlock_unlock(&logbuf.listLock);
    }
  }

  return ret;
}

static ssize_t writeToLocalGetReadbleSize(
        struct android_log_logger *logger,
        struct android_log_transport_context *transp __unused) {
  ssize_t ret = -EINVAL;
  log_id_t logId = logger->logId;

  if (logId < LOG_ID_SECURITY) {
    pthread_rwlock_rdlock(&logbuf.listLock);
    ret = logbuf.serviceName ? logbuf.size[logId] : -EBADF;
    pthread_rwlock_unlock(&logbuf.listLock);
  }

  return ret;
}
