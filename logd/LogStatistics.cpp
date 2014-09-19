/*
 * Copyright (C) 2014 The Android Open Source Project
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

#include <fcntl.h>
#include <stdarg.h>
#include <time.h>

#include <log/logger.h>
#include <private/android_filesystem_config.h>
#include <utils/String8.h>

#include "LogStatistics.h"

PidStatisticsGone::PidStatisticsGone(const PidStatistics *copy)
        : pid(copy->getPid())
        , mElements(copy->elements())
{ }

PidStatistics::PidStatistics(pid_t pid, char *name)
        : pid(pid)
        , mSizesTotal(0)
        , mElementsTotal(0)
        , mSizes(0)
        , mElements(0)
        , name(name)
        , mGone(false)
        , mMultiple(false)
{ }

#ifdef DO_NOT_ERROR_IF_PIDSTATISTICS_USES_A_COPY_CONSTRUCTOR
PidStatistics::PidStatistics(const PidStatistics &copy)
        : pid(copy.pid)
        , mSizesTotal(copy.mSizesTotal)
        , mElementsTotal(copy.mElementsTotal)
        , mSizes(copy.mSizes)
        , mElements(copy.mElements)
        , name(copy.name ? strdup(copy.name) : NULL)
        , mGone(copy.mGone)
        , mMultiple(copy.mMultiple)
        , gonePids(copy.gonePids)
{ }
#endif

PidStatistics::~PidStatistics() {
    free(name);
}

bool PidStatistics::pidGone() {
    if (mGone || (pid == gone)) {
        return true;
    }
    if (pid == 0) {
        return false;
    }
    if (kill(pid, 0) && (errno != EPERM)) {
        mGone = true;
        return true;
    }
    return false;
}

void PidStatistics::setName(char *new_name) {
    free(name);
    name = new_name;
}

PidStatisticsGone *PidStatistics::findMatch(pid_t ppid) {
    PidStatisticsGoneCollection::iterator it;
    for (it = begin(); it != end(); ++it) {
        PidStatisticsGone &p = *it;
        if (p.getPid() == ppid) {
            return &p;
        }
    }
    return NULL;
}

bool PidStatistics::pidMatches(pid_t ppid) {
    if (getPid() == ppid) {
        return true;
    }
    return findMatch(ppid) != NULL;
}

void PidStatistics::add(unsigned short size) {
    mSizesTotal += size;
    ++mElementsTotal;
    mSizes += size;
    ++mElements;
}

void PidStatistics::add(PidStatistics *p) {
    mSizesTotal += p->mSizesTotal;
    mElementsTotal += p->mElementsTotal;
    mSizes += p->mSizes;
    mElements += p->mElements;

    pid_t ppid = p->getPid();
    if (getPid() != ppid) {
        PidStatisticsGone *pq = findMatch(ppid);
        if (pq) {
            pq->add(p);
        } else {
            PidStatisticsGone pg(p);
            push_back(pg);
        }
    }
    for(PidStatisticsGoneCollection::iterator it = p->begin(); it != p->end(); ++it) {
        PidStatisticsGone &pl = *it;
        PidStatisticsGone *pr = findMatch(pl.getPid());
        if (pr) {
            pr->add(pl);
        } else {
            push_back(pl);
        }
    }
}

bool PidStatistics::subtract(unsigned short size, pid_t ppid) {
    PidStatisticsGoneCollection::iterator it;
    for (it = begin(); it != end(); ++it) {
        PidStatisticsGone &pg = *it;
        if ((pg.getPid() == ppid) && pg.subtract()) {
            erase(it);
            break;
        }
    }
    if (mSizes < size) {
        mSizes = 0;
    } else {
        mSizes -= size;
    }
    if (mElements) {
        --mElements;
    }
    return (mElements == 0) && pidGone();
}

void PidStatistics::addTotal(size_t size, size_t element) {
    if (pid == gone) {
        mSizesTotal += size;
        mElementsTotal += element;
    }
}

// must call free to release return value
//  If only we could sniff our own logs for:
//   <time> <pid> <pid> E AndroidRuntime: Process: <name>, PID: <pid>
//  which debuggerd prints as a process is crashing.
char *PidStatistics::pidToName(pid_t pid) {
    char *retval = NULL;
    if (pid == 0) { // special case from auditd for kernel
        retval = strdup("logd.auditd");
    } else if (pid != gone) {
        char buffer[512];
        snprintf(buffer, sizeof(buffer), "/proc/%u/cmdline", pid);
        int fd = open(buffer, O_RDONLY);
        if (fd >= 0) {
            ssize_t ret = read(fd, buffer, sizeof(buffer));
            if (ret > 0) {
                buffer[sizeof(buffer)-1] = '\0';
                // frameworks intermediate state
                if (strcmp(buffer, "<pre-initialized>")) {
                    retval = strdup(buffer);
                }
            }
            close(fd);
        }
    }
    return retval;
}

char PidStatistics::pidType() {
    return pidMultiple()
        ? (pidGone() ? '@' : '*')
        : (pidGone() ? '?' : ' ');
}

UidStatistics::UidStatistics(uid_t uid)
        : uid(uid)
        , mSizes(0)
        , mElements(0) {
    Pids.clear();
}

UidStatistics::~UidStatistics() {
    PidStatisticsCollection::iterator it;
    for (it = begin(); it != end();) {
        delete (*it);
        it = erase(it);
    }
}

bool UidStatistics::add(unsigned short size, pid_t pid) {
    mSizes += size;
    ++mElements;

    PidStatistics *p = NULL;
    PidStatisticsCollection::iterator last;
    PidStatisticsCollection::iterator it;
    for (last = it = begin(); it != end(); last = it, ++it) {
        p = *it;
        if (p->pidMatches(pid)) {
            char *name = p->getName();
            if (!name || !*name) {
                name = pidToName(p->getPid());
                if (name) {
                    if (*name) {
                        p->setName(name);
                    } else {
                        free(name);
                        name = NULL;
                    }
                }
            }
            p->add(size);
            return false;
        }
    }
    // insert if the gone entry.
    bool insert_before_last = (last != it) && p && (p->getPid() == p->gone);

    // Second pass to see if new pid is a restart, this will allow us
    // to coalesce reports from a single service that crashes, but not from a
    // service that runs multiple parallel instances (eg: dex2oat)
    bool replace = false;
    char *name = pidToName(pid);
    if (name) {
        for (it = begin(); it != end();  ++it) {
            p = *it;
            char *pname = p->getName();
            bool gone = false, set_gone = !pname || !*pname;
            if (set_gone) {
                gone = p->pidGone();
                if (gone) {
                    pname = NULL;
                } else {
                    pname = pidToName(p->getPid());
                    if (pname) {
                        if (*pname) {
                            p->setName(pname);
                        } else {
                            free(pname);
                            pname = NULL;
                        }
                    }
                }
            }
            if (pname && !strcmp(name, pname)) {
               replace = set_gone ? gone : p->pidGone();
               if (!replace) {
                   break;
               }
            }
        }
    }
    p = new PidStatistics(pid, name);
    if (replace) {
        for (it = begin(); it != end();) {
           PidStatistics *pp = *it;
           char *pname = pp->getName();
           if (pname && *pname && !strcmp(name, pname)) {
               p->add(pp);
               delete pp;
               it = erase(it);
           } else {
               ++it;
           }
        }
    }

    if (insert_before_last) {
        insert(last, p);
    } else {
        push_back(p);
    }
    p->add(size);
    return replace;
}

void UidStatistics::subtract(unsigned short size, pid_t pid) {
    if (size > mSizes) {
        mSizes = 0;
    } else {
        mSizes -= size;
    }
    if (mElements) {
        --mElements;
    }

    PidStatisticsCollection::iterator it;
    for (it = begin(); it != end(); ++it) {
        PidStatistics *p = *it;
        if (p->pidMatches(pid)) {
            if (p->subtract(size, pid)) {
                size_t szsTotal = p->sizesTotal();
                size_t elsTotal = p->elementsTotal();
                delete p;
                erase(it);
                it = end();
                --it;
                if (it == end()) {
                    p = new PidStatistics(p->gone);
                    push_back(p);
                } else {
                    p = *it;
                    if (p->getPid() != p->gone) {
                        p = new PidStatistics(p->gone);
                        push_back(p);
                    }
                }
                p->addTotal(szsTotal, elsTotal);
            }
            return;
        }
    }
}

void UidStatistics::sort() {
    for (bool pass = true; pass;) {
        pass = false;
        PidStatisticsCollection::iterator it = begin();
        if (it != end()) {
            PidStatisticsCollection::iterator lt = it;
            PidStatistics *l = (*lt);
            while (++it != end()) {
                PidStatistics *n = (*it);
                if ((n->getPid() != n->gone) && (n->sizes() > l->sizes())) {
                    pass = true;
                    erase(it);
                    insert(lt, n);
                    it = lt;
                    n = l;
                }
                lt = it;
                l = n;
            }
        }
    }
}

size_t UidStatistics::sizes(pid_t pid) {
    if (pid == pid_all) {
        return sizes();
    }

    PidStatisticsCollection::iterator it;
    for (it = begin(); it != end(); ++it) {
        PidStatistics *p = *it;
        if (p->pidMatches(pid)) {
            return p->sizes();
        }
    }
    return 0;
}

size_t UidStatistics::elements(pid_t pid) {
    if (pid == pid_all) {
        return elements();
    }

    PidStatisticsCollection::iterator it;
    for (it = begin(); it != end(); ++it) {
        PidStatistics *p = *it;
        if (p->pidMatches(pid)) {
            return p->elements();
        }
    }
    return 0;
}

size_t UidStatistics::sizesTotal(pid_t pid) {
    size_t sizes = 0;
    PidStatisticsCollection::iterator it;
    for (it = begin(); it != end(); ++it) {
        PidStatistics *p = *it;
        if ((pid == pid_all) || p->pidMatches(pid)) {
            sizes += p->sizesTotal();
        }
    }
    return sizes;
}

size_t UidStatistics::elementsTotal(pid_t pid) {
    size_t elements = 0;
    PidStatisticsCollection::iterator it;
    for (it = begin(); it != end(); ++it) {
        PidStatistics *p = *it;
        if ((pid == pid_all) || p->pidMatches(pid)) {
            elements += p->elementsTotal();
        }
    }
    return elements;
}

LidStatistics::LidStatistics() {
    Uids.clear();
}

LidStatistics::~LidStatistics() {
    UidStatisticsCollection::iterator it;
    for (it = begin(); it != end();) {
        delete (*it);
        it = Uids.erase(it);
    }
}

bool LidStatistics::add(unsigned short size, uid_t uid, pid_t pid) {
    UidStatistics *u;
    UidStatisticsCollection::iterator it;
    UidStatisticsCollection::iterator last;

    if (uid == (uid_t) -1) { // init
        uid = (uid_t) AID_ROOT;
    }

    for (last = it = begin(); it != end(); last = it, ++it) {
        u = *it;
        if (uid == u->getUid()) {
            bool replace = u->add(size, pid);
            if ((last != it) && ((*last)->sizesTotal() < u->sizesTotal())) {
                Uids.erase(it);
                Uids.insert(last, u);
            }
            return replace;
        }
    }
    u = new UidStatistics(uid);
    if ((last != it) && ((*last)->sizesTotal() < (size_t) size)) {
        Uids.insert(last, u);
    } else {
        Uids.push_back(u);
    }
    return u->add(size, pid);
}

void LidStatistics::subtract(unsigned short size, uid_t uid, pid_t pid) {
    if (uid == (uid_t) -1) { // init
        uid = (uid_t) AID_ROOT;
    }

    UidStatisticsCollection::iterator it;
    for (it = begin(); it != end(); ++it) {
        UidStatistics *u = *it;
        if (uid == u->getUid()) {
            u->subtract(size, pid);
            return;
        }
    }
}

void LidStatistics::sort() {
    for (bool pass = true; pass;) {
        pass = false;
        UidStatisticsCollection::iterator it = begin();
        if (it != end()) {
            UidStatisticsCollection::iterator lt = it;
            UidStatistics *l = (*lt);
            while (++it != end()) {
                UidStatistics *n = (*it);
                if (n->sizes() > l->sizes()) {
                    pass = true;
                    Uids.erase(it);
                    Uids.insert(lt, n);
                    it = lt;
                    n = l;
                }
                lt = it;
                l = n;
            }
        }
    }
}

size_t LidStatistics::sizes(uid_t uid, pid_t pid) {
    size_t sizes = 0;
    UidStatisticsCollection::iterator it;
    for (it = begin(); it != end(); ++it) {
        UidStatistics *u = *it;
        if ((uid == uid_all) || (uid == u->getUid())) {
            sizes += u->sizes(pid);
        }
    }
    return sizes;
}

size_t LidStatistics::elements(uid_t uid, pid_t pid) {
    size_t elements = 0;
    UidStatisticsCollection::iterator it;
    for (it = begin(); it != end(); ++it) {
        UidStatistics *u = *it;
        if ((uid == uid_all) || (uid == u->getUid())) {
            elements += u->elements(pid);
        }
    }
    return elements;
}

size_t LidStatistics::sizesTotal(uid_t uid, pid_t pid) {
    size_t sizes = 0;
    UidStatisticsCollection::iterator it;
    for (it = begin(); it != end(); ++it) {
        UidStatistics *u = *it;
        if ((uid == uid_all) || (uid == u->getUid())) {
            sizes += u->sizesTotal(pid);
        }
    }
    return sizes;
}

size_t LidStatistics::elementsTotal(uid_t uid, pid_t pid) {
    size_t elements = 0;
    UidStatisticsCollection::iterator it;
    for (it = begin(); it != end(); ++it) {
        UidStatistics *u = *it;
        if ((uid == uid_all) || (uid == u->getUid())) {
            elements += u->elementsTotal(pid);
        }
    }
    return elements;
}

LogStatistics::LogStatistics()
        : mStatistics(false)
        , dgramQlenStatistics(false)
        , start(CLOCK_MONOTONIC) {
    log_id_for_each(i) {
        mSizes[i] = 0;
        mElements[i] = 0;
    }

    for(unsigned short bucket = 0; dgramQlen(bucket); ++bucket) {
        mMinimum[bucket].tv_sec = mMinimum[bucket].tv_sec_max;
        mMinimum[bucket].tv_nsec = mMinimum[bucket].tv_nsec_max;
    }
}

//   Each bucket below represents a dgramQlen of log messages. By
//   finding the minimum period of time from start to finish
//   of each dgramQlen, we can get a performance expectation for
//   the user space logger. The net result is that the period
//   of time divided by the dgramQlen will give us the average time
//   between log messages; at the point where the average time
//   is greater than the throughput capability of the logger
//   we will not longer require the benefits of the FIFO formed
//   by max_dgram_qlen. We will also expect to see a very visible
//   knee in the average time between log messages at this point,
//   so we do not necessarily have to compare the rate against the
//   measured performance (BM_log_maximum_retry) of the logger.
//
//   for example (reformatted):
//
//       Minimum time between log events per dgramQlen:
//       1   2   3   5   10  20  30  50  100  200 300 400 500 600
//       5u2 12u 13u 15u 16u 27u 30u 36u 407u 3m1 3m3 3m9 3m9 5m5
//
//   demonstrates a clear knee rising at 100, so this means that for this
//   case max_dgram_qlen = 100 would be more than sufficient to handle the
//   worst that the system could stuff into the logger. The
//   BM_log_maximum_retry performance (derated by the log collection) on the
//   same system was 33.2us so we would almost be fine with max_dgram_qlen = 50.
//   BM_log_maxumum_retry with statistics off is roughly 20us, so
//   max_dgram_qlen = 20 would work. We will be more than willing to have
//   a large engineering margin so the rule of thumb that lead us to 100 is
//   fine.
//
// bucket dgramQlen are tuned for /proc/sys/net/unix/max_dgram_qlen = 300
const unsigned short LogStatistics::mBuckets[] = {
    1, 2, 3, 5, 10, 20, 30, 50, 100, 200, 300, 400, 500, 600
};

unsigned short LogStatistics::dgramQlen(unsigned short bucket) {
    if (bucket >= sizeof(mBuckets) / sizeof(mBuckets[0])) {
        return 0;
    }
    return mBuckets[bucket];
}

unsigned long long LogStatistics::minimum(unsigned short bucket) {
    if (mMinimum[bucket].tv_sec == mMinimum[bucket].tv_sec_max) {
        return 0;
    }
    return mMinimum[bucket].nsec();
}

void LogStatistics::recordDiff(log_time diff, unsigned short bucket) {
    if ((diff.tv_sec || diff.tv_nsec) && (mMinimum[bucket] > diff)) {
        mMinimum[bucket] = diff;
    }
}

void LogStatistics::add(unsigned short size,
                        log_id_t log_id, uid_t uid, pid_t pid) {
    mSizes[log_id] += size;
    ++mElements[log_id];
    if (!mStatistics) {
        return;
    }

    LidStatistics *l = &id(log_id);
    if (!l->add(size, uid, pid)) {
        return;
    }

    // Garbage Collection, PID restarted, merge in other log ids
    if (uid == (uid_t) -1) { // init
        uid = (uid_t) AID_ROOT;
    }

    // Find the direct reference to the uid/pid
    UidStatistics *u;
    UidStatisticsCollection::iterator iu;
    for (iu = l->begin(); iu != l->end(); ++iu) {
        u = *iu;
        if (uid == u->getUid()) {
            break;
        }
    }
    if (iu == l->end()) {
        return;
    }
    PidStatistics *p;
    PidStatisticsCollection::iterator ip;
    for (ip = u->begin(); ip != u->end(); ++ip) {
        p = *ip;
        if (pid == p->getPid()) {
            break;
        }
    }
    if (ip == u->end()) {
        return;
    }
    const char *name = p->getName();
    if (!name || !*name) {
        return;
    }

    // Find all references to our set of pids in other logs
    log_id_for_each(i) {
        if (i == log_id) {
            continue;
        }
        l = &id(i);
        for (iu = l->begin(); iu != l->end(); ++iu) {
            u = *iu;
            if (uid != u->getUid()) {
                continue;
            }
            // Find the master pid (match, or highest pid)
            PidStatistics *mp = NULL;
            PidStatistics *pp;
            for (ip = u->begin(); ip != u->end(); ++ip) {
                pp = *ip;
                pid_t ppid = pp->getPid();
                if (!p->pidMatches(ppid)) {
                    continue;
                }
                const char *pname = pp->getName();
                if (!pname || !*pname) {
                    continue;
                }
                if (strcmp(name, pname)) {
                    continue;
                }
                if (pid == ppid) {
                    mp = pp;
                    break;
                }
                if (!mp || (mp->getPid() < ppid)) {
                    mp = pp;
                }
            }
            if (!mp) {
                continue;
            }
            // now merge all that match into master
            for (ip = u->begin(); ip != u->end();) {
                pp = *ip;
                if (pp == mp) {
                    ++ip;
                    continue;
                }
                pid_t ppid = pp->getPid();
                if (!p->pidMatches(ppid)) {
                    ++ip;
                    continue;
                }
                const char *pname = pp->getName();
                if (pname && !*pname && strcmp(name, pname)) {
                    ++ip;
                    continue;
                }

                mp->add(pp);
                delete pp;
                ip = u->erase(ip);
            }
        }
    }
}

void LogStatistics::subtract(unsigned short size,
                             log_id_t log_id, uid_t uid, pid_t pid) {
    mSizes[log_id] -= size;
    --mElements[log_id];
    if (!mStatistics) {
        return;
    }
    id(log_id).subtract(size, uid, pid);
}

size_t LogStatistics::sizes(log_id_t log_id, uid_t uid, pid_t pid) {
    if (log_id != log_id_all) {
        return id(log_id).sizes(uid, pid);
    }
    size_t sizes = 0;
    log_id_for_each(i) {
        sizes += id(i).sizes(uid, pid);
    }
    return sizes;
}

size_t LogStatistics::elements(log_id_t log_id, uid_t uid, pid_t pid) {
    if (log_id != log_id_all) {
        return id(log_id).elements(uid, pid);
    }
    size_t elements = 0;
    log_id_for_each(i) {
        elements += id(i).elements(uid, pid);
    }
    return elements;
}

size_t LogStatistics::sizesTotal(log_id_t log_id, uid_t uid, pid_t pid) {
    if (log_id != log_id_all) {
        return id(log_id).sizesTotal(uid, pid);
    }
    size_t sizes = 0;
    log_id_for_each(i) {
        sizes += id(i).sizesTotal(uid, pid);
    }
    return sizes;
}

size_t LogStatistics::elementsTotal(log_id_t log_id, uid_t uid, pid_t pid) {
    if (log_id != log_id_all) {
        return id(log_id).elementsTotal(uid, pid);
    }
    size_t elements = 0;
    log_id_for_each(i) {
        elements += id(i).elementsTotal(uid, pid);
    }
    return elements;
}

void LogStatistics::format(char **buf,
                           uid_t uid, unsigned int logMask, log_time oldest) {
    static const unsigned short spaces_current = 13;
    static const unsigned short spaces_total = 19;

    if (*buf) {
        free(*buf);
        *buf = NULL;
    }

    android::String8 string("        span -> size/num");
    size_t oldLength;
    short spaces = 2;

    log_id_for_each(i) {
        if (!(logMask & (1 << i))) {
            continue;
        }
        oldLength = string.length();
        if (spaces < 0) {
            spaces = 0;
        }
        string.appendFormat("%*s%s", spaces, "", android_log_id_to_name(i));
        spaces += spaces_total + oldLength - string.length();

        LidStatistics &l = id(i);
        l.sort();

        UidStatisticsCollection::iterator iu;
        for (iu = l.begin(); iu != l.end(); ++iu) {
            (*iu)->sort();
        }
    }

    spaces = 1;
    log_time t(CLOCK_MONOTONIC);
    unsigned long long d;
    if (mStatistics) {
        d = t.nsec() - start.nsec();
        string.appendFormat("\nTotal%4llu:%02llu:%02llu.%09llu",
                  d / NS_PER_SEC / 60 / 60, (d / NS_PER_SEC / 60) % 60,
                  (d / NS_PER_SEC) % 60, d % NS_PER_SEC);

        log_id_for_each(i) {
            if (!(logMask & (1 << i))) {
                continue;
            }
            oldLength = string.length();
            if (spaces < 0) {
                spaces = 0;
            }
            string.appendFormat("%*s%zu/%zu", spaces, "",
                                sizesTotal(i), elementsTotal(i));
            spaces += spaces_total + oldLength - string.length();
        }
        spaces = 1;
    }

    d = t.nsec() - oldest.nsec();
    string.appendFormat("\nNow%6llu:%02llu:%02llu.%09llu",
                  d / NS_PER_SEC / 60 / 60, (d / NS_PER_SEC / 60) % 60,
                  (d / NS_PER_SEC) % 60, d % NS_PER_SEC);

    log_id_for_each(i) {
        if (!(logMask & (1 << i))) {
            continue;
        }

        size_t els = elements(i);
        if (els) {
            oldLength = string.length();
            if (spaces < 0) {
                spaces = 0;
            }
            string.appendFormat("%*s%zu/%zu", spaces, "", sizes(i), els);
            spaces -= string.length() - oldLength;
        }
        spaces += spaces_total;
    }

    // Construct list of worst spammers by Pid
    static const unsigned char num_spammers = 10;
    bool header = false;

    log_id_for_each(i) {
        if (!(logMask & (1 << i))) {
            continue;
        }

        PidStatisticsCollection pids;
        pids.clear();
        PidStatisticsCollection::iterator q;

        LidStatistics &l = id(i);
        UidStatisticsCollection::iterator iu;
        for (iu = l.begin(); iu != l.end(); ++iu) {
            UidStatistics &u = *(*iu);
            PidStatisticsCollection::iterator ip;
            for (ip = u.begin(); ip != u.end(); ++ip) {
                PidStatistics *p = (*ip);
                if (p->getPid() == p->gone) {
                    break;
                }

                char *name = p->getName();
                if (!name || !*name) {
                    name = pidToName(p->getPid());
                    if (name) {
                        if (*name) {
                            p->setName(name);
                        } else {
                            free(name);
                            name = NULL;
                        }
                    }
                }

                // Make a copy, or merge into name-match
                PidStatistics *qp = NULL;
                q = pids.end();
                if (name) {
                    for (q = pids.begin(); q != pids.end(); ++q) {
                        qp = *q;
                        char *qname = qp->getName();
                        if (qname && *qname && !strcmp(name, qname)) {
                            pids.erase(q);
                            break;
                        }
                    }
                }
                if (q == pids.end()) {
                    if (name) {
                        char *nname = new char[strlen(name) + 1];
                        name = strcpy(nname, name);
                    }
                    qp = new PidStatistics(p->getPid(), name);
                }
                if (qp == NULL) {
                    // NOTREACH
                    continue;
                }
                qp->add(p);
                p = qp;

                size_t mySizes = p->sizes();

                unsigned char num = 0;
                for (q = pids.begin(); q != pids.end(); ++q) {
                    if (mySizes > (*q)->sizes()) {
                        pids.insert(q, p);
                        break;
                    }
                    // do we need to traverse deeper in the list?
                    if (++num > num_spammers) {
                        break;
                    }
                }
                if (q == pids.end()) {
                   pids.push_back(p);
                   p = NULL;
                }
            }
        }

        size_t threshold = sizes(i);
        if (threshold < 65536) {
            threshold = 65536;
        }
        threshold /= 100;

        PidStatisticsCollection::iterator pt = pids.begin();

        for(int line = 0;
                (pt != pids.end()) && (line < num_spammers);
                ++line, pt = pids.erase(pt)) {
            PidStatistics *p = *pt;

            size_t sizes = p->sizes();
            if (sizes < threshold) {
                break;
            }

            char *name = p->getName();
            pid_t pid = p->getPid();
            if (!name || !*name) {
                name = pidToName(pid);
                if (name) {
                    if (*name) {
                        p->setName(name);
                    } else {
                        free(name);
                        name = NULL;
                    }
                }
            }

            if (!header) {
                string.appendFormat("\n\nChattiest clients:\n"
                                    "log id %-*s PID[x] name"
                                    "    gone: x=? multiple pids: x=* both: x=@",
                                    spaces_total, "size/total");
                header = true;
            }

            size_t sizesTotal = p->sizesTotal();

            android::String8 sz("");
            if (sizes == sizesTotal) {
                sz.appendFormat("%zu", sizes);
            } else {
                sz.appendFormat("%zu/%zu", sizes, sizesTotal);
            }

            android::String8 pd("");
            pd.appendFormat("%u%c", pid, p->pidType());

            string.appendFormat("\n%-7s%-*s %-7s%s",
                                line ? "" : android_log_id_to_name(i),
                                spaces_total, sz.string(), pd.string(),
                                name ? name : "");
        }

        for (q = pids.begin(); q != pids.end(); q = pids.erase(q)) {
            delete (*q);
        }
    }

    if (dgramQlenStatistics) {
        const unsigned short spaces_time = 6;
        const unsigned long long max_seconds = 100000;
        spaces = 0;
        string.append("\n\nMinimum time between log events per max_dgram_qlen:\n");
        for(unsigned short i = 0; dgramQlen(i); ++i) {
            oldLength = string.length();
            if (spaces < 0) {
                spaces = 0;
            }
            string.appendFormat("%*s%u", spaces, "", dgramQlen(i));
            spaces += spaces_time + oldLength - string.length();
        }
        string.append("\n");
        spaces = 0;
        unsigned short n;
        for(unsigned short i = 0; (n = dgramQlen(i)); ++i) {
            unsigned long long duration = minimum(i);
            if (duration) {
                duration /= n;
                if (duration >= (NS_PER_SEC * max_seconds)) {
                    duration = NS_PER_SEC * (max_seconds - 1);
                }
                oldLength = string.length();
                if (spaces < 0) {
                    spaces = 0;
                }
                string.appendFormat("%*s", spaces, "");
                if (duration >= (NS_PER_SEC * 10)) {
                    string.appendFormat("%llu",
                        (duration + (NS_PER_SEC / 2))
                            / NS_PER_SEC);
                } else if (duration >= (NS_PER_SEC / (1000 / 10))) {
                    string.appendFormat("%llum",
                        (duration + (NS_PER_SEC / 2 / 1000))
                            / (NS_PER_SEC / 1000));
                } else if (duration >= (NS_PER_SEC / (1000000 / 10))) {
                    string.appendFormat("%lluu",
                        (duration + (NS_PER_SEC / 2 / 1000000))
                            / (NS_PER_SEC / 1000000));
                } else {
                    string.appendFormat("%llun", duration);
                }
                spaces -= string.length() - oldLength;
            }
            spaces += spaces_time;
        }
    }

    log_id_for_each(i) {
        if (!(logMask & (1 << i))) {
            continue;
        }

        header = false;
        bool first = true;

        UidStatisticsCollection::iterator ut;
        for(ut = id(i).begin(); ut != id(i).end(); ++ut) {
            UidStatistics *up = *ut;
            if ((uid != AID_ROOT) && (uid != up->getUid())) {
                continue;
            }

            PidStatisticsCollection::iterator pt = up->begin();
            if (pt == up->end()) {
                continue;
            }

            android::String8 intermediate;

            if (!header) {
                // header below tuned to match spaces_total and spaces_current
                spaces = 0;
                intermediate = string.format("%s: UID/PID Total size/num",
                                             android_log_id_to_name(i));
                string.appendFormat("\n\n%-31sNow          "
                                         "UID/PID[x]  Total              Now",
                                    intermediate.string());
                intermediate.clear();
                header = true;
            }

            bool oneline = ++pt == up->end();
            --pt;

            if (!oneline) {
                first = true;
            } else if (!first && (spaces > 0)) {
                string.appendFormat("%*s", spaces, "");
            }
            spaces = 0;

            uid_t u = up->getUid();
            PidStatistics *pp = *pt;
            pid_t p = pp->getPid();

            if (!oneline) {
                intermediate = string.format("%d", u);
            } else if (p == PidStatistics::gone) {
                intermediate = string.format("%d/%c", u, pp->pidType());
            } else {
                intermediate = string.format("%d/%d%c", u, p, pp->pidType());
            }
            string.appendFormat(first ? "\n%-12s" : "%-12s",
                                intermediate.string());
            intermediate.clear();

            size_t elsTotal = up->elementsTotal();
            oldLength = string.length();
            string.appendFormat("%zu/%zu", up->sizesTotal(), elsTotal);
            spaces += spaces_total + oldLength - string.length();

            size_t els = up->elements();
            if (els == elsTotal) {
                if (spaces < 0) {
                    spaces = 0;
                }
                string.appendFormat("%*s=", spaces, "");
                spaces = -1;
            } else if (els) {
                oldLength = string.length();
                if (spaces < 0) {
                    spaces = 0;
                }
                string.appendFormat("%*s%zu/%zu", spaces, "", up->sizes(), els);
                spaces -= string.length() - oldLength;
            }
            spaces += spaces_current;

            first = !first;

            if (oneline) {
                continue;
            }

            size_t gone_szs = 0;
            size_t gone_els = 0;

            for(; pt != up->end(); ++pt) {
                pp = *pt;
                p = pp->getPid();

                // If a PID no longer has any current logs, and is not
                // active anymore, skip & report totals for gone.
                elsTotal = pp->elementsTotal();
                size_t szsTotal = pp->sizesTotal();
                if (p == pp->gone) {
                    gone_szs += szsTotal;
                    gone_els += elsTotal;
                    continue;
                }
                els = pp->elements();
                bool gone = pp->pidGone();
                if (gone && (els == 0)) {
                    // ToDo: garbage collection: move this statistical bucket
                    //       from its current UID/PID to UID/? (races and
                    //       wrap around are our achilles heel). Below is
                    //       merely lipservice to catch PIDs that were still
                    //       around when the stats were pruned to zero.
                    gone_szs += szsTotal;
                    gone_els += elsTotal;
                    continue;
                }

                if (!first && (spaces > 0)) {
                    string.appendFormat("%*s", spaces, "");
                }
                spaces = 0;

                intermediate = string.format(gone ? "%d/%d?" : "%d/%d", u, p);
                string.appendFormat(first ? "\n%-12s" : "%-12s",
                                    intermediate.string());
                intermediate.clear();

                oldLength = string.length();
                string.appendFormat("%zu/%zu", szsTotal, elsTotal);
                spaces += spaces_total + oldLength - string.length();

                if (els == elsTotal) {
                    if (spaces < 0) {
                        spaces = 0;
                    }
                    string.appendFormat("%*s=", spaces, "");
                    spaces = -1;
                } else if (els) {
                    oldLength = string.length();
                    if (spaces < 0) {
                        spaces = 0;
                    }
                    string.appendFormat("%*s%zu/%zu", spaces, "",
                                        pp->sizes(), els);
                    spaces -= string.length() - oldLength;
                }
                spaces += spaces_current;

                first = !first;
            }

            if (gone_els) {
                if (!first && (spaces > 0)) {
                    string.appendFormat("%*s", spaces, "");
                }

                intermediate = string.format("%d/?", u);
                string.appendFormat(first ? "\n%-12s" : "%-12s",
                                    intermediate.string());
                intermediate.clear();

                spaces = spaces_total + spaces_current;

                oldLength = string.length();
                string.appendFormat("%zu/%zu", gone_szs, gone_els);
                spaces -= string.length() - oldLength;

                first = !first;
            }
        }
    }

    *buf = strdup(string.string());
}

uid_t LogStatistics::pidToUid(pid_t pid) {
    log_id_for_each(i) {
        LidStatistics &l = id(i);
        UidStatisticsCollection::iterator iu;
        for (iu = l.begin(); iu != l.end(); ++iu) {
            UidStatistics &u = *(*iu);
            PidStatisticsCollection::iterator ip;
            for (ip = u.begin(); ip != u.end(); ++ip) {
                if ((*ip)->pidMatches(pid)) {
                    return u.getUid();
                }
            }
        }
    }
    return getuid(); // associate this with the logger
}
