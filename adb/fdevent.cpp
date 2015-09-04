/* http://frotznet.googlecode.com/svn/trunk/utils/fdevent.c
**
** Copyright 2006, Brian Swetland <swetland@frotz.net>
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

#include "sysdeps.h"
#include "fdevent.h"

#include <fcntl.h>
#include <poll.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include <list>
#include <unordered_map>
#include <vector>

#include <base/logging.h>
#include <base/stringprintf.h>

#include "adb_io.h"

#if !ADB_HOST
// This socket is used when a subproc shell service exists.
// It wakes up the fdevent_loop() and cause the correct handling
// of the shell's pseudo-tty master. I.e. force close it.
int SHELL_EXIT_NOTIFY_FD = -1;
#endif // !ADB_HOST

#define FDE_EVENTMASK  0x00ff
#define FDE_STATEMASK  0xff00

#define FDE_ACTIVE     0x0100
#define FDE_PENDING    0x0200
#define FDE_CREATED    0x0400

static std::list<fdevent*> pending_list;

struct PollNode {
  fdevent* fde;
  pollfd pollfd;

  PollNode(fdevent* fde) : fde(fde) {
      memset(&pollfd, 0, sizeof(pollfd));
      pollfd.fd = fde->fd;
  }
};

static std::unordered_map<int, PollNode> poll_node_map;

static std::ostream& operator<<(std::ostream& os, const fdevent& fde) {
    std::string state;
    if (fde.state & FDE_ACTIVE) {
        state += "A";
    }
    if (fde.state & FDE_PENDING) {
        state += "P";
    }
    if (fde.state & FDE_CREATED) {
        state += "C";
    }
    if (fde.state & FDE_READ) {
        state += "R";
    }
    if (fde.state & FDE_WRITE) {
        state += "W";
    }
    if (fde.state & FDE_ERROR) {
        state += "E";
    }
    if (fde.state & FDE_DONT_CLOSE) {
        state += "D";
    }

    os << "(fdevent " << fde.fd << " " << state << ")";
    return os;
}

fdevent *fdevent_create(int fd, fd_func func, void *arg)
{
    fdevent *fde = (fdevent*) malloc(sizeof(fdevent));
    if(fde == 0) return 0;
    fdevent_install(fde, fd, func, arg);
    fde->state |= FDE_CREATED;
    return fde;
}

void fdevent_destroy(fdevent *fde)
{
    if(fde == 0) return;
    if(!(fde->state & FDE_CREATED)) {
        LOG(FATAL) << "destroying fde not created by fdevent_create(): " << *fde;
    }
    fdevent_remove(fde);
    free(fde);
}

void fdevent_install(fdevent* fde, int fd, fd_func func, void* arg) {
    CHECK_GE(fd, 0);
    memset(fde, 0, sizeof(fdevent));
    fde->state = FDE_ACTIVE;
    fde->fd = fd;
    fde->func = func;
    fde->arg = arg;
    if (fcntl(fd, F_SETFL, O_NONBLOCK) != 0) {
      // Here is not proper to handle the error. If it fails here, some error is
      // likely to be detected by poll(), then we can let the callback function
      // to handle it.
      LOG(ERROR) << "failed to fcntl(" << fd << ") to be nonblock";
    }
    auto pair = poll_node_map.emplace(fde->fd, PollNode(fde));
    CHECK(pair.second) << "install existing fd " << fd;
    LOG(DEBUG) << "fdevent_install " << *fde;
}

void fdevent_remove(fdevent* fde) {
    LOG(DEBUG) << "fdevent_remove " << *fde;
    if (fde->state & FDE_ACTIVE) {
        poll_node_map.erase(fde->fd);
        if (fde->state & FDE_PENDING) {
            pending_list.remove(fde);
        }
        if (!(fde->state & FDE_DONT_CLOSE)) {
            adb_close(fde->fd);
            fde->fd = -1;
        }
        fde->state = 0;
        fde->events = 0;
    }
}

static void fdevent_update(fdevent* fde, unsigned events) {
    auto it = poll_node_map.find(fde->fd);
    CHECK(it != poll_node_map.end());
    PollNode& node = it->second;
    if (events & FDE_READ) {
        node.pollfd.events |= POLLIN;
    } else {
        node.pollfd.events &= ~POLLIN;
    }

    if (events & FDE_WRITE) {
        node.pollfd.events |= POLLOUT;
    } else {
        node.pollfd.events &= ~POLLOUT;
    }
    fde->state = (fde->state & FDE_STATEMASK) | events;
}

void fdevent_set(fdevent* fde, unsigned events) {
    events &= FDE_EVENTMASK;
    if ((fde->state & FDE_EVENTMASK) == events) {
        return;
    }
    if (fde->state & FDE_ACTIVE) {
        fdevent_update(fde, events);
        LOG(DEBUG) << "fdevent_set: " << *fde << ", events = " << events;

        if (fde->state & FDE_PENDING) {
            // If we are pending, make sure we don't signal an event that is no longer wanted.
            fde->events &= ~events;
            if (fde->events == 0) {
                pending_list.remove(fde);
                fde->state &= ~FDE_PENDING;
            }
        }
    }
}

void fdevent_add(fdevent* fde, unsigned events) {
    fdevent_set(fde, (fde->state & FDE_EVENTMASK) | events);
}

void fdevent_del(fdevent* fde, unsigned events) {
    fdevent_set(fde, (fde->state & FDE_EVENTMASK) & ~events);
}

static std::string dump_pollfds(const std::vector<pollfd>& pollfds) {
    std::string result;
    for (auto& pollfd : pollfds) {
        std::string op;
        if (pollfd.events & POLLIN) {
            op += "R";
        }
        if (pollfd.events & POLLOUT) {
            op += "W";
        }
        android::base::StringAppendF(&result, " %d(%s)", pollfd.fd, op.c_str());
    }
    return result;
}

static void fdevent_process() {
    std::vector<pollfd> pollfds;
    for (auto it = poll_node_map.begin(); it != poll_node_map.end(); ++it) {
        pollfds.push_back(it->second.pollfd);
    }
    CHECK_GT(pollfds.size(), 0u);
    LOG(DEBUG) << "poll(), pollfds =" << dump_pollfds(pollfds);
    int ret = TEMP_FAILURE_RETRY(poll(&pollfds[0], pollfds.size(), -1));
    if (ret == -1) {
      PLOG(ERROR) << "poll(), ret = " << ret;
      return;
    }
    for (auto& pollfd : pollfds) {
        unsigned events = 0;
        if (pollfd.revents & POLLIN) {
            events |= FDE_READ;
        }
        if (pollfd.revents & POLLOUT) {
            events |= FDE_WRITE;
        }
        if (pollfd.revents & (POLLERR | POLLHUP | POLLNVAL)) {
            // We fake a read, as the rest of the code assumes that errors will
            // be detected at that point.
            events |= FDE_READ | FDE_ERROR;
        }
        if (events != 0) {
            auto it = poll_node_map.find(pollfd.fd);
            CHECK(it != poll_node_map.end());
            fdevent* fde = it->second.fde;
            CHECK_EQ(fde->fd, pollfd.fd);
            fde->events |= events;
            LOG(DEBUG) << *fde << ", got events " << std::hex << events;
            fde->state |= FDE_PENDING;
            pending_list.push_back(fde);
        }
    }
}

static void fdevent_call_fdfunc(fdevent* fde)
{
    unsigned events = fde->events;
    fde->events = 0;
    if(!(fde->state & FDE_PENDING)) return;
    fde->state &= (~FDE_PENDING);
    LOG(DEBUG) << "fdevent_call_fdfunc " << *fde;
    fde->func(fde->fd, events, fde->arg);
}

#if !ADB_HOST
static void fdevent_subproc_event_func(int fd, unsigned ev,
                                       void* /* userdata */)
{

    LOG(DEBUG) << "subproc handling on fd = " << fd << ", ev = " << std::hex << ev;

    CHECK_GE(fd, 0);

    if (ev & FDE_READ) {
        int subproc_fd;

        if(!ReadFdExactly(fd, &subproc_fd, sizeof(subproc_fd))) {
            LOG(FATAL) << "Failed to read the subproc's fd from " << fd;
        }
        auto it = poll_node_map.find(subproc_fd);
        if (it == poll_node_map.end()) {
            LOG(DEBUG) << "subproc_fd " << subproc_fd << " cleared from fd_table";
            return;
        }
        fdevent* subproc_fde = it->second.fde;
        if(subproc_fde->fd != subproc_fd) {
            // Already reallocated?
            LOG(DEBUG) << "subproc_fd " << subproc_fd << " != subproc_fde->fde " << subproc_fde->fd;
            return;
        }

        subproc_fde->force_eof = 1;

        int rcount = 0;
        ioctl(subproc_fd, FIONREAD, &rcount);
        PLOG(DEBUG) << "subproc with fd " << subproc_fd << " has rcount " << rcount;
        if (rcount != 0) {
            // If there is data left, it will show up in the select().
            // This works because there is no other thread reading that
            // data when in this fd_func().
            return;
        }

        LOG(DEBUG) << "subproc_fde " << *subproc_fde;
        subproc_fde->events |= FDE_READ;
        if(subproc_fde->state & FDE_PENDING) {
            return;
        }
        subproc_fde->state |= FDE_PENDING;
        fdevent_call_fdfunc(subproc_fde);
    }
}

void fdevent_subproc_setup()
{
    int s[2];

    if(adb_socketpair(s)) {
        PLOG(FATAL) << "cannot create shell-exit socket-pair";
    }
    LOG(DEBUG) << "fdevent_subproc: socket pair (" << s[0] << ", " << s[1] << ")";

    SHELL_EXIT_NOTIFY_FD = s[0];
    fdevent *fde = fdevent_create(s[1], fdevent_subproc_event_func, NULL);
    CHECK(fde != nullptr) << "cannot create fdevent for shell-exit handler";
    fdevent_add(fde, FDE_READ);
}
#endif // !ADB_HOST

void fdevent_loop()
{
#if !ADB_HOST
    fdevent_subproc_setup();
#endif // !ADB_HOST

    while (true) {
        LOG(DEBUG) << "--- --- waiting for events";

        fdevent_process();

        while (!pending_list.empty()) {
            fdevent* fde = pending_list.front();
            pending_list.pop_front();
            fdevent_call_fdfunc(fde);
        }
    }
}
