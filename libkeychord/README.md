Android Keychord Library
=======================

Introduction
------------
Provide a means to instantiate a keychord callback once the combination
occurs.  A keychord consists of an input event type, one or more keys, and
a debounce duration.  The library relies on epoll(7) I/O event notification
facility, either managed synchronously in an executive, or in a dedicated
thread.

#include <keychord/keychord.h>

epollfd
-------

Provide a basic default epollfd layer should the caller not have its own, or
the caller can provide an epoll file descriptor from its own
epoll_create1(EPOLL_CLOEXEC) call.  Means to register (EPOLL_CTL_ADD) or
unregister (EPOLL_CTL_DEL) a file descriptor and a unique callback function
(referenced in data.ptr) when action (EPOLLIN) is triggered. Ability to close
and delete all registrants in order to tear down.  A default epoll wait with
timeout in ms, calling up to the keychord handler to ask when the next check
interval is required.

For additional convenience, an optional thread runner is supplied, start
and stop.

All can be supplied by the caller, this portion of the library is purely
optional.

        typedef void (*keychord_epoll_handler_fn)(void);
        typedef int (*keychord_register_epoll_handler_fn)(
            keychord_epoll_handler_fn handler, int fd, const char* name);
        typedef int (*keychord_unregister_epoll_handler_fn)(
            int fd, const char* name);

        int keychord_default_reset_epoll_fd(int fd);
        void keychord_default_clear_epoll();
        int keychord_default_register_epoll_handler(
            keychord_epoll_handler_fn fn, int fd, const char* name);
        int keychord_default_unregister_epoll_handler(
            int fd, const char* name);
        int keychord_default_epoll_wait(int epoll_timeout_ms);
        std::chrono::milliseconds keychord_default_epoll_wait(
            std::chrono::milliseconds epoll_timeout);
        int keychord_timeout_ms(int epoll_timeout_ms);
        std::chrono::milliseconds keychord_timeout(
            std::chrono::milliseconds epoll_timeout);

        int keychord_run(int d = 0, const char* threadname = nullptr);
        int keychord_stop(int d = 0);

kernel keychord
---------------

If the kernel has the Android keychord driver, then a single registration is
made to the epoll interface to collect keychord ids, and the registered
keychords will be transferred down to the driver when enabled.

This driver will ignore any effort to register anything other than EV_KEY, and
ignores debounce duration.

getevent
--------

If the keychord driver is not provided, then the input events interface is
utilized.  The interface will provide two levels: raw and keychord id filtered.
The raw interface is a secondary citizen, if keychords are registered the
layer will endeavor to only keep nodes active that provide the filtered events
(EVIOCGBIT to retrieve set), to minimize processing churn. If available, issue
a mask (EVIOCSMASK) to further reduce the interruption rate.  Current state
will be pulled (EVIOCGKEY, EVIOCGLED, EVIOCGSND, EVIOCGSW) and then updated as
events come in.

The raw interface also provides access to some internal helpful information:

        typedef void (*keychord_event_handler_fn)(
            const struct input_event* event, int fd, const char* name);

        int keychord_register_event_handler(
            int d, keychord_event_handler_fn event_handler);

        int keychord_get_event_fd(int d, int idx);
        bool keychord_get_event_active(int d, int idx);
        std::vector<bool> keychord_get_event_active(int d);
        bool keychord_get_event_available(int d, int idx, int type, int code);
        std::vector<bool> keychord_get_event_available(int d);
        bool keychord_get_event_available(int d, int idx);
        const std::vector<bool>& keychord_get_event_available(
            int d, int idx, int type);
        int keychord_get_event_version(int d, int idx);
        bool keychord_get_event_current(int d, int type, int code);
        const std::vector<bool>& keychord_get_event_current(
            int d, int type = EV_KEY);
        const char* keychord_get_event_name(int d, int idx);
        std::string keychord_get_event_name_string(int d, int idx);
        bool keychord_get_event_mask(int d, int type, int code);
        std::vector<bool> keychord_get_event_mask(int d, int type = EV_KEY);

keychord
--------

Provide the high level registration interface, and will select kernel keychord
or getevent to fulfill requests.

        int keychord_init(
            keychord_register_epoll_handler_fn register_epoll_handler,
            keychord_unregister_epoll_handler_fn unregister_epoll_handler);
        int keychord_init();
        int keychord_release(int d);

        int keychord_enable(int d, int code,
                            const int* keycodes, size_t num_keycodes,
                            int duration_ms = 0);
        int keychord_enable(int d, int type, std::vector<int>& keycodes,
                            std::chrono::milliseconds duration =
                                std::chrono::milliseconds::zero());
        int keychord_disable(int d, int id);

        typedef void (*keychord_id_handler_fn)(int id);
        int keychord_register_id_handler(int d, keychord_id_handler_fn id_handler);
