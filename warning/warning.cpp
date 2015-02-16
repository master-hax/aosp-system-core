/*
 * Copyright (C) 2015 The Android Open Source Project
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
#include <limits.h>
#include <linux/input.h>
#include <cutils/klog.h>
#include "minui/minui.h"

#define WARNING_TIMEOUT 5000
#define LOGE(x...) do { KLOG_ERROR("warning", x); } while (0)

struct warning_state {
    bool wait;
    int timeout;
};

static int input_cb(int fd, unsigned int epevents, void *data)
{
    struct input_event ev;
    struct warning_state *state = (struct warning_state *)data;

    if (ev_get_input(fd, epevents, &ev)) {
        return -1;
    }

    if (ev.type != EV_KEY) {
        return 0;
    }

    if (state->wait) {
        if (ev.code == KEY_POWER) {
            state->wait = false;
        }
    } else {
        state->wait = true;
    }

    return 0;
}

static void clear()
{
    gr_color(0, 0, 0, 0);
    gr_clear();
    gr_flip();
}

static void draw(const char *resname)
{
    gr_surface surface;
    int w, h, x, y;

    if (res_create_display_surface(resname, &surface) < 0) {
        LOGE("failed to create surface for %s\n", resname);
        return;
    }

    w = gr_get_width(surface);
    h = gr_get_height(surface);
    x = (gr_fb_width() - w) / 2;
    y = (gr_fb_height() - h) / 2;

    gr_blit(surface, 0, 0, w, h, x, y);
    gr_flip();

    res_free_surface(surface);
}

int main(int argc, char **argv)
{
    struct warning_state state;

    if (argc < 3) {
        LOGE("usage: warning timeout.png permanent.png [timeout]\n");
        return EXIT_FAILURE;
    }

    state.wait = false;
    state.timeout = WARNING_TIMEOUT;

    if (argc == 4) {
        state.timeout = strtol(argv[3], NULL, 0);

        if (state.timeout < 0 || state.timeout >= LONG_MAX) {
            LOGE("invalid timeout %s, defaulting to %u\n", argv[3],
                WARNING_TIMEOUT);
            state.timeout = WARNING_TIMEOUT;
        }
    }

    if (gr_init() == -1 || ev_init(input_cb, &state) == -1) {
        LOGE("failed to initialize minui\n");
        return EXIT_FAILURE;
    }

    draw(argv[1]);

    do {
        if (ev_wait(state.timeout) == 0) {
            ev_dispatch();

            if (state.wait && state.timeout > 0) {
                draw(argv[2]);
                state.timeout = -1;
            }
        }
    } while (state.wait);

    clear();
    gr_exit();
    ev_exit();

    return EXIT_SUCCESS;
}
