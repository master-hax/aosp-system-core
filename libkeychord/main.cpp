/*
 * Copyright (C) 2018 The Android Open Source Project
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

#define LOG_TAG "getchord"

// getchord / getevent mainline

#include <inttypes.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <android-base/logging.h>
#include <android-base/parseint.h>
#include <android-base/strings.h>
#include <keychord/keychord.h>

void EventHandler(const input_event* event, int fd, const char* name) {
    const char* nm = strrchr(name, '/');
    if (nm) {
        ++nm;
    } else {
        nm = name;
    }
    printf("%s(%d) %5lu.%06lu 0x%04" PRIx16 " 0x%04" PRIx16 " %" PRId32 "\n", nm, fd,
           event->time.tv_sec, event->time.tv_usec, event->type, event->code, event->value);
}

void ChordHandler(int id) {
    printf("KEYCHORD ID %d\n", id);
}

std::string format(std::vector<int> keycodes) {
    std::string out;
    bool prefix = false;
    for (auto& c : keycodes) {
        if (prefix) out += ',';
        out += std::to_string(c);
        prefix = true;
    }
    return out;
}

int main(int argc, char** argv) {
    android::base::InitLogging(argv, &android::base::StderrLogger);

    auto fd = keychord_initialize();

    bool hasKeycodes = false;
    opterr = 0;
    bool showInfo = false;
    bool quiet = false;
    do {
        int c = getopt(argc, argv, "tns:Sv::dpilqc:rhC:");
        if (c == EOF) break;
        switch (c) {
            case 'i':
                showInfo = true;
                break;
            case 'q':
                quiet = true;
                break;
            case 'C': {
                auto codes = android::base::Split(optarg, ",:; \t");
                std::vector<int> keycodes;
                bool valid = true;
                for (auto& s : codes) {
                    int val;
                    if (!android::base::ParseUint(s, &val, 0x2FF)) {
                        LOG(ERROR) << "code out of range " << s;
                        valid = false;
                        break;
                    }
                    keycodes.push_back(val);
                }
                if (!valid) break;
                hasKeycodes = true;
                auto id = keychord_enable(fd, EV_KEY, keycodes);
                printf("KEYCHORD ID %d EV_KEY:%s\n", id, format(keycodes).c_str());
            } break;
            case '?':
                fprintf(stderr, "%s: invalid option -%c\n", argv[0], optopt);
            case 'h':
                fprintf(stderr, "%s [-C <keychord>]\n", argv[0]);
            default:
                break;
        }
    } while (true);
    if (!quiet) {
        keychord_register_event_handler(fd, EventHandler);
    }
    if (hasKeycodes) {
        keychord_register_id_handler(fd, ChordHandler);
    }

    if (showInfo) {
        auto available = keychord_get_event_available(fd);
        auto active = keychord_get_event_active(fd);
        for (int idx = 0; idx < available.size(); ++idx) {
            if (!available[idx]) continue;
            printf("add device %d: %s (%sactive)\n", idx,
                   keychord_get_event_name_string(fd, idx).c_str(),
                   ((idx < active.size()) && active[idx]) ? "" : "in");
            auto version = keychord_get_event_version(fd, idx);
            printf("  version:  %d.%d.%d\n", version >> 16, (version >> 8) & 255, version & 255);
            printf("  events:\n");
            for (int type = EV_KEY; type < EV_MAX; ++type) {
                auto codes = keychord_get_event_available(fd, idx, type);
                if (codes.size() == 0) continue;
                printf("    (%04x):", type);
                for (int code = 0; code < codes.size(); ++code) {
                    if (codes[code]) printf(" %04x", code);
                }
                printf("\n");
            }
        }
        bool allHeader = false;
        for (int type = EV_KEY; type < EV_MAX; ++type) {
            auto codes = keychord_get_event_current(fd, type);
            if (codes.size()) {
                bool header = false;
                for (int code = 0; code < codes.size(); ++code) {
                    if (codes[code]) {
                        if (!allHeader) {
                            printf("All:\n");
                            allHeader = true;
                        }
                        if (!header) {
                            printf("ON  (%04x):", type);
                            header = true;
                        }
                        printf(" %04x", code);
                    }
                }
                if (header) printf("\n");
            }
            if (!hasKeycodes) continue;
            codes = keychord_get_event_mask(fd, type);
            if (codes.size() == 0) continue;
            if (!allHeader) {
                printf("All:\n");
                allHeader = true;
            }
            printf("MASK(%04x):", type);
            for (int code = 0; code < codes.size(); ++code) {
                if (codes[code]) printf(" %04x", code);
            }
            printf("\n");
        }
        if (quiet && !hasKeycodes) exit(0);
    }

    if (keychord_run(fd, "libkeychord.ev") != 0) exit(-1);
    pause();
    keychord_stop(fd);
    keychord_release(fd);
    return 0;
}
