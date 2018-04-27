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

#ifndef _LIBKEYCHORD_H_
#define _LIBKEYCHORD_H_

#include <linux/input-event-codes.h>
#include <stdint.h>

#include <algorithm>
#include <chrono>
#include <functional>
#include <unordered_map>
#include <vector>

#include <keychord/keychord.h>

#ifndef LIBKEYCHORD_HIDDEN
#define LIBKEYCHORD_HIDDEN __attribute__((visibility("hidden")))
#endif

extern keychord_register_epoll_handler_fn KeychordRegisterEpollHandler;
extern keychord_unregister_epoll_handler_fn KeychordUnregisterEpollHandler;
extern keychord_id_handler_fn KeychordIdHandler;

LIBKEYCHORD_HIDDEN bool KeychordIsDefault(void);

// Internal types
typedef uint8_t event_id_t;
typedef uint16_t event_code_t;
typedef uint16_t event_type_t;
typedef uint8_t mask_t;

// maximum of EV_MAX, KEY_MAX, REL_MAX, ABS_MAX, SW_MAX, MSC_MAX, LED_MAX,
// REP_MAX, SND_MAX is 0x2ff, fits in a uint16_t and matches internal
// representation of the array used by the keychord driver.
constexpr event_code_t event_code_max =
    std::max({EV_MAX, KEY_MAX, REL_MAX, ABS_MAX, SW_MAX, MSC_MAX, LED_MAX, REP_MAX, SND_MAX, 0x2FF});

class internalKeycodes : public std::vector<event_code_t> {
  public:
    internalKeycodes(std::vector<int> keycodes, event_code_t max = KEY_MAX);
    internalKeycodes(const int* keycodes, size_t num_keycodes, event_code_t max = KEY_MAX);
};

class KeychordEntry {
    const event_type_t type;
    const internalKeycodes keycodes;
    const std::chrono::milliseconds duration;
    bool match;
    std::chrono::milliseconds time;

  public:
    KeychordEntry(event_type_t type, std::vector<int> keycodes, std::chrono::milliseconds duration);
    KeychordEntry(event_type_t type, const int* keycodes, size_t num_keycodes, int duration_ms);

    bool valid() const;
    int getType() const;

    const std::vector<event_code_t>& getKeycodes() const;

    std::chrono::milliseconds getDurationLeft(
        std::chrono::milliseconds current = std::chrono::milliseconds::zero()) const;
    void setMatch(bool value = true,
                  std::chrono::milliseconds current = std::chrono::milliseconds::zero());
    void trigger();
    bool isTriggered() const;
    bool isImmediate() const;

    bool operator==(const KeychordEntry& rval) const;
};

class KeychordEntries : public std::unordered_map<event_id_t, KeychordEntry> {  // ISA
  public:
    event_id_t unique_id() const;
    std::vector<mask_t> mask(event_type_t type) const;
    std::chrono::milliseconds getDurationLeft();
};

extern class KeychordEntries KeychordEntries;

#endif /* _LIBKEYCHORD_H_ */
