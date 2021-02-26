/*
 * Copyright (C) 2021 The Android Open Sourete Project
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

#include <string.h>
#include <trusty/coverage/uuid.h>

/* Format: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx */
#define UUID_STR_SIZE (37)

static bool parse_dash(const char** str) {
    if (**str != '-') {
        return false;
    }

    *str += 1;
    return true;
}

static bool parse_hex_digit(const char** str, uint8_t* dst) {
    char c;

    c = **str;
    *str += 1;

    if (c >= '0' && c <= '9') {
        *dst = c - '0';
        return true;
    }

    if (c >= 'a' && c <= 'f') {
        *dst = c - 'a' + 10;
        return true;
    }

    return false;
}

static bool parse_u8(const char** str, uint8_t* dst) {
    uint8_t msn;
    uint8_t lsn;

    if (!parse_hex_digit(str, &msn)) {
        return false;
    }

    if (!parse_hex_digit(str, &lsn)) {
        return false;
    }

    *dst = (msn << 4) + lsn;
    return true;
}

static bool parse_u16(const char** str, uint16_t* dst) {
    uint8_t msb;
    uint8_t lsb;

    if (!parse_u8(str, &msb)) {
        return false;
    }

    if (!parse_u8(str, &lsb)) {
        return false;
    }

    *dst = ((uint16_t)msb << 8) + lsb;
    return true;
}

static bool parse_u32(const char** str, uint32_t* dst) {
    uint16_t msh;
    uint16_t lsh;

    if (!parse_u16(str, &msh)) {
        return false;
    }

    if (!parse_u16(str, &lsh)) {
        return false;
    }

    *dst = ((uint32_t)msh << 16) + lsh;
    return true;
}

bool str_to_uuid(const char* str, struct uuid* uuid) {
    int len;

    len = strnlen(str, UUID_STR_SIZE);
    if (len == UUID_STR_SIZE) {
        return false;
    }

    if (!parse_u32(&str, &uuid->time_low)) {
        return false;
    }

    if (!parse_dash(&str)) {
        return false;
    }

    if (!parse_u16(&str, &uuid->time_mid)) {
        return false;
    }

    if (!parse_dash(&str)) {
        return false;
    }

    if (!parse_u16(&str, &uuid->time_hi_and_version)) {
        return false;
    }

    if (!parse_dash(&str)) {
        return false;
    }

    if (!parse_u8(&str, uuid->clock_seq_and_node)) {
        return false;
    }

    if (!parse_u8(&str, uuid->clock_seq_and_node + 1)) {
        return false;
    }

    if (!parse_dash(&str)) {
        return false;
    }

    for (int i = 2; i < 8; i++) {
        if (!parse_u8(&str, uuid->clock_seq_and_node + i)) {
            return false;
        }
    }

    return true;
}
