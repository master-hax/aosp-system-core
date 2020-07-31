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

#pragma once

struct rpmb_key {
    uint8_t byte[32];
};

struct rpmb_nonce {
    uint8_t byte[16];
};

struct rpmb_u16 {
    uint8_t byte[2];
};

struct rpmb_u32 {
    uint8_t byte[4];
};

static inline uint16_t rpmb_get_u16(struct rpmb_u16 u16) {
    size_t i;
    uint16_t val;

    val = 0;
    for (i = 0; i < sizeof(u16.byte); i++) val = val << 8 | u16.byte[i];

    return val;
}

#define RPMB_PACKET_DATA_SIZE (256)

struct rpmb_packet {
    uint8_t pad[196];
    struct rpmb_key key_mac;
    uint8_t data[RPMB_PACKET_DATA_SIZE];
    struct rpmb_nonce nonce;
    struct rpmb_u32 write_counter;
    struct rpmb_u16 address;
    struct rpmb_u16 block_count;
    struct rpmb_u16 result;
    struct rpmb_u16 req_resp;
};

enum rpmb_result {
    RPMB_RES_OK = 0x0000,
    RPMB_RES_GENERAL_FAILURE = 0x0001,
    RPMB_RES_AUTH_FAILURE = 0x0002,
    RPMB_RES_COUNT_FAILURE = 0x0003,
    RPMB_RES_ADDR_FAILURE = 0x0004,
    RPMB_RES_WRITE_FAILURE = 0x0005,
    RPMB_RES_READ_FAILURE = 0x0006,
    RPMB_RES_NO_AUTH_KEY = 0x0007,

    RPMB_RES_WRITE_COUNTER_EXPIRED = 0x0080,
};
