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
#include <stdio.h>
#include <string.h>
#include "tcp.h"

// Factory method to create the appropriate transport
// as function of |trans_spec| transport specification
Transport* create_transport(const char* trans_spec)
{
    Transport *transport;

    if (trans_spec == nullptr || strlen(trans_spec) < 4)
        return nullptr;

    if (strncmp("tcp:", trans_spec, 4) == 0) {
        transport = tcp_open(trans_spec + 4);

        if (transport == nullptr)
           fprintf(stderr, "Failed to create TCP transport for %s\n", trans_spec);

        return transport;
    }

/**
    if (strncmp("udp:", trans_spec, 4) == 0) {
        transport = udp_open(tran_spec + 4);

        if (transport == nullptr)
           fprintf(stderr, "Failed to create UDP transport for %s\n", trans_spec);

        return transport;
    }
 */

/**
 * USB transport spec might be defined as, ie:
 *    usb:<vendor>:<product>:<serial>
 */

/**
    if (strncmp("usb:", trans_spec, 4) == 0) {
        transport = usb_open(tran_spec + 4);

        if (transport == nullptr)
           fprintf(stderr, "Failed to create USB transport for %s\n", trans_spec);

        return transport;
    }
 */
    return nullptr;
}
