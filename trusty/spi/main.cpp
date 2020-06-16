/*
 * Copyright (C) 2020 The Android Open Source Project
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

#define LOG_TAG "spiproxyd"

#include <getopt.h>
#include <log/log.h>
#include <stdlib.h>
#include <string.h>

#include "proxy.h"

#define SPI_FINGERPRINT_PROXY_PORT "com.android.trusty.spi.fingerprint.proxy"

using ::android::trusty::spi::SpiProxy;

static const char* trusty_dev_name;
static const char* spi_dev_name;

static void show_usage() {
    ALOGE("usage: spiproxyd -t TRUSTY_DEVICE -s SPI_DEVICE\n");
}

static void parse_args(int argc, char* argv[]) {
    int opt;
    while ((opt = getopt(argc, argv, "ht:s:")) != -1) {
        switch (opt) {
            case 'h':
                show_usage();
                exit(EXIT_SUCCESS);
                break;
            case 't':
                trusty_dev_name = strdup(optarg);
                break;
            case 's':
                spi_dev_name = strdup(optarg);
                break;
            default:
                show_usage();
                exit(EXIT_FAILURE);
                break;
        }
    }

    ALOGI("Trusty device: %s\n", trusty_dev_name);
    ALOGI("SPI device: %s\n", spi_dev_name);
}

int main(int argc, char* argv[]) {
    parse_args(argc, argv);

    SpiProxy proxy(trusty_dev_name, spi_dev_name, SPI_FINGERPRINT_PROXY_PORT);

    int rc = proxy.Init();
    if (rc < 0) {
        ALOGE("failed (%d) to initialize SPI proxy\n", rc);
        return rc;
    }

    return proxy.StartEventLoop();
}
