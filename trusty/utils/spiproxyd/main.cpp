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
#include <stdlib.h>
#include <string.h>

#include <android-base/logging.h>
#include <android-base/result.h>

#include "proxy.h"

#define SPI_PROXY_PORT "com.android.trusty.spi.proxy"

using ::android::trusty::spi::SpiProxy;

static void show_usage() {
    LOG(ERROR) << "usage: spiproxyd -t TRUSTY_DEVICE -s SPI_DEVICE";
}

int main(int argc, char* argv[]) {
    std::string trusty_dev_name;
    std::string spi_dev_name;
    int opt;

    while ((opt = getopt(argc, argv, "ht:s:")) != -1) {
        switch (opt) {
            case 'h':
                show_usage();
                exit(EXIT_SUCCESS);
                break;
            case 't':
                trusty_dev_name = optarg;
                break;
            case 's':
                spi_dev_name = optarg;
                break;
            default:
                show_usage();
                exit(EXIT_FAILURE);
                break;
        }
    }

    LOG(INFO) << "Trusty device: " << trusty_dev_name;
    LOG(INFO) << "SPI device: " << spi_dev_name;

    SpiProxy proxy(std::move(trusty_dev_name), std::move(spi_dev_name), SPI_PROXY_PORT);

    auto ret = proxy.Init();
    if (!ret.ok()) {
        LOG(ERROR) << "failed to initialize SPI proxy: " << ret.error();
        return EXIT_FAILURE;
    }

    ret = proxy.StartEventLoop();
    if (!ret.ok()) {
        LOG(ERROR) << ret.error();
    }

    return EXIT_FAILURE;
}
