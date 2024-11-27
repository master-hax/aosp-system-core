/*
 * Copyright (C) 2024 The Android Open Source Project
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
#include <aidl/android/hardware/security/see/hwcrypto/BnHwCryptoKey.h>
#include <android-base/logging.h>
#include <android/binder_libbinder.h>
#include <android/binder_manager.h>
#include <android/binder_process.h>
#include <binder/IServiceManager.h>
#include <binder/ProcessState.h>
#include <binder/RpcServer.h>
#include <binder/RpcSession.h>
#include <binder/RpcTransportRaw.h>
#include <sys/system_properties.h>

#include <getopt.h>

#include <linux/vm_sockets.h>
#include <sys/socket.h>

using aidl::android::hardware::security::see::hwcrypto::IHwCryptoKey;
using aidl::android::hardware::security::see::hwcrypto::IHwCryptoKeyDelegator;
using android::defaultServiceManager;
using android::IBinder;
using android::IInterface;
using android::sp;
using android::String16;
using android::base::unique_fd;

android::sp<android::IBinder> mBinder;

static long cid = 200;
static long port = 4;

static const char* _sopts = "hCP:";
static const struct option _lopts[] = {
        {"help", no_argument, 0, 'h'},
        {"cid", required_argument, 0, 'C'},
        {"port", required_argument, 0, 'P'},
        {0, 0, 0, 0},
};

static const char* usage =
        "Usage: %s [options]\n"
        "\n"
        "options:\n"
        "  -h, --help            prints this message and exit\n"
        "  -C, --cid cid         CID to connect to\n"
        "  -P, --port port       port to connect to\n"
        "\n";

static const char* usage_long = "\n";

static void print_usage_and_exit(const char* prog, int code, bool verbose) {
    fprintf(stderr, usage, prog);
    if (verbose) {
        fprintf(stderr, "%s", usage_long);
    }
    exit(code);
}

static void set_cid(const char* cid_str) {
    char* conv_str;
    long hwcrypto_hal_cid = strtol(cid_str, &conv_str, 0);
    if (conv_str[0] != '\0') {
        ALOGE("invalid cid passed as command line");
        exit(EXIT_FAILURE);
    }
    cid = hwcrypto_hal_cid;
}

static void set_port(const char* port_str) {
    char* conv_str;
    long hwcrypto_hal_port = strtol(port_str, &conv_str, 0);
    if (conv_str[0] != '\0') {
        ALOGE("invalid cid passed as command line argument");
        exit(EXIT_FAILURE);
    }
    port = hwcrypto_hal_port;
}

static void parse_options(int argc, char** argv) {
    int c;
    int oidx = 0;

    while (1) {
        c = getopt_long(argc, argv, _sopts, _lopts, &oidx);
        if (c == -1) {
            break; /* done */
        }

        switch (c) {
            case 'C':
                set_cid(optarg);
                break;

            case 'P':
                set_port(optarg);
                break;

            case 'h':
                print_usage_and_exit(argv[0], EXIT_SUCCESS, true);
                break;

            default:
                print_usage_and_exit(argv[0], EXIT_FAILURE, false);
        }
    }
}

std::shared_ptr<IHwCryptoKey> connect_to_trusty_vsock() {
    if (!mBinder) {
        auto session = android::RpcSession::make();
        if (!session) {
            ALOGE("couldn't create session\n");
            return NULL;
        }
        auto request = [=] {
            // Connecting to HwCrypto service
            int s = socket(AF_VSOCK, SOCK_STREAM, 0);
            if (s < 0) {
                ALOGE("couldn't get vsock; errno: %d\n", errno);
                return unique_fd();
            }
            struct timeval connect_timeout = {.tv_sec = 60, .tv_usec = 0};
            int res = setsockopt(s, AF_VSOCK, SO_VM_SOCKETS_CONNECT_TIMEOUT, &connect_timeout,
                                 sizeof(connect_timeout));
            if (res) {
                ALOGE("couldn't set timeout; errno: %d\n", errno);
            }
            struct sockaddr_vm addr = {
                    .svm_family = AF_VSOCK,
                    .svm_port = static_cast<unsigned int>(port),
                    .svm_cid = static_cast<unsigned int>(cid),
            };

            int retry = 10;
            do {
                res = TEMP_FAILURE_RETRY(connect(s, (struct sockaddr*)&addr, sizeof(addr)));
                if (res && (errno == ENODEV || errno == ESOCKTNOSUPPORT) && --retry) {
                    // The kernel returns ESOCKTNOSUPPORT instead of ENODEV if the socket type is
                    // SOCK_SEQPACKET and the guest CID we are trying to connect to is not ready yet
                    sleep(1);
                } else {
                    retry = 0;
                }
            } while (retry);
            if (res != 0) {
                ALOGE("Failed to connect to Trusty service. Error code: %d\n", res);
                return unique_fd();
            }

            // This is a temporary workaround because currently the TIPC bridge sends a packet back
            // after initial connection
            int8_t status;
            res = TEMP_FAILURE_RETRY(read(s, &status, sizeof(status)));
            if (res != sizeof(status)) {
                ALOGE("Failed to connect to Trusty service. Error code: %d\n", res);
                return unique_fd();
            }
            return unique_fd(s);
        };
        auto status = session->setupPreconnectedClient(unique_fd{}, request);
        if (status != android::OK) {
            ALOGE("couldn't create vsock client\n");
            return NULL;
        }
        mBinder = session->getRootObject();
        if (!mBinder) {
            ALOGE("couldn't get root object\n");
            return NULL;
        }
    }
    auto comm_service =
            IHwCryptoKey::fromBinder(ndk::SpAIBinder(AIBinder_fromPlatformBinder((mBinder))));
    return comm_service;
}

int main(int argc, char** argv) {
    parse_options(argc, argv);
    ABinderProcess_setThreadPoolMaxThreadCount(0);
    auto hw_crypto = connect_to_trusty_vsock();
    if (hw_crypto == nullptr) {
        ALOGE("couldn't connect to trusty to get hwcrypto hal");
        exit(EXIT_FAILURE);
    }
    auto hw_Crypto_delegator = ndk::SharedRefBase::make<IHwCryptoKey::DefaultDelegator>(hw_crypto);
    const std::string instance = std::string() + IHwCryptoKey::descriptor + "/default";
    binder_status_t status =
            AServiceManager_addService(hw_Crypto_delegator->asBinder().get(), instance.c_str());
    if (status != STATUS_OK) {
        ALOGE("couldn't register hwcrypto service\n");
    }
    CHECK_EQ(status, STATUS_OK);
    ABinderProcess_joinThreadPool();
    return 0;
}