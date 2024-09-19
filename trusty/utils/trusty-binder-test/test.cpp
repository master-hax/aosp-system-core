#include <android/trusty/test/commservice/ICommService.h>
#include <binder/RpcServer.h>
#include <binder/RpcSession.h>
#include <binder/RpcTransportRaw.h>
#include <binder/RpcTransportTipcAndroid.h>
#include <binder/RpcTrusty.h>
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/system_properties.h>
#include <trusty/tipc.h>

#include <linux/vm_sockets.h>
#include <sys/socket.h>

using android::base::unique_fd;

#define PORT_NAME "com.android.trusty.test.transact"

using ::android::trusty::test::commservice::ICommService;

android::sp<android::IBinder> mBinder;

const char* direct_connection = "VSOCK:5566:0";

static android::sp<ICommService> connect_to_trusty_tipc() {
    const char* port = PORT_NAME;
    const char* legacy_device = "/dev/trusty-ipc-dev0";
    const char* ipc_dev_prop = "ro.hardware.trusty_ipc_dev";
    char ipc_dev[PROP_VALUE_MAX];
    int get_prop_result = __system_property_get(ipc_dev_prop, ipc_dev);
    if (!mBinder) {
        if (get_prop_result > 0) {
            mBinder = android::RpcTrustyConnect(ipc_dev, port);
        } else {
            mBinder = android::RpcTrustyConnect(direct_connection, port);
        }
        if (!mBinder) {
            fprintf(stderr, "couldn't create session\n");
            return NULL;
        }
    } else {
        fprintf(stderr, "trusty already connected\n");
    }

    auto comm_service = ICommService::asInterface(mBinder);
    return comm_service;
}

static android::sp<ICommService> connect_to_trusty_vsock() {
    if (!mBinder) {
        auto session = android::RpcSession::make();
        if (!session) {
            fprintf(stderr, "couldn't create session\n");
            return NULL;
        }
        // auto status = session->setupVsockClient(5566,9);
        ///////////
        auto request = [=] {
            int s = socket(AF_VSOCK, SOCK_STREAM, 0);
            if (s < 0) {
                fprintf(stderr, "-----couldn't get vsock; errno: %d\n", errno);
                return unique_fd();
            }
            struct timeval connect_timeout = {.tv_sec = 60, .tv_usec = 0};
            int res = setsockopt(s, AF_VSOCK, SO_VM_SOCKETS_CONNECT_TIMEOUT, &connect_timeout,
                                 sizeof(connect_timeout));
            if (res) {
                fprintf(stderr, "-----couldn't set timeout; errno: %d\n", errno);
            }
            struct sockaddr_vm addr = {
                    .svm_family = AF_VSOCK,
                    .svm_cid = 5566,
                    .svm_port = 9,
            };

            int retry = 10;
            do {
                res = TEMP_FAILURE_RETRY(connect(s, (struct sockaddr*)&addr, sizeof(addr)));
                if (res && (errno == ENODEV || errno == ESOCKTNOSUPPORT) && --retry) {
                    fprintf(stderr,
                            "%s: Can't connect to vsock %u:%u for tipc service (err=%d) %d retries "
                            "remaining\n",
                            __func__, addr.svm_cid, addr.svm_port, errno, retry);
                    sleep(1);
                } else {
                    retry = 0;
                }
            } while (retry);
            if (res != 0) {
                fprintf(stderr, "-----Failed to connect to Trusty service. Error code: %d\n", res);
                return unique_fd();
            } else {
                fprintf(stderr, "connection succesful\n");
            }
            fprintf(stderr, "not reading status code!!\n");

            return unique_fd(s);
        };

        auto status = session->setupPreconnectedClient(unique_fd{}, request);
        if (status != android::OK) {
            fprintf(stderr, "couldn't create vsock client\n");
            return NULL;
        }
        //////////////////
        mBinder = session->getRootObject();
        if (!mBinder) {
            fprintf(stderr, "couldn't get root object\n");
            return NULL;
        }
    }
    auto comm_service = ICommService::asInterface(mBinder);
    return comm_service;
}

int message_test(bool use_tipc) {
    char propvalue[PROP_VALUE_MAX];
    int ret_val = __system_property_get("ro.hardware.trusty_ipc_dev", propvalue);
    if (ret_val > 0) {
        std::cout << "trusty_ipc_dev property:" << propvalue << std::endl;
    } else {
        std::cout << "__system_property_get failed, return value:" << ret_val << " will use "
                  << direct_connection << std::endl;
    }

    std::vector<uint8_t> request_vec(15);
    std::fill(std::begin(request_vec), std::end(request_vec), 9);
    std::vector<uint8_t> response_vec;

    std::cout << "sending message of length:" << request_vec.size() << std::endl;

    android::sp<ICommService> comm_service;
    if (use_tipc) {
        comm_service = connect_to_trusty_tipc();
    } else {
        comm_service = connect_to_trusty_vsock();
    }

    if (!comm_service) {
        std::cout << "couldn't connect" << std::endl;
        return -1;
    }
    auto ret = comm_service->execute_transact(request_vec, &response_vec);

    if (!ret.isOk()) {
        std::cout << "couldn't execute transaction" << std::endl;
        return -1;
    }

    std::cout << "response_vec size:" << response_vec.size() << std::endl;

    std::cout << "Test application finished!!" << std::endl;

    return 0;
}

int main(int argc, char* argv[]) {
    // Not doing real parsing of command line arguments
    bool use_tipc = false;
    if (argc > 1) {
        if (!strcmp(argv[1], "tipc")) {
            use_tipc = true;
        }
    }
    if (use_tipc) {
        std::cout << "using tipc" << std::endl;
    } else {
        std::cout << "using vsock" << std::endl;
    }
    // return liboemcryptotest();
    return message_test(use_tipc);
}
