#define WV_PORT_NAME "com.android.trusty.test.transact"

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

using ::android::trusty::test::commservice::ICommService;

android::sp<android::IBinder> mBinder;

static android::sp<ICommService> connect_to_trusty() {
    const char* port = WV_PORT_NAME;
    const char* legacy_device = "/dev/trusty-ipc-dev0";
    const char* ipc_dev_prop = "ro.hardware.trusty_ipc_dev";
    char ipc_dev[PROP_VALUE_MAX];
    int get_prop_result = __system_property_get(ipc_dev_prop, ipc_dev);
    if (!mBinder) {
        if (get_prop_result > 0) {
            mBinder = android::RpcTrustyConnect(ipc_dev, port);
        } else {
            mBinder = android::RpcTrustyConnect(legacy_device, port);
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

int main() {
    char propvalue[PROP_VALUE_MAX];
    int ret_val = __system_property_get("ro.hardware.trusty_ipc_dev", propvalue);
    if (ret_val > 0) {
        std::cout << "trusty_ipc_dev property:" << propvalue << std::endl;
    } else {
        std::cout << "__system_property_get failed, return value:" << ret_val << std::endl;
    }

    std::vector<uint8_t> request_vec(15);
    std::fill(std::begin(request_vec), std::end(request_vec), 9);
    std::vector<uint8_t> response_vec;

    std::cout << "sending message of length:" << request_vec.size() << std::endl;

    auto comm_service = connect_to_trusty();
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
