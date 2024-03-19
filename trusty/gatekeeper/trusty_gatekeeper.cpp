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

#define LOG_TAG "TrustyGateKeeper"

#include <endian.h>
#include <limits>

#include <android-base/logging.h>
#include <android/hardware/gatekeeper/IGatekeeper.h>
#include <binder/RpcTrusty.h>
#include <gatekeeper/password_handle.h>
#include <hardware/hw_auth_token.h>

#include "gatekeeper_ipc.h"
#include "trusty_gatekeeper.h"
#include "trusty_gatekeeper_ipc.h"

namespace aidl::android::hardware::gatekeeper {

using ::gatekeeper::ERROR_INVALID;
using ::gatekeeper::ERROR_NONE;
using ::gatekeeper::ERROR_RETRY;
using ::gatekeeper::SizedBuffer;
using ::gatekeeper::VerifyRequest;
using ::gatekeeper::VerifyResponse;

#define TIPC_DEFAULT_DEVNAME "/dev/trusty-ipc-dev0"
#define GATEKEEPER_SOCKET "com.android.trusty.gatekeeper_v2"

TrustyGateKeeperDevice::TrustyGateKeeperDevice() {
    auto gkBinder = ::android::RpcTrustyConnect(TIPC_DEFAULT_DEVNAME, GATEKEEPER_SOCKET);
    gk_ = ::android::hardware::gatekeeper::IGatekeeper::asInterface(gkBinder);
}

TrustyGateKeeperDevice::~TrustyGateKeeperDevice() {
    trusty_gatekeeper_disconnect();
}

::ndk::ScopedAStatus TrustyGateKeeperDevice::enroll(
        int32_t uid, const std::vector<uint8_t>& currentPasswordHandle,
        const std::vector<uint8_t>& currentPassword, const std::vector<uint8_t>& desiredPassword,
        GatekeeperEnrollResponse* rsp) {
    if (!gk_) {
        return ndk::ScopedAStatus(AStatus_fromServiceSpecificError(ERROR_GENERAL_FAILURE));
    }

    if (desiredPassword.size() == 0) {
        return ndk::ScopedAStatus(AStatus_fromServiceSpecificError(ERROR_GENERAL_FAILURE));
    }

    ::android::hardware::gatekeeper::GatekeeperEnrollResponse x;
    ::android::binder::Status status =
            gk_->enroll(uid, currentPasswordHandle, currentPassword, desiredPassword, &x);

    if (!status.isOk()) {
        return ndk::ScopedAStatus(AStatus_fromServiceSpecificError(ERROR_GENERAL_FAILURE));
    } else {
        const ::gatekeeper::password_handle_t* password_handle =
                reinterpret_cast<::gatekeeper::password_handle_t*>(x.data.data());

        *rsp = {x.statusCode, 0, static_cast<int64_t>(password_handle->user_id), x.data};
    }
    return ndk::ScopedAStatus::ok();
}

::ndk::ScopedAStatus TrustyGateKeeperDevice::verify(
        int32_t uid, int64_t challenge, const std::vector<uint8_t>& enrolledPasswordHandle,
        const std::vector<uint8_t>& providedPassword, GatekeeperVerifyResponse* rsp) {
    if (!gk_) {
        return ndk::ScopedAStatus(AStatus_fromServiceSpecificError(ERROR_GENERAL_FAILURE));
    }

    if (enrolledPasswordHandle.size() == 0) {
        return ndk::ScopedAStatus(AStatus_fromServiceSpecificError(ERROR_GENERAL_FAILURE));
    }

    ::android::hardware::gatekeeper::GatekeeperVerifyResponse x;
    ::android::binder::Status status =
            gk_->verify(uid, challenge, enrolledPasswordHandle, providedPassword, &x);

    if (!status.isOk()) {
        return ndk::ScopedAStatus(AStatus_fromServiceSpecificError(ERROR_GENERAL_FAILURE));
    } else {
        *rsp = {x.statusCode, x.timeoutMs};
        rsp->hardwareAuthToken = {x.hardwareAuthToken.challenge, x.hardwareAuthToken.userId,
                                  x.hardwareAuthToken.authenticatorId};

        rsp->hardwareAuthToken.authenticatorType = static_cast<
                ::aidl::android::hardware::security::keymint::HardwareAuthenticatorType>(
                x.hardwareAuthToken.authenticatorType);
        rsp->hardwareAuthToken.timestamp = {x.hardwareAuthToken.timestamp.milliSeconds};
    }
    return ndk::ScopedAStatus::ok();
}

::ndk::ScopedAStatus TrustyGateKeeperDevice::deleteUser(int32_t uid) {
    if (!gk_) {
        return ndk::ScopedAStatus(AStatus_fromServiceSpecificError(ERROR_GENERAL_FAILURE));
    }

    ::android::binder::Status status = gk_->deleteUser(uid);

    if (!status.isOk()) {
        return ndk::ScopedAStatus(AStatus_fromServiceSpecificError(ERROR_GENERAL_FAILURE));
    } else {
        return ndk::ScopedAStatus::ok();
    }
}

::ndk::ScopedAStatus TrustyGateKeeperDevice::deleteAllUsers() {
    if (!gk_) {
        return ndk::ScopedAStatus(AStatus_fromServiceSpecificError(ERROR_GENERAL_FAILURE));
    }

    ::android::binder::Status status = gk_->deleteAllUsers();

    if (!status.isOk()) {
        return ndk::ScopedAStatus(AStatus_fromServiceSpecificError(ERROR_GENERAL_FAILURE));
    } else {
        return ndk::ScopedAStatus::ok();
    }
}

}  // namespace aidl::android::hardware::gatekeeper
