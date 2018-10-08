/*
 * Copyright 2018 The Android Open Source Project
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

#include "Gatekeeper1Wrapper.h"

#define LOG_TAG "gatekeeperd"

#include <keymaster_capability/keymaster_capability_utils.h>
#include <log/log.h>

namespace gk1 = android::hardware::gatekeeper::V1_0;

using namespace android::hardware;
using namespace android::hardware::gatekeeper::V2_0;
using namespace android::hardware::keymaster_capability::V1_0;

using android::sp;
using android::hardware::hidl_vec;
using android::hardware::details::StatusOf;
using gk1::GatekeeperStatusCode;

class Gatekeeper1Wrapper : public IGatekeeper {
  public:
    using Gatekeeper1 = gatekeeper::V1_0::IGatekeeper;

    Gatekeeper1Wrapper(sp<Gatekeeper1> gk1) : wrapped_(gk1) {}

    Return<void> enroll(uint32_t uid, const hidl_vec<uint8_t>& currentPasswordHandle,
                        const hidl_vec<uint8_t>& currentPassword,
                        const hidl_vec<uint8_t>& desiredPassword, enroll_cb _hidl_cb) override {
        return wrapped_->enroll(uid, currentPasswordHandle, currentPassword, desiredPassword,
                                [_hidl_cb](const gk1::GatekeeperResponse& rsp) {
                                    _hidl_cb(rsp.code, rsp.timeout, rsp.data);
                                });
    }

    Return<void> verify(uint32_t uid, uint64_t challenge,
                        const hidl_vec<uint8_t>& enrolledPasswordHandle,
                        const hidl_vec<uint8_t>& providedPassword, verify_cb _hidl_cb) override {
        return wrapped_->verify(uid, challenge, enrolledPasswordHandle, providedPassword,
                                [_hidl_cb](const gk1::GatekeeperResponse& rsp) {
                                    _hidl_cb(rsp.code, rsp.timeout,
                                             hidlVec2KeymasterCapability(rsp.data));
                                });
    }

    Return<GatekeeperStatusCode> deleteUser(uint32_t uid) override {
        GatekeeperStatusCode code;
        auto result = wrapped_->deleteUser(
                uid, [&](const gk1::GatekeeperResponse& rsp) { code = rsp.code; });
        return result.isOk() ? Return<GatekeeperStatusCode>(code)
                             : StatusOf<void, GatekeeperStatusCode>(result);
    }

    Return<GatekeeperStatusCode> deleteAllUsers() override {
        GatekeeperStatusCode code;
        auto result = wrapped_->deleteAllUsers(
                [&](const gk1::GatekeeperResponse& rsp) { code = rsp.code; });
        return result.isOk() ? Return<GatekeeperStatusCode>(code)
                             : StatusOf<void, GatekeeperStatusCode>(result);
    }

  private:
    sp<Gatekeeper1> wrapped_;
};

sp<IGatekeeper> wrapGatekeeper1(sp<gk1::IGatekeeper> gk1service) {
    if (!gk1service) return nullptr;

    ALOGW("Using wrapped Gatekeeprer1 device");
    return new Gatekeeper1Wrapper(gk1service);
}
