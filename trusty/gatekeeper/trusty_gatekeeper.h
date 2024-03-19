/*
 * Copyright (C) 2014 The Android Open Source Project
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

#ifndef TRUSTY_GATEKEEPER_H
#define TRUSTY_GATEKEEPER_H

#include <memory>

#include <aidl/android/hardware/gatekeeper/BnGatekeeper.h>

#include <android/hardware/gatekeeper/IGatekeeper.h>
#include <binder/RpcTrusty.h>

#include <gatekeeper/gatekeeper_messages.h>

namespace aidl::android::hardware::gatekeeper {

class TrustyGateKeeperDevice : public BnGatekeeper {
  public:
    explicit TrustyGateKeeperDevice();
    ~TrustyGateKeeperDevice();
    /**
     * Enrolls password_payload, which should be derived from a user selected pin or password,
     * with the authentication factor private key used only for enrolling authentication
     * factor data.
     *
     * Returns: 0 on success or an error code less than 0 on error.
     */
    ::ndk::ScopedAStatus enroll(int32_t uid, const std::vector<uint8_t>& currentPasswordHandle,
                                const std::vector<uint8_t>& currentPassword,
                                const std::vector<uint8_t>& desiredPassword,
                                GatekeeperEnrollResponse* _aidl_return) override;

    /**
     * Verifies provided_password matches enrolledPasswordHandle.
     *
     * Implementations of this module may retain the result of this call
     * to attest to the recency of authentication.
     *
     * On success, _aidl_return will contain an auth token, usable to attest password verification
     * to other trusted services.
     *
     * Returns: 0 on success or an error code less than 0 on error
     */
    ::ndk::ScopedAStatus verify(int32_t uid, int64_t challenge,
                                const std::vector<uint8_t>& enrolledPasswordHandle,
                                const std::vector<uint8_t>& providedPassword,
                                GatekeeperVerifyResponse* _aidl_return) override;

    ::ndk::ScopedAStatus deleteAllUsers() override;

    ::ndk::ScopedAStatus deleteUser(int32_t uid) override;

  private:
    ::android::sp<::android::hardware::gatekeeper::IGatekeeper> gk_;
};

}  // namespace aidl::android::hardware::gatekeeper

#endif
