/*
 * Copyright (C) 2019 The Android Open Source Project
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

#include "healthd_mode_charger_nops.h"

#include <android-base/logging.h>
#include <android/hardware/health/2.0/IHealthInfoCallback.h>
#include <health/utils.h>
#include <health2impl/HalHealthLoop.h>
#include <health2impl/Health.h>

#include "charger_utils.h"

using android::sp;
using android::hardware::Return;
using android::hardware::Void;
using android::hardware::health::GetPassthroughHealth;
using android::hardware::health::V2_1::IHealth;
using IHealth_2_0 = ::android::hardware::health::V2_0::IHealth;
using android::hardware::health::V2_1::implementation::HalHealthLoop;

namespace android {

class ChargerNops : public ::android::hardware::health::V2_1::implementation::HalHealthLoop,
                    public ::android::hardware::health::V2_0::IHealthInfoCallback {
  public:
    using HealthInfo_2_0 = android::hardware::health::V2_0::HealthInfo;

    ChargerNops(const sp<android::hardware::health::V2_1::IHealth>& service)
        : HalHealthLoop("charger", service) {}

    // IHealthInfoCallback overrides.
    android::hardware::Return<void> healthInfoChanged(const HealthInfo_2_0& health_info) override;

  protected:
    virtual void Init(struct healthd_config* config) override;

    bool charger_connected_ = false;
};

// See Charger::healthInfoChanged.
Return<void> ChargerNops::healthInfoChanged(const HealthInfo_2_0& health_info) {
    const auto& props = health_info.legacy;
    charger_connected_ =
            props.chargerAcOnline || props.chargerUsbOnline || props.chargerWirelessOnline;

    // adjust uevent / wakealarm periods
    SetChargerOnline(charger_connected_);
    return Void();
}

void ChargerNops::Init(struct healthd_config* config) {
    // Initialize HealthLoop and retrieve healthd_config from the existing health HAL.
    HalHealthLoop::Init(config);
    // HealthLoop invokes HealthHalLoop::ScheduleBatteryUpdate() periodically, which calls
    // service()->update(). Register |this| as a callback to service() so that healthInfoChanged()
    // is invoked periodically.
    service()->registerCallback(this);
}

}  // namespace android

int healthd_charger_nops(int /* argc */, char** /* argv */) {
    sp<android::ChargerNops> charger = new android::ChargerNops(GetPassthroughHealth());
    return charger->StartLoop();
}
