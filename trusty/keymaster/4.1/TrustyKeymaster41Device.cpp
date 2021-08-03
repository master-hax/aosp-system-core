/*
 **
 ** Copyright 2021, The Android Open Source Project
 **
 ** Licensed under the Apache License, Version 2.0 (the "License");
 ** you may not use this file except in compliance with the License.
 ** You may obtain a copy of the License at
 **
 **     http://www.apache.org/licenses/LICENSE-2.0
 **
 ** Unless required by applicable law or agreed to in writing, software
 ** distributed under the License is distributed on an "AS IS" BASIS,
 ** WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 ** See the License for the specific language governing permissions and
 ** limitations under the License.
 */

#define LOG_TAG "android.hardware.keymaster@4.1-impl.trusty"

#include <android/hardware/keymaster/3.0/IKeymasterDevice.h>
#include <authorization_set.h>
#include <cutils/log.h>
#include <keymaster/android_keymaster_messages.h>
#include <trusty_keymaster/TrustyKeymaster41Device.h>
#include <trusty_keymaster/ipc/trusty_keymaster_ipc.h>

using ::keymaster::ng::Tag;
typedef ::android::hardware::keymaster::V4_0::Tag Tag4;

namespace keymaster::V4_1 {

namespace {

inline V41ErrorCode legacy_enum_conversion(const keymaster_error_t value) {
    return static_cast<V41ErrorCode>(value);
}

inline keymaster_tag_t legacy_enum_conversion(const Tag4 value) {
    return keymaster_tag_t(value);
}

inline keymaster_tag_type_t typeFromTag(const keymaster_tag_t tag) {
    return keymaster_tag_get_type(tag);
}

keymaster_key_param_set_t hidlKeyParams2Km(const hidl_vec<KeyParameter>& keyParams) {
    keymaster_key_param_set_t set;

    set.params = new keymaster_key_param_t[keyParams.size()];
    set.length = keyParams.size();

    for (size_t i = 0; i < keyParams.size(); ++i) {
        auto tag = legacy_enum_conversion(keyParams[i].tag);
        switch (typeFromTag(tag)) {
            case KM_ENUM:
            case KM_ENUM_REP:
                set.params[i] = keymaster_param_enum(tag, keyParams[i].f.integer);
                break;
            case KM_UINT:
            case KM_UINT_REP:
                set.params[i] = keymaster_param_int(tag, keyParams[i].f.integer);
                break;
            case KM_ULONG:
            case KM_ULONG_REP:
                set.params[i] = keymaster_param_long(tag, keyParams[i].f.longInteger);
                break;
            case KM_DATE:
                set.params[i] = keymaster_param_date(tag, keyParams[i].f.dateTime);
                break;
            case KM_BOOL:
                if (keyParams[i].f.boolValue)
                    set.params[i] = keymaster_param_bool(tag);
                else
                    set.params[i].tag = KM_TAG_INVALID;
                break;
            case KM_BIGNUM:
            case KM_BYTES:
                set.params[i] =
                        keymaster_param_blob(tag, &keyParams[i].blob[0], keyParams[i].blob.size());
                break;
            case KM_INVALID:
            default:
                set.params[i].tag = KM_TAG_INVALID;
                /* just skip */
                break;
        }
    }

    return set;
}

}  // namespace

Return<V41ErrorCode> TrustyKeymaster41Device::deviceLocked(
        bool passwordOnly, const VerificationToken& verificationToken) {
    keymaster::VerificationToken serializableToken;
    serializableToken.challenge = verificationToken.challenge;
    serializableToken.timestamp = verificationToken.timestamp;
    serializableToken.parameters_verified.Reinitialize(
            hidlKeyParams2Km(verificationToken.parametersVerified));
    serializableToken.security_level =
            static_cast<keymaster_security_level_t>(verificationToken.securityLevel);
    serializableToken.mac =
            KeymasterBlob(verificationToken.mac.data(), verificationToken.mac.size());
    return legacy_enum_conversion(
            impl_->DeviceLocked(DeviceLockedRequest(impl_->message_version(), passwordOnly,
                                                    std::move(serializableToken)))
                    .error);
}

Return<V41ErrorCode> TrustyKeymaster41Device::earlyBootEnded() {
    return legacy_enum_conversion(impl_->EarlyBootEnded().error);
}

}  // namespace keymaster::V4_1
