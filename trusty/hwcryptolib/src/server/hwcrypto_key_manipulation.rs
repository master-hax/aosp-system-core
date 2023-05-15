/*
 * Copyright (C) 2023 The Android Open Source Project
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

//! Implementation of the `IHwCryptoKeyManipulation` AIDL interface. It contains the different
//! operations that change key metadata.

use android_hardware_security_see::aidl::android::hardware::security::see::hwcrypto::types::{
    HalErrorCode::HalErrorCode, KeyCharacteristicsResult::KeyCharacteristicsResult,
    OpaqueKeyMaterial::OpaqueKeyMaterial,
};
use android_hardware_security_see::aidl::android::hardware::security::see::hwcrypto::{
    IHwCryptoKeyProperties::{BnHwCryptoKeyProperties, IHwCryptoKeyProperties},
};
use android_hardware_security_see::binder;

/// The `IHwCryptoKeyProperties` implementation.
pub struct HwCryptoKeyProperties;

impl HwCryptoKeyProperties {
    pub(crate) fn new_operation() -> binder::Result<binder::Strong<dyn IHwCryptoKeyProperties>> {
        let hwcrypto_key_properties = HwCryptoKeyProperties;
        let hwcrypto_key_properties_binder = BnHwCryptoKeyProperties::new_binder(
            hwcrypto_key_properties,
            binder::BinderFeatures::default(),
        );
        Ok(hwcrypto_key_properties_binder)
    }
}

impl binder::Interface for HwCryptoKeyProperties {}

impl IHwCryptoKeyProperties for HwCryptoKeyProperties {
    fn set_key_validity(
        &self,
        _key: &OpaqueKeyMaterial,
        _validity_period: i64,
    ) -> binder::Result<HalErrorCode> {
        unimplemented!("set_key_validity not implemented")
    }

    fn get_key_characteristics(
        &self,
        _key: &OpaqueKeyMaterial,
    ) -> binder::Result<KeyCharacteristicsResult> {
        unimplemented!("get_key_characteristics not implemented")
    }
}
