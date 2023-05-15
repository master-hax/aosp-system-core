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

use android_hardware_security_see::aidl::android::hardware::security::see::hwcrypto::base_types::{
    HalErrorCode::HalErrorCode
};
use android_hardware_security_see::aidl::android::hardware::security::see::hwcrypto::{
    HwCryptoKeyMaterial::HwCryptoKeyMaterial,
    IHwCryptoKeyManipulation::{BnHwCryptoKeyManipulation, IHwCryptoKeyManipulation},
};
use android_hardware_security_see::binder;

/// The `IHwCryptoKeyManipulation` implementation.
pub struct HwCryptoKeyManipulation;

impl HwCryptoKeyManipulation {
    pub(crate) fn new_operation() -> binder::Result<binder::Strong<dyn IHwCryptoKeyManipulation>> {
        let hwcrypto_key_manipulation = HwCryptoKeyManipulation;
        let hwcrypto_key_manipulation_binder = BnHwCryptoKeyManipulation::new_binder(
            hwcrypto_key_manipulation,
            binder::BinderFeatures::default(),
        );
        Ok(hwcrypto_key_manipulation_binder)
    }
}

impl binder::Interface for HwCryptoKeyManipulation {}

impl IHwCryptoKeyManipulation for HwCryptoKeyManipulation {
    fn set_key_validity(
        &self,
        _key: &HwCryptoKeyMaterial,
        _validity_period: i64,
    ) -> binder::Result<HalErrorCode> {
        unimplemented!("set_key_validity not implemented")
    }
}
