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

//! Implementation of the `IHwCryptoKeyHashOperations` AIDL interface.

use android_hardware_security_see::aidl::android::hardware::security::see::hwcrypto::types::{
    HmacOperationParameters::HmacOperationParameters, OpaqueKeyMaterial::OpaqueKeyMaterial,
};
use android_hardware_security_see::aidl::android::hardware::security::see::hwcrypto::{
    IAccumulatingOperation::IAccumulatingOperation,
    IHwCryptoKeyHashOperations::{BnHwCryptoKeyHashOperations, IHwCryptoKeyHashOperations},
};
use android_hardware_security_see::binder;

use crate::hmac_operations::HmacOperations;

/// The `IHwCryptoKeyHashOperations` implementation.
pub struct HwCryptoKeyHashOperations;

impl HwCryptoKeyHashOperations {
    pub(crate) fn new_operation() -> binder::Result<binder::Strong<dyn IHwCryptoKeyHashOperations>>
    {
        let hwcryptokey_hash_operations = HwCryptoKeyHashOperations;
        let hwcryptokey_hash_operations_binder = BnHwCryptoKeyHashOperations::new_binder(
            hwcryptokey_hash_operations,
            binder::BinderFeatures::default(),
        );
        Ok(hwcryptokey_hash_operations_binder)
    }
}

impl binder::Interface for HwCryptoKeyHashOperations {}

impl IHwCryptoKeyHashOperations for HwCryptoKeyHashOperations {
    fn begin_hmac(
        &self,
        key: &OpaqueKeyMaterial,
        parameters: &HmacOperationParameters,
    ) -> binder::Result<binder::Strong<dyn IAccumulatingOperation>> {
        HmacOperations::new_operation(key, parameters)
    }
}
