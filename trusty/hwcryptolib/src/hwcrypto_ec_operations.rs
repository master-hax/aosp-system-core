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

//! Implementation of the `IHwCryptoKeyEcOperations` AIDL interface. It contains all the EC related
//! functionality

use android_hardware_security_see::aidl::android::hardware::security::see::hwcrypto::base_types::{
    AccumulatingOperationResult::AccumulatingOperationResult, EcSignParameters::EcSignParameters,
    VectorResult::VectorResult,
};
use android_hardware_security_see::aidl::android::hardware::security::see::hwcrypto::{
    HwCryptoKeyMaterial::HwCryptoKeyMaterial,
    IHwCryptoKeyEcOperations::{BnHwCryptoKeyEcOperations, IHwCryptoKeyEcOperations},
};
use android_hardware_security_see::binder;

use crate::ec_shared_secret_operation::EcSharedSecretOperation;
use crate::ec_sign_operation::EcSignOperation;

/// The `IHwCryptoKeyEcOperations` implementation.
pub struct HwCryptoKeyEcOperations;

impl HwCryptoKeyEcOperations {
    pub(crate) fn new_operation() -> binder::Result<binder::Strong<dyn IHwCryptoKeyEcOperations>> {
        let hwcryptokey_ec_operations = HwCryptoKeyEcOperations;
        let hwcryptokey_ec_operations_binder = BnHwCryptoKeyEcOperations::new_binder(
            hwcryptokey_ec_operations,
            binder::BinderFeatures::default(),
        );
        Ok(hwcryptokey_ec_operations_binder)
    }
}

impl binder::Interface for HwCryptoKeyEcOperations {}

impl IHwCryptoKeyEcOperations for HwCryptoKeyEcOperations {
    fn begin_sign(
        &self,
        key: &HwCryptoKeyMaterial,
        parameters: &EcSignParameters,
    ) -> binder::Result<AccumulatingOperationResult> {
        EcSignOperation::new_operation(key, parameters)
    }

    fn begin_shared_secret(
        &self,
        key: &HwCryptoKeyMaterial,
    ) -> binder::Result<AccumulatingOperationResult> {
        EcSharedSecretOperation::new_operation(key)
    }

    fn get_public_key(&self, _key: &HwCryptoKeyMaterial) -> binder::Result<VectorResult> {
        unimplemented!("get_public_key not implemented")
    }
}
