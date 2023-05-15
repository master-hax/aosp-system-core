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

//! Implementation of the `IHwCryptoKeyRsaOperations` AIDL interface.

use android_hardware_security_see::aidl::android::hardware::security::see::hwcrypto::types::{
    OpaqueKeyMaterial::OpaqueKeyMaterial, RsaDecryptParameters::RsaDecryptParameters,
    RsaSignParameters::RsaSignParameters,
};
use android_hardware_security_see::aidl::android::hardware::security::see::hwcrypto::{
    IAccumulatingOperation::IAccumulatingOperation,
    IHwCryptoKeyRsaOperations::{BnHwCryptoKeyRsaOperations, IHwCryptoKeyRsaOperations},
};
use android_hardware_security_see::binder;

use crate::rsa_decrypt_operation::RsaDecryptOperation;
use crate::rsa_sign_operation::RsaSignOperation;

/// The `IHwCryptoKeyRsaOperations` implementation for RSA encryption. It contains all the RSA
/// related functionality.
pub struct HwCryptoKeyRsaOperations;

impl HwCryptoKeyRsaOperations {
    pub(crate) fn new_operation() -> binder::Result<binder::Strong<dyn IHwCryptoKeyRsaOperations>> {
        let hwcryptokey_rsa_operations = HwCryptoKeyRsaOperations;
        let hwcryptokey_rsa_operations_binder = BnHwCryptoKeyRsaOperations::new_binder(
            hwcryptokey_rsa_operations,
            binder::BinderFeatures::default(),
        );
        Ok(hwcryptokey_rsa_operations_binder)
    }
}

impl binder::Interface for HwCryptoKeyRsaOperations {}

impl IHwCryptoKeyRsaOperations for HwCryptoKeyRsaOperations {
    fn begin_sign(
        &self,
        key: &OpaqueKeyMaterial,
        parameters: &RsaSignParameters,
    ) -> binder::Result<binder::Strong<dyn IAccumulatingOperation>> {
        RsaSignOperation::new_operation(key, parameters)
    }

    fn begin_decrypt(
        &self,
        key: &OpaqueKeyMaterial,
        parameters: &RsaDecryptParameters,
    ) -> binder::Result<binder::Strong<dyn IAccumulatingOperation>> {
        RsaDecryptOperation::new_operation(key, parameters)
    }

    fn get_public_key(&self, _key: &OpaqueKeyMaterial) -> binder::Result<Vec<u8>> {
        unimplemented!("finish not implemented")
    }
}
