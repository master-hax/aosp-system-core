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

//! Implementation of the `IHwCryptoKey` AIDL interface. It can be use to retrieve the different
//! HwCrypto interfaces.

use android_hardware_security_see::aidl::android::hardware::security::see::hwcrypto::{
    IHwCryptoKey::IHwCryptoKey, IHwCryptoKeyEcOperations::IHwCryptoKeyEcOperations,
    IHwCryptoKeyGeneration::IHwCryptoKeyGeneration,
    IHwCryptoKeyHashOperations::IHwCryptoKeyHashOperations,
    IHwCryptoKeyProperties::IHwCryptoKeyProperties,
    IHwCryptoKeyRsaOperations::IHwCryptoKeyRsaOperations,
    IHwCryptoKeySymmetricOperations::IHwCryptoKeySymmetricOperations,
};
use android_hardware_security_see::binder;

use crate::hwcrypto_ec_operations::HwCryptoKeyEcOperations;
use crate::hwcrypto_hash_operations::HwCryptoKeyHashOperations;
use crate::hwcrypto_key_generation::HwCryptoKeyGeneration;
use crate::hwcrypto_key_manipulation::HwCryptoKeyProperties;
use crate::hwcrypto_rsa_operations::HwCryptoKeyRsaOperations;
use crate::hwcrypto_symmetric_operations::HwCryptoKeySymmetricOperations;

/// The `IHwCryptoKey` implementation.
pub struct HwCryptoKey;

impl binder::Interface for HwCryptoKey {}

impl IHwCryptoKey for HwCryptoKey {
    fn get_key_generation(&self) -> binder::Result<binder::Strong<dyn IHwCryptoKeyGeneration>> {
        HwCryptoKeyGeneration::new_operation()
    }

    fn get_key_properties(&self) -> binder::Result<binder::Strong<dyn IHwCryptoKeyProperties>> {
        HwCryptoKeyProperties::new_operation()
    }

    fn get_symmetric_key_operations(
        &self,
    ) -> binder::Result<binder::Strong<dyn IHwCryptoKeySymmetricOperations>> {
        HwCryptoKeySymmetricOperations::new_operation()
    }

    fn get_ec_key_operations(
        &self,
    ) -> binder::Result<binder::Strong<dyn IHwCryptoKeyEcOperations>> {
        HwCryptoKeyEcOperations::new_operation()
    }

    fn get_rsa_key_operations(
        &self,
    ) -> binder::Result<binder::Strong<dyn IHwCryptoKeyRsaOperations>> {
        HwCryptoKeyRsaOperations::new_operation()
    }

    fn get_hash_operations(
        &self,
    ) -> binder::Result<binder::Strong<dyn IHwCryptoKeyHashOperations>> {
        HwCryptoKeyHashOperations::new_operation()
    }
}
