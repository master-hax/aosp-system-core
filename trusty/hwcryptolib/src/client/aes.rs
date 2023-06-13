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

//! Wrapper over AES functions. It will route the calls either through AIDL if the key material
//! is opaque, or to a local BoringSSL library.

use hwcryptocommon::err::HwCryptoError;
use kmr_common::crypto::{self, Aes as KmAes, OpaqueOr, AadOperation, EmittingOperation, SymmetricOperation};
use android_hardware_security_see::aidl::android::hardware::security::see::hwcrypto::types::{
    OpaqueKeyMaterial::OpaqueKeyMaterial,
};
use kmr_crypto_boring::aes::BoringAes;

use crate::key_transformation;
use crate::symmetric_operations;

pub struct Aes;

/// Abstraction of AES functionality.
impl Aes {
    /// Create an AES operation.
    pub fn begin(
        &self,
        key: OpaqueOr<crypto::aes::Key>,
        mode: crypto::aes::CipherMode,
        dir: SymmetricOperation,
    ) -> Result<Box<dyn EmittingOperation>, HwCryptoError> {
        match key {
            OpaqueOr::Explicit(_) => {
                let boring_aes = BoringAes;
                Ok(boring_aes.begin(key, mode, dir)?)
            }
            OpaqueOr::Opaque(key_material) => {
                let parameters = key_transformation::aes_to_symmetric_parameters(mode, dir)?;
                let key_material = OpaqueKeyMaterial { key_blob: key_material.0 };
                symmetric_operations::begin_symmetric_operation(key_material, parameters)
            }
        }
    }

    /// Create an AES-GCM operation.
    pub fn begin_aead(
        &self,
        key: OpaqueOr<crypto::aes::Key>,
        mode: crypto::aes::GcmMode,
        dir: SymmetricOperation,
    ) -> Result<Box<dyn AadOperation>, HwCryptoError> {
        match key {
            OpaqueOr::Explicit(_) => {
                let boring_aes = BoringAes;
                Ok(boring_aes.begin_aead(key, mode, dir)?)
            }
            OpaqueOr::Opaque(key_material) => {
                let parameters = key_transformation::aes_aead_to_symmetric_parameters(mode, dir)?;
                let key_material = OpaqueKeyMaterial { key_blob: key_material.0 };
                symmetric_operations::begin_aead_operation(key_material, parameters)
            }
        }
    }

    //TODO: Add DMA operations (begin_dma and begin_dma_aead)
}
