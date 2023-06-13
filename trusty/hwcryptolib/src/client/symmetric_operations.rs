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

//! Adapter to use KM traits with an HWCrypto AIDL backend

use android_hardware_security_see::aidl::android::hardware::security::see::hwcrypto::types::{
    OpaqueKeyMaterial::OpaqueKeyMaterial,
    SymmetricOperationParameters::SymmetricOperationParameters,
};
use hwcryptocommon::err::HwCryptoError;
use kmr_common::{
    crypto::{AadOperation, EmittingOperation},
    Error as KmError,
};

pub(crate) struct SymmetricEmittingOperations;

impl SymmetricEmittingOperations {
    fn new() -> Result<Self, HwCryptoError> {
        unimplemented!("SymmetricEmittingOperations::new not implemented")
    }
}

impl EmittingOperation for SymmetricEmittingOperations {
    /// Update operation with data.
    fn update(&mut self, _data: &[u8]) -> Result<Vec<u8>, KmError> {
        unimplemented!("SymmetricEmittingOperations::update not implemented")
    }

    /// Complete operation, consuming `self`.
    fn finish(self: Box<Self>) -> Result<Vec<u8>, KmError> {
        unimplemented!("SymmetricEmittingOperations::finish not implemented")
    }
}

pub(crate) struct SymmetricAadOperations;

impl SymmetricAadOperations {
    fn new() -> Result<Self, HwCryptoError> {
        unimplemented!("SymmetricEmittingOperations::new not implemented")
    }
}

impl EmittingOperation for SymmetricAadOperations {
    /// Update operation with data.
    fn update(&mut self, _data: &[u8]) -> Result<Vec<u8>, KmError> {
        unimplemented!("SymmetricEmittingOperations::update not implemented")
    }

    /// Complete operation, consuming `self`.
    fn finish(self: Box<Self>) -> Result<Vec<u8>, KmError> {
        unimplemented!("SymmetricEmittingOperations::finish not implemented")
    }
}

impl AadOperation for SymmetricAadOperations {
    /// Updates operation with additional authenticated data. Should be called before update or
    /// finish
    fn update_aad(&mut self, _aad: &[u8]) -> Result<(), KmError> {
        unimplemented!("SymmetricAadOperations::update_aad not implemented")
    }
}

pub(crate) fn begin_symmetric_operation(
    _key: OpaqueKeyMaterial,
    _parameters: SymmetricOperationParameters,
) -> Result<Box<dyn EmittingOperation>, HwCryptoError> {
    Ok(Box::new(SymmetricEmittingOperations::new()?))
}

pub(crate) fn begin_aead_operation(
    _key: OpaqueKeyMaterial,
    _parameters: SymmetricOperationParameters,
) -> Result<Box<dyn AadOperation>, HwCryptoError> {
    Ok(Box::new(SymmetricAadOperations::new()?))
}
