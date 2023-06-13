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

//! Helper module implementing transformations from AIDL format to on-process-library format

use android_hardware_security_see::aidl::android::hardware::security::see::hwcrypto::types::{
    AesCipherMode::AesCipherMode, AesCipherModeParameters::AesCipherModeParameters,
    AesGcmMode::AesGcmMode, AesGcmModeParameters::AesGcmModeParameters,
    AesParameters::AesParameters, EmptyEnum::EmptyEnum,
    SymmetricAlgorithmParameters::SymmetricAlgorithmParameters,
    SymmetricOperation::SymmetricOperation,
    SymmetricOperationParameters::SymmetricOperationParameters,
};
use hwcryptocommon::err::HwCryptoError;
use kmr_common::crypto::{self, try_to_vec, SymmetricOperation as KmSymmetricOperation};

fn rust_to_aidl_symmetric_direction(dir: KmSymmetricOperation) -> SymmetricOperation {
    match dir {
        KmSymmetricOperation::Encrypt => SymmetricOperation::ENCRYPT,
        KmSymmetricOperation::Decrypt => SymmetricOperation::DECRYPT,
    }
}

fn rust_to_aidl_aes_cipher_params(
    params: crypto::aes::CipherMode,
) -> Result<AesCipherMode, HwCryptoError> {
    match params {
        crypto::aes::CipherMode::EcbNoPadding => Ok(AesCipherMode::EcbNoPadding(EmptyEnum::NONE)),
        crypto::aes::CipherMode::EcbPkcs7Padding => {
            Ok(AesCipherMode::EcbPkcs7Padding(EmptyEnum::NONE))
        }
        crypto::aes::CipherMode::CbcNoPadding { nonce } => {
            let params = AesCipherModeParameters { nonce: try_to_vec(&nonce)? };
            Ok(AesCipherMode::CbcNoPadding(params))
        }
        crypto::aes::CipherMode::CbcPkcs7Padding { nonce } => {
            let params = AesCipherModeParameters { nonce: try_to_vec(&nonce)? };
            Ok(AesCipherMode::CbcPkcs7Padding(params))
        }
        crypto::aes::CipherMode::Ctr { nonce } => {
            let params = AesCipherModeParameters { nonce: try_to_vec(&nonce)? };
            Ok(AesCipherMode::Ctr(params))
        }
    }
}

pub(crate) fn aes_to_symmetric_parameters(
    mode: crypto::aes::CipherMode,
    dir: KmSymmetricOperation,
) -> Result<SymmetricOperationParameters, HwCryptoError> {
    let direction = rust_to_aidl_symmetric_direction(dir);
    let aes_params = rust_to_aidl_aes_cipher_params(mode)?;
    let parameters = SymmetricAlgorithmParameters::Aes(AesParameters::CipherMode(aes_params));
    Ok(SymmetricOperationParameters { direction, parameters })
}

fn rust_to_aidl_aes_gcm_params(params: crypto::aes::GcmMode) -> Result<AesGcmMode, HwCryptoError> {
    match params {
        crypto::aes::GcmMode::GcmTag12 { nonce } => {
            let params = AesGcmModeParameters { nonce };
            Ok(AesGcmMode::GcmTag12(params))
        }
        crypto::aes::GcmMode::GcmTag13 { nonce } => {
            let params = AesGcmModeParameters { nonce };
            Ok(AesGcmMode::GcmTag13(params))
        }
        crypto::aes::GcmMode::GcmTag14 { nonce } => {
            let params = AesGcmModeParameters { nonce };
            Ok(AesGcmMode::GcmTag14(params))
        }
        crypto::aes::GcmMode::GcmTag15 { nonce } => {
            let params = AesGcmModeParameters { nonce };
            Ok(AesGcmMode::GcmTag15(params))
        }
        crypto::aes::GcmMode::GcmTag16 { nonce } => {
            let params = AesGcmModeParameters { nonce };
            Ok(AesGcmMode::GcmTag16(params))
        }
    }
}

pub(crate) fn aes_aead_to_symmetric_parameters(
    mode: crypto::aes::GcmMode,
    dir: KmSymmetricOperation,
) -> Result<SymmetricOperationParameters, HwCryptoError> {
    let direction = rust_to_aidl_symmetric_direction(dir);
    let aes_params = rust_to_aidl_aes_gcm_params(mode)?;
    let parameters = SymmetricAlgorithmParameters::Aes(AesParameters::Gcm(aes_params));
    Ok(SymmetricOperationParameters { direction, parameters })
}
