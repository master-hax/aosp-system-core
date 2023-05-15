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

//! Implementation of the `IDmaAeadOperation` AIDL interface for symmetric cryptography.

use android_hardware_security_see::aidl::android::hardware::security::see::hwcrypto::types::{
    DmaOperationBuffers::DmaOperationBuffers, HalErrorCode::HalErrorCode,
    OpaqueKeyMaterial::OpaqueKeyMaterial,
    SymmetricOperationParameters::SymmetricOperationParameters,
};
use android_hardware_security_see::aidl::android::hardware::security::see::hwcrypto::{
    IDmaAeadOperation::IDmaAeadOperation,
};
use android_hardware_security_see::binder;

/// The `IDmaAeadOperation` implementation for symmetric cryptography (AES for now).
pub struct SymmetricDmaAeadOperation;

impl SymmetricDmaAeadOperation {
    pub(crate) fn new_operation(
        _key: &OpaqueKeyMaterial,
        _parameters: &SymmetricOperationParameters,
        _dma_buffers: &DmaOperationBuffers,
    ) -> binder::Result<binder::Strong<dyn IDmaAeadOperation>> {
        unimplemented!("SymmetricDmaAeadOperation::new not implemented")
    }
}

impl binder::Interface for SymmetricDmaAeadOperation {}

impl IDmaAeadOperation for SymmetricDmaAeadOperation {
    fn update_aad(&self) -> binder::Result<HalErrorCode> {
        unimplemented!("update not implemented")
    }

    fn update(&self) -> binder::Result<HalErrorCode> {
        unimplemented!("update not implemented")
    }

    fn is_busy(&self) -> binder::Result<bool> {
        unimplemented!("is_busy not implemented")
    }

    fn wait_for_completion(&self) -> binder::Result<HalErrorCode> {
        unimplemented!("wait_for_completion not implemented")
    }

    fn finish(&self) -> binder::Result<HalErrorCode> {
        unimplemented!("finish not implemented")
    }

    fn abort(&self) -> binder::Result<()> {
        unimplemented!("abort not implemented")
    }
}
