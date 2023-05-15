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

//! Implementation of the `IAccumulatingOperation` AIDL interface for RSA signing.

use android_hardware_security_see::aidl::android::hardware::security::see::hwcrypto::types::{
    HalErrorCode::HalErrorCode,
    OpaqueKeyMaterial::OpaqueKeyMaterial, RsaSignParameters::RsaSignParameters,
};
use android_hardware_security_see::aidl::android::hardware::security::see::hwcrypto::{
    IAccumulatingOperation::IAccumulatingOperation,
};
use android_hardware_security_see::binder;

/// The `IAccumulatingOperation` implementation for RSA signing.
pub struct RsaSignOperation;

impl RsaSignOperation {
    pub(crate) fn new_operation(
        _key: &OpaqueKeyMaterial,
        _parameters: &RsaSignParameters,
    ) -> binder::Result<binder::Strong<dyn IAccumulatingOperation>> {
        unimplemented!("RsaSignOperation::new not implemented")
    }
}

impl binder::Interface for RsaSignOperation {}

impl IAccumulatingOperation for RsaSignOperation {
    fn max_input_size(&self) -> binder::Result<i64> {
        unimplemented!("max_input_size not implemented")
    }

    fn update(&self, _data: &[u8]) -> binder::Result<HalErrorCode> {
        unimplemented!("update not implemented")
    }

    fn finish(&self, _data: &[u8]) -> binder::Result<Vec<u8>> {
        unimplemented!("finish not implemented")
    }

    fn abort(&self) -> binder::Result<()> {
        unimplemented!("abort not implemented")
    }
}
