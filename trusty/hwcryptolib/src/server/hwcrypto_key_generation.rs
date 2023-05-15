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

//! Implementation of the `IHwCryptoKeyGeneration` AIDL interface. It contains the different key
//! generation functions.

use android_hardware_security_see::aidl::android::hardware::security::see::hwcrypto::base_types::{
    ComponentVersion::ComponentVersion, ExplicitKeyMaterial::ExplicitKeyMaterial,
    HwCryptoKeyResult::HwCryptoKeyResult, KeyVersionSource::KeyVersionSource,
    NullableInt::NullableInt, NullableKdfVersion::NullableKdfVersion,
    OpaqueKeyMaterial::OpaqueKeyMaterial, OpaqueKeyMaterialResult::OpaqueKeyMaterialResult,
    VectorResult::VectorResult,
};
use android_hardware_security_see::aidl::android::hardware::security::see::hwcrypto::{
    IHwCryptoKeyGeneration::{BnHwCryptoKeyGeneration, IHwCryptoKeyGeneration},
    KeyPolicy::KeyPolicy,
};
use android_hardware_security_see::binder;

/// The `IHwCryptoKeyGeneration` implementation.
pub struct HwCryptoKeyGeneration;

impl HwCryptoKeyGeneration {
    pub(crate) fn new_operation() -> binder::Result<binder::Strong<dyn IHwCryptoKeyGeneration>> {
        let hwcrypto_key_generation = HwCryptoKeyGeneration;
        let hwcrypto_key_generation_binder = BnHwCryptoKeyGeneration::new_binder(
            hwcrypto_key_generation,
            binder::BinderFeatures::default(),
        );
        Ok(hwcrypto_key_generation_binder)
    }
}

impl binder::Interface for HwCryptoKeyGeneration {}

impl IHwCryptoKeyGeneration for HwCryptoKeyGeneration {
    fn get_keyslot_data(&self, _slot_id: &str) -> binder::Result<OpaqueKeyMaterialResult> {
        unimplemented!("get_keyslot_data not implemented")
    }

    fn hwkey_derive_versioned(
        &self,
        _kdf_version: Option<&NullableKdfVersion>,
        _batch_key: bool,
        _key_policy: &KeyPolicy,
        _rollback_version_source: KeyVersionSource,
        _rollback_versions: &[ComponentVersion],
        _context: &[u8],
        _key_size: Option<&NullableInt>,
        _derive_opaque_key: bool,
    ) -> binder::Result<HwCryptoKeyResult> {
        unimplemented!("hwkey_derive_versioned not implemented")
    }

    fn import_clear_key(
        &self,
        _key_to_be_imported: &ExplicitKeyMaterial,
        _new_key_policy: &KeyPolicy,
    ) -> binder::Result<OpaqueKeyMaterialResult> {
        unimplemented!("import_clear_key not implemented")
    }

    fn import_wrapped_key(
        &self,
        _key_to_be_imported: &[u8],
        _wrapping_key: &OpaqueKeyMaterial,
    ) -> binder::Result<OpaqueKeyMaterialResult> {
        unimplemented!("import_wrapped_key not implemented")
    }

    fn export_wrapped_key(
        &self,
        _key_to_be_exported: &OpaqueKeyMaterial,
        _wrapping_key: &OpaqueKeyMaterial,
    ) -> binder::Result<VectorResult> {
        unimplemented!("export_wrapped_key not implemented")
    }

    fn generate_key(
        &self,
        _policy: &KeyPolicy,
        _key_size: Option<&NullableInt>,
    ) -> binder::Result<OpaqueKeyMaterialResult> {
        unimplemented!("generate_key not implemented")
    }

    fn derive_key(
        &self,
        _derivation_key: &OpaqueKeyMaterial,
        _policy: &KeyPolicy,
        _context: &[u8],
        _key_size: Option<&NullableInt>,
    ) -> binder::Result<OpaqueKeyMaterialResult> {
        unimplemented!("generate_key not implemented")
    }
}
