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

//! Key Generation functions

use android_hardware_security_see::aidl::android::hardware::security::see::hwcrypto::types::{
    ComponentVersion::ComponentVersion, KdfVersion::KdfVersion, KeyLifetime::KeyLifetime,
    KeyType::KeyType, KeyUse::KeyUse, KeyVersionSource::KeyVersionSource,
};
use android_hardware_security_see::aidl::android::hardware::security::see::hwcrypto::KeyPolicy::KeyPolicy;
use hwcryptocommon::{err::HwCryptoError, hwcrypto_err};
use kmr_common::crypto::{KeyMaterial, OpaqueKeyMaterial};

#[allow(dead_code)]
pub struct KeyPolicyBuilder {
    key_usage: Vec<KeyUse>,
    key_lifetime: KeyLifetime,
    key_type: KeyType,
}

impl KeyPolicyBuilder {
    pub fn new(key_type: KeyType, key_lifetime: KeyLifetime) -> Self {
        KeyPolicyBuilder { key_usage: Vec::<KeyUse>::new(), key_lifetime, key_type }
    }

    pub fn add_key_usage(mut self, key_usage: KeyUse) -> Result<Self, HwCryptoError> {
        if self.key_usage.iter().any(|existing_usage| existing_usage.0 == key_usage.0) {
            return Err(hwcrypto_err!(BAD_PARAMETER, "usage {:?} already added", key_usage));
        }
        self.key_usage.try_reserve(1)?;
        self.key_usage.push(key_usage);
        Ok(self)
    }
}

#[allow(dead_code)]
pub struct VersionedKeyParameters {
    kdf_version: Option<KdfVersion>,
    batch_key: bool,
    rollback_version_source: KeyVersionSource,
    rollback_versions: Vec<ComponentVersion>,
    derive_opaque_key: bool,
}

pub struct VersionedKeyParametersBuilder(VersionedKeyParameters);

impl VersionedKeyParametersBuilder {
    pub fn new(batch_key: bool, derive_opaque_key: bool) -> Self {
        let parameters = VersionedKeyParameters {
            kdf_version: None,
            batch_key,
            rollback_version_source: KeyVersionSource::COMMITTED_VERSION,
            rollback_versions: Vec::<ComponentVersion>::new(),
            derive_opaque_key,
        };
        VersionedKeyParametersBuilder(parameters)
    }

    pub fn build(self) -> VersionedKeyParameters {
        self.0
    }

    pub fn rollback_version_source(mut self, rollback_version_source: KeyVersionSource) -> Self {
        self.0.rollback_version_source = rollback_version_source;
        self
    }

    pub fn kdf_version(mut self, kdf_version: KdfVersion) -> Self {
        self.0.kdf_version = Some(kdf_version);
        self
    }

    pub fn rollback_version(
        mut self,
        component_version: ComponentVersion,
    ) -> Result<Self, HwCryptoError> {
        if self
            .0
            .rollback_versions
            .iter()
            .any(|existing_component| existing_component.component == component_version.component)
        {
            return Err(hwcrypto_err!(
                BAD_PARAMETER,
                "parameter {:?} already added",
                component_version.component
            ));
        }
        self.0.rollback_versions.try_reserve(1)?;
        self.0.rollback_versions.push(component_version);
        Ok(self)
    }
}

pub struct KeyGeneration;

impl KeyGeneration {
    /// Retrieves a key from a keyslot and returns a per-boot opaque key
    pub fn get_keyslot_data(&self, _slot_id: &str) -> Result<KeyMaterial, HwCryptoError> {
        unimplemented!("get_keyslot_data not implemented")
    }

    /// Deterministically derives a key unique to the caller, including on the derivation the
    /// provided context and the requested version. The service will check if the application
    /// current version(s) is greater or equal than the requested version. The returned key material
    /// could be opaque or explicit, depending on the `versioned_key_parameters`. Note that each
    /// case returns a different key value, so that an opaque key cannot be re-derived in the clear
    pub fn hwkey_derive_versioned(
        &self,
        _versioned_key_parameters: VersionedKeyParameters,
        _key_policy: &KeyPolicy,
        _context: &[u8],
        _key_size: Option<u32>,
    ) -> Result<KeyMaterial, HwCryptoError> {
        unimplemented!("hwkey_derive_versioned not implemented")
    }

    /// Imports explicit KeyMaterial and returns a per-boot opaque key
    pub fn import_clear_key(
        &self,
        _key_to_be_imported: &KeyMaterial,
        _new_key_policy: &KeyPolicy,
    ) -> Result<KeyMaterial, HwCryptoError> {
        unimplemented!("import_clear_key not implemented")
    }

    /// Imports a previously exported and wrapped for long term storage key and returns a per-boot
    /// opaque key
    pub fn import_wrapped_key(
        &self,
        _key_to_be_imported: &[u8],
        _wrapping_key: &OpaqueKeyMaterial,
    ) -> Result<KeyMaterial, HwCryptoError> {
        unimplemented!("import_wrapped_key not implemented")
    }

    /// Exports and wraps (encrypts) a per-boot opaque key for long term storage
    pub fn export_wrapped_key(
        &self,
        _key_to_be_exported: &OpaqueKeyMaterial,
        _wrapping_key: &OpaqueKeyMaterial,
    ) -> Result<Vec<u8>, HwCryptoError> {
        unimplemented!("export_wrapped_key not implemented")
    }

    /// Generates a key using a random source and returns a per-boot opaque key
    pub fn generate_key(
        &self,
        _policy: &KeyPolicy,
        _key_size: Option<u32>,
    ) -> Result<KeyMaterial, HwCryptoError> {
        unimplemented!("generate_key not implemented")
    }

    /// Derives a new key from `derivation_key` using a KDF. If the input key is opaque, the
    /// returned key willl be opaque.If the input key is explicit, the returned key will be explicit
    pub fn derive_key(
        &self,
        _derivation_key: &KeyMaterial,
        _policy: &KeyPolicy,
        _context: &[u8],
        _key_size: Option<u32>,
    ) -> Result<KeyMaterial, HwCryptoError> {
        unimplemented!("derive_key not implemented")
    }
}
