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

//! Utilities to transform a key from its Opaque representation (used by the service clients) to
//! a clear representation for use inside the service

use android_hardware_security_see::aidl::android::hardware::security::see::hwcrypto::types::{
    EvictReason::EvictReason, KeyLifetime::KeyLifetime, KeyPermissions::KeyPermissions,
    KeyType::KeyType, KeyUse::KeyUse, OpaqueKeyMaterial::OpaqueKeyMaterial,
};
use android_hardware_security_see::aidl::android::hardware::security::see::hwcrypto::{
    HwCryptoKeyMaterial::HwCryptoKeyMaterial, KeyPolicy::KeyPolicy,
};
use ciborium::value::Value;
use core::fmt;
use coset::{self, CborSerializable};
use hwcryptocommon::{err::HwCryptoError, hwcrypto_err};
use kmr_common::crypto::{self, KeyMaterial};
use kmr_common::FallibleAllocExt;
use kmr_wire::AsCborValue;
use std::sync::Once;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Number of bytes of unique value used to check if a key was created on current HWCrypto boot.
const NUMBER_BYTES_UNIQUE_VALUES: usize = 32;

/// Nonce value of all zeroes used in AES-GCM key encryption.
const ZERO_NONCE: [u8; 12] = [0u8; 12];

/// Extra labels used to serialize key policy on opaque key
enum CoseLabels {
    ExpirationTime = -65537,
    BootUniqueValue = -65538,
    KeyLifetime = -65539,
    EvictPolicy = -65540,
    KeyPermissions = -65541,
    KeyDerivationInput = -65542,
    KeyUsage = -65543,
    KeyType = -65544,
}

impl TryFrom<i64> for CoseLabels {
    type Error = HwCryptoError;

    fn try_from(value: i64) -> Result<Self, Self::Error> {
        match value {
            x if x == CoseLabels::BootUniqueValue as i64 => Ok(CoseLabels::BootUniqueValue),
            x if x == CoseLabels::ExpirationTime as i64 => Ok(CoseLabels::ExpirationTime),
            x if x == CoseLabels::KeyLifetime as i64 => Ok(CoseLabels::KeyLifetime),
            x if x == CoseLabels::EvictPolicy as i64 => Ok(CoseLabels::EvictPolicy),
            x if x == CoseLabels::KeyPermissions as i64 => Ok(CoseLabels::KeyPermissions),
            x if x == CoseLabels::KeyDerivationInput as i64 => Ok(CoseLabels::KeyDerivationInput),
            x if x == CoseLabels::KeyUsage as i64 => Ok(CoseLabels::KeyUsage),
            x if x == CoseLabels::KeyType as i64 => Ok(CoseLabels::KeyType),
            _ => Err(hwcrypto_err!(SERIALIZATION_ERROR, "unsupported COSE header label {}", value)),
        }
    }
}

// Functions to transform between primitive/rust types and AIDL types (enum). We are not
// implementing Try/TryFrom because these types are defined on the AIDL crate.

fn get_key_lifetime(value: u64) -> Result<KeyLifetime, HwCryptoError> {
    match value {
        x if x == KeyLifetime::EPHEMERAL.0 as u64 => Ok(KeyLifetime::EPHEMERAL),
        x if x == KeyLifetime::HARDWARE.0 as u64 => Ok(KeyLifetime::HARDWARE),
        x if x == KeyLifetime::PORTABLE.0 as u64 => Ok(KeyLifetime::PORTABLE),
        _ => Err(hwcrypto_err!(SERIALIZATION_ERROR, "unsupported KeyLifetime value {}", value)),
    }
}

fn get_key_type(value: u64) -> Result<KeyType, HwCryptoError> {
    match value {
        x if x == KeyType::AES_128_ECB.0 as u64 => Ok(KeyType::AES_128_ECB),
        x if x == KeyType::AES_128_CBC.0 as u64 => Ok(KeyType::AES_128_CBC),
        x if x == KeyType::AES_128_CTR.0 as u64 => Ok(KeyType::AES_128_CTR),
        x if x == KeyType::AES_128_GCM.0 as u64 => Ok(KeyType::AES_128_GCM),
        x if x == KeyType::AES_128_XTS.0 as u64 => Ok(KeyType::AES_128_XTS),
        x if x == KeyType::AES_128_CMAC.0 as u64 => Ok(KeyType::AES_128_CMAC),
        x if x == KeyType::AES_128_KEY_WRAP.0 as u64 => Ok(KeyType::AES_128_KEY_WRAP),
        x if x == KeyType::AES_192_ECB.0 as u64 => Ok(KeyType::AES_192_ECB),
        x if x == KeyType::AES_192_CBC.0 as u64 => Ok(KeyType::AES_192_CBC),
        x if x == KeyType::AES_192_CTR.0 as u64 => Ok(KeyType::AES_192_CTR),
        x if x == KeyType::AES_192_GCM.0 as u64 => Ok(KeyType::AES_192_GCM),
        x if x == KeyType::AES_192_XTS.0 as u64 => Ok(KeyType::AES_192_XTS),
        x if x == KeyType::AES_192_CMAC.0 as u64 => Ok(KeyType::AES_192_CMAC),
        x if x == KeyType::AES_192_KEY_WRAP.0 as u64 => Ok(KeyType::AES_192_KEY_WRAP),
        x if x == KeyType::AES_256_ECB.0 as u64 => Ok(KeyType::AES_256_ECB),
        x if x == KeyType::AES_256_CBC.0 as u64 => Ok(KeyType::AES_256_CBC),
        x if x == KeyType::AES_256_CTR.0 as u64 => Ok(KeyType::AES_256_CTR),
        x if x == KeyType::AES_256_GCM.0 as u64 => Ok(KeyType::AES_256_GCM),
        x if x == KeyType::AES_256_XTS.0 as u64 => Ok(KeyType::AES_256_XTS),
        x if x == KeyType::AES_256_CMAC.0 as u64 => Ok(KeyType::AES_256_CMAC),
        x if x == KeyType::AES_256_KEY_WRAP.0 as u64 => Ok(KeyType::AES_256_KEY_WRAP),
        x if x == KeyType::TDES_ECB.0 as u64 => Ok(KeyType::TDES_ECB),
        x if x == KeyType::TDES_CBC.0 as u64 => Ok(KeyType::TDES_CBC),
        x if x == KeyType::HMAC_SHA224.0 as u64 => Ok(KeyType::HMAC_SHA224),
        x if x == KeyType::HMAC_SHA256.0 as u64 => Ok(KeyType::HMAC_SHA256),
        x if x == KeyType::HMAC_SHA384.0 as u64 => Ok(KeyType::HMAC_SHA384),
        x if x == KeyType::HMAC_SHA512.0 as u64 => Ok(KeyType::HMAC_SHA512),
        x if x == KeyType::RSA2048.0 as u64 => Ok(KeyType::RSA2048),
        x if x == KeyType::RSA3072.0 as u64 => Ok(KeyType::RSA3072),
        x if x == KeyType::RSA4096.0 as u64 => Ok(KeyType::RSA4096),
        x if x == KeyType::ECC_NIST_P224.0 as u64 => Ok(KeyType::ECC_NIST_P224),
        x if x == KeyType::ECC_NIST_P256.0 as u64 => Ok(KeyType::ECC_NIST_P256),
        x if x == KeyType::ECC_NIST_P384.0 as u64 => Ok(KeyType::ECC_NIST_P384),
        x if x == KeyType::ECC_NIST_P521.0 as u64 => Ok(KeyType::ECC_NIST_P521),
        x if x == KeyType::ECC_ED25519.0 as u64 => Ok(KeyType::ECC_ED25519),
        x if x == KeyType::ECC_X25519.0 as u64 => Ok(KeyType::ECC_X25519),
        _ => Err(hwcrypto_err!(SERIALIZATION_ERROR, "unsupported KeyType value {}", value)),
    }
}

fn get_key_use(value: u64) -> Result<KeyUse, HwCryptoError> {
    match value {
        x if x == KeyUse::ENCRYPT.0 as u64 => Ok(KeyUse::ENCRYPT),
        x if x == KeyUse::DECRYPT.0 as u64 => Ok(KeyUse::DECRYPT),
        //x if x == KeyUse::ENCRYPT_DECRYPT.0 as u64 => Ok(KeyUse::ENCRYPT_DECRYPT),
        x if x == KeyUse::SIGN.0 as u64 => Ok(KeyUse::SIGN),
        x if x == KeyUse::VERIFY.0 as u64 => Ok(KeyUse::VERIFY),
        x if x == KeyUse::EXCHANGE.0 as u64 => Ok(KeyUse::EXCHANGE),
        x if x == KeyUse::DERIVE.0 as u64 => Ok(KeyUse::DERIVE),
        x if x == KeyUse::WRAP.0 as u64 => Ok(KeyUse::WRAP),
        // TODO: Check fi we should support UNSPECIFIED here
        x if x == KeyUse::UNSPECIFIED.0 as u64 => Ok(KeyUse::UNSPECIFIED),
        _ => Err(hwcrypto_err!(SERIALIZATION_ERROR, "unsupported KeyUse value {}", value)),
    }
}

fn get_key_permissions(value: u64) -> Result<Vec<KeyPermissions>, HwCryptoError> {
    let mut key_permissions = Vec::<KeyPermissions>::new();
    let mut value_to_process = value;
    // KeyPermissions enum values follow a bitmask pattern, use this fact to extract all the
    // possible key permissions
    for enum_val in KeyPermissions::enum_values() {
        if value_to_process == 0 {
            break;
        }
        let inner_val = enum_val.0 as u64;
        if (inner_val & value_to_process) == inner_val {
            key_permissions.push(enum_val);
            // Clear the used bit to check if we do not have spurious bit on the value passed
            value_to_process &= !inner_val;
        }
    }
    if value_to_process == 0 {
        Ok(key_permissions)
    } else {
        Err(hwcrypto_err!(SERIALIZATION_ERROR, "spurious bits set on key permissions: {}", value))
    }
}

fn compress_key_permissions(key_permissions: &[KeyPermissions]) -> Result<u64, HwCryptoError> {
    let mut value = 0;
    // KeyPermissions enum values follow a bitmask pattern, use this fact to compress all the
    // possible key permissions
    for key_permission in key_permissions {
        value |= key_permission.0 as u64;
    }
    Ok(value)
}

fn get_evict_policy(value: u64) -> Result<Vec<EvictReason>, HwCryptoError> {
    let mut evict_policy = Vec::<EvictReason>::new();
    let mut value_to_process = value;
    // EvictReason enum values follow a bitmask pattern, use this fact to extract all the possible
    // evict reasons
    for enum_val in EvictReason::enum_values() {
        if value_to_process == 0 {
            break;
        }
        let inner_val = enum_val.0 as u64;
        if (inner_val & value_to_process) == inner_val {
            evict_policy.push(enum_val);
            // Clear the used bit to check if we do not have spurious bit on the value passed
            value_to_process &= !inner_val;
        }
    }
    if value_to_process == 0 {
        Ok(evict_policy)
    } else {
        Err(hwcrypto_err!(SERIALIZATION_ERROR, "spurious bits set on eviction policy: {}", value))
    }
}

fn compress_evict_policy(evict_policy: &[EvictReason]) -> Result<u64, HwCryptoError> {
    let mut value = 0;
    // EvictReason enum values follow a bitmask pattern, use this fact to compress all the possible
    // evicy reasons
    for evict_reason in evict_policy {
        value |= evict_reason.0 as u64;
    }
    Ok(value)
}

/// function used to deserialize boot unique value and key encryption key derivation context. This
/// function relies on the fact that both arrays are of the same length
fn parse_cborium_bytes_to_array(
    value: &ciborium::value::Value,
    value_name: &str,
) -> Result<[u8; NUMBER_BYTES_UNIQUE_VALUES], HwCryptoError> {
    let value_bytes = if let ciborium::value::Value::Bytes(value_bytes) = value {
        Ok(value_bytes)
    } else {
        Err(hwcrypto_err!(
            SERIALIZATION_ERROR,
            "wrong type when trying to parse bytes for {}",
            value_name
        ))
    }?;
    if value_bytes.len() != NUMBER_BYTES_UNIQUE_VALUES {
        return Err(hwcrypto_err!(
            SERIALIZATION_ERROR,
            "wrong number of bytes for {}, found {}, expected {}",
            value_name,
            value_bytes.len(),
            NUMBER_BYTES_UNIQUE_VALUES
        ));
    }
    Ok(value_bytes.clone().try_into().expect("Shouldn't fail, we checked size already"))
}

fn parse_cborium_u64(
    value: &ciborium::value::Value,
    value_name: &str,
) -> Result<u64, HwCryptoError> {
    let integer_value = value.as_integer().ok_or(hwcrypto_err!(
        SERIALIZATION_ERROR,
        "wrong type when trying to parse a u64 from {}",
        value_name
    ))?;
    integer_value.try_into().map_err(|e| {
        hwcrypto_err!(SERIALIZATION_ERROR, "Error converting {} to u64: {}", value_name, e)
    })
}

/// Function used to deserialize a single HWCrypto key header element from a coset header `rest`
/// vector element.
fn parse_cose_header(
    header_element: &(coset::Label, ciborium::value::Value),
    key_header: &mut ClearKeyHeader,
) -> Result<(), HwCryptoError> {
    let label = if let coset::Label::Int(integer_label) = header_element.0 {
        CoseLabels::try_from(integer_label)
    } else {
        Err(hwcrypto_err!(
            SERIALIZATION_ERROR,
            "unsupported string header label {:?}",
            header_element.0
        ))
    }?;
    match label {
        CoseLabels::BootUniqueValue => {
            key_header.boot_unique_value = BootUniqueValue(parse_cborium_bytes_to_array(
                &header_element.1,
                "BootUniqueValue",
            )?);
            Ok(())
        }
        CoseLabels::ExpirationTime => {
            key_header.expiration_time =
                Some(parse_cborium_u64(&header_element.1, "ExpirationTime")?);
            Ok(())
        }
        CoseLabels::KeyLifetime => {
            let key_lifetime = parse_cborium_u64(&header_element.1, "KeyLifetime")?;
            key_header.key_lifetime = get_key_lifetime(key_lifetime)?;
            Ok(())
        }
        CoseLabels::EvictPolicy => {
            let evict_policy = parse_cborium_u64(&header_element.1, "EvictPolicy")?;
            key_header.evict_policy = get_evict_policy(evict_policy)?;
            Ok(())
        }
        CoseLabels::KeyPermissions => {
            let key_permissions = parse_cborium_u64(&header_element.1, "KeyPermissions")?;
            key_header.key_permissions = get_key_permissions(key_permissions)?;
            Ok(())
        }
        CoseLabels::KeyDerivationInput => {
            key_header.kek_derivation_context =
                parse_cborium_bytes_to_array(&header_element.1, "KeyDerivationInput")?;
            Ok(())
        }
        CoseLabels::KeyUsage => {
            let key_usage = parse_cborium_u64(&header_element.1, "KeyUsage")?;
            key_header.key_usage = get_key_use(key_usage)?;
            Ok(())
        }
        CoseLabels::KeyType => {
            let key_type = parse_cborium_u64(&header_element.1, "KeyType")?;
            key_header.key_type = get_key_type(key_type)?;
            Ok(())
        }
    }
}

/// Struct to wrap boot unique counter so it can be zeroized on drop
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
struct BootUniqueValue([u8; NUMBER_BYTES_UNIQUE_VALUES]); // TODO: is this length OK for this?

impl fmt::Debug for BootUniqueValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[BootUniqueValue size: {}; data redacted]", self.0.len())
    }
}

// Boot unique value is lazily initialized on the first call to retrieve it
static mut BOOT_UNIQUE_VALUE: Option<BootUniqueValue> = None;
static BOOT_UNIQUE_VALUE_INIT: Once = Once::new();

/// Retrieves boot unique value used to check if the key material was created on this boot. It
/// lazily initializes it.
fn get_boot_unique_value(rng: &mut dyn crypto::Rng) -> Result<BootUniqueValue, HwCryptoError> {
    // SAFETY: We are using Once, so the mut global will only be written once even with multiple
    // calls
    let boot_unique_value = unsafe {
        BOOT_UNIQUE_VALUE_INIT.call_once(|| {
            let mut new_boot_unique_value = [0u8; NUMBER_BYTES_UNIQUE_VALUES];
            rng.fill_bytes(&mut new_boot_unique_value[..]);
            BOOT_UNIQUE_VALUE = Some(BootUniqueValue(new_boot_unique_value));
        });
        // BOOT_UNIQUE_VALUE is always Some(_) at this point, so we just unwrap it
        BOOT_UNIQUE_VALUE.as_ref().unwrap()
    };
    Ok(boot_unique_value.clone())
}

/// Internal structure used to handle key material on the server side.
#[derive(Debug)]
struct ClearKey {
    key_header: ClearKeyHeader,
    key_material: KeyMaterial,
}

#[derive(Debug)]
struct ClearKeyHeader {
    kek_derivation_context: [u8; NUMBER_BYTES_UNIQUE_VALUES],
    boot_unique_value: BootUniqueValue,
    expiration_time: Option<u64>,
    key_lifetime: KeyLifetime,
    evict_policy: Vec<EvictReason>,
    key_permissions: Vec<KeyPermissions>,
    key_usage: KeyUse,
    key_type: KeyType,
}

impl ClearKeyHeader {
    fn new(
        cose_header_rest: &[(coset::Label, ciborium::value::Value)],
    ) -> Result<Self, HwCryptoError> {
        let mut header = ClearKeyHeader {
            kek_derivation_context: [0u8; NUMBER_BYTES_UNIQUE_VALUES],
            boot_unique_value: BootUniqueValue([0u8; NUMBER_BYTES_UNIQUE_VALUES]),
            expiration_time: None,
            key_lifetime: KeyLifetime::EPHEMERAL,
            evict_policy: Vec::<EvictReason>::new(),
            key_permissions: Vec::<KeyPermissions>::new(),
            key_usage: KeyUse::UNSPECIFIED,
            key_type: KeyType::AES_256_GCM,
        };
        for element in cose_header_rest {
            parse_cose_header(element, &mut header)?
        }
        Ok(header)
    }
}

// TODO: Implement this function
fn get_encryption_key() -> Result<Vec<u8>, HwCryptoError> {
    Ok(Vec::<u8>::new())
}

// TODO: Implement this function
fn get_current_time_for_expiration_checks() -> Result<u64, HwCryptoError> {
    Ok(0)
}

/// Uses hkdf to derive a key encryption key from HWCrypto internal master key using the provided
/// context.
fn derive_key_encryption_key(
    kdf: &dyn crypto::Hkdf,
    derivation_context: &[u8],
) -> Result<crypto::aes::Key, HwCryptoError> {
    let encryption_key = get_encryption_key()?;
    let raw_key = kdf.hkdf(&[], &encryption_key, derivation_context, 32)?;
    let key_material = crypto::aes::Key::Aes256(
        raw_key.try_into().expect("should not fail, derive_key_encryption_key returns 32 bits"),
    );
    Ok(key_material)
}

/// Derives a key to be used to encrypt another (single) key.
#[allow(dead_code)]
fn generate_key_encryption_key(
    kdf: &dyn crypto::Hkdf,
    rng: &mut dyn crypto::Rng,
) -> Result<(crypto::aes::Key, [u8; NUMBER_BYTES_UNIQUE_VALUES]), HwCryptoError> {
    let mut kek_derivation_context = [0u8; 32];
    rng.fill_bytes(&mut kek_derivation_context[..]);
    let der_kek = derive_key_encryption_key(kdf, &kek_derivation_context)?;
    Ok((der_kek, kek_derivation_context))
}

fn decrypt_key(
    _key: &HwCryptoKeyMaterial,
    opaque_key_material: &[u8],
    aes: &dyn crypto::Aes,
    kdf: &dyn crypto::Hkdf,
) -> Result<ClearKey, HwCryptoError> {
    let encrypted_key: coset::CoseEncrypt0 =
        coset::CborSerializable::from_slice(opaque_key_material)?;
    let key_header = ClearKeyHeader::new(&encrypted_key.protected.header.rest)?;
    let derived_kek = derive_key_encryption_key(kdf, &key_header.kek_derivation_context)?;
    // Decrypting key blob
    let mut op = aes.begin_aead(
        derived_kek.into(),
        crypto::aes::GcmMode::GcmTag16 { nonce: ZERO_NONCE },
        crypto::SymmetricOperation::Decrypt,
    )?;
    let extended_aad = coset::enc_structure_data(
        coset::EncryptionContext::CoseEncrypt0,
        encrypted_key.protected.clone(),
        &[], // no external AAD
    );
    op.update_aad(&extended_aad)?;
    let mut pt_data = op.update(&encrypted_key.ciphertext.unwrap_or_default())?;
    pt_data.try_extend_from_slice(
        &op.finish().map_err(|e| hwcrypto_err!(INVALID_KEY, "failed to decrypt key: {:?}", e))?,
    )?;
    let key_material = <crypto::KeyMaterial>::from_slice(&pt_data)?;
    // TODO: Check that all the parameters on _key matches with the into on ClearKeyHeader and
    //       with the crypto::KeyMaterial
    Ok(ClearKey { key_header, key_material })
}

/// Given an AIDL opaque HwCryptoKey creates a clear key usable by the HWCrypto key service
#[allow(dead_code)]
fn deserialize_key(
    key: &HwCryptoKeyMaterial,
    aes: &dyn crypto::Aes,
    kdf: &dyn crypto::Hkdf,
) -> Result<ClearKey, HwCryptoError> {
    match key {
        HwCryptoKeyMaterial::Opaque(key_material) => {
            Ok(decrypt_key(key, &key_material.key_blob, aes, kdf)?)
        }
        HwCryptoKeyMaterial::Explicit(_) => {
            Err(hwcrypto_err!(UNSUPPORTED, "Explicit keys not supported"))
        }
    }
}

#[allow(dead_code)]
fn serialize_key(
    key: ClearKey,
    aes: &dyn crypto::Aes,
    kdf: &dyn crypto::Hkdf,
) -> Result<(HwCryptoKeyMaterial, KeyPolicy), HwCryptoError> {
    let mut boot_unique_value = Vec::<u8>::new(); //TODO: try to simplify boot_unique_value
    boot_unique_value.try_extend_from_slice(&key.key_header.boot_unique_value.0)?;
    let mut kek_derivation_context = Vec::<u8>::new();
    kek_derivation_context.try_extend_from_slice(&key.key_header.kek_derivation_context)?;
    let derived_kek = derive_key_encryption_key(kdf, &key.key_header.kek_derivation_context)?;
    let evict_policy = compress_evict_policy(&key.key_header.evict_policy)?;
    let key_permissions = compress_key_permissions(&key.key_header.key_permissions)?;
    let cose_protected_header = if key.key_header.expiration_time.is_none() {
        coset::HeaderBuilder::new()
    } else {
        coset::HeaderBuilder::new().value(
            CoseLabels::ExpirationTime as i64,
            Value::Integer(key.key_header.expiration_time.unwrap().into()),
        )
    }
    .algorithm(coset::iana::Algorithm::A256GCM)
    .value(CoseLabels::BootUniqueValue as i64, Value::Bytes(boot_unique_value))
    .value(CoseLabels::KeyLifetime as i64, Value::Integer(key.key_header.key_lifetime.0.into()))
    .value(CoseLabels::EvictPolicy as i64, Value::Integer(evict_policy.into()))
    .value(CoseLabels::KeyPermissions as i64, Value::Integer(key_permissions.into()))
    .value(CoseLabels::KeyDerivationInput as i64, Value::Bytes(kek_derivation_context))
    .value(CoseLabels::KeyUsage as i64, Value::Integer(key.key_header.key_usage.0.into()))
    .value(CoseLabels::KeyType as i64, Value::Integer(key.key_header.key_type.0.into()))
    .build();

    let cose_encrypt = coset::CoseEncrypt0Builder::new()
        .protected(cose_protected_header)
        .try_create_ciphertext::<_, HwCryptoError>(
            &key.key_material.into_vec()?,
            &[],
            move |pt, aad| {
                let mut op = aes.begin_aead(
                    derived_kek.into(),
                    crypto::aes::GcmMode::GcmTag16 { nonce: ZERO_NONCE },
                    crypto::SymmetricOperation::Encrypt,
                )?;
                op.update_aad(aad)?;
                let mut ct = op.update(pt)?;
                ct.try_extend_from_slice(&op.finish()?)?;
                Ok(ct)
            },
        )?
        .build();

    let policy = KeyPolicy {
        usage: key.key_header.key_usage,
        key_lifetime: key.key_header.key_lifetime,
        evict_policy: key.key_header.evict_policy,
        key_permissions: key.key_header.key_permissions,
        key_type: key.key_header.key_type,
    };
    let opaque_key_material = OpaqueKeyMaterial { key_blob: cose_encrypt.to_vec()? };
    Ok((HwCryptoKeyMaterial::Opaque(opaque_key_material), policy))
}

fn wrap_derivation_allowed(
    key_lifetime: &KeyLifetime,
    wrap_derivation_permission: &[KeyPermissions],
) -> Result<bool, HwCryptoError> {
    let compress_permissions = compress_key_permissions(wrap_derivation_permission)?;
    let ephemeral_requested =
        (compress_permissions & (KeyPermissions::ALLOW_EPHEMERAL_KEY_WRAPPING.0 as u64)) != 0;
    let hardware_requested =
        (compress_permissions & (KeyPermissions::ALLOW_HARDWARE_KEY_WRAPPING.0 as u64)) != 0;
    match *key_lifetime {
        KeyLifetime::EPHEMERAL => Ok(true), //ephemeral keys can be used to derive/wrap any other key
        KeyLifetime::HARDWARE => {
            // Hardware keys cannot be used to derive/wrap ephemeral keys
            if ephemeral_requested {
                Ok(false)
            } else {
                Ok(true)
            }
        }
        KeyLifetime::PORTABLE => {
            // portable keys can only derive/wrap other portable keys
            if ephemeral_requested || hardware_requested {
                Ok(false)
            } else {
                Ok(true)
            }
        }
        // AIDL structure have more values added than the ones defined on the AIDL file
        _ => Err(hwcrypto_err!(UNSUPPORTED, "unsupported Key lifetime {:?}", key_lifetime)),
    }
}

fn is_key_from_current_boot(
    key_boot_unique_value: &BootUniqueValue,
    rng: &mut dyn crypto::Rng,
) -> Result<bool, HwCryptoError> {
    Ok(get_boot_unique_value(rng)? == *key_boot_unique_value)
}

#[allow(dead_code)]
fn check_key_policies(key: &ClearKey, rng: &mut dyn crypto::Rng) -> Result<(), HwCryptoError> {
    // Checking for wrapping rules
    if !wrap_derivation_allowed(&key.key_header.key_lifetime, &key.key_header.key_permissions)? {
        return Err(hwcrypto_err!(
            UNSUPPORTED,
            "wrapping issue. Key class {:?}, key permissions {:?}",
            key.key_header.key_lifetime,
            key.key_header.key_permissions
        ));
    }
    // Checking that boot unique value matches current one
    if !is_key_from_current_boot(&key.key_header.boot_unique_value, rng)? {
        return Err(hwcrypto_err!(UNSUPPORTED, "key has not been generated on the current boot"));
    }
    // Check that expiration time has not passed
    if key.key_header.expiration_time.is_some() {
        let current_time = get_current_time_for_expiration_checks()?;
        // directly unwrapping becuase we've checked that value exists
        let expiration_time = key.key_header.expiration_time.expect("should not happen");
        if expiration_time >= current_time {
            return Err(hwcrypto_err!(
                INVALID_KEY,
                "expiration time reached: {:?}, current time {:?}",
                expiration_time,
                current_time
            ));
        }
    }
    // TODO: Check evict policy (if it makes sense)
    // TODO: Check if we should add more policy checks here
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use kmr_common::crypto::{self, ec::NistCurve, Aes, Ec, Hmac, Rng, Rsa};
    use kmr_crypto_boring::{
        aes::BoringAes, ec::BoringEc, hmac::BoringHmac, rng::BoringRng, rsa::BoringRsa,
    };
    use kmr_wire::{KeySizeInBits, RsaExponent};

    #[test]
    fn check_boot_value() {
        let mut rng = BoringRng::default();
        let boot_value = get_boot_unique_value(&mut rng).expect("couldn't get boot unique value");
        let boot_value2 = get_boot_unique_value(&mut rng).expect("couldn't get boot unique value");
        assert_eq!(boot_value, boot_value2, "boot unique values should match");
        assert!(
            is_key_from_current_boot(&boot_value, &mut rng).unwrap(),
            "boot_value should match current one"
        );
        let zero_boot_value = BootUniqueValue([0u8; NUMBER_BYTES_UNIQUE_VALUES]);
        assert!(
            !is_key_from_current_boot(&zero_boot_value, &mut rng).unwrap(),
            "current one boot value should not be 0"
        );
        let mut random_value = [0u8; NUMBER_BYTES_UNIQUE_VALUES];
        rng.fill_bytes(&mut random_value[..]);
        assert!(
            !is_key_from_current_boot(&BootUniqueValue(random_value), &mut rng).unwrap(),
            "current one boot value should not match random one"
        );
    }

    #[test]
    fn check_wrapping_allowed() {
        let all_requested = vec![
            KeyPermissions::ALLOW_EPHEMERAL_KEY_WRAPPING,
            KeyPermissions::ALLOW_HARDWARE_KEY_WRAPPING,
            KeyPermissions::ALLOW_PORTABLE_KEY_WRAPPING,
        ];
        let all_but_hardware = vec![
            KeyPermissions::ALLOW_EPHEMERAL_KEY_WRAPPING,
            KeyPermissions::ALLOW_PORTABLE_KEY_WRAPPING,
        ];
        let all_but_ephemeral = vec![
            KeyPermissions::ALLOW_HARDWARE_KEY_WRAPPING,
            KeyPermissions::ALLOW_PORTABLE_KEY_WRAPPING,
        ];
        let all_but_portable = vec![
            KeyPermissions::ALLOW_EPHEMERAL_KEY_WRAPPING,
            KeyPermissions::ALLOW_HARDWARE_KEY_WRAPPING,
        ];
        let just_hardware = vec![KeyPermissions::ALLOW_HARDWARE_KEY_WRAPPING];
        let just_ephemeral = vec![KeyPermissions::ALLOW_EPHEMERAL_KEY_WRAPPING];
        let just_portable = vec![KeyPermissions::ALLOW_PORTABLE_KEY_WRAPPING];

        //checking ephemeral keys
        assert!(
            wrap_derivation_allowed(&KeyLifetime::EPHEMERAL, &all_requested).unwrap(),
            "ephemeral keys should be able to wrap any key"
        );
        assert!(
            wrap_derivation_allowed(&KeyLifetime::EPHEMERAL, &all_but_hardware).unwrap(),
            "ephemeral keys should be able to wrap any key"
        );
        assert!(
            wrap_derivation_allowed(&KeyLifetime::EPHEMERAL, &all_but_ephemeral).unwrap(),
            "ephemeral keys should be able to wrap any key"
        );
        assert!(
            wrap_derivation_allowed(&KeyLifetime::EPHEMERAL, &all_but_portable).unwrap(),
            "ephemeral keys should be able to wrap any key"
        );
        assert!(
            wrap_derivation_allowed(&KeyLifetime::EPHEMERAL, &just_hardware).unwrap(),
            "ephemeral keys should be able to wrap any key"
        );
        assert!(
            wrap_derivation_allowed(&KeyLifetime::EPHEMERAL, &just_ephemeral).unwrap(),
            "ephemeral keys should be able to wrap any key"
        );
        assert!(
            wrap_derivation_allowed(&KeyLifetime::EPHEMERAL, &just_portable).unwrap(),
            "ephemeral keys should be able to wrap any key"
        );
        //checking hardware keys
        assert!(
            !wrap_derivation_allowed(&KeyLifetime::HARDWARE, &all_requested).unwrap(),
            "hardware keys should be able to wrap any key but ephemeral"
        );
        assert!(
            !wrap_derivation_allowed(&KeyLifetime::HARDWARE, &all_but_hardware).unwrap(),
            "hardware keys should be able to wrap any key but ephemeral"
        );
        assert!(
            wrap_derivation_allowed(&KeyLifetime::HARDWARE, &all_but_ephemeral).unwrap(),
            "hardware keys should be able to wrap any key but ephemeral"
        );
        assert!(
            !wrap_derivation_allowed(&KeyLifetime::HARDWARE, &all_but_portable).unwrap(),
            "hardware keys should be able to wrap any key but ephemeral"
        );
        assert!(
            wrap_derivation_allowed(&KeyLifetime::HARDWARE, &just_hardware).unwrap(),
            "hardware keys should be able to wrap any key but ephemeral"
        );
        assert!(
            !wrap_derivation_allowed(&KeyLifetime::HARDWARE, &just_ephemeral).unwrap(),
            "hardware keys should be able to wrap any key but ephemeral"
        );
        assert!(
            wrap_derivation_allowed(&KeyLifetime::HARDWARE, &just_portable).unwrap(),
            "hardware keys should be able to wrap any key but ephemeral"
        );
        //checking portable keys
        assert!(
            !wrap_derivation_allowed(&KeyLifetime::PORTABLE, &all_requested).unwrap(),
            "portable keys should only be able to wrap portable keys"
        );
        assert!(
            !wrap_derivation_allowed(&KeyLifetime::PORTABLE, &all_but_hardware).unwrap(),
            "portable keys should only be able to wrap portable keys"
        );
        assert!(
            !wrap_derivation_allowed(&KeyLifetime::PORTABLE, &all_but_ephemeral).unwrap(),
            "portable keys should only be able to wrap portable keys"
        );
        assert!(
            !wrap_derivation_allowed(&KeyLifetime::PORTABLE, &all_but_portable).unwrap(),
            "portable keys should only be able to wrap portable keys"
        );
        assert!(
            !wrap_derivation_allowed(&KeyLifetime::PORTABLE, &just_hardware).unwrap(),
            "portable keys should only be able to wrap portable keys"
        );
        assert!(
            !wrap_derivation_allowed(&KeyLifetime::PORTABLE, &just_ephemeral).unwrap(),
            "portable keys should only be able to wrap portable keys"
        );
        assert!(
            wrap_derivation_allowed(&KeyLifetime::PORTABLE, &just_portable).unwrap(),
            "portable keys should only be able to wrap portable keys"
        );
    }

    #[test]
    fn serialize_deserialize_aes_key() {
        let mut rng = BoringRng::default();
        let kdf = BoringHmac;
        let aes = BoringAes;
        let key_material = aes
            .generate_key(&mut rng, crypto::aes::Variant::Aes256, &[])
            .expect("couldn't generate AES key");
        let boot_unique_value =
            get_boot_unique_value(&mut rng).expect("couldn't generate boot unique value");
        let (_, kek_derivation_context) =
            generate_key_encryption_key(&kdf, &mut rng).expect("couldn't generate kek context");
        let evict_policy = vec![EvictReason::SECURE_ENCLAVE_STATE_CHANGE];
        let key_permissions = vec![
            KeyPermissions::KEY_MANAGEMENT_KEY,
            KeyPermissions::ALLOW_HARDWARE_KEY_WRAPPING,
            KeyPermissions::BOOTSTATE_BINDING,
        ];

        let key_header = ClearKeyHeader {
            kek_derivation_context,
            boot_unique_value,
            expiration_time: None,
            key_lifetime: KeyLifetime::EPHEMERAL,
            evict_policy: evict_policy.clone(),
            key_permissions: key_permissions.clone(),
            key_usage: KeyUse::WRAP,
            key_type: KeyType::AES_256_KEY_WRAP,
        };
        let key = ClearKey { key_header, key_material };
        let (serialized_key, _policy) =
            serialize_key(key, &aes, &kdf).expect("couldn't serialize key");
        let deserialized_key =
            deserialize_key(&serialized_key, &aes, &kdf).expect("couldn't deserialize key");
        assert_eq!(
            deserialized_key.key_header.kek_derivation_context, kek_derivation_context,
            "Key derivation context doesn't match"
        );
        assert_eq!(
            deserialized_key.key_header.boot_unique_value,
            get_boot_unique_value(&mut rng).expect("couldn't generate boot unique value"),
            "Boot unique value doesn't match"
        );
        assert!(
            deserialized_key.key_header.expiration_time.is_none(),
            "Expiration time should be None"
        );
        assert_eq!(
            deserialized_key.key_header.key_lifetime,
            KeyLifetime::EPHEMERAL,
            "key class doesn't match"
        );
        assert_eq!(
            deserialized_key.key_header.key_type,
            KeyType::AES_256_KEY_WRAP,
            "key type doesn't match"
        );
        assert_eq!(
            compress_evict_policy(&deserialized_key.key_header.evict_policy).unwrap(),
            compress_evict_policy(&evict_policy).unwrap(),
            "evict policy doesn't match"
        );
        assert_eq!(
            compress_key_permissions(&deserialized_key.key_header.key_permissions).unwrap(),
            compress_key_permissions(&key_permissions).unwrap(),
            "key permissions doesn't match"
        );
        assert_eq!(deserialized_key.key_header.key_usage, KeyUse::WRAP, "key use doesn't match");
    }

    #[test]
    fn serialize_deserialize_hmac_key() {
        let mut rng = BoringRng::default();
        let kdf = BoringHmac;
        let aes = BoringAes;
        let key_material = kdf
            .generate_key(&mut rng, KeySizeInBits(256), &[])
            .expect("couldn't generate HMAC key");
        let boot_unique_value =
            get_boot_unique_value(&mut rng).expect("couldn't generate boot unique value");
        let (_, kek_derivation_context) =
            generate_key_encryption_key(&kdf, &mut rng).expect("couldn't generate kek context");
        let evict_policy = Vec::<EvictReason>::new();
        let key_permissions = vec![KeyPermissions::ALLOW_PORTABLE_KEY_WRAPPING];

        let key_header = ClearKeyHeader {
            kek_derivation_context,
            boot_unique_value,
            expiration_time: Some(27272828),
            key_lifetime: KeyLifetime::PORTABLE,
            evict_policy: evict_policy.clone(),
            key_permissions: key_permissions.clone(),
            key_usage: KeyUse::SIGN,
            key_type: KeyType::ECC_NIST_P256,
        };
        let key = ClearKey { key_header, key_material };
        let (serialized_key, _policy) =
            serialize_key(key, &aes, &kdf).expect("couldn't serialize key");
        let deserialized_key =
            deserialize_key(&serialized_key, &aes, &kdf).expect("couldn't deserialize key");
        assert_eq!(
            deserialized_key.key_header.kek_derivation_context, kek_derivation_context,
            "Key derivation context doesn't match"
        );
        assert_eq!(
            deserialized_key.key_header.boot_unique_value,
            get_boot_unique_value(&mut rng).expect("couldn't generate boot unique value"),
            "Boot unique value doesn't match"
        );
        assert_eq!(
            deserialized_key.key_header.expiration_time.expect("Couldn't get expiration time"),
            27272828,
            "Expiration time should didn't match"
        );
        assert_eq!(
            deserialized_key.key_header.key_lifetime,
            KeyLifetime::PORTABLE,
            "key class doesn't match"
        );
        assert_eq!(
            deserialized_key.key_header.key_type,
            KeyType::ECC_NIST_P256,
            "key type doesn't match"
        );
        assert_eq!(
            compress_evict_policy(&deserialized_key.key_header.evict_policy).unwrap(),
            compress_evict_policy(&evict_policy).unwrap(),
            "evict policy doesn't match"
        );
        assert_eq!(
            compress_key_permissions(&deserialized_key.key_header.key_permissions).unwrap(),
            compress_key_permissions(&key_permissions).unwrap(),
            "key permissions doesn't match"
        );
        assert_eq!(deserialized_key.key_header.key_usage, KeyUse::SIGN, "key use doesn't match");
    }

    #[test]
    fn serialize_deserialize_rsa_key() {
        let mut rng = BoringRng::default();
        let kdf = BoringHmac;
        let aes = BoringAes;
        let rsa = BoringRsa::default();
        let key_material = rsa
            .generate_key(&mut rng, KeySizeInBits(2048), RsaExponent(65537), &[])
            .expect("couldn't generate RSA key");
        let boot_unique_value =
            get_boot_unique_value(&mut rng).expect("couldn't generate boot unique value");
        let (_, kek_derivation_context) =
            generate_key_encryption_key(&kdf, &mut rng).expect("couldn't generate kek context");
        let evict_policy = vec![EvictReason::SECURITY_ANCHOR_STATE_CHANGE];
        let key_permissions = vec![KeyPermissions::ALLOW_EPHEMERAL_KEY_WRAPPING];

        let key_header = ClearKeyHeader {
            kek_derivation_context,
            boot_unique_value,
            expiration_time: Some(10),
            key_lifetime: KeyLifetime::HARDWARE,
            evict_policy: evict_policy.clone(),
            key_permissions: key_permissions.clone(),
            key_usage: KeyUse::DECRYPT,
            key_type: KeyType::RSA4096,
        };
        let key = ClearKey { key_header, key_material };
        let (serialized_key, _policy) =
            serialize_key(key, &aes, &kdf).expect("couldn't serialize key");
        let deserialized_key =
            deserialize_key(&serialized_key, &aes, &kdf).expect("couldn't deserialize key");
        assert_eq!(
            deserialized_key.key_header.kek_derivation_context, kek_derivation_context,
            "Key derivation context doesn't match"
        );
        assert_eq!(
            deserialized_key.key_header.boot_unique_value,
            get_boot_unique_value(&mut rng).expect("couldn't generate boot unique value"),
            "Boot unique value doesn't match"
        );
        assert_eq!(
            deserialized_key.key_header.expiration_time.expect("Couldn't get expiration time"),
            10,
            "Expiration time should didn't match"
        );
        assert_eq!(
            deserialized_key.key_header.key_lifetime,
            KeyLifetime::HARDWARE,
            "key class doesn't match"
        );
        assert_eq!(
            deserialized_key.key_header.key_type,
            KeyType::RSA4096,
            "key type doesn't match"
        );
        assert_eq!(
            compress_evict_policy(&deserialized_key.key_header.evict_policy).unwrap(),
            compress_evict_policy(&evict_policy).unwrap(),
            "evict policy doesn't match"
        );
        assert_eq!(
            compress_key_permissions(&deserialized_key.key_header.key_permissions).unwrap(),
            compress_key_permissions(&key_permissions).unwrap(),
            "key permissions doesn't match"
        );
        assert_eq!(deserialized_key.key_header.key_usage, KeyUse::DECRYPT, "key use doesn't match");
    }

    #[test]
    fn serialize_deserialize_ec_key() {
        let mut rng = BoringRng::default();
        let kdf = BoringHmac;
        let aes = BoringAes;
        let ec = BoringEc::default();
        let key_material =
            ec.generate_nist_key(&mut rng, NistCurve::P256, &[]).expect("couldn't generate EC key");
        let boot_unique_value =
            get_boot_unique_value(&mut rng).expect("couldn't generate boot unique value");
        let (_, kek_derivation_context) =
            generate_key_encryption_key(&kdf, &mut rng).expect("couldn't generate kek context");
        let evict_policy = vec![EvictReason::SECURITY_ANCHOR_STATE_CHANGE];
        let key_permissions = vec![KeyPermissions::ALLOW_EPHEMERAL_KEY_WRAPPING];

        let key_header = ClearKeyHeader {
            kek_derivation_context,
            boot_unique_value,
            expiration_time: Some(10),
            key_lifetime: KeyLifetime::HARDWARE,
            evict_policy: evict_policy.clone(),
            key_permissions: key_permissions.clone(),
            key_usage: KeyUse::DECRYPT,
            key_type: KeyType::AES_128_GCM,
        };
        let key = ClearKey { key_header, key_material };
        let (serialized_key, _policy) =
            serialize_key(key, &aes, &kdf).expect("couldn't serialize key");
        let deserialized_key =
            deserialize_key(&serialized_key, &aes, &kdf).expect("couldn't deserialize key");
        assert_eq!(
            deserialized_key.key_header.kek_derivation_context, kek_derivation_context,
            "Key derivation context doesn't match"
        );
        assert_eq!(
            deserialized_key.key_header.boot_unique_value,
            get_boot_unique_value(&mut rng).expect("couldn't generate boot unique value"),
            "Boot unique value doesn't match"
        );
        assert_eq!(
            deserialized_key.key_header.expiration_time.expect("Couldn't get expiration time"),
            10,
            "Expiration time should didn't match"
        );
        assert_eq!(
            deserialized_key.key_header.key_lifetime,
            KeyLifetime::HARDWARE,
            "key class doesn't match"
        );
        assert_eq!(
            deserialized_key.key_header.key_type,
            KeyType::AES_128_GCM,
            "key type doesn't match"
        );
        assert_eq!(
            compress_evict_policy(&deserialized_key.key_header.evict_policy).unwrap(),
            compress_evict_policy(&evict_policy).unwrap(),
            "evict policy doesn't match"
        );
        assert_eq!(
            compress_key_permissions(&deserialized_key.key_header.key_permissions).unwrap(),
            compress_key_permissions(&key_permissions).unwrap(),
            "key permissions doesn't match"
        );
        assert_eq!(deserialized_key.key_header.key_usage, KeyUse::DECRYPT, "key use doesn't match");
    }
}
