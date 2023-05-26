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

//! Library implementing the different `IHwCrypto` AIDL interfaces.

mod ec_sign_operation;
mod hmac_operations;
mod hwcrypto_ec_operations;
mod hwcrypto_hash_operations;
mod hwcrypto_key;
mod hwcrypto_key_generation;
mod hwcrypto_key_manipulation;
mod hwcrypto_rsa_operations;
mod hwcrypto_symmetric_operations;
mod key_processing;
mod rsa_decrypt_operation;
mod rsa_sign_operation;
mod symmetric_aead_operation;
mod symmetric_dma_aead_operation;
mod symmetric_dma_emitting_operation;
mod symmetric_emitting_operation;
