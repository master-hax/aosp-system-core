/*
 * Copyright (C) 2024 The Android Open Source Project
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

//! VTS test library for HwCrypto functionality.
//! It provides the base clases necessaries to write HwCrypto VTS tests

use android_hardware_security_see_hwcrypto::aidl::android::hardware::security::see::hwcrypto::IHwCryptoKey::{BpHwCryptoKey, IHwCryptoKey};

/// Get a HwCryptoKey binder service object
pub fn get_hwcryptokey() -> Result<binder::Strong<dyn IHwCryptoKey>, binder::StatusCode> {
    let interface_name = <BpHwCryptoKey as IHwCryptoKey>::get_descriptor().to_owned() + "/default";
    binder::get_interface(&interface_name)
}
