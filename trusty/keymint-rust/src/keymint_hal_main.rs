//
// Copyright (C) 2022 The Android Open-Source Project
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! This module implements the HAL service for Keymint (Rust) in Trusty.
use log::{error, info};
use std::panic;
use trusty::{TipcChannel, DEFAULT_DEVICE};

const TRUSTY_KEYMINT_RUST_SERVICE_NAME: &str = "com.android.trusty.keymint";

fn main() {
    // Initialize Android logging.
    android_logger::init_once(
        android_logger::Config::default()
            .with_tag("keymint-hal-trusty")
            .with_min_level(log::Level::Debug)
            .with_log_id(android_logger::LogId::System),
    );
    // Redirect panic messages to logcat.
    panic::set_hook(Box::new(|panic_info| {
        error!("{}", panic_info);
    }));

    info!("In KM HAL: Connecting.");
    let mut connection = TipcChannel::connect(DEFAULT_DEVICE, TRUSTY_KEYMINT_RUST_SERVICE_NAME)
        .expect("Failed to connect to Trusty Keymint service.");
    info!("In KM HAL: Sending.");
    connection.send("Hello Keymint!".as_bytes()).unwrap();
    info!("In KM HAL: Receiving.");
    // let mut recv_buf = Vec::new();
    // connection.recv(&mut recv_buf).unwrap();
    let mut recv_buf = [0u8; 4096];
    let read_len = connection.recv_no_alloc(recv_buf.as_mut_slice()).unwrap();
    info!("In KM HAL: Received. {}", read_len);
}
