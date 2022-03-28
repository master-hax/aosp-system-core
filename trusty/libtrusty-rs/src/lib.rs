// Copyright (C) 2022 The Android Open Source Project
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

//! Functionality for communicating with Trusty services.
//!
//! This crate provides the [`TipcStream`] type, which allows you to establish a
//! connection to a Trusty service and then communicate with that service.
//!
//! # Usage
//!
//! To connect to a Trusty service you need two things:
//!
//! * The filesystem path to the Trusty IPC device. This is usually
//!   `/dev/trusty-ipc-dev0`.
//! * The port name defined by the service, e.g.
//!   `com.android.ipc-unittest.srv.echo`.
//!
//! Pass these values to [`TipcStream::connect`] to establish a connection to a
//! service.
//!
//! Once connected, bytes can be written to the stream to send data to the service,
//! and bytes can be read from the stream to receive responses. This is done with
//! the standard [`std::io::Read`] and [`std::io::Write`] traits.
//!
//! The connection is closed automatically when [`TipcStream`] is dropped.
//!
//! # Examples
//!
//! This example is a simplified version of the echo test from `tipc-test-rs`:
//!
//! ```no_run
//! use trusty::TipcStream;
//! use std::io::{Read, Write};
//!
//! let mut stream = TipcStream::connect(
//!     "/dev/trusty-ipc-dev0",
//!     "com.android.ipc-unittest.srv.echo",
//! ).unwrap();
//!
//! write!(stream, "Hello, world!").unwrap();
//!
//! let mut read_buf = [0u8; 1024];
//! let read_len = stream.read(&mut read_buf[..]).unwrap();
//!
//! let response = std::str::from_utf8(&read_buf[..read_len]).unwrap();
//! assert_eq!("Hello, world!", response);
//!
//! // The connection is closed here.
//! ```

use crate::sys::tipc_connect;
use std::ffi::CString;
use std::fs::File;
use std::io;
use std::io::prelude::*;
use std::os::unix::prelude::AsRawFd;
use std::path::Path;

pub const TIPC_DEFAULT_DEVNAME: &str = "/dev/trusty-ipc-dev0";

/// A channel for communicating with a Trusty service.
///
/// See the [crate-level documentation][crate] for usage details and examples.
#[derive(Debug)]
pub struct TipcStream(File);

impl TipcStream {
    /// Attempts to establish a connection to the specified Trusty service.
    ///
    /// The first argument is the path of the Trusty device in the local filesystem,
    /// e.g. `/dev/trusty-ipc-dev0`. The second argument is the name of the service
    /// to connect to, e.g. `com.android.ipc-unittest.srv.echo`.
    ///
    /// # Panics
    ///
    /// This function will panic if `service` contains any intermediate `NUL`
    /// bytes. This is handled with a panic because the service names are all
    /// hard-coded constants, and so such an error should always be indicative of a
    /// bug in the calling code.
    pub fn connect(device: impl AsRef<Path>, service: &str) -> io::Result<Self> {
        let file = File::options().read(true).write(true).open(device)?;

        let srv_name = CString::new(service).expect("Service name contained null bytes");
        unsafe {
            tipc_connect(file.as_raw_fd(), srv_name.as_ptr())?;
        }

        Ok(TipcStream(file))
    }

    // TODO: Add a `send` method that supports sending shared memory buffers.
}

impl Read for TipcStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.0.read(buf)
    }
}

impl Write for TipcStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.0.flush()
    }
}

// NOTE: The ioctl definitions are sequestered into this module because the
// `ioctl_*!` macros provided by the nix crate generate public functions that we
// don't want to be part of this crate's public API.
mod sys {
    use std::os::raw::c_char;

    const TIPC_IOC_MAGIC: u8 = b'r';

    #[derive(Debug, Clone, Copy)]
    #[repr(C)]
    pub struct TipcSendMsgReq {
        pub iov: u64,
        pub shm: u64,
        pub iov_cnt: u64,
        pub shm_cnt: u64,
    }

    // NOTE: We use `ioctl_write_ptr_bad!` here due to an error in how the ioctl
    // code is defined in `trusty/ipc.h`.
    //
    // If we were to do `ioctl_write_ptr!(TIPC_IOC_MAGIC, 0x80, c_char)` it would
    // generate a function that takes a `*const c_char` data arg and would use
    // `size_of::<c_char>()` when generating the ioctl number. However, in
    // `trusty/ipc.h` the definition for `TIPC_IOC_CONNECT` declares the ioctl with
    // `char*`, meaning we need to use `size_of::<*const c_char>()` to generate an
    // ioctl number that matches what Trusty expects.
    //
    // To maintain compatibility with the `trusty/ipc.h` and the kernel driver we
    // use `ioctl_write_ptr_bad!` and manually use `request_code_write!` to generate
    // the ioctl number using the correct size.
    nix::ioctl_write_ptr_bad!(
        tipc_connect,
        nix::request_code_write!(TIPC_IOC_MAGIC, 0x80, std::mem::size_of::<*const c_char>()),
        c_char
    );

    nix::ioctl_write_ptr!(tipc_send, TIPC_IOC_MAGIC, 0x81, TipcSendMsgReq);
}
