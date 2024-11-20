// Copyright (C) 2024 The Android Open Source Project
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

//! A library to prefetch files on the file system to optimize startup times
//!

mod args;
mod error;
mod format;
mod replay;
mod tracer;

use std::fs::File;
use std::fs::OpenOptions;
use std::io;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::string::ToString;
use std::thread;
use std::time::Duration;

#[cfg(target_os = "android")]
use log::Level;
#[cfg(target_os = "linux")]
use log::LevelFilter;

pub use args::args_from_env;
use args::OutputFormat;
pub use args::ReplayArgs;
#[cfg(target_os = "android")]
pub use args::StartArgs;
pub use args::{DumpArgs, MainArgs, RecordArgs, SubCommands};
pub use error::Error;
pub use format::FileId;
pub use format::InodeInfo;
pub use format::Record;
pub use format::RecordsFile;
use log::info;
#[cfg(target_os = "android")]
use log::warn;
pub use replay::Replay;
pub use tracer::nanoseconds_since_boot;

#[cfg(target_os = "android")]
use rustutils::system_properties::error::PropertyWatcherError;
#[cfg(target_os = "android")]
use rustutils::system_properties::PropertyWatcher;

#[cfg(target_os = "android")]
const PREFETCH_RECORD_PROPERTY: &str = "prefetch_boot.record";
#[cfg(target_os = "android")]
const PREFETCH_REPLAY_PROPERTY: &str = "prefetch_boot.replay";
#[cfg(target_os = "android")]
const PREFETCH_RECORD_PROPERTY_STOP: &str = "prefetch_boot.record_stop";
// Default record timeout if "prefetch_boot.record_stop" is not set
#[cfg(target_os = "android")]
const DEFAULT_RECORD_TIMEOUT: Duration = Duration::from_secs(10);

#[cfg(target_os = "android")]
fn wait_for_property_true(
    property_name: &str,
    timeout: Option<Duration>,
) -> Result<(), PropertyWatcherError> {
    let mut prop = PropertyWatcher::new(property_name)?;
    prop.wait_for_value("true", timeout)?;
    Ok(())
}

#[cfg(target_os = "android")]
fn start_prefetch_service(property_name: &str) -> Result<(), Error> {
    match rustutils::system_properties::write(property_name, "true") {
        Ok(_) => {}
        Err(_) => {
            return Err(Error::Custom { error: "Failed to start prefetch service".to_string() });
        }
    }
    Ok(())
}

/// Start prefetch services
#[cfg(target_os = "android")]
pub fn start_prefetch(args: &StartArgs) -> Result<(), Error> {
    // 1: Check the presence of the file 'prefetch_ready'. If it doesn't
    // exist then the device is booting for the first time after wipe.
    // Thus, we would just create the file and exit as we do not want
    // to initiate the record after data wipe primiarly because boot
    // after data wipe is long and the I/O pattern during first boot may not actually match
    // with subsequent boot.
    //
    // 2: If the file 'prefetch_ready' is present:
    //
    //   a: Compare the build-finger-print of the device with the one record format
    //   is associated with by reading the file 'build_finger_print'. If they match,
    //   start the prefetch_replay.
    //
    //   b: If they don't match, then the device was updated through OTA. Hence, start
    //   a fresh record and delete the build-finger-print file. This should also cover
    //   the case of device rollback.
    //
    //   c: If the build-finger-print file doesn't exist, then just restart the record
    //   from scratch.
    if !args.path.exists() {
        match File::create(args.path.clone()) {
            Ok(_) => {}
            Err(_) => {
                return Err(Error::Custom { error: "File Creation failed".to_string() });
            }
        }
        return Ok(());
    }

    if args.build_fingerprint_path.exists() {
        let device_build_fingerprint = rustutils::system_properties::read("ro.build.fingerprint")
            .map_err(|e| Error::Custom {
            error: format!("Failed to read ro.build.fingerprint: {}", e),
        })?;
        let pack_build_fingerprint = std::fs::read_to_string(&args.build_fingerprint_path)?;
        if pack_build_fingerprint.trim() == device_build_fingerprint.as_deref().unwrap_or_default()
        {
            info!("Start replay");
            start_prefetch_service(PREFETCH_REPLAY_PROPERTY)?;
        } else {
            info!("Start record");
            std::fs::remove_file(&args.build_fingerprint_path)?;
            start_prefetch_service(PREFETCH_RECORD_PROPERTY)?;
        }
    } else {
        info!("Start record");
        start_prefetch_service(PREFETCH_RECORD_PROPERTY)?;
    }
    Ok(())
}

/// Write build finger print of of the device to associate record format
#[cfg(target_os = "android")]
fn write_build_fingerprint(args: &RecordArgs) -> Result<(), Error> {
    let mut build_fingerprint_file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(&args.build_fingerprint_path)
        .map_err(|source| Error::Create {
            source,
            path: args.build_fingerprint_path.to_str().unwrap().to_owned(),
        })?;

    let device_build_fingerprint =
        rustutils::system_properties::read("ro.build.fingerprint").unwrap_or_default();
    let device_build_fingerprint = device_build_fingerprint.unwrap_or_default();

    build_fingerprint_file.write_all(device_build_fingerprint.as_bytes())?;
    build_fingerprint_file.sync_all()?;

    Ok(())
}

/// Records prefetch data for the given configuration
pub fn record(args: &RecordArgs) -> Result<(), Error> {
    let (mut tracer, exit_tx) = tracer::Tracer::create(
        args.trace_buffer_size_kib,
        args.tracing_subsystem.clone(),
        args.tracing_instance.clone(),
        args.setup_tracing,
    )?;
    let duration = Duration::from_secs(args.duration as u64);

    let thd = thread::spawn(move || {
        if !duration.is_zero() {
            info!("Record start - waiting for duration: {:?}", duration);
            thread::sleep(duration);
        } else {
            #[cfg(target_os = "android")]
            wait_for_property_true("sys.boot_completed", None).unwrap_or_else(|e| {
                warn!("failed to wait for sys.boot_completed with error: {}", e)
            });
            #[cfg(target_os = "android")]
            wait_for_property_true(PREFETCH_RECORD_PROPERTY_STOP, Some(DEFAULT_RECORD_TIMEOUT))
                .unwrap_or_else(|e| {
                    warn!("failed to wait for {} with error: {}", PREFETCH_RECORD_PROPERTY_STOP, e)
                });
        }

        // We want to unwrap here on failure to send this signal. Otherwise
        // tracer will continue generating huge records data.
        exit_tx.send(()).unwrap();
    });

    let mut rf = tracer.trace(args.int_path.as_ref())?;
    thd.join()
        .map_err(|_| Error::ThreadPool { error: "Failed to join timeout thread".to_string() })?;

    let mut out_file =
        OpenOptions::new().write(true).create(true).truncate(true).open(&args.path).map_err(
            |source| Error::Create { source, path: args.path.to_str().unwrap().to_owned() },
        )?;

    std::fs::set_permissions(&args.path, std::fs::Permissions::from_mode(0o644))
        .map_err(|source| Error::Create { source, path: args.path.to_str().unwrap().to_owned() })?;

    // Write the record file
    out_file
        .write_all(&rf.add_checksum_and_serialize()?)
        .map_err(|source| Error::Write { path: args.path.to_str().unwrap().to_owned(), source })?;
    out_file.sync_all()?;

    // Write build-finger-print file
    #[cfg(target_os = "android")]
    write_build_fingerprint(args)?;

    Ok(())
}

/// Replays prefetch data for the given configuration
pub fn replay(args: &ReplayArgs) -> Result<(), Error> {
    let replay = Replay::new(args)?;
    replay.replay()
}

/// Dumps prefetch data in the human readable form
pub fn dump(args: &DumpArgs) -> Result<(), Error> {
    let reader = File::open(&args.path)
        .map_err(|source| Error::Open { source, path: args.path.to_str().unwrap().to_string() })?;
    let rf: RecordsFile =
        serde_cbor::from_reader(reader).map_err(|e| Error::Deserialize { error: e.to_string() })?;
    match args.format {
        OutputFormat::Json => println!(
            "{:#}",
            serde_json::to_string_pretty(&rf)
                .map_err(|e| Error::Serialize { error: e.to_string() })?
        ),
        OutputFormat::Csv => rf.serialize_records_to_csv(&mut io::stdout())?,
    }
    Ok(())
}

/// An alias of android_logger::Level to use log level across android and linux.
#[cfg(target_os = "android")]
pub type LogLevel = Level;

/// An alias of log::LevelFilter to use log level across android and linux.
#[cfg(not(target_os = "android"))]
pub type LogLevel = LevelFilter;

/// Convenience logging initializer that is shared between the prefetch tool and c wrapper library
#[cfg(target_os = "android")]
pub fn init_logging(_level: LogLevel) {
    android_logger::init_once(
        android_logger::Config::default().with_max_level(log::LevelFilter::Info).format(
            |f, record| {
                write!(
                    f,
                    "{} prefetch_rs: {}:{} {}: {}",
                    nanoseconds_since_boot(),
                    record.file().unwrap_or("unknown_file"),
                    record.line().unwrap_or(0),
                    record.level(),
                    record.args()
                )
            },
        ),
    )
}

/// Convenience logging initializer that is shared between the prefetch tool and c wrapper library
#[cfg(target_os = "linux")]
pub fn init_logging(level: LogLevel) {
    let mut builder = env_logger::Builder::from_default_env();

    builder
        .filter(None, level)
        .format(|buf, record| {
            writeln!(
                buf,
                "{} prefetch_rs: {}:{} {}: {}",
                nanoseconds_since_boot(),
                record.file().unwrap_or("unknown_file"),
                record.line().unwrap_or(0),
                record.level(),
                record.args()
            )
        })
        .init();
}
