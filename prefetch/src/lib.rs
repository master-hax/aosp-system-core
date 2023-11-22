// Copyright 2023, The Android Open Source Project
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! A library to prefetch files on the file system to optimize startup times
//!

mod args;
mod c_exports;
mod error;
mod format;
mod replay;
mod tracer;

use std::fs::File;
use std::io;
use std::io::Write;
use std::process::id;
use std::string::ToString;
use std::thread;
use std::time::Duration;

use libc::c_int;
use libc::syscall;
use libc::SYS_ioprio_get;
use libc::SYS_ioprio_set;
use libc::{getpriority, setpriority, PRIO_PROCESS};
#[cfg(target_os = "android")]
use log::Level;
#[cfg(target_os = "linux")]
use log::LevelFilter;

pub use args::args_from_env;
use args::OutputFormat;
pub use args::ReplayArgs;
pub use args::{DumpArgs, MainArgs, RecordArgs, SubCommands};
pub use error::Error;
pub use format::FileId;
pub use format::InodeInfo;
pub use format::Record;
pub use format::RecordsFile;
use log::{info, warn};
use nix::errno::{errno, Errno};
pub use replay::Replay;
pub use tracer::nanoseconds_since_boot;

pub use c_exports::prefetch_record;
pub use c_exports::prefetch_replay;

// Set process priority to a max value so that prefetch
// - during record doesn't drop any trace lines because buffer is running full and prefetch process
//   is reading the buffer slow.
// - during replay gets highest priority to run and read from the disk
//   ionice value is tied to nice value by default so we rely on setting nice value only.
//   See: https://linux.die.net/man/1/ionice
//
// `-20` seems to the highest value.
//   See: https://man7.org/linux/man-pages/man2/setpriority.2.html
#[allow(dead_code)]
static CPU_MAX_PROCESS_PRIORITY: i32 = -20;

//  Get/set process' io priority
static IOPRIO_WHO_PROCESS: c_int = 1;

// Returns max IO priority
#[allow(dead_code)]
fn get_max_io_priority() -> i64 {
    // These const are used from
    // https://android.googlesource.com/kernel/common/+/ASB-2017-12-05_3.18-o-mr1/include/linux/ioprio.h?autodive=0%2F%2F#7
    static IOPRIO_CLASS_SHIFT: i64 = 13;
    static IOPRIO_CLASS_RT: i64 = 1;

    IOPRIO_CLASS_RT << IOPRIO_CLASS_SHIFT
}

// Helper struct to set and restore process priority
#[derive(Default)]
struct ProcessPriority {
    cpu_new_val: Option<i32>,
    cpu_old_val: Option<i32>,
    io_new_val: Option<i64>,
    io_old_val: Option<i64>,
}

impl ProcessPriority {
    fn cpu_get_priority() -> Result<i32, Error> {
        Errno::clear();
        // SAFETY: This is safe because we check return value immediately after the call.
        let old_val = unsafe { getpriority(PRIO_PROCESS, id()) };
        if old_val == -1 && errno() != 0 {
            return Err(Error::Custom {
                error: format!("failed to get process cpu priority:{}", Errno::last().desc()),
            });
        }
        Ok(old_val)
    }

    fn io_get_priority() -> Result<i64, Error> {
        Errno::clear();
        // SAFETY: This is safe because we check return value immediately after the call.
        let old_val = unsafe { syscall(SYS_ioprio_get, IOPRIO_WHO_PROCESS, id()) };

        if old_val == -1 {
            return Err(Error::Custom {
                error: format!("failed to get process io priority:{}", Errno::last().desc()),
            });
        }
        #[allow(clippy::useless_conversion)]
        Ok(i64::from(old_val))
    }

    fn cpu_set_priority(cpu_new_val: i32) -> Result<(), Error> {
        // SAFETY: This is safe because we check return value immediately after the call.
        let ret = unsafe { setpriority(PRIO_PROCESS, id(), cpu_new_val) };

        if ret != 0 {
            return Err(Error::Custom {
                error: format!(
                    "failed to set process priority to:{} with:{}",
                    cpu_new_val,
                    Errno::last().desc()
                ),
            });
        }
        Ok(())
    }

    fn io_set_priority(io_new_val: i64) -> Result<(), Error> {
        // SAFETY: This is safe because we check return value immediately after the call.
        let ret = unsafe { syscall(SYS_ioprio_set, IOPRIO_WHO_PROCESS, id(), io_new_val) };

        if ret != 0 {
            return Err(Error::Custom {
                error: format!(
                    "failed to set process io priority to:{} with:{}",
                    io_new_val,
                    Errno::last().desc()
                ),
            });
        }
        Ok(())
    }

    fn increase_cpu_priority_if_needed(cpu_new_val: i32) -> Result<i32, Error> {
        let cpu_old_val = Self::cpu_get_priority()?;
        if cpu_old_val > cpu_new_val {
            Self::cpu_set_priority(cpu_new_val)?;
        }
        info!("set process cpu priority from:{} to:{}", cpu_old_val, cpu_new_val);
        Ok(cpu_old_val)
    }

    fn increase_io_priority_if_needed(io_new_val: i64) -> Result<i64, Error> {
        let io_old_val = Self::io_get_priority()?;
        if io_old_val > io_new_val {
            Self::io_set_priority(io_new_val)?;
        }
        info!("set process io priority from:{} to:{}", io_old_val, io_new_val);
        Ok(io_old_val)
    }

    pub fn new(cpu_new_val: Option<i32>, io_new_val: Option<i64>) -> Result<Self, Error> {
        let cpu_old_val = if let Some(cpu_new_val) = &cpu_new_val {
            Some(Self::increase_cpu_priority_if_needed(*cpu_new_val)?)
        } else {
            None
        };
        let io_old_val = if let Some(io_new_val) = &io_new_val {
            Some(Self::increase_io_priority_if_needed(*io_new_val)?)
        } else {
            None
        };
        Ok(Self { cpu_new_val, cpu_old_val, io_new_val, io_old_val })
    }
}

impl Drop for ProcessPriority {
    fn drop(&mut self) {
        if self.cpu_new_val != self.cpu_old_val && self.cpu_new_val.is_some() {
            let cpu_old_val = self.cpu_old_val.unwrap();
            let cpu_new_val = self.cpu_new_val.unwrap();
            if let Err(e) = Self::cpu_set_priority(cpu_old_val) {
                warn!(
                    "failed to restore process cpu priority from:{} to:{} with:{}",
                    cpu_new_val, cpu_old_val, e
                );
            } else {
                info!("restored process cpu priority from:{} to:{}", cpu_new_val, cpu_old_val);
            }
        } else {
            info!("process cpu priority {} unchanged", self.cpu_old_val.unwrap());
        }

        let io_old_val = self.io_old_val.unwrap();
        let io_new_val = self.io_new_val.unwrap();
        if self.io_new_val != self.io_old_val {
            if let Err(e) = Self::io_set_priority(io_old_val) {
                warn!(
                    "failed to restore process io priority from:{} to:{} with:{}",
                    io_new_val, io_old_val, e
                );
            } else {
                info!("restored process io priority from:{} to:{}", io_new_val, io_old_val);
            }
        } else {
            info!("process io priority {} unchanged", io_old_val);
        }
    }
}

/// Records prefetch data for the given configuration
///
/// For the duration of record, the function might increase the process priority
/// above certain levels if needed.
pub fn record(args: &RecordArgs) -> Result<(), Error> {
    init_logging();
    let _priority = if args.cpu_priority.is_some() || args.io_priority.is_some() {
        Some(ProcessPriority::new(args.cpu_priority, args.io_priority)?)
    } else {
        None
    };

    let (mut tracer, exit_tx) = tracer::Tracer::create(
        args.trace_buffer_size_kib,
        args.tracing_subsystem.clone(),
        args.tracing_instance.clone(),
        args.setup_tracing,
    )?;
    let duration = Duration::from_secs(args.duration as u64);

    let thd = thread::spawn(move || {
        thread::sleep(duration);

        // We want to unwrap here on failure to send this signal. Otherwise
        // tracer will continue generating huge records data.
        exit_tx.send(()).unwrap();
    });

    let mut rf = tracer.trace(args.int_path.as_ref())?;
    thd.join()
        .map_err(|_| Error::ThreadPool { error: "Failed to join timeout thread".to_string() })?;

    let mut out_file = File::create(&args.path)
        .map_err(|source| Error::Create { source, path: args.path.to_str().unwrap().to_owned() })?;
    out_file
        .write_all(&rf.add_checksum_and_serialize()?)
        .map_err(|source| Error::Write { path: args.path.to_str().unwrap().to_owned(), source })?;
    Ok(())
}

/// Replays prefetch data for the given configuration
///
/// For the duration of replay, the function might increase the process priority
/// above certain levels if needed.
pub fn replay(args: &ReplayArgs) -> Result<(), Error> {
    init_logging();
    let _priority = if args.cpu_priority.is_some() || args.io_priority.is_some() {
        let priority = match ProcessPriority::new(args.cpu_priority, args.io_priority) {
            Ok(p) => p,
            Err(e) => {
                if args.exit_on_error {
                    return Err(e);
                } else {
                    warn!("set priority failed with: {}", e);
                    // Since the default old and new value will be same, drop is a noop.
                    // Keeps rustc happy.
                    ProcessPriority::default()
                }
            }
        };
        Some(priority)
    } else {
        None
    };
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
pub fn init_logging(level: LogLevel) {
    android_logger::init_once(android_logger::Config::default().with_min_level(level).format(
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
    ))
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

#[cfg(test)]
mod tests {
    use super::*;

    #[ignore = "b/303887119 - test runner might not have privileges to increase process priority"]
    #[test]
    fn test_set_and_restore_priority() {
        // The test can be running with highest priority. To have a room to adjust priority
        // during test, lower priority
        let cpu_old_priority = ProcessPriority::cpu_get_priority().unwrap() + 2;
        ProcessPriority::cpu_set_priority(cpu_old_priority).unwrap();
        let io_old_priority = ProcessPriority::io_get_priority().unwrap();

        {
            let cpu_new_priority = cpu_old_priority - 1;
            let io_new_priority = get_max_io_priority();
            let _p = ProcessPriority::new(Some(cpu_new_priority), Some(io_new_priority)).unwrap();
            assert_eq!(ProcessPriority::cpu_get_priority().unwrap(), cpu_new_priority);
            assert_ne!(ProcessPriority::io_get_priority().unwrap(), io_old_priority);
            assert_eq!(ProcessPriority::io_get_priority().unwrap(), io_new_priority);
        }
        assert_eq!(ProcessPriority::cpu_get_priority().unwrap(), cpu_old_priority);
        assert_eq!(ProcessPriority::io_get_priority().unwrap(), io_old_priority);
    }

    #[ignore = "b/303887119 - test runner might not have privileges to increase process priority"]
    #[test]
    fn test_current_priority_high_enough() {
        // The test can be running with highest priority. To have a room to adjust priority
        // during test, lower priority
        let cpu_old_priority = ProcessPriority::cpu_get_priority().unwrap() + 2;
        ProcessPriority::cpu_set_priority(cpu_old_priority).unwrap();
        let io_old_priority = ProcessPriority::io_get_priority().unwrap();

        {
            let cpu_new_priority = cpu_old_priority + 1;
            let io_new_priority = get_max_io_priority();
            let _p = ProcessPriority::new(Some(cpu_new_priority), Some(io_new_priority)).unwrap();
            assert_eq!(ProcessPriority::cpu_get_priority().unwrap(), cpu_old_priority);
            assert_ne!(ProcessPriority::io_get_priority().unwrap(), io_old_priority);
            assert_eq!(ProcessPriority::io_get_priority().unwrap(), io_new_priority);
        }
        assert_eq!(ProcessPriority::cpu_get_priority().unwrap(), cpu_old_priority);
        assert_eq!(ProcessPriority::io_get_priority().unwrap(), io_old_priority);
    }
}
