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

use std::{
    ffi::OsString, option::Option, path::PathBuf, process::exit, result::Result::Ok, str::FromStr,
};

use clap::{value_t, App, Arg, ArgMatches, SubCommand};
use log::error;
use serde::Deserialize;
use serde::Serialize;

use crate::args::ensure_path_doesnt_exist;
use crate::args::ensure_path_exists;
use crate::args::ARG_NAME_CONFIG_PATH;
use crate::args::ARG_NAME_CPU_PRIORITY;
use crate::args::ARG_NAME_DEBUG;
use crate::args::ARG_NAME_DURATION;
use crate::args::ARG_NAME_EXIT_ON_ERROR;
use crate::args::ARG_NAME_FORMAT;
use crate::args::ARG_NAME_IO_DEPTH;
use crate::args::ARG_NAME_IO_PRIORITY;
use crate::args::ARG_NAME_MAX_FDS;
use crate::args::ARG_NAME_PATH;
use crate::args::ARG_NAME_SETUP_TRACING;
use crate::args::ARG_NAME_TRACE_BUFFER_SIZE;
use crate::args::ARG_NAME_TRACING_INSTANCE;
use crate::args::ARG_NAME_TRACING_SUBSYSTEM;
use crate::args::DEFAULT_EXIT_ON_ERROR;
use crate::args::DEFAULT_IO_DEPTH;
use crate::args::DEFAULT_MAX_FDS;
use crate::Error;

// Default trace buffer size in KiB. Set it large enough to not wrap around soon
// enough.
static TRACE_BUFFER_SIZE_KIB: u64 = 8192;

fn value_t_or_error<T: FromStr>(
    args: &ArgMatches<'_>,
    value: &str,
    default: Option<T>,
) -> Result<T, Error> {
    if !args.is_present(value) {
        if let Some(x) = default {
            return Ok(x);
        }
    }

    value_t!(args.value_of(value), T).map_err(|e| Error::InvalidArgs {
        arg_name: "Error parsing value".to_owned(),
        arg_value: value.to_owned(),
        error: e.to_string(),
    })
}

pub fn args_from_vec<I, T>(args_vec: Option<I>) -> Result<MainArgs, Error>
where
    I: IntoIterator<Item = T>,
    T: Into<OsString> + Clone,
{
    let trace_buffer_size_help = format!(
        "size of the trace buffer which holds trace events. We need \
                         larger buffer on a system that has faster disks or has large number of \
                         events enabled. Defaults to {} KiB. \
                         See: https://www.kernel.org/doc/Documentation/trace/ftrace.txt",
        TRACE_BUFFER_SIZE_KIB
    );

    let app = App::new("prefetch")
        .about("A utility to prefetch data to optimize startup times")
        .subcommand(
            SubCommand::with_name("record")
                .about("Records prefetch data")
                .arg(
                    Arg::with_name(ARG_NAME_PATH)
                        .long(ARG_NAME_PATH)
                        .value_name("FILE")
                        .required(true)
                        .help(
                            "file path where the records will be written. A new file is created \
                        at the given path. Errors out if the file already exists.",
                        )
                        .takes_value(true),
                )
                .arg(
                    Arg::with_name(ARG_NAME_DEBUG)
                        .long(ARG_NAME_DEBUG)
                        .value_name("BOOL")
                        .required(false)
                        .help(
                            "save intermediate file that helps in debugging. A new file is created \
                        at the given \"path\".int. Errors out if the file already exists.",
                        )
                        .takes_value(true),
                )
                .arg(
                    Arg::with_name(ARG_NAME_DURATION)
                        .long(ARG_NAME_DURATION)
                        .value_name("SECONDS")
                        .required(true)
                        .help("duration in seconds to record the data")
                        .takes_value(true),
                )
                .arg(
                    Arg::with_name(ARG_NAME_TRACE_BUFFER_SIZE)
                        .long(ARG_NAME_TRACE_BUFFER_SIZE)
                        .value_name("KiBs")
                        .required(false)
                        .help(&trace_buffer_size_help
                    )
                        .takes_value(true),
                )
                .arg(
                    Arg::with_name(ARG_NAME_TRACING_SUBSYSTEM)
                        .long(ARG_NAME_TRACING_SUBSYSTEM)
                        .value_name("fs|mem")
                        .required(false)
                        .help(
                            "tracing subsystem to use. Available options are \"fs\" and \
                        \"mem\". mem provides better data than fs subsystem. mem is also easier to \
                        setup. fs subsystem needs patching kernel and exists only for certain \
                        use case. mem is default.",
                        )
                        .takes_value(true),
                )
                .arg(
                    Arg::with_name(ARG_NAME_SETUP_TRACING)
                        .long(ARG_NAME_SETUP_TRACING)
                        .value_name("true|false")
                        .required(false)
                        .help(
                            "If true enables all the needed trace events. And at the end it \
                            restores the values of those events. If false, assumes that user has \
                            setup the needed trace events. defaults to false",
                        )
                        .takes_value(true),
                )
                .arg(
                    Arg::with_name(ARG_NAME_TRACING_INSTANCE)
                        .long(ARG_NAME_TRACING_INSTANCE)
                        .value_name("my_instance_name")
                        .required(false)
                        .help(
                            "If specified, works on a tracing instance (like \
                                /sys/kernel/tracing/instance/my_instance) rather that using on \
                                shared global instance (i.e. /sys/kernel/tracing)."
                        )
                        .takes_value(true),
                )
                .arg(
                    Arg::with_name(ARG_NAME_IO_PRIORITY)
                        .long(ARG_NAME_IO_PRIORITY)
                        .value_name("io_priority")
                        .required(false)
                        .help(
                            "Sets io priority to given value before recording."
                        )
                        .takes_value(true),
                )
                .arg(
                    Arg::with_name(ARG_NAME_CPU_PRIORITY)
                        .long(ARG_NAME_CPU_PRIORITY)
                        .value_name("cpu_priority")
                        .required(false)
                        .help(
                            "Sets cpu priority to given value before recording."
                        )
                        .takes_value(true),
                ),
        )
        .subcommand(
            SubCommand::with_name("replay")
                .about("Prefetch data from the recorded file")
                .arg(
                    Arg::with_name(ARG_NAME_PATH)
                        .long(ARG_NAME_PATH)
                        .value_name("FILE")
                        .required(true)
                        .help("file path from where the records will be read")
                        .takes_value(true),
                )
                .arg(
                    Arg::with_name(ARG_NAME_IO_DEPTH)
                        .long(ARG_NAME_IO_DEPTH)
                        .value_name("NUMBER")
                        .help("IO depth. Number of IO that can go in parallel.")
                        .takes_value(true),
                )
                .arg(
                    Arg::with_name(ARG_NAME_MAX_FDS)
                        .long(ARG_NAME_MAX_FDS)
                        .value_name("NUMBER")
                        .required(false)
                        .help("max number of open fds to cache. Default: 128")
                        .takes_value(true),
                )
                .arg(
                    Arg::with_name(ARG_NAME_EXIT_ON_ERROR)
                        .long(ARG_NAME_EXIT_ON_ERROR)
                        .value_name("true|false")
                        .required(false)
                        .help(
                            "if true, command exits on encountering any error. This defaults to \
                        false as there is not harm prefetching if we encounter non-fatal errors",
                        )
                        .takes_value(true)
                    )
                .arg(
                    Arg::with_name(ARG_NAME_IO_PRIORITY)
                        .long(ARG_NAME_IO_PRIORITY)
                        .value_name("io_priority")
                        .required(false)
                        .help(
                            "Sets io priority to given value before recording."
                        )
                        .takes_value(true),
                )
                .arg(
                    Arg::with_name(ARG_NAME_CPU_PRIORITY)
                        .long(ARG_NAME_CPU_PRIORITY)
                        .value_name("cpu_priority")
                        .required(false)
                        .help(
                            "Sets cpu priority to given value before recording."
                        )
                        .takes_value(true),
                )
                .arg(
                    Arg::with_name(ARG_NAME_CONFIG_PATH)
                        .long(ARG_NAME_CONFIG_PATH)
                        .value_name("FILE")
                        .required(false)
                        .help("file path from where the prefetch config will be read")
                        .takes_value(true),
                ),
        )
        .subcommand(
            SubCommand::with_name("dump")
                .about("Prints recorded data in human readable form")
                .arg(
                    Arg::with_name(ARG_NAME_PATH)
                        .long(ARG_NAME_PATH)
                        .value_name("FILE")
                        .required(true)
                        .help("file path from where the records will be read")
                        .takes_value(true),
                )
                .arg(
                    Arg::with_name(ARG_NAME_FORMAT)
                        .long(ARG_NAME_FORMAT)
                        .value_name("csv|json")
                        .required(true)
                        .help(
                            "output format. One of json or csv. Note: In csv format, a few \
                        fields are excluded from the dump",
                        )
                        .takes_value(true),
                ),
        );

    let matches = match args_vec {
        Some(args_vec) => app.get_matches_from_safe(args_vec),
        None => app.get_matches_safe(),
    }
    .map_err(|e| Error::InvalidArgs {
        arg_name: "".to_owned(),
        arg_value: "".to_owned(),
        error: e.to_string(),
    })?;

    let nested = match matches.subcommand() {
        ("record", Some(args)) => {
            let path: PathBuf = value_t_or_error(args, ARG_NAME_PATH, None)?;
            let int_path: PathBuf = PathBuf::from(format!("{}.int", path.to_str().unwrap()));
            ensure_path_doesnt_exist(path.to_str().unwrap())?;
            SubCommands::Record(RecordArgs {
                duration: value_t_or_error(args, ARG_NAME_DURATION, None)?,
                path,
                trace_buffer_size_kib: if args.is_present(ARG_NAME_TRACE_BUFFER_SIZE) {
                    Some(value_t_or_error(args, ARG_NAME_TRACE_BUFFER_SIZE, None)?)
                } else {
                    None
                },
                tracing_subsystem: value_t_or_error(
                    args,
                    ARG_NAME_TRACING_SUBSYSTEM,
                    Some(TracerType::default()),
                )?,
                debug: value_t_or_error(args, ARG_NAME_DEBUG, Some(false))?,
                int_path: if value_t_or_error(args, ARG_NAME_DEBUG, Some(false))? {
                    ensure_path_doesnt_exist(int_path.to_str().unwrap())?;
                    Some(int_path)
                } else {
                    None
                },
                setup_tracing: value_t_or_error(args, ARG_NAME_SETUP_TRACING, Some(false))?,
                tracing_instance: if args.is_present(ARG_NAME_TRACING_INSTANCE) {
                    Some(value_t_or_error(args, ARG_NAME_TRACING_INSTANCE, None)?)
                } else {
                    None
                },
                io_priority: if args.is_present(ARG_NAME_IO_PRIORITY) {
                    Some(value_t_or_error(args, ARG_NAME_IO_PRIORITY, None)?)
                } else {
                    None
                },
                cpu_priority: if args.is_present(ARG_NAME_CPU_PRIORITY) {
                    Some(value_t_or_error(args, ARG_NAME_CPU_PRIORITY, None)?)
                } else {
                    None
                },
            })
        }
        ("replay", Some(args)) => {
            let path: PathBuf = value_t_or_error(args, ARG_NAME_PATH, None)?;
            let config_path: PathBuf =
                value_t_or_error(args, ARG_NAME_CONFIG_PATH, Some(PathBuf::new()))?;
            if !config_path.as_os_str().is_empty() {
                ensure_path_exists(config_path.to_str().unwrap())?;
            }
            ensure_path_exists(path.to_str().unwrap())?;
            SubCommands::Replay(ReplayArgs {
                path,
                io_depth: value_t_or_error(args, ARG_NAME_IO_DEPTH, Some(DEFAULT_IO_DEPTH))?,
                max_fds: value_t_or_error(args, ARG_NAME_MAX_FDS, Some(DEFAULT_MAX_FDS))?,
                exit_on_error: value_t_or_error(
                    args,
                    ARG_NAME_EXIT_ON_ERROR,
                    Some(DEFAULT_EXIT_ON_ERROR),
                )?,
                config_path,
                io_priority: if args.is_present(ARG_NAME_IO_PRIORITY) {
                    Some(value_t_or_error(args, ARG_NAME_IO_PRIORITY, None)?)
                } else {
                    None
                },
                cpu_priority: if args.is_present(ARG_NAME_CPU_PRIORITY) {
                    Some(value_t_or_error(args, ARG_NAME_CPU_PRIORITY, None)?)
                } else {
                    None
                },
            })
        }
        ("dump", Some(args)) => {
            let path: PathBuf = value_t_or_error(args, ARG_NAME_PATH, None)?;
            ensure_path_exists(path.to_str().unwrap())?;
            SubCommands::Dump(DumpArgs {
                path,
                format: value_t_or_error(args, ARG_NAME_FORMAT, None)?,
            })
        }
        (x, y) => {
            return Err(Error::InvalidArgs {
                arg_name: x.to_owned(),
                arg_value: format!("{:?}", y),
                error: "unknown args".to_owned(),
            });
        }
    };

    Ok(MainArgs { nested })
}

/// Build args struct from command line arguments
pub fn args_from_env() -> MainArgs {
    let vec_args: Option<Vec<String>> = None;
    let ret = args_from_vec(vec_args);
    match ret {
        Err(e) => {
            error!("Failed to parse args: {:?}", e);
            exit(1);
        }
        Ok(ret) => ret,
    }
}

/// prefetch-rs
#[derive(Eq, PartialEq, Debug, Default)]
pub struct MainArgs {
    /// Subcommands
    pub nested: SubCommands,
}

/// Sub commands for prefetch functions
#[derive(Eq, PartialEq, Debug)]
pub enum SubCommands {
    /// Records prefetch data.
    Record(RecordArgs),
    /// Replays from prefetch data
    Replay(ReplayArgs),
    /// Dump prefetch data in human readable format
    Dump(DumpArgs),
}

impl Default for SubCommands {
    fn default() -> Self {
        Self::Dump(DumpArgs::default())
    }
}

#[derive(Eq, PartialEq, Debug, Default)]
/// Records prefect data.
pub struct RecordArgs {
    /// duration in seconds to record the data
    pub duration: u16,
    /// file path where the records will be written to
    ///
    /// A new file is created at the given path. Errors out if the file
    /// already exists.
    pub path: PathBuf,

    /// when set an intermediate file will be created that provides more information
    /// about collected data.
    pub debug: bool,

    /// file path where the intermediate file will be written to
    ///
    /// A new file is created at the given path. Errors out if the file
    /// already exists.
    pub int_path: Option<PathBuf>,

    /// Size of the trace buffer which holds trace events. We need larger
    /// buffer on a system that has faster disks or has large number of events
    /// enabled. Defaults to TRACE_BUFFER_SIZE_KIB KiB.
    pub trace_buffer_size_kib: Option<u64>,

    /// Trace subsystem to use. mem subsystem is better and potentially easier
    /// to use. "fs" subsystem might need patching kernel and exists only
    /// for some special use cases.
    pub tracing_subsystem: TracerType,

    /// If true enables all the needed trace events. And at the end it restores
    /// the values of those events.
    /// If false, assumes that user has setup the needed trace events.
    pub setup_tracing: bool,

    /// If specified, works on a tracing instance (like /sys/kernel/tracing/instance/my_instance)
    ///  rather than using on shared global instance (i.e. /sys/kernel/tracing)."
    pub tracing_instance: Option<String>,

    /// Sets io priority to given value before recording.
    pub io_priority: Option<i64>,

    /// Sets cpu priority to given value before recording.
    pub cpu_priority: Option<i32>,
}

/// Type of tracing subsystem to use.
#[derive(Deserialize, Clone, Eq, PartialEq, Debug)]
pub enum TracerType {
    /// fs subsystem relies on entry points like open, open_exec and uselib.
    Fs,
    /// mem tracing subsystem relies on when a file's in-memory page gets added to the fs cache.
    Mem,
}

impl FromStr for TracerType {
    type Err = Error;
    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        Ok(match s.to_lowercase().as_str() {
            "fs" => Self::Fs,
            "mem" => Self::Mem,
            _ => {
                return Err(Error::InvalidArgs {
                    arg_name: "tracing_subsystem".to_owned(),
                    arg_value: s.to_owned(),
                    error: "unknown value".to_owned(),
                })
            }
        })
    }
}

impl Default for TracerType {
    fn default() -> Self {
        Self::Mem
    }
}

#[derive(Eq, PartialEq, Debug, Default)]
/// Prefetch data from the recorded file.
pub struct ReplayArgs {
    /// file path from where the records will be read
    pub path: PathBuf,

    /// IO depth. Number of IO that can go in parallel.
    pub io_depth: u16,

    /// max number of open fds to cache
    pub max_fds: u16,

    /// if true, command exits on encountering any error.
    ///
    /// This defaults to false as there is not harm prefetching if we encounter
    /// non-fatal errors.
    pub exit_on_error: bool,

    /// file path from where the prefetch config file will be read
    pub config_path: PathBuf,

    /// Sets io priority to given value before recording.
    pub io_priority: Option<i64>,

    /// Sets cpu priority to given value before recording.
    pub cpu_priority: Option<i32>,
}

#[derive(Eq, PartialEq, Debug, Default)]
/// dump records file in given format
pub struct DumpArgs {
    /// file path from where the records will be read
    pub path: PathBuf,
    /// output format. One of json or csv.
    /// Note: In csv format, few fields are excluded from the output.
    pub format: OutputFormat,
}

#[derive(Deserialize, Eq, PartialEq, Debug)]
pub enum OutputFormat {
    Json,
    Csv,
}

// Deserialized form of the config file
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq)]
pub struct ConfigFile {
    // Files to be excluded in prefetch. These files might have been
    // added in the record file while recording,but we do not want to
    // replay these files. These can be two types of files:
    // 1) installation-specific files (e.g. files in /data) and
    // 2) large files which we do not want to load in replay (e.g. APK files).
    pub files_to_exclude_regex: Vec<String>,
    // Files that are not in the record file, but need to be loaded during replay
    pub additional_replay_files: Vec<String>,
}

impl FromStr for OutputFormat {
    type Err = Error;
    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        Ok(match s.to_lowercase().as_str() {
            "csv" => Self::Csv,
            "json" => Self::Json,
            _ => {
                return Err(Error::InvalidArgs {
                    arg_name: "format".to_owned(),
                    arg_value: s.to_owned(),
                    error: "unknown value".to_owned(),
                })
            }
        })
    }
}

impl Default for OutputFormat {
    fn default() -> Self {
        Self::Json
    }
}
