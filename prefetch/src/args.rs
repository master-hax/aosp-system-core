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

pub(crate) static ARG_NAME_PATH: &str = "path";
pub(crate) static ARG_NAME_DEBUG: &str = "debug";
pub(crate) static ARG_NAME_DURATION: &str = "duration";
pub(crate) static ARG_NAME_TRACE_BUFFER_SIZE: &str = "trace-buffer-size";
pub(crate) static ARG_NAME_TRACING_SUBSYSTEM: &str = "tracing-subsystem";
pub(crate) static ARG_NAME_TRACING_INSTANCE: &str = "tracing-instance";
pub(crate) static ARG_NAME_SETUP_TRACING: &str = "setup-tracing";
pub(crate) static ARG_NAME_IO_DEPTH: &str = "io-depth";
pub(crate) static ARG_NAME_MAX_FDS: &str = "max-fds";
pub(crate) static ARG_NAME_EXIT_ON_ERROR: &str = "exit-on-error";
#[allow(dead_code)]
pub(crate) static ARG_NAME_FORMAT: &str = "format";
pub(crate) static ARG_NAME_CONFIG_PATH: &str = "config-path";
#[allow(dead_code)]
pub(crate) static ARG_NAME_IO_PRIORITY: &str = "io-priority";
#[allow(dead_code)]
pub(crate) static ARG_NAME_CPU_PRIORITY: &str = "cpu-priority";

pub(crate) static DEFAULT_IO_DEPTH: u16 = 4;
pub(crate) static DEFAULT_MAX_FDS: u16 = 128;
pub(crate) static DEFAULT_EXIT_ON_ERROR: bool = false;

#[cfg(all(feature = "use_clap", feature = "use_argh"))]
compile_error!("only one of feature 'use_argh' or 'use_clap' should be specified");

#[cfg(not(any(feature = "use_clap", feature = "use_argh")))]
compile_error!("one of 'use_argh' or 'use_clap' is required");

#[cfg(feature = "use_argh")]
mod args_argh;
#[cfg(feature = "use_argh")]
use args_argh as args_internal;

#[cfg(feature = "use_clap")]
mod args_clap;
#[cfg(feature = "use_clap")]
use args_clap as args_internal;

use std::ffi::OsString;
use std::path::PathBuf;
use std::process::exit;

pub use args_internal::OutputFormat;
pub use args_internal::ReplayArgs;
pub use args_internal::TracerType;
pub use args_internal::{DumpArgs, MainArgs, RecordArgs, SubCommands};
use serde::Deserialize;
use serde::Serialize;

use crate::Error;
use log::error;

// Deserialized form of the config file
#[derive(Clone, Debug, Default, Deserialize, Serialize, Eq, PartialEq)]
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

fn verify_and_fix(args: &mut MainArgs) -> Result<(), Error> {
    match &mut args.nested {
        SubCommands::Record(arg) => {
            if arg.debug && arg.int_path.is_none() {
                arg.int_path = Some(PathBuf::from(format!("{}.int", arg.path.to_str().unwrap())));
            }

            let _ = ensure_path_doesnt_exist(arg.path.as_os_str().to_str().unwrap())?;
            if let Some(p) = &arg.int_path {
                let _ = ensure_path_doesnt_exist(p.as_os_str().to_str().unwrap())?;
            }
        }
        SubCommands::Replay(arg) => {
            let _ = ensure_path_exists(arg.path.as_os_str().to_str().unwrap())?;
            if !arg.config_path.as_os_str().is_empty() {
                ensure_path_exists(arg.config_path.to_str().unwrap())?;
            }
        }
        SubCommands::Dump(arg) => {
            let _ = ensure_path_exists(arg.path.as_os_str().to_str().unwrap())?;
        }
    }
    Ok(())
}

/// Returns `PathBuf` if the given path at `value` doesn't exist.
pub(crate) fn ensure_path_doesnt_exist(value: &str) -> Result<PathBuf, Error> {
    let p = PathBuf::from(value);
    if p.exists() {
        Err(Error::InvalidArgs {
            arg_name: "path".to_string(),
            arg_value: value.to_owned(),
            error: format!("Path {} already exists", value),
        })
    } else {
        Ok(p)
    }
}

/// Returns `PathBuf` if the given path at `value` t exists.
pub(crate) fn ensure_path_exists(value: &str) -> Result<PathBuf, Error> {
    let p = PathBuf::from(value);
    if p.is_file() {
        Ok(p)
    } else {
        Err(Error::InvalidArgs {
            arg_name: "path".to_string(),
            arg_value: value.to_owned(),
            error: format!("Path {} does not exist", value),
        })
    }
}

/// Builds `MainArgs` from iterable strings that resemble command line arguments.
pub fn args_from_vec<I, T>(args_vec: Option<I>) -> Result<MainArgs, Error>
where
    I: IntoIterator<Item = T>,
    T: Into<OsString> + Clone,
{
    let mut args = args_internal::args_from_vec(args_vec)?;
    verify_and_fix(&mut args)?;
    Ok(args)
}

/// Builds `MainArgs` from command line arguments. On error prints error/help message
/// and exits.
pub fn args_from_env() -> MainArgs {
    let mut args = args_internal::args_from_env();
    if let Err(e) = verify_and_fix(&mut args) {
        error!("failed to verify args: {}", e);
        exit(1);
    }
    args
}
