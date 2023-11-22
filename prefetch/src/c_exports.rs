use libc::c_char;
use log::error;
use log::info;

use std::ffi::CStr;
use std::fmt::Display;
use std::os::raw::c_int;

use crate::args::args_from_vec;
use crate::args::ARG_NAME_CONFIG_PATH;
use crate::args::ARG_NAME_DEBUG;
use crate::args::ARG_NAME_DURATION;
use crate::args::ARG_NAME_EXIT_ON_ERROR;
use crate::args::ARG_NAME_IO_DEPTH;
use crate::args::ARG_NAME_MAX_FDS;
use crate::args::ARG_NAME_PATH;
use crate::args::ARG_NAME_SETUP_TRACING;
use crate::args::ARG_NAME_TRACE_BUFFER_SIZE;
use crate::args::ARG_NAME_TRACING_INSTANCE;
use crate::args::ARG_NAME_TRACING_SUBSYSTEM;
use crate::init_logging;
use crate::record;
use crate::replay;
use crate::Error;
use crate::LogLevel;
use crate::RecordArgs;
use crate::ReplayArgs;
use crate::SubCommands;

fn result_to_int(result: Result<(), Error>) -> c_int {
    match result {
        Ok(_) => 0,
        Err(e) => {
            error!("subcommand failed: {}", e);
            -1
        }
    }
}

fn push_cstr_conditionally(
    args: &mut Vec<String>,
    arg_name: &str,
    arg_value: *const c_char,
) -> Result<(), Error> {
    // SAFETY: 
    // Value returned from this block is always valid for the scope of this
    // function, and we already performed a null check
    let value = unsafe {
        if arg_value.is_null() {
            return Ok(());
        }
        CStr::from_ptr(arg_value)
    };

    let arg_name = format!("--{}", arg_name);
    let value = value
        .to_str()
        .map_err(|e| Error::InvalidArgs {
            arg_name: arg_name.to_owned(),
            arg_value: "".to_owned(),
            error: format!("failed to make string: {}", e),
        })?
        .to_owned();
    args.extend_from_slice(&[arg_name, value]);
    Ok(())
}

fn push_bool(args: &mut Vec<String>, arg_name: &str, arg_value: i8) -> Result<(), Error> {
    let arg_name = format!("--{}", arg_name);
    args.extend_from_slice(&[
        arg_name,
        {
            if arg_value == 0 {
                "false"
            } else {
                "true"
            }
        }
        .to_owned(),
    ]);
    Ok(())
}

fn push_type_conditionally<T: Display>(
    args: &mut Vec<String>,
    arg_name: &str,
    arg_value: *const T,
) -> Result<(), Error> {
    let arg_name = format!("--{}", arg_name);
    // SAFETY: 
    // Value returned from this block is always valid for the scope of this
    // function, and we already performed a null check
    unsafe {
        if arg_value.is_null() {
            return Ok(());
        }
        args.extend_from_slice(&[arg_name, format!("{}", *arg_value)]);
    };
    Ok(())
}

fn build_record_args(
    path: *const c_char,
    debug: i8,
    duration: u16,
    trace_buffer_size: *const u64,
    tracing_subsystem: *const c_char,
    setup_tracing: i8,
    tracing_instance: *const c_char,
) -> Result<RecordArgs, Error> {
    let mut args = vec!["libprefetch".to_owned(), "record".to_owned()];
    push_cstr_conditionally(&mut args, ARG_NAME_PATH, path)?;
    push_bool(&mut args, ARG_NAME_DEBUG, debug)?;
    push_type_conditionally(&mut args, ARG_NAME_DURATION, &duration)?;
    push_type_conditionally(&mut args, ARG_NAME_TRACE_BUFFER_SIZE, trace_buffer_size)?;
    push_cstr_conditionally(&mut args, ARG_NAME_TRACING_SUBSYSTEM, tracing_subsystem)?;
    push_bool(&mut args, ARG_NAME_SETUP_TRACING, setup_tracing)?;
    push_cstr_conditionally(&mut args, ARG_NAME_TRACING_INSTANCE, tracing_instance)?;
    let main_arg = args_from_vec(Some(args))?;
    match main_arg.nested {
        SubCommands::Record(args) => Ok(args),
        x => Err(Error::InvalidArgs {
            arg_name: "record".to_owned(),
            arg_value: "".to_owned(),
            error: format!("expect record. found: {:?}", x),
        }),
    }
}

fn prefetch_record_internal(
    path: *const c_char,
    debug: i8,
    duration: u16,
    trace_buffer_size: *const u64,
    tracing_subsystem: *const c_char,
    setup_tracing: i8,
    tracing_instance: *const c_char,
) -> Result<(), Error> {
    let args = build_record_args(
        path,
        debug,
        duration,
        trace_buffer_size,
        tracing_subsystem,
        setup_tracing,
        tracing_instance,
    )?;
    info!("Calling record with {:?}", args);
    record(&args)
}

/// A c friendly wrapper around `crate::record`.
#[no_mangle]
pub extern "C" fn prefetch_record(
    path: *const c_char,
    debug: i8,
    duration: u16,
    trace_buffer_size: *const u64,
    tracing_subsystem: *const c_char,
    setup_tracing: i8,
    tracing_instance: *const c_char,
) -> c_int {
    init_logging(LogLevel::Info);
    result_to_int(prefetch_record_internal(
        path,
        debug,
        duration,
        trace_buffer_size,
        tracing_subsystem,
        setup_tracing,
        tracing_instance,
    ))
}

fn build_replay_args(
    path: *const c_char,
    io_depth: *const u16,
    max_fds: *const u16,
    exit_on_error: i8,
    config_path: *const c_char,
) -> Result<ReplayArgs, Error> {
    let mut args = vec!["libprefetch".to_owned(), "replay".to_owned()];
    push_cstr_conditionally(&mut args, ARG_NAME_PATH, path)?;
    push_type_conditionally(&mut args, ARG_NAME_IO_DEPTH, io_depth)?;
    push_type_conditionally(&mut args, ARG_NAME_MAX_FDS, max_fds)?;
    push_bool(&mut args, ARG_NAME_EXIT_ON_ERROR, exit_on_error)?;
    push_cstr_conditionally(&mut args, ARG_NAME_CONFIG_PATH, config_path)?;

    let main_arg = args_from_vec(Some(args))?;
    match main_arg.nested {
        SubCommands::Replay(args) => Ok(args),
        x => Err(Error::InvalidArgs {
            arg_name: "replay".to_owned(),
            arg_value: "".to_owned(),
            error: format!("expect replay. found: {:?}", x),
        }),
    }
}

fn prefetch_replay_internal(
    path: *const c_char,
    io_depth: *const u16,
    max_fds: *const u16,
    exit_on_error: i8,
    config_path: *const c_char,
) -> Result<(), Error> {
    let args = build_replay_args(path, io_depth, max_fds, exit_on_error, config_path)?;
    info!("Calling replay with {:?}", args);
    replay(&args)
}

/// A c friendly wrapper around `crate::replay`.
#[no_mangle]
pub extern "C" fn prefetch_replay(
    path: *const c_char,
    io_depth: *const u16,
    max_fds: *const u16,
    exit_on_error: i8,
    config_path: *const c_char,
) -> c_int {
    init_logging(LogLevel::Info);
    result_to_int(prefetch_replay_internal(path, io_depth, max_fds, exit_on_error, config_path))
}

#[cfg(test)]
mod tests {
    use std::ffi::CString;
    use std::ptr::null;

    use tempfile::NamedTempFile;

    use crate::args::TracerType;

    use super::*;

    // we ensure here that all args are considered.
    #[test]
    fn all_record_args_covered() {
        let c_str = CString::new("my path").unwrap();
        let path_ptr: *const c_char = c_str.as_ptr() as *const c_char;
        let c_str = CString::new("fs").unwrap();
        let fs_ptr: *const c_char = c_str.as_ptr() as *const c_char;
        let c_str = CString::new("my_instance").unwrap();
        let instance_ptr: *const c_char = c_str.as_ptr() as *const c_char;
        let args = build_record_args(path_ptr, 1, 12, &20, fs_ptr, 1, instance_ptr).unwrap();
        assert_eq!(args.path.to_str().unwrap(), "my path");
        assert_eq!(args.duration, 12);
        assert_eq!(args.int_path.as_ref().unwrap().to_str().unwrap(), "my path.int");
        assert_eq!(args.trace_buffer_size_kib, Some(20));
        assert_eq!(args.tracing_subsystem, TracerType::Fs);
        assert!(args.setup_tracing);
        assert_eq!(args.tracing_instance, Some("my_instance".to_owned()));
    }

    #[test]
    fn record_args_no_null_deref() {
        let c_str = CString::new("my path").unwrap();
        let path_ptr: *const c_char = c_str.as_ptr() as *const c_char;
        let c_str = CString::new("fs").unwrap();
        let fs_ptr: *const c_char = c_str.as_ptr() as *const c_char;
        let c_str = CString::new("my_instance").unwrap();
        let instance_ptr: *const c_char = c_str.as_ptr() as *const c_char;
        let _args = build_record_args(null(), 1, 12, &20, fs_ptr, 1, instance_ptr)
            .expect_err("path is required");
        let _args = build_record_args(path_ptr, 1, 12, null(), fs_ptr, 1, instance_ptr).unwrap();
        let _args = build_record_args(path_ptr, 1, 12, &20, null(), 1, instance_ptr).unwrap();
        let _args = build_record_args(path_ptr, 1, 12, &20, fs_ptr, 1, null()).unwrap();
    }

    // we ensure here that all args are considered.
    #[test]
    fn all_replay_args_covered() {
        let file = NamedTempFile::new().unwrap();
        let path = file.path().to_str().unwrap();
        let c_str = CString::new(path).unwrap();
        let path_ptr: *const c_char = c_str.as_ptr() as *const c_char;
        let config_path_ptr: *const c_char = c_str.as_ptr() as *const c_char;
        let args = build_replay_args(path_ptr, &120, &2000, 1, config_path_ptr).unwrap();
        assert_eq!(args.path.to_str().unwrap(), path);
        assert_eq!(args.io_depth, 120);
        assert_eq!(args.max_fds, 2000);
        assert!(args.exit_on_error);
    }

    #[test]
    fn replay_args_no_null_deref() {
        let file = NamedTempFile::new().unwrap();
        let path = file.path().to_str().unwrap();
        let c_str = CString::new(path).unwrap();
        let path_ptr: *const c_char = c_str.as_ptr() as *const c_char;
        let config_path_ptr: *const c_char = c_str.as_ptr() as *const c_char;
        let _args = build_replay_args(null(), &120, &2000, 1, config_path_ptr)
            .expect_err("path i require arg");
        let _args = build_replay_args(path_ptr, null(), &2000, 1, config_path_ptr).unwrap();
        let _args = build_replay_args(path_ptr, &120, null(), 1, config_path_ptr).unwrap();
        let _args = build_replay_args(path_ptr, &120, &2000, 0, config_path_ptr).unwrap();
    }
}
