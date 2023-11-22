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

use std::clone::Clone;
use std::convert::TryInto;
use std::fmt::Display;
use std::fs::File;
use std::mem::replace;
use std::os::unix::io::AsRawFd;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::RwLock;
use std::thread;

use log::debug;
use log::error;
use log::warn;
use lru_cache::LruCache;
use nix::fcntl::posix_fadvise;
use regex::Regex;

use crate::args::ConfigFile;
use crate::format::FileId;
use crate::format::Record;
use crate::Error;
use crate::RecordsFile;
use crate::ReplayArgs;

macro_rules! replay_log {
    ($msg:expr) => {
        debug!("{}", $msg);
    };
}

struct Dbg<T: Display + Sized> {
    msg: T,
    thd_id: usize,
}

fn get_dbg<T: Display + Sized>(ctx: usize, msg: T) -> Dbg<T> {
    let thd_id = ctx;
    replay_log!(format!("{} {} start", thd_id, msg));
    Dbg { msg, thd_id }
}

impl<T: Display> Drop for Dbg<T> {
    fn drop(&mut self) {
        replay_log!(format!("{} {} end", self.thd_id, self.msg));
    }
}

fn readahead(id: usize, file: Arc<File>, record: &Record) -> Result<(), Error> {
    debug!("readahead {:?}", record);
    let _ = get_dbg(id, "readahead");

    // SAFETY: This is safe because
    // - the file is known to exist
    // - we do not read into a buffer and we check return value
    // - failure to read is not fatal
    let ret = unsafe {
        libc::readahead(
            file.as_raw_fd(),
            record.offset.try_into().unwrap(),
            record.length.try_into().unwrap(),
        )
    };

    if ret < 0 {
        Err(Error::Read { error: format!("readahead failed: {}", nix::errno::errno()) })
    } else {
        Ok(())
    }
}

fn worker_internal(
    id: usize,
    state: Arc<Mutex<SharedState>>,
    records_file: Arc<RwLock<RecordsFile>>,
    exit_on_error: bool,
    exclude_files_regex: Vec<Regex>,
) -> Result<(), Error> {
    loop {
        let index = {
            let mut state = state.lock().unwrap();
            if state.result.is_err() {
                return Ok(());
            }
            state.next_record()
        };

        let record = {
            let rf = records_file.read().unwrap();
            if index >= rf.inner.records.len() {
                return Ok(());
            }
            rf.inner.records.get(index).unwrap().clone()
        };

        let _ = get_dbg(id, "record_replay");

        let file = state.lock().unwrap().fds.get_mut(&record.file_id).map(|f| f.clone());

        let file = if let Some(file) = file {
            file
        } else {
            let file = Arc::new({
                let file = records_file
                    .read()
                    .unwrap()
                    .open_file(record.file_id.clone(), exclude_files_regex.clone());
                if let Err(e) = file {
                    if exit_on_error {
                        return Err(e);
                    } else {
                        match e {
                            Error::SkipPrefetch { path } => {
                                warn!("Skipping file during replay: {}", path);
                            }
                            _ => error!(
                                "Failed to open file id: {} with {}",
                                record.file_id.clone(),
                                e.to_string()
                            ),
                        }
                        continue;
                    }
                }
                let file = file.unwrap();
                // We do not want the filesystem be intelligent and prefetch more than what this
                // code is reading. So turn off prefetch.
                if let Err(e) = posix_fadvise(
                    file.as_raw_fd(),
                    0,
                    0,
                    nix::fcntl::PosixFadviseAdvice::POSIX_FADV_RANDOM,
                ) {
                    warn!(
                        "Failed to turn off filesystem read ahead for file id: {} with {}",
                        record.file_id.clone(),
                        e.to_string()
                    );
                }
                file
            });
            let cache_file = file.clone();
            state.lock().unwrap().fds.insert(record.file_id.clone(), cache_file);
            file
        };
        if let Err(e) = readahead(id, file, &record) {
            if exit_on_error {
                return Err(e);
            } else {
                error!(
                    "readahead failed on file id: {} with: {}",
                    record.file_id.clone(),
                    e.to_string()
                );
                continue;
            }
        }
    }
}

fn worker(
    id: usize,
    state: Arc<Mutex<SharedState>>,
    records_file: Arc<RwLock<RecordsFile>>,
    exit_on_error: bool,
    exclude_files_regex: Vec<Regex>,
) {
    let _ = get_dbg(id, "read_loop");
    let result =
        worker_internal(id, state.clone(), records_file, exit_on_error, exclude_files_regex);
    if result.is_err() {
        error!("worker failed with {:?}", result);
        let mut state = state.lock().unwrap();
        if state.result.is_ok() {
            state.result = result;
        }
    }
}

#[derive(Debug)]
pub struct SharedState {
    fds: LruCache<FileId, Arc<File>>,
    records_index: usize,
    result: Result<(), Error>,
}

impl SharedState {
    fn next_record(&mut self) -> usize {
        let ret = self.records_index;
        self.records_index += 1;
        ret
    }
}

/// Runtime, in-memory, representation of records file structure.
#[derive(Debug)]
pub struct Replay {
    records_file: Arc<RwLock<RecordsFile>>,
    io_depth: u16,
    exit_on_error: bool,
    state: Arc<Mutex<SharedState>>,
    exclude_files_regex: Vec<Regex>,
}

impl Replay {
    /// Creates Replay from input `args`.
    pub fn new(args: &ReplayArgs) -> Result<Self, Error> {
        let _ = get_dbg(1, "new");
        let reader: File = File::open(&args.path).map_err(|source| Error::Open {
            source,
            path: args.path.to_str().unwrap().to_owned(),
        })?;
        let rf: RecordsFile = serde_cbor::from_reader(reader)
            .map_err(|error| Error::Deserialize { error: error.to_string() })?;

        let mut exclude_files_regex: Vec<Regex> = Vec::new();
        // The path to the configuration file is optional in the command.
        // If the path is provided, the configuration file will be read.
        if !&args.config_path.as_os_str().is_empty() {
            let config_reader = File::open(&args.config_path).map_err(|source| Error::Open {
                source,
                path: args.path.to_str().unwrap().to_owned(),
            })?;
            let cf: ConfigFile = serde_json::from_reader(config_reader)
                .map_err(|error| Error::Deserialize { error: error.to_string() })?;

            for file_to_exclude in &cf.files_to_exclude_regex {
                exclude_files_regex.push(Regex::new(file_to_exclude).unwrap());
            }
        }

        Ok(Self {
            records_file: Arc::new(RwLock::new(rf)),
            io_depth: args.io_depth,
            exit_on_error: args.exit_on_error,
            state: Arc::new(Mutex::new(SharedState {
                fds: LruCache::new(args.max_fds.into()),
                records_index: 0,
                result: Ok(()),
            })),
            exclude_files_regex,
        })
    }

    /// Replay records.
    pub fn replay(self) -> Result<(), Error> {
        let _ = get_dbg(1, "replay");
        let mut threads = vec![];
        for i in 0..self.io_depth {
            let i_clone = i as usize;
            let state = self.state.clone();
            let records_file = self.records_file.clone();
            let exit_on_error = self.exit_on_error;
            let exclude_files_regex = self.exclude_files_regex.clone();

            threads.push(thread::Builder::new().spawn(move || {
                worker(i_clone, state, records_file, exit_on_error, exclude_files_regex)
            }));
        }
        for thread in threads {
            thread.unwrap().join().unwrap();
        }
        replace(&mut self.state.lock().unwrap().result, Ok(()))
    }
}

// WARNING: flaky tests.
// In these tests we create files, invalidate their caches and then replay.
// Verify that after reply the same portions of data is in memory.
//
// Since these tests to rely on presence or absence of data in cache, the
// files used by the tests should not be in tmp filesystem. So we use relative
// path as target directory. There is no guarantee that this target directory
// is not on temp filesystem but chances are better than using target directory
// in tempfs.
//
// Tests can be flaky if the system under tests is running low on memory. The
// tests create file using O_DIRECT so that no data is left in file cache.
// Though this is sufficient to avoid caching, but other processes reading these
// files(like anti-virus) or some other system processes might change the state
// of the cache. Or it may happen that the filesystem evicts the file before
// we verify that read ahead worked as intended.
#[cfg(test)]
mod tests {
    use std::{
        assert,
        io::Write,
        ops::Range,
        path::{Path, PathBuf},
        time::Duration,
    };

    use tempfile::NamedTempFile;

    use super::*;
    use crate::{
        tracer::fs::RecordsFileBuilder,
        tracer::{
            page_size,
            tests::{copy_files, generate_test_data_in, setup_test_dir},
        },
    };

    fn rebuild_records_file(files: &[(PathBuf, Vec<Range<u64>>)]) -> RecordsFile {
        // Validate that caches are dropped
        let mut f: RecordsFileBuilder = Default::default();
        for (path, _) in files {
            f.add_file(path.to_str().unwrap());
        }
        f.build().unwrap()
    }

    fn ensure_files_not_cached(files: &mut [(PathBuf, Vec<Range<u64>>)]) {
        assert!(rebuild_records_file(files).inner.records.is_empty());
    }

    fn has_record(records: &[Record], key: &Record) -> bool {
        for r in records {
            if r.offset == key.offset && r.length == key.length {
                return true;
            }
        }
        false
    }

    fn compare_records(old: &[Record], new: &[Record]) {
        for key in new {
            if !has_record(old, key) {
                panic!("Failed to file {:?} in {:?}", key, old);
            }
        }
    }

    fn create_test_config_file(files_to_exclude_regex: Vec<String>) -> String {
        let cfg = ConfigFile { files_to_exclude_regex, ..Default::default() };
        serde_json::to_string(&cfg).unwrap()
    }

    fn test_replay_internal(
        create_symlink: bool,
        exit_on_error: bool,
        inject_error: bool,
        exclude_all_files: bool,
        empty_exclude_file_list: bool,
    ) {
        let page_size = page_size().unwrap() as u64;
        let test_base_dir = setup_test_dir();
        let (rf, mut files) = generate_test_data_in(None, create_symlink, Some(page_size));

        // Here "uncached_files" emulate the files after reboot when none of those files data is in cache.
        let (mut uncached_rf, mut uncached_files) =
            copy_files(Path::new(&test_base_dir), &mut files, &rf);

        // Injects error(s) in the form of invalid filename
        if inject_error {
            if let Some(v) = uncached_rf.inner.inode_map.values_mut().next() {
                for path in &mut v.paths {
                    path.push('-');
                }
            }
        }

        let mut file = NamedTempFile::new().unwrap();
        file.write_all(&uncached_rf.add_checksum_and_serialize().unwrap()).unwrap();
        let mut config_file = NamedTempFile::new().unwrap();

        let mut files_to_exclude: Vec<String> = Vec::new();
        if exclude_all_files {
            // Exclude files from replay by adding them in config
            for v in uncached_rf.inner.inode_map.values_mut() {
                for path in &mut v.paths {
                    files_to_exclude.push(path.to_string())
                }
            }
        } else if empty_exclude_file_list {
            files_to_exclude.extend(vec![]);
        } else {
            files_to_exclude.extend(vec!["file1".to_owned(), "file2".to_owned()]);
        }

        config_file.write_all(create_test_config_file(files_to_exclude).as_bytes()).unwrap();

        ensure_files_not_cached(&mut uncached_files);

        let replay = Replay::new(&ReplayArgs {
            path: file.path().to_owned(),
            io_depth: 15,
            max_fds: 128,
            exit_on_error,
            config_path: config_file.path().to_owned(),
            cpu_priority: None,
            io_priority: None,
        })
        .unwrap();

        let result = replay.replay();
        // Sleep a bit so that readaheads are complete.
        thread::sleep(Duration::from_secs(1));

        if exit_on_error && inject_error {
            result.expect_err("Failure was expected");
        } else if exclude_all_files {
            let new_rf = rebuild_records_file(&uncached_files);
            assert!(new_rf.inner.records.is_empty());
        } else {
            result.unwrap();

            // At this point, we have prefetched data for uncached file bringing same set of
            // data in memory as the original cached files.
            // If we record prefetch data for new files, we should get same records files
            // (offset and lengths) except that the file names should be different.
            // This block verifies it.
            // Note: `new_rf` is for uncached_files. But, [un]fortunately, those "uncached_files"
            // are now cached after we replayed the records.
            let new_rf = rebuild_records_file(&uncached_files);
            assert!(!new_rf.inner.records.is_empty());
            assert_eq!(rf.inner.inode_map.len(), new_rf.inner.inode_map.len());
            assert_eq!(rf.inner.records.len(), new_rf.inner.records.len());
            compare_records(&rf.inner.records, &new_rf.inner.records);
            compare_records(&new_rf.inner.records, &rf.inner.records);
        }
    }

    #[test]
    fn test_replay() {
        test_replay_internal(true, false, false, false, false);
    }

    #[test]
    fn test_replay_strict() {
        test_replay_internal(true, true, false, false, false);
    }

    #[test]
    fn test_replay_no_symlink() {
        test_replay_internal(false, false, false, false, false);
    }

    #[test]
    fn test_replay_no_symlink_strict() {
        test_replay_internal(false, true, false, false, false);
    }

    #[test]
    fn test_replay_fails_on_error() {
        test_replay_internal(true, true, true, false, false);
    }

    #[test]
    fn test_replay_exclude_all_files() {
        test_replay_internal(true, false, false, true, false);
    }

    #[test]
    fn test_replay_empty_exclude_files_list() {
        test_replay_internal(true, false, false, false, true);
    }
}
