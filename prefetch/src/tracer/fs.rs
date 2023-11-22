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

//! See top level documentation for `crate::tracer`.

use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::num::NonZeroUsize;
use std::os::unix::fs::MetadataExt;
use std::os::fd::FromRawFd;
use std::os::{raw::c_void, unix::io::AsRawFd};
use std::path::{Path, PathBuf};

use log::{debug, error};
use nix::sys::mman::ProtFlags;
use nix::{errno::errno, sys::mman::MapFlags};
use serde::Deserialize;
use serde::Serialize;

use crate::format::{DeviceNumber, FileId, FsInfo, InodeNumber, RecordsFile};
use crate::tracer::{
    nanoseconds_since_boot, page_size, TraceSubsystem, TracerConfigs, EXCLUDE_PATHS,
};
use crate::{error::Error, format::Record};

// Operation that can be traced.
static INCLUDE_OPERATIONS: &[&str] = &["do_sys_open", "open_exec", "uselib"];

// Trace events to enable
// Paths are relative to trace mount point
static TRACE_EVENTS: &[&str] = &[
    "events/fs/do_sys_open/enable",
    "events/fs/open_exec/enable",
    "events/fs/uselib/enable",
    "tracing_on",
];

#[derive(Debug, Default, Deserialize, Serialize)]
pub struct RecordsFileBuilder {
    // Temporarily holds paths of all files opened by other processes.
    pub(crate) paths: HashMap<String, FileId>,

    // Read inode numbers
    inode_numbers: HashMap<(DeviceNumber, InodeNumber), FileId>,
}

impl RecordsFileBuilder {
    pub fn add_file(&mut self, path: &str) {
        if self.paths.contains_key(path) {
            return;
        }

        self.paths.insert(path.to_owned(), FileId(self.paths.len() as u64));
    }

    pub fn build(&mut self) -> Result<RecordsFile, Error> {
        let mut rf = RecordsFile::default();
        for (path, mut id) in self.paths.drain() {
            let stat = Path::new(&path)
                .metadata()
                .map_err(|source| Error::Stat { source, path: path.clone() })?;

            rf.inner.filesystems.entry(stat.dev()).or_insert(FsInfo { block_size: stat.blksize() });

            if let Some(orig_id) = self.inode_numbers.get(&(stat.dev(), stat.ino())) {
                let inode = rf.inner.inode_map.get_mut(orig_id).unwrap();
                inode.paths.push(path.clone());

                // There may be multiple paths for the file so from those path we may have multiple
                // ids. Override the id.
                id = orig_id.clone();
            } else {
                self.inode_numbers.insert((stat.dev(), stat.ino()), id.clone());
                rf.insert_or_update_inode(id.clone(), &stat, path.clone());
            }
            if let Some(mmap) = Mmap::create(&path, id)? {
                mmap.get_records(&mut rf.inner.records)?;
            }
        }
        Ok(rf)
    }
}

fn parse_line(line: &str) -> Result<Option<(String, PathBuf)>, Error> {
    let start = match line.find('"') {
        Some(start) => start,
        None => return Ok(None),
    };
    let end = match line.rfind('"') {
        Some(end) => end,
        None => return Ok(None),
    };
    if start == end || (start + 1 == end - 1) {
        return Ok(None);
    }
    let path = &line[start + 1..end];
    let operation = line.split_whitespace().nth(4);
    if let Some(operation) = operation {
        Ok(Some((operation[..operation.len() - 1].to_owned(), PathBuf::from(path.to_owned()))))
    } else {
        Ok(None)
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub(crate) struct FsTraceSubsystem {
    builder: RecordsFileBuilder,
    configs: TracerConfigs,
}

impl FsTraceSubsystem {
    pub fn update_configs(configs: &mut TracerConfigs) {
        for path in EXCLUDE_PATHS {
            configs.excluded_paths.push(path.to_owned().to_string());
        }

        for event in TRACE_EVENTS {
            configs.trace_events.push(event.to_owned().to_string());
        }

        for op in INCLUDE_OPERATIONS {
            configs.trace_operations.insert(op.to_owned().to_string());
        }
    }

    pub fn create_with_configs(configs: TracerConfigs) -> Result<Self, Error> {
        Ok(Self { builder: RecordsFileBuilder::default(), configs })
    }

    fn get_path(&self, line: &str) -> Result<Option<String>, Error> {
        if let Some((operation, path)) = parse_line(line)? {
            if path.is_relative() {
                return Ok(None);
            }

            if !self.configs.trace_operations.contains(&operation) {
                return Ok(None);
            }

            for excluded in &self.configs.excluded_paths {
                if path.to_str().unwrap().starts_with(excluded) {
                    return Ok(None);
                }
            }
            return Ok(Some(path.to_str().unwrap().to_owned()));
        }
        Ok(None)
    }
}

impl TraceSubsystem for FsTraceSubsystem {
    fn add_line(&mut self, line: &str) -> Result<(), Error> {
        if let Some(path) = self.get_path(line)? {
            self.builder.add_file(&path);
        }

        Ok(())
    }

    fn build_records_file(&mut self) -> Result<RecordsFile, Error> {
        self.builder.build()
    }

    fn serialize(&self, write: &mut dyn Write) -> Result<(), Error> {
        write
            .write_all(
                &serde_json::to_vec(&self)
                    .map_err(|e| Error::Serialize { error: e.to_string() })?,
            )
            .map_err(|source| Error::Write { path: "intermediate file".to_owned(), source })
    }
}

#[derive(Debug)]
pub(crate) struct Mmap {
    map_addr: *mut c_void,
    length: usize,
    #[allow(dead_code)]
    file: File,
    file_id: FileId,
}

impl Mmap {
    pub fn create(path: &str, file_id: FileId) -> Result<Option<Self>, Error> {
        let file = OpenOptions::new()
            .read(true)
            .write(false)
            .open(path)
            .map_err(|source| Error::Open { source, path: path.to_owned() })?;

        let length =
            file.metadata().map_err(|source| Error::Stat { source, path: path.to_owned() })?.len()
                as usize;

        if length == 0 {
            return Ok(None);
        }

        // SAFETY: This is safe because
        // - the file is known to exist and opened
        // - we check the return value
        // - failure to touch the page is not fatal
        let map_addr = unsafe {
            nix::sys::mman::mmap(
                None,
                NonZeroUsize::new(length).unwrap(),
                ProtFlags::PROT_READ,
                MapFlags::MAP_SHARED,
                Some(File::from_raw_fd(file.as_raw_fd())),
                0,
            )
            .map_err(|source| Error::Mmap { error: source.to_string(), path: path.to_owned() })?
        };

        Ok(Some(Self { map_addr, length, file, file_id }))
    }

    pub(crate) fn get_records(&self, records: &mut Vec<Record>) -> Result<(), Error> {
        let page_size = page_size()?;
        let page_count = (self.length + page_size - 1) / page_size;
        let mut buf: Vec<u8> = vec![0_u8; page_count];
        // SAFETY: This is safe because
        // - the file is mapped
        // - we check the return value
        // - failure to get information about the page, within which given record's offset and
        //   length fall, is not fatal.
        let ret = unsafe { libc::mincore(self.map_addr, self.length, buf.as_mut_ptr()) };
        if ret < 0 {
            return Err(Error::Custom {
                error: format!("failed to query resident pages: {}", errno()),
            });
        }
        let mut i = 0;

        let mut offset_length: Option<(u64, u64)> = None;
        for (index, resident) in buf.iter().enumerate() {
            if *resident != 0 {
                if let Some((_, length)) = &mut offset_length {
                    *length += page_size as u64;
                } else {
                    offset_length = Some((index as u64 * page_size as u64, page_size as u64));
                }
            } else if let Some((offset, length)) = offset_length {
                i += 1;
                records.push(Record {
                    file_id: self.file_id.clone(),
                    offset,
                    length,
                    timestamp: nanoseconds_since_boot(),
                });

                offset_length = None;
            }
        }

        if let Some((offset, length)) = offset_length {
            i += 1;
            records.push(Record {
                file_id: self.file_id.clone(),
                offset,
                length,
                timestamp: nanoseconds_since_boot(),
            });
        }
        debug!("records found: {} for {:?}", i, self);

        Ok(())
    }
}

impl Drop for Mmap {
    fn drop(&mut self) {
        // SAFETY: This is safe because
        // - the file is mapped
        // - we check the return value
        // - failure to munmap the page is not fatal
        let ret = unsafe { nix::sys::mman::munmap(self.map_addr, self.length) };
        if let Err(e) = ret {
            error!("failed to munmap {:p} {} with {}", self.map_addr, self.length, e.to_string());
        }
    }
}

#[cfg(test)]
pub mod tests {
    use std::{
        fs::metadata,
        io::Write,
        ops::Range,
        os::{unix::fs::symlink, unix::io::AsRawFd},
        path::Path,
    };

    use nix::sys::uio::pwrite;
    use tempfile::NamedTempFile;

    use crate::{tracer::tests::generate_test_data, InodeInfo};

    use super::*;

    #[test]
    fn test_add_file() {
        let mut f: RecordsFileBuilder = Default::default();
        f.add_file("hello");
        f.add_file("world");
        assert!(f.paths.get("hello").unwrap() < f.paths.get("world").unwrap());
    }

    #[test]
    fn test_add_file_duplicate() {
        let mut f: RecordsFileBuilder = Default::default();
        f.add_file("hello");
        let id1 = f.paths.get("hello").unwrap().clone();
        f.add_file("world");
        f.add_file("hello");
        let id2 = f.paths.get("hello").unwrap().clone();
        assert_eq!(id1, id2);
        assert!(f.paths.get("hello").unwrap() < f.paths.get("world").unwrap());
    }

    fn compare_inode_info(info: &InodeInfo, path: &Path) {
        let stat = metadata(path).unwrap();
        assert_eq!(info.device_number, stat.dev());
        assert_eq!(info.file_size, stat.size());
        assert_eq!(info.inode_number, stat.ino());
    }

    static MB: u64 = 1024 * 1024;
    static KB: u64 = 1024;

    fn random_write(file: &mut NamedTempFile, base: u64) -> Range<u64> {
        let start: u64 = base + (rand::random::<u64>() % (base / 2)) as u64;
        let len: u64 = rand::random::<u64>() % (32 * KB);
        let buf = vec![5; len as usize];
        nix::sys::uio::pwrite(file.as_raw_fd(), &buf, start as i64).unwrap();
        start..(start + len)
    }

    pub(crate) fn create_file(
        path: Option<&Path>,
        align: Option<u64>,
    ) -> (NamedTempFile, Vec<Range<u64>>) {
        let mut file = if let Some(path) = path {
            NamedTempFile::new_in(path).unwrap()
        } else {
            NamedTempFile::new().unwrap()
        };
        let range1 = random_write(&mut file, 32 * KB);
        let range2 = random_write(&mut file, 128 * KB);
        let range3 = random_write(&mut file, 4 * MB);
        if let Some(align) = align {
            let orig_size = file.metadata().unwrap().len();
            let aligned_size = orig_size + (align - (orig_size % align));
            file.set_len(aligned_size).unwrap();
        }
        (file, vec![range1, range2, range3])
    }

    #[test]
    fn test_build() {
        let file1_size = 10;
        let file2_size = 20;
        let file1 = NamedTempFile::new().unwrap();
        let file2 = NamedTempFile::new().unwrap();
        file1.set_len(file1_size).unwrap();
        file2.set_len(file2_size).unwrap();

        let mut f: RecordsFileBuilder = Default::default();
        f.add_file(file1.path().to_str().unwrap());
        f.add_file(file2.path().to_str().unwrap());
        let rf = f.build().unwrap();

        assert_eq!(rf.inner.inode_map.len(), 2);
        assert_eq!(rf.inner.filesystems.len(), 1);
        for info in rf.inner.inode_map.values() {
            compare_inode_info(
                info,
                if info.paths.get(0).unwrap() == file1.path().to_str().unwrap() {
                    file1.path()
                } else {
                    file2.path()
                },
            );
        }
    }

    #[test]
    fn test_build_with_duplicate() {
        let file1_size = 10;
        let file2_size = 20;
        let file1 = NamedTempFile::new().unwrap();
        let file2 = NamedTempFile::new().unwrap();
        file1.set_len(file1_size).unwrap();
        file2.set_len(file2_size).unwrap();

        let mut f: RecordsFileBuilder = Default::default();
        f.add_file(file1.path().to_str().unwrap());
        f.add_file(file2.path().to_str().unwrap());
        f.add_file(file1.path().to_str().unwrap());
        let rf = f.build().unwrap();

        assert_eq!(rf.inner.inode_map.len(), 2);
        assert_eq!(rf.inner.filesystems.len(), 1);
        for info in rf.inner.inode_map.values() {
            compare_inode_info(
                info,
                if info.paths.get(0).unwrap() == file1.path().to_str().unwrap() {
                    file1.path()
                } else {
                    file2.path()
                },
            );
        }
    }

    #[test]
    fn test_build_with_link() {
        let file1_size = 10;
        let file2_size = 20;
        let file1 = NamedTempFile::new().unwrap();
        let file2 = NamedTempFile::new().unwrap();
        file1.set_len(file1_size).unwrap();
        file2.set_len(file2_size).unwrap();
        let symlink_path = format!("{}-symlink", file1.path().to_str().unwrap());
        symlink(file1.path(), &symlink_path).unwrap();

        let mut f: RecordsFileBuilder = Default::default();
        f.add_file(file1.path().to_str().unwrap());
        f.add_file(file2.path().to_str().unwrap());
        f.add_file(&symlink_path);
        let rf = f.build().unwrap();

        assert_eq!(rf.inner.inode_map.len(), 2);
        assert_eq!(rf.inner.filesystems.len(), 1);
        for info in rf.inner.inode_map.values() {
            compare_inode_info(
                info,
                if info.paths.get(0).unwrap() == file2.path().to_str().unwrap() {
                    assert_eq!(info.paths.len(), 1);
                    file2.path()
                } else {
                    assert_eq!(info.paths.len(), 2);
                    assert!(
                        info.paths.get(0).unwrap() == file1.path().to_str().unwrap()
                            || info.paths.get(0).unwrap() == &symlink_path
                    );
                    assert!(
                        info.paths.get(1).unwrap() == file1.path().to_str().unwrap()
                            || info.paths.get(1).unwrap() == &symlink_path
                    );
                    file1.path()
                },
            );
        }
    }

    #[test]
    fn test_open_file_opens_right_file() {
        let file1_size = 10;
        let file2_size = 20;
        let file1 = NamedTempFile::new().unwrap();
        let file2 = NamedTempFile::new().unwrap();
        file1.set_len(file1_size).unwrap();
        file2.set_len(file2_size).unwrap();
        let symlink_path = format!("{}-symlink", file1.path().to_str().unwrap());
        symlink(file1.path(), &symlink_path).unwrap();

        let mut f: RecordsFileBuilder = Default::default();
        f.add_file(file1.path().to_str().unwrap());
        f.add_file(file2.path().to_str().unwrap());
        f.add_file(&symlink_path);
        let rf = f.build().unwrap();

        for open_file_id in rf.inner.inode_map.keys() {
            let inode = rf.inner.inode_map.get(open_file_id).unwrap();
            let file = rf.open_file(open_file_id.clone(), Vec::new()).unwrap();
            let open_metadata = file.metadata().unwrap();
            assert_eq!(open_metadata.size(), inode.file_size);
            assert_eq!(open_metadata.ino(), inode.inode_number);
            assert_eq!(open_metadata.dev(), inode.device_number);
        }
    }

    #[test]
    fn deserialize_serialized() {
        let file1_size = 10;
        let file2_size = 20;
        let file1 = NamedTempFile::new().unwrap();
        let file2 = NamedTempFile::new().unwrap();
        file1.set_len(file1_size).unwrap();
        file2.set_len(file2_size).unwrap();
        let symlink_path = format!("{}-symlink", file1.path().to_str().unwrap());
        symlink(file1.path(), &symlink_path).unwrap();

        let mut f: RecordsFileBuilder = Default::default();
        f.add_file(file1.path().to_str().unwrap());
        f.add_file(file2.path().to_str().unwrap());
        f.add_file(&symlink_path);
        let mut rf = f.build().unwrap();
        for file_id in rf.inner.inode_map.keys() {
            rf.inner.records.push(Record {
                file_id: file_id.clone(),
                offset: 0,
                length: 10,
                timestamp: 10,
            });
        }
        let serialized = rf.add_checksum_and_serialize().unwrap();
        let deserialized: RecordsFile = serde_cbor::from_slice(&serialized).unwrap();

        assert_eq!(rf, deserialized);
    }

    #[test]
    fn mmap_page_aligned() {
        let (_rf, mut files) = generate_test_data();
        let page_size = page_size().unwrap() as u64;
        assert!(page_size != 0);
        let (file, _ranges) = files.get_mut(0).unwrap();

        // Set the file size to align to page_size by rounding file size up.
        file.set_len(((file.metadata().unwrap().len() + page_size - 1) / page_size) * page_size)
            .unwrap();

        let _mmap = Mmap::create(file.path().to_str().unwrap(), FileId(1)).unwrap().unwrap();
    }

    #[test]
    fn mmap_page_unaligned() {
        let (_rf, mut files) = generate_test_data();
        let page_size =
            nix::unistd::sysconf(nix::unistd::SysconfVar::PAGE_SIZE).unwrap().unwrap() as u64;
        assert!(page_size != 0);
        let (file, _ranges) = files.get_mut(0).unwrap();
        file.set_len(
            (((file.metadata().unwrap().len() + page_size - 1) / page_size) * page_size) + 10,
        )
        .unwrap();

        let _mmap = Mmap::create(file.path().to_str().unwrap(), FileId(1)).unwrap().unwrap();
    }

    fn overlaps(ranges: &[Range<u64>], range: Range<u64>) -> bool {
        for r in ranges {
            if r.start <= range.end && range.start <= r.end {
                return true;
            }
        }
        false
    }

    #[test]
    fn get_ranges() {
        let (_rf, files) = generate_test_data();

        for (tmp_file, ranges) in &files {
            let mmap = Mmap::create(tmp_file.path().to_str().unwrap(), FileId(1)).unwrap().unwrap();

            let mut records = vec![];
            mmap.get_records(&mut records).unwrap();
            assert!(!records.is_empty());

            // In test environment, we cannot guarantee that only part of the page that we
            // accessed will be in memory. So we try to match the parts of the file we prefetched.
            for record in &records {
                assert!(overlaps(ranges, record.offset..record.offset + record.length));
            }
        }
    }

    #[test]
    fn records_coalesced() {
        let mut file = NamedTempFile::new().unwrap();
        let page_size = page_size().unwrap();
        let buf = vec![5; page_size * 5];
        pwrite(file.as_raw_fd(), &buf, 0_i64).unwrap();
        pwrite(file.as_raw_fd(), &buf, page_size as i64 * 5).unwrap();
        file.flush().unwrap();

        let mmap = Mmap::create(file.path().to_str().unwrap(), FileId(1)).unwrap().unwrap();
        let mut records = vec![];
        mmap.get_records(&mut records).unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records.first().unwrap().offset, 0);
        assert_eq!(records.first().unwrap().length, page_size as u64 * 10);
    }

    #[test]
    fn records_non_coalesced() {
        let mut file = NamedTempFile::new().unwrap();
        let page_size = page_size().unwrap();
        let buf = vec![5; page_size * 5];
        pwrite(file.as_raw_fd(), &buf, 0_i64).unwrap();
        pwrite(file.as_raw_fd(), &buf, page_size as i64 * 10).unwrap();
        file.flush().unwrap();

        let mmap = Mmap::create(file.path().to_str().unwrap(), FileId(1)).unwrap().unwrap();
        let mut records = vec![];
        mmap.get_records(&mut records).unwrap();
        assert_eq!(records.len(), 2);
        assert_eq!(records.first().unwrap().offset, 0);
        assert_eq!(records.first().unwrap().length, page_size as u64 * 5);
        assert_eq!(records.get(1).unwrap().offset, page_size as u64 * 10);
        assert_eq!(records.get(1).unwrap().length, page_size as u64 * 5);
    }

    pub(crate) fn sample_fs_traces() -> (String, Vec<String>, Vec<String>) {
        let raw_buffer =
            r#"             cat-2903    [000] .N..   134.837023: open_exec: "/system/bin/cat"
    cat-2903    [000] ....   134.837064: open_exec: "/system/bin/linker64"
    cat-2903    [000] ....   134.837800: do_sys_open: "/dev/null" 8002 0
    cat-2903    [000] ....   134.837853: do_sys_open: "/dev/__prop/property_info" a8000 0
    cat-2903    [000] ....   134.837883: do_sys_open: "/dev/__prop/properties_serial" a8000 0
    cat-2903    [000] ....   134.837910: do_sys_open: "/home/__prop/u:object_r:build:s0" a8000 0
    cat-2903    [000] ....   134.837924: do_sys_open: "/dev/__prop/u:object_r:debug:s0" a8000 0
    cat-2903    [000] ....   134.838026: sys_enter: "/linkerconfig/ld.config.txt" a8000 0
    cat-2903    [000] ....   134.838397: do_sys_open: "/system/bin" 280000 0
    cat-2903    [000] ....   134.839103: do_sys_open: "/dev/__prop/u:object_r:vndk:s0" a8000 0
    cat-2903    [000] ....   134.839143: do_sys_open: "/apex/com.android.vndk.v32/lib64" 280000 0
    cat-2903    [000] ....   134.839223: do_sys_open: "/vendor/lib64" 280000 0
    cat-2903    [000] ....   134.839258: do_sys_open: "/apex/com.android.tethering/lib64" 280000 0
    cat-2903    [000] ....   134.839277: do_sys_open: "/sys/com.android.runtime/lib64" 280000 0
    cat-2903    [000] ....   134.839298: do_sys_open: "/apex/com.android.art/lib64" 280000 0
    cat-2903    [000] ....   134.839319: do_sys_open: "/apex/com.android.resolv/lib64" 280000 0
    cat-2903    [000] ....   134.839338: do_sys_open: "/proc/com.android.media/lib64" 280000 0
    cat-2903    [000] ....   134.839378: do_sys_open: "/apex/com.android.conscrypt/lib64" 280000 0
    cat-2903    [000] ....   134.839399: do_sys_open: "/run/lib64/egl" 280000 0
    cat-2903    [000] ....   134.839420: do_sys_open: "/vendor/lib64/hw" 280000 0
"#
            .to_owned();

        let operations = vec![
            "open_exec".to_owned(),
            "open_exec".to_owned(),
            "do_sys_open".to_owned(),
            "do_sys_open".to_owned(),
            "do_sys_open".to_owned(),
            "do_sys_open".to_owned(),
            "do_sys_open".to_owned(),
            "sys_enter".to_owned(),
            "do_sys_open".to_owned(),
            "do_sys_open".to_owned(),
            "do_sys_open".to_owned(),
            "do_sys_open".to_owned(),
            "do_sys_open".to_owned(),
            "do_sys_open".to_owned(),
            "do_sys_open".to_owned(),
            "do_sys_open".to_owned(),
            "do_sys_open".to_owned(),
            "do_sys_open".to_owned(),
            "do_sys_open".to_owned(),
            "do_sys_open".to_owned(),
        ];

        let files = vec![
            "/system/bin/cat".to_owned(),
            "/system/bin/linker64".to_owned(),
            "/dev/null".to_owned(),
            "/dev/__prop/property_info".to_owned(),
            "/dev/__prop/properties_serial".to_owned(),
            "/home/__prop/u:object_r:build:s0".to_owned(),
            "/dev/__prop/u:object_r:debug:s0".to_owned(),
            "/linkerconfig/ld.config.txt".to_owned(),
            "/system/bin".to_owned(),
            "/dev/__prop/u:object_r:vndk:s0".to_owned(),
            "/apex/com.android.vndk.v32/lib64".to_owned(),
            "/vendor/lib64".to_owned(),
            "/apex/com.android.tethering/lib64".to_owned(),
            "/sys/com.android.runtime/lib64".to_owned(),
            "/apex/com.android.art/lib64".to_owned(),
            "/apex/com.android.resolv/lib64".to_owned(),
            "/proc/com.android.media/lib64".to_owned(),
            "/apex/com.android.conscrypt/lib64".to_owned(),
            "/run/lib64/egl".to_owned(),
            "/vendor/lib64/hw".to_owned(),
        ];
        (raw_buffer, operations, files)
    }

    #[test]
    fn test_parse_line() {
        let (buf, ops, paths) = sample_fs_traces();
        for (index, line) in buf.lines().enumerate() {
            let (op, path) = parse_line(line).unwrap().unwrap();
            assert_eq!(&op, ops.get(index).unwrap());
            assert_eq!(path.to_str().unwrap(), paths.get(index).unwrap());
        }
    }
}
