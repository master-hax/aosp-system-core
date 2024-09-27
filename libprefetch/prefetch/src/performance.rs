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

//! A small utility around prefetch-rs library to evaluate performance of different serde
//! implementations.

use std::time::SystemTime;

use bincode::Bounded;
use rand::{distributions::Alphanumeric, Rng};

use prefetch_rs::FileId;
use prefetch_rs::InodeInfo;
use prefetch_rs::Record;
use prefetch_rs::RecordsFile;

fn generate_filename(len: u32) -> String {
    rand::thread_rng().sample_iter(&Alphanumeric).take(len as usize).map(char::from).collect()
}

// Generates a tests records file for given configuration.
fn generate_records_file(
    file_count: u64,
    filename_length: u32,
    records_per_file: u64,
) -> RecordsFile {
    let mut rf = RecordsFile::default();

    for i in 0..file_count {
        rf.insert_or_update_inode_info(
            FileId(i),
            InodeInfo::new(i, i, vec![generate_filename(filename_length)], 20),
        );
        for _ in 0..records_per_file {
            rf.insert_record(Record {
                file_id: FileId(i),
                offset: 100,
                length: 10000,
                timestamp: SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos() as u64,
            })
        }
    }
    rf
}

fn print_size(file_count: u64, filename_length: u32, records_per_file: u64) {
    let rf = generate_records_file(file_count, filename_length, records_per_file);

    println!(
        "For {} files each containing {} records. (Total records:{}). Each filename length: {}",
        file_count,
        records_per_file,
        file_count * records_per_file,
        filename_length,
    );

    let bincoded: Vec<u8> = bincode::serialize(&rf, Bounded(2 * 1024 * 1024)).unwrap();
    let bnow = {
        let n = std::time::Instant::now();
        let _: RecordsFile = bincode::deserialize(&bincoded).unwrap();
        n.elapsed().as_nanos()
    };
    let jsoned = serde_json::to_string(&rf).unwrap();
    let jnow = {
        let n = std::time::Instant::now();
        let _: RecordsFile = serde_json::from_str(&jsoned).unwrap();
        n.elapsed().as_nanos()
    };
    let cbored = serde_cbor::to_vec(&rf).unwrap();
    let cnow = {
        let n = std::time::Instant::now();
        let _: RecordsFile = serde_cbor::from_slice(&cbored).unwrap();
        n.elapsed().as_nanos()
    };
    println!("bincode    size(bytes): {} time:{}", bincoded.len(), bnow);
    println!("json size(bytes):       {} time:{}", jsoned.as_bytes().len(), jnow,);
    println!("cbor size(bytes):       {} time:{}", cbored.len(), cnow);
}

fn main() {
    print_size(0, 0, 0);
    let ubuntu_boot_files = 2990;
    let ubuntu_file_len = 48;
    let ubuntu_record_per_file: u64 = 2;
    print_size(ubuntu_boot_files, ubuntu_file_len, ubuntu_record_per_file);
}
