//! Utility for testing libtrusty-rs.

use std::io::prelude::*;
use std::str;
use structopt::StructOpt;
use trusty::{TipcStream, DEFAULT_DEVICE};

const ECHO_NAME: &str = "com.android.ipc-unittest.srv.echo";

fn main() {
    let opt = Opt::from_args();

    for test in opt.tests {
        match test.as_str() {
            "echo" => run_echo(),

            _ => todo!("Implement test for {:?}", test),
        }
    }
}

fn run_echo() {
    let mut connection = TipcStream::connect(DEFAULT_DEVICE, ECHO_NAME)
        .expect("Failed to connect to Trusty service");

    write!(connection, "Hello, world?").expect("Failed to write to connection");

    let mut read_buf = [0u8; 1024];
    let read_len = connection
        .read(&mut read_buf[..])
        .expect("Failed to read from connection");

    match str::from_utf8(&read_buf[..read_len]) {
        Ok(msg) => println!("Service responded with {:?}", msg),
        Err(_) => println!("Service responded with {} non-utf8 bytes", read_len),
    }
}

#[derive(Debug, StructOpt)]
struct Opt {
    #[structopt(long = "test", short, required(true))]
    tests: Vec<String>,
}
