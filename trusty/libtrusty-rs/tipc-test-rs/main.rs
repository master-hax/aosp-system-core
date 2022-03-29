//! Utility for testing libtrusty-rs.

use rand::Rng;
use std::str;
use structopt::StructOpt;
use trusty::{TipcChannel, DEFAULT_DEVICE};

const ECHO_NAME: &str = "com.android.ipc-unittest.srv.echo";

fn main() {
    let opt = Opt::from_args();

    for test in &opt.tests {
        match test.as_str() {
            "echo" => run_echo(&opt),

            _ => todo!("Implement test for {:?}", test),
        }
    }
}

fn run_echo(opt: &Opt) {
    let mut connection = TipcChannel::connect(DEFAULT_DEVICE, ECHO_NAME)
        .expect("Failed to connect to Trusty service");

    for _ in 0..opt.repeat {
        // Determine the length of the message to send. If the user selected
        // variable-length messages we generate a random length for each attempt.
        let msg_len = if opt.variable {
            rand::thread_rng().gen_range(0..opt.max_message_size)
        } else {
            opt.max_message_size
        };

        // Generate a message with random contents and send the message to the TA.
        let mut send_buf = vec![0u8; msg_len];
        rand::thread_rng().fill(send_buf.as_mut_slice());
        connection.send(send_buf.as_slice()).unwrap();

        // Receive the response message from the TA.
        let mut recv_buf = vec![0u8; 8];
        let read_len = connection.recv(&mut recv_buf[..]).expect("Failed to read from connection");

        assert_eq!(
            msg_len, read_len,
            "Received data was wrong size (expected {} bytes, received {})",
            msg_len, read_len
        );
        assert_eq!(send_buf, recv_buf, "Received data does not match sent data");
    }

    println!("echo test: {} attempts passed", opt.repeat);
}

#[derive(Debug, StructOpt)]
struct Opt {
    #[structopt(long = "test", short, required(true))]
    tests: Vec<String>,

    #[structopt(long, short, default_value = "1")]
    repeat: usize,

    #[structopt(long = "msgsize", short, default_value = "32")]
    max_message_size: usize,

    #[structopt(long, short)]
    variable: bool,
}
