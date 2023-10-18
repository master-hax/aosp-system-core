//! A crate for Trusty binder.
use binder::{
    self, /*FromIBinder,SpIBinder, StatusCode, Strong,*/ unstable_api::new_spibinder,
    SpIBinder,
};
use binder_ndk_sys::AIBinder;
use libc::c_char;
use std::ffi::CString;
use std::io::Result;

extern "C" {
    fn rpc_trusty_connect(device: *const c_char, port: *const c_char) -> *mut AIBinder;
}

/// Does something
pub fn connect_rpc_server(device: &str, port: &str) -> Result<SpIBinder> {
    //pub fn connect_rpc_server<T: binder::FromIBinder>(device: &str, port: &str) -> binder::Strong<T> {
    let port_name = CString::new(port).expect("Port name contained null bytes");
    let device_name = CString::new(device).expect("Device name contained null bytes");
    // SAFETY: tbd
    let binder =
        unsafe { new_spibinder(rpc_trusty_connect(device_name.as_ptr(), port_name.as_ptr())) };
    //<*mut binder_ndk_sys::AIBinder as std::convert::Into<T>>::into(binder.unwrap())
    Ok(binder.unwrap())
}
