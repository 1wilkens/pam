#![feature(core)]

extern crate libc;

extern crate "pam-sys" as ffi;

use libc::{c_char, c_int, c_void};

use std::ptr;
use std::ffi::{CString};

pub struct PamAuth {
    pub conv: *mut ffi::PamConv,
    pub handle: *mut ffi::PamHandle
}

impl PamAuth {
    pub fn new(service: &String) -> Option<PamAuth> {
        let srvc = CString::new(service.as_slice()).unwrap();
        let user = CString::new("login".as_slice()).unwrap();
        let mut conv = ffi::PamConv{
            conv: ptr::null(),
            data_ptr: 0 as *mut c_void
        };
        let mut handle: *const ffi::PamHandle = ptr::null();
        let res = unsafe {
            ffi::pam_start(srvc.as_ptr(), user.as_ptr(), &conv, &mut handle)
        };

        println!("res: {}", res);
        match res {
            0 => Some(PamAuth {
                conv: &mut conv,
                handle: handle as *mut ffi::PamHandle
            }),
            _ => None
        }
    }
}

impl Drop for PamAuth {
    fn drop(&mut self) {
        let status: c_int = 0;
        unsafe {
            ffi::pam_end(self.handle, status);
        }
        println!("Dropped PamAuth with status: {}", status);
    }
}

#[test]
fn test() {
    use std::io;

    let service = "rdm".to_string();
    let pa = match PamAuth::new(&service) {
        Some(a) => a,
        None    => panic!("failed to get PamAuth")
    };
    let mut user = String::new();
    match io::stdin().read_line(&mut user) {
        Ok(_)   => println!("Got user: {}", user),
        Err(_)  => panic!("Failed to get user!")
    };
    let mut pw = String::new();
    match io::stdin().read_line(&mut pw) {
        Ok(_)   => println!("Got pw: {}", pw),
        Err(_)  => panic!("Failed to get pw!")
    };
}
