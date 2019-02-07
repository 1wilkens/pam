// Copyright 2017-2019 pam-auth Developers
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use libc::c_char;
use pam::{self, PamHandle};

use std::ffi::CStr;

pub struct PamEnvList {
    ptr: *const *const c_char,
}

pub fn get_pam_env(handle: &mut PamHandle) -> Option<PamEnvList> {
    let env = pam::getenvlist(handle);
    if !env.is_null() {
        Some(PamEnvList { ptr: env })
    } else {
        None
    }
}

impl PamEnvList {
    pub fn to_vec(&mut self) -> Vec<(String, String)> {
        let mut vec = Vec::new();

        let mut idx = 0;
        loop {
            let env_ptr: *const *const c_char = unsafe { self.ptr.offset(idx) };
            if unsafe { !(*env_ptr).is_null() } {
                idx += 1;

                let env = unsafe { CStr::from_ptr(*env_ptr) }.to_string_lossy();
                let split: Vec<_> = env.splitn(2, '=').collect();

                if split.len() == 2 {
                    // Only add valid env vars (contain at least one '=')
                    vec.push((split[0].into(), split[1].into()));
                }
            } else {
                // Reached the end of the env array -> break out of the loop
                break;
            }
        }

        vec
    }
}

#[cfg(target_os = "linux")]
impl Drop for PamEnvList {
    fn drop(&mut self) {
        unsafe { pam::raw::pam_misc_drop_env(self.ptr as *mut *mut c_char) };
    }
}
