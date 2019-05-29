use libc::{c_char, free};
use pam_sys::{getenvlist, raw, PamHandle};

use core::iter::FusedIterator;
use std::ffi::CStr;

pub struct PamEnvList {
    ptr: *const *const c_char,
}

pub struct PamEnvIter<'a> {
    envs: &'a PamEnvList,
    idx: isize,
    ended: bool,
}

pub(crate) fn get_pam_env(handle: &mut PamHandle) -> Option<PamEnvList> {
    let env = getenvlist(handle);
    if !env.is_null() {
        Some(PamEnvList { ptr: env })
    } else {
        None
    }
}

impl PamEnvList {
    pub fn iter(&self) -> PamEnvIter {
        PamEnvIter {
            envs: self,
            idx: 0,
            ended: false,
        }
    }

    pub fn as_ptr(&self) -> *const *const c_char {
        self.ptr
    }
}

impl<'a> Iterator for PamEnvIter<'a> {
    type Item = &'a CStr;

    fn next(&mut self) -> Option<&'a CStr> {
        if self.ended {
            return None;
        }

        let env_ptr = unsafe { self.envs.ptr.offset(self.idx) };
        self.idx += 1;

        if env_ptr.is_null() || unsafe { (*env_ptr).is_null() } {
            self.ended = true;
            None
        } else {
            Some(unsafe { CStr::from_ptr(*env_ptr) })
        }
    }
}

impl FusedIterator for PamEnvIter<'_> {}

#[cfg(target_os = "linux")]
impl Drop for PamEnvList {
    fn drop(&mut self) {
        unsafe { raw::pam_misc_drop_env(self.ptr as *mut *mut c_char) };
    }
}

#[cfg(not(target_os = "linux"))]
impl Drop for PamEnvList {
    fn drop(&mut self) {
        let mut ptr = self.ptr;
        while !ptr.is_null() {
            unsafe { free(ptr) };
            ptr = ptr.add(1);
        }
        unsafe { free(self.ptr) };
    }
}
