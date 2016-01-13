// Copyright 2015-2016 pam-auth Developers
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use std::ffi::CString;

use pam::{PamConversation, PamHandle, PamFlag, PamReturnCode};

/// #[Deprecated]
/// Use Authenticator.authenticate() instead
pub fn login(service: &str, user: &str, password: &str) -> bool {
    use std::ptr;

    let creds: [&str; 2] = [user, password];
    let conv = PamConversation{
        conv: Some(::ffi::converse),
        data_ptr: creds.as_ptr() as *mut ::libc::c_void
    };
    let mut handle: *mut PamHandle = ptr::null_mut();

    let success = PamReturnCode::SUCCESS;
    let mut res = unsafe { ::pam::start(CString::new(service).unwrap().as_ptr(), ptr::null(), &conv, &mut handle) };
    if res != success {
        return pam_fail(handle, "pam_start", res);
    }
    res = unsafe { ::pam::authenticate(handle, PamFlag::NONE) };
    if res != success {
        return pam_fail(handle, "pam_authenticate", res);
    }
    res = unsafe { ::pam::acct_mgmt(handle, PamFlag::NONE) };
    if res != success {
        return pam_fail(handle, "pam_acct_mgmt", res);
    }
    res = unsafe { ::pam::setcred(handle, PamFlag::ESTABLISH_CRED) };
    if res != success {
        return pam_fail(handle, "pam_setcred", res);
    }
    res = unsafe { ::pam::open_session(handle, PamFlag::NONE) };
    if res != success {
        return pam_fail(handle, "pam_open_session", res);
    }
    true
}

fn pam_fail(handle: *mut PamHandle, func: &str, res: PamReturnCode) -> bool {
    println!("{} returned: {:?}", func, res);
    unsafe {
        ::pam::setcred(handle, PamFlag::DELETE_CRED);
        ::pam::end(handle, PamReturnCode::SUCCESS);
    }
    false
}
