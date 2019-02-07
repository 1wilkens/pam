// Copyright 2015-2019 pam-auth Developers
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use libc::c_void;
use pam::{PamConversation, PamFlag, PamHandle, PamReturnCode};

use std::ptr;

use crate::ffi::converse;

/// #[Deprecated]
/// Use Authenticator.authenticate() instead
pub fn login(service: &str, user: &str, password: &str) -> bool {
    let creds: [&str; 2] = [user, password];
    let conv = PamConversation {
        conv: Some(converse),
        data_ptr: creds.as_ptr() as *mut c_void,
    };
    let mut handle: *mut PamHandle = ptr::null_mut();

    let success = PamReturnCode::SUCCESS;
    let mut res = pam::start(service, None, &conv, &mut handle);
    if res != success {
        return false;
    }
    let handle: &mut PamHandle = unsafe { &mut *handle };
    res = pam::authenticate(handle, PamFlag::NONE);
    if res != success {
        return pam_fail(handle);
    }
    res = pam::acct_mgmt(handle, PamFlag::NONE);
    if res != success {
        return pam_fail(handle);
    }
    res = pam::setcred(handle, PamFlag::ESTABLISH_CRED);
    if res != success {
        return pam_fail(handle);
    }
    res = pam::open_session(handle, PamFlag::NONE);
    if res != success {
        return pam_fail(handle);
    }
    true
}

fn pam_fail(handle: &mut PamHandle) -> bool {
    pam::setcred(handle, PamFlag::DELETE_CRED);
    pam::end(handle, PamReturnCode::SUCCESS);
    false
}
