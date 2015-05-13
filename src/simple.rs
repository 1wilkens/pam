// Copyright (C) 2015 Florian Wilkens
//
// Permission is hereby granted, free of charge, to any person obtaining a copy of this software and
// associated documentation files (the "Software"), to deal in the Software without restriction,
// including without limitation the rights to use, copy, modify, merge, publish, distribute,
// sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all copies or substantial
// portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT
// NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
// NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES
// OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
// CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

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
        ::pam::end(handle, 0);
    }
    false
}
