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

// Crate dependencies
extern crate libc;
extern crate pam_sys as pam;
extern crate users;

// Modules
mod ffi;
mod simple;

// Re-Exports
pub use simple::*;

// Usings
use pam::{PamConversation, PamFlag, PamHandle, PamReturnCode};

/// Main struct to authenticate a user
/// Currently closes the session on drop() but this might change!
pub struct Authenticator<'a> {
    handle:         *mut PamHandle,
    credentials:    Box<[&'a str; 2]>
}

impl <'a> Authenticator<'a> {
    /// Creates a new Authenticator with a given service name
    pub fn new(service: &str) -> Option<Authenticator> {
        use std::ffi::CString;
        use std::ptr;

        let creds = Box::new([""; 2]);
        let conv = PamConversation {
            conv:       Some(ffi::converse),
            data_ptr:   creds.as_ptr() as *mut ::libc::c_void
        };
        let mut handle: *mut PamHandle = ptr::null_mut();

        match unsafe {
            pam::start(CString::new(service).unwrap().as_ptr(), ptr::null(), &conv, &mut handle)
        } {
            PamReturnCode::SUCCESS => Some(Authenticator {
                handle:         handle,
                credentials:    creds
            }),
            _   => None
        }
    }

    /// Set the credentials which should be used in the authentication process
    pub fn set_credentials(&mut self, user: &'a str, password: &'a str) {
        self.credentials[0] = user;
        self.credentials[1] = password;
    }

    /// Perform the authentication with the provided credentials
    pub fn authenticate(&self) -> Result<(), PamReturnCode> {
        let success = PamReturnCode::SUCCESS;

        let mut res = unsafe { pam::authenticate(self.handle, PamFlag::NONE) };
        if res != success {
            return self.cleanup(res);
        }

        res = unsafe { pam::acct_mgmt(self.handle, PamFlag::NONE) };
        if res != success {
            return self.cleanup(res);
        }

        res = unsafe { pam::setcred(self.handle, PamFlag::ESTABLISH_CRED) };
        if res != success {
            return self.cleanup(res);
        }
        Ok(())
    }

    /// Open a session for a previously authenticated user and
    /// initialize the environment appropriately (in PAM and regular enviroment variables).
    ///
    /// Does not currently check for authentication and just calls the ffi method,
    /// but clients should not rely on that.
    pub fn open_session(&self) -> Result<(), PamReturnCode> {
        let res = unsafe { pam::open_session(self.handle, PamFlag::NONE) };
        if res != PamReturnCode::SUCCESS {
            return self.cleanup(res);
        }

        self.initialize_environment()
    }

    // Initialize the client environment with common variables.
    // Currently always called from Authenticator.open_session()
    fn initialize_environment(&self) -> Result<(), PamReturnCode> {
        let user = users::get_user_by_name(self.credentials[0])
            .expect(&format!("Could not get user by name: {:?}", self.credentials[0]));

        self.set_env("USER", &user.name)
            .and(self.set_env("LOGNAME", &user.name))
            .and(self.set_env("HOME", &user.home_dir))
            .and(self.set_env("PWD", &user.home_dir))
            .and(self.set_env("SHELL", &user.shell))
            // Taken from https://github.com/gsingh93/display-manager/blob/master/pam.c
            // Should be a better way to get this. Revisit later.
            .and(self.set_env("PATH", "$PATH:/usr/local/sbin:/usr/local/bin:/usr/bin"))
    }

    // Utility function to set an environment variable in PAM and the process
    fn set_env(&self, key: &str, value: &str) -> Result<(), PamReturnCode> {
        use std::env;
        use std::ffi::CString;

        // Set regular environment variable
        env::set_var(key, value);

        // Set pam environment variable
        let name_value = CString::new(format!("{}={}", key, value)).unwrap();
        match unsafe { pam::putenv(self.handle, name_value.as_ptr()) } {
            PamReturnCode::SUCCESS  => Ok(()),
            code                    => Err(code)
        }
    }

    // Utility function to properly clean up pam
    fn cleanup(&self, code: PamReturnCode) -> Result<(), PamReturnCode> {
        unsafe {
            // Currently the session is closed if PamReturnCode::SUCCESS is passed //TODO: change this
            if code == PamReturnCode::SUCCESS {
                pam::close_session(self.handle, PamFlag::NONE);
            }
            pam::setcred(self.handle, pam::PamFlag::DELETE_CRED);
            pam::end(self.handle, 0);
        }
        Err(code)
    }
}

impl <'a> Drop for Authenticator<'a> {
    fn drop(&mut self) {
        self.cleanup(PamReturnCode::SUCCESS);
    }
}
