// Copyright 2015-2017 pam-auth Developers
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use ffi;

use pam::{self, PamConversation, PamFlag, PamHandle, PamReturnCode};
use users;

/// Main struct to authenticate a user
/// Currently closes the session on drop() but this might change!
pub struct Authenticator<'a, 'b> {
    /// Flag indicating whether the Authenticator should close the session on drop
    pub close_on_drop: bool,
    handle: &'a mut PamHandle,
    credentials: Box<[&'b str; 2]>,
    is_authenticated: bool,
    has_open_session: bool,
    last_code: PamReturnCode,
}

impl<'a, 'b> Authenticator<'a, 'b> {
    /// Creates a new Authenticator with a given service name
    pub fn new(service: &str) -> Option<Authenticator> {
        use std::ptr;

        let creds = Box::new([""; 2]);
        let conv = PamConversation {
            conv: Some(ffi::converse),
            data_ptr: creds.as_ptr() as *mut ::libc::c_void,
        };
        let mut handle: *mut PamHandle = ptr::null_mut();

        match pam::start(service, None, &conv, &mut handle) {
            PamReturnCode::SUCCESS => unsafe {
                println!("handle: {:p}", handle);
                Some(Authenticator {
                    close_on_drop: true,
                    handle: handle.as_mut().unwrap(),
                    credentials: creds,
                    is_authenticated: false,
                    has_open_session: false,
                    last_code: PamReturnCode::SUCCESS,
                })
            },
            _ => None,
        }
    }

    /// Set the credentials which should be used in the authentication process.
    /// Currently only username/password combinations are supported
    pub fn set_credentials(&mut self, user: &'b str, password: &'b str) {
        self.credentials[0] = user;
        self.credentials[1] = password;
    }

    /// Perform the authentication with the provided credentials
    pub fn authenticate(&mut self) -> ::Result<()> {
        self.last_code = pam::authenticate(self.handle, PamFlag::NONE);
        if self.last_code != PamReturnCode::SUCCESS {
            // No need to reset here
            return Err(From::from(self.last_code));
        }

        self.is_authenticated = true;

        self.last_code = pam::acct_mgmt(self.handle, PamFlag::NONE);
        if self.last_code != PamReturnCode::SUCCESS {
            // Probably not strictly neccessary but better be sure
            return self.reset();
        }
        Ok(())
    }

    /// Open a session for a previously authenticated user and
    /// initialize the environment appropriately (in PAM and regular enviroment variables).
    pub fn open_session(&mut self) -> ::Result<()> {
        if !self.is_authenticated {
            //TODO: is this the right return code?
            return Err(From::from(PamReturnCode::PERM_DENIED));
        }

        self.last_code = pam::setcred(self.handle, PamFlag::ESTABLISH_CRED);
        if self.last_code != PamReturnCode::SUCCESS {
            return self.reset();
        }

        self.last_code = pam::open_session(self.handle, PamFlag::NONE);
        if self.last_code != PamReturnCode::SUCCESS {
            return self.reset();
        }

        // Follow openSSH and call pam_setcred before and after open_session
        self.last_code = pam::setcred(self.handle, PamFlag::REINITIALIZE_CRED);
        if self.last_code != PamReturnCode::SUCCESS {
            return self.reset();
        }

        self.has_open_session = true;
        self.initialize_environment()
    }

    // Initialize the client environment with common variables.
    // Currently always called from Authenticator.open_session()
    fn initialize_environment(&mut self) -> ::Result<()> {
        use users::os::unix::UserExt;
        use std::env;

        println!("Copying PAM environment");
        // Set PAM environment in the local process
        if let Some(mut env_list) = ::env::get_pam_env(self.handle) {
            let env = env_list.to_vec();
            for (key, value) in env {
                env::set_var(&key, &value);
            }
        }
        println!("Copied PAM environment");

        let user = users::get_user_by_name(self.credentials[0])
            .expect(&format!("Could not get user by name: {:?}", self.credentials[0]));

        // Set some common environment variables
        try!(self.set_env("USER", user.name()));
        try!(self.set_env("LOGNAME", user.name()));
        try!(self.set_env("HOME", user.home_dir().to_str().unwrap()));
        try!(self.set_env("PWD", user.home_dir().to_str().unwrap()));
        try!(self.set_env("SHELL", user.shell().to_str().unwrap()));
        // Taken from https://github.com/gsingh93/display-manager/blob/master/pam.c
        // Should be a better way to get this. Revisit later.
        try!(self.set_env("PATH", "$PATH:/usr/local/sbin:/usr/local/bin:/usr/bin"));

        Ok(())
    }

    // Utility function to set an environment variable in PAM and the process
    fn set_env(&mut self, key: &str, value: &str) -> ::Result<()> {
        use std::env;

        // Set regular environment variable
        env::set_var(key, value);

        // Set pam environment variable
        if pam::getenv(self.handle, key).is_none() {
            let name_value = format!("{}={}", key, value);
            match pam::putenv(self.handle, &name_value) {
                PamReturnCode::SUCCESS => Ok(()),
                code => Err(From::from(code)),
            }
        } else {
            Ok(())
        }
    }

    // Utility function to reset the pam handle in case of intermediate errors
    fn reset(&mut self) -> ::Result<()> {
        pam::setcred(self.handle, PamFlag::DELETE_CRED);
        self.is_authenticated = false;
        Err(From::from(self.last_code))
    }
}

impl<'a, 'b> Drop for Authenticator<'a, 'b> {
    fn drop(&mut self) {
        if self.has_open_session && self.close_on_drop {
            pam::close_session(self.handle, PamFlag::NONE);
        }
        let code = pam::setcred(self.handle, PamFlag::DELETE_CRED);
        pam::end(self.handle, code);
    }
}