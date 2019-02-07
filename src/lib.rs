// Copyright 2015-2019 pam-auth Developers
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

extern crate pam_sys as pam;

mod authenticator;
mod env;
mod ffi;
mod simple;

pub use crate::authenticator::*;
pub use crate::simple::*;

pub struct PamError(pam::PamReturnCode);
pub type PamResult<T> = std::result::Result<T, PamError>;

impl std::fmt::Debug for PamError {
    fn fmt(&self, fmt: &mut std::fmt::Formatter) -> std::fmt::Result {
        self.0.fmt(fmt)
    }
}

impl std::fmt::Display for PamError {
    fn fmt(&self, fmt: &mut std::fmt::Formatter) -> std::fmt::Result {
        self.0.fmt(fmt)
    }
}

impl std::error::Error for PamError {
    fn description(&self) -> &str {
        "PAM returned an error code"
    }
}

impl From<pam::PamReturnCode> for PamError {
    fn from(err: pam::PamReturnCode) -> PamError {
        PamError(err)
    }
}
