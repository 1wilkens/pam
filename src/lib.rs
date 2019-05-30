extern crate pam_sys;

mod authenticator;
mod conversation;
mod env;
mod ffi;

use pam_sys::PamReturnCode;

pub use crate::authenticator::*;
pub use crate::conversation::*;

pub struct PamError(PamReturnCode);
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

impl From<PamReturnCode> for PamError {
    fn from(err: PamReturnCode) -> PamError {
        PamError(err)
    }
}
