extern crate pam_sys as pam;

mod authenticator;
mod env;
mod ffi;

pub use crate::authenticator::*;

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
