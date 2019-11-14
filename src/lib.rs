// TODO: only for now
#![allow(non_camel_case_types)]

mod conv;
mod enums;
pub mod wrapped;

#[cfg(feature = "auth")]
pub mod auth;
#[cfg(feature = "module")]
pub mod module;

pub use crate::{conv::Conversation, enums::*};

pub struct PamError(pub PamReturnCode);

pub type PamHandle = pam_sys::pam_handle_t;
pub type PamMessage = pam_sys::pam_message;
pub type PamResponse = pam_sys::pam_response;
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
