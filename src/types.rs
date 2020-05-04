use crate::enums::PamReturnCode;

/// Opaque PAM main structure. Used for nearly all application functions
pub type PamHandle = pam_sys::pam_handle_t;
/// PAM message that is passed to modules
pub type PamMessage = pam_sys::pam_message;
/// PAM response returned by modules
pub type PamResponse = pam_sys::pam_response;

/// PAM related error with `PamReturnCode` inside it
pub struct PamError(pub PamReturnCode);

/// Convenience type for functions that might fail with a `PamError`
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
