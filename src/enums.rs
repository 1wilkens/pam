//! Types defined by Linux-PAM
//!
//! This modules contains struct and enum definitions used by `pam-sys`.

/// The Linux-PAM return values
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum PamReturnCode {
    /// Successful function return
    SUCCESS = pam_sys::PAM_SUCCESS as isize,

    /// dlopen() failure when dynamically loading a service module
    OPEN_ERR = pam_sys::PAM_OPEN_ERR as isize,

    /// Symbol not found
    SYMBOL_ERR = pam_sys::PAM_SYMBOL_ERR as isize,

    /// Error in service module
    SERVICE_ERR = pam_sys::PAM_SERVICE_ERR as isize,

    /// System error
    SYSTEM_ERR = pam_sys::PAM_SYSTEM_ERR as isize,

    /// Memory buffer error
    BUF_ERR = pam_sys::PAM_BUF_ERR as isize,

    /// Permission denied
    PERM_DENIED = pam_sys::PAM_PERM_DENIED as isize,

    /// Authentication failure
    AUTH_ERR = pam_sys::PAM_AUTH_ERR as isize,

    /// Can not access authentication data due to insufficient credentials
    CRED_INSUFFICIENT = pam_sys::PAM_CRED_INSUFFICIENT as isize,

    /// Underlying authentication service can not retrieve authentication information
    AUTHINFO_UNAVAIL = pam_sys::PAM_AUTHINFO_UNAVAIL as isize,

    /// User not known to the underlying authentication module
    USER_UNKNOWN = pam_sys::PAM_USER_UNKNOWN as isize,

    /// An authentication service has maintained a retry count which has been reached.
    /// No further retries should be attempted
    MAXTRIES = pam_sys::PAM_MAXTRIES as isize,

    /// New authentication token required.
    /// This is normally returned if the machine security policies require
    /// that the password should be changed beccause the password is NULL or it has aged
    NEW_AUTHTOK_REQD = pam_sys::PAM_NEW_AUTHTOK_REQD as isize,

    /// User account has expired
    ACCT_EXPIRED = pam_sys::PAM_ACCT_EXPIRED as isize,

    /// Can not make/remove an entry for the specified session
    SESSION_ERR = pam_sys::PAM_SESSION_ERR as isize,

    /// Underlying authentication service can not retrieve user credentials unavailable
    CRED_UNAVAIL = pam_sys::PAM_CRED_UNAVAIL as isize,

    /// User credentials expired
    CRED_EXPIRED = pam_sys::PAM_CRED_EXPIRED as isize,

    /// Failure setting user credentials
    CRED_ERR = pam_sys::PAM_CRED_ERR as isize,

    /// No module specific data is present
    NO_MODULE_DATA = pam_sys::PAM_NO_MODULE_DATA as isize,

    /// Conversation error
    CONV_ERR = pam_sys::PAM_CONV_ERR as isize,

    /// Authentication token manipulation error
    AUTHTOK_ERR = pam_sys::PAM_AUTHTOK_ERR as isize,

    /// Authentication information cannot be recovered
    AUTHTOK_RECOVERY_ERR = pam_sys::PAM_AUTHTOK_RECOVERY_ERR as isize,

    /// Authentication token lock busy
    AUTHTOK_LOCK_BUSY = pam_sys::PAM_AUTHTOK_LOCK_BUSY as isize,

    /// Authentication token aging disabled
    AUTHTOK_DISABLE_AGING = pam_sys::PAM_AUTHTOK_DISABLE_AGING as isize,

    /// Preliminary check by password service
    TRY_AGAIN = pam_sys::PAM_TRY_AGAIN as isize,

    /// Ignore underlying account module regardless of whether
    /// the control flag is required as isize, optional as isize, or sufficient
    IGNORE = pam_sys::PAM_IGNORE as isize,

    /// Critical error (?module fail now request)
    AUTHTOK_EXPIRED = pam_sys::PAM_AUTHTOK_EXPIRED as isize,

    /// user's authentication token has expired
    ABORT = pam_sys::PAM_ABORT as isize,

    /// module is not known
    MODULE_UNKNOWN = pam_sys::PAM_MODULE_UNKNOWN as isize,

    /// Bad item passed to pam_*_item()
    BAD_ITEM = pam_sys::PAM_BAD_ITEM as isize,

    /// conversation function is event driven and data is not available yet
    CONV_AGAIN = pam_sys::PAM_CONV_AGAIN as isize,

    /// please call this function again to complete authentication stack.
    /// Before calling again as isize, verify that conversation is completed
    INCOMPLETE = pam_sys::PAM_INCOMPLETE as isize,
}

impl std::fmt::Display for PamReturnCode {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> Result<(), std::fmt::Error> {
        f.write_str(&format!("{:?} ({})", self, *self as i32))
    }
}

impl From<i32> for PamReturnCode {
    fn from(status: i32) -> PamReturnCode {
        match status {
            0 => PamReturnCode::SUCCESS,
            1 => PamReturnCode::OPEN_ERR,
            2 => PamReturnCode::SYMBOL_ERR,
            3 => PamReturnCode::SERVICE_ERR,
            4 => PamReturnCode::SYSTEM_ERR,
            5 => PamReturnCode::BUF_ERR,
            6 => PamReturnCode::PERM_DENIED,
            7 => PamReturnCode::AUTH_ERR,
            8 => PamReturnCode::CRED_INSUFFICIENT,
            9 => PamReturnCode::AUTHINFO_UNAVAIL,
            10 => PamReturnCode::USER_UNKNOWN,
            11 => PamReturnCode::MAXTRIES,
            12 => PamReturnCode::NEW_AUTHTOK_REQD,
            13 => PamReturnCode::ACCT_EXPIRED,
            14 => PamReturnCode::SESSION_ERR,
            15 => PamReturnCode::CRED_UNAVAIL,
            16 => PamReturnCode::CRED_EXPIRED,
            17 => PamReturnCode::CRED_ERR,
            18 => PamReturnCode::NO_MODULE_DATA,
            19 => PamReturnCode::CONV_ERR,
            20 => PamReturnCode::AUTHTOK_ERR,
            21 => PamReturnCode::AUTHTOK_RECOVERY_ERR,
            22 => PamReturnCode::AUTHTOK_LOCK_BUSY,
            23 => PamReturnCode::AUTHTOK_DISABLE_AGING,
            24 => PamReturnCode::TRY_AGAIN,
            25 => PamReturnCode::IGNORE,
            26 => PamReturnCode::ABORT,
            27 => PamReturnCode::AUTHTOK_EXPIRED,
            28 => PamReturnCode::MODULE_UNKNOWN,
            29 => PamReturnCode::BAD_ITEM,
            30 => PamReturnCode::CONV_AGAIN,
            31 => PamReturnCode::INCOMPLETE,
            _ => PamReturnCode::SYSTEM_ERR,
        }
    }
}

/// The Linux-PAM flags
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum PamFlag {
    /// Authentication service should not generate any messages
    SILENT = pam_sys::PAM_SILENT as isize,

    /// The authentication service should return AUTH_ERROR
    /// if the user has a null authentication token
    /// (used by pam_authenticate{,_secondary}())
    DISALLOW_NULL_AUTHTOK = pam_sys::PAM_DISALLOW_NULL_AUTHTOK as isize,

    /// Set user credentials for an authentication service
    /// (used for pam_setcred())
    ESTABLISH_CRED = pam_sys::PAM_ESTABLISH_CRED as isize,

    /// Delete user credentials associated with an authentication service
    /// (used for pam_setcred())
    DELETE_CRED = pam_sys::PAM_DELETE_CRED as isize,

    /// Reinitialize user credentials
    /// (used for pam_setcred())
    REINITIALIZE_CRED = pam_sys::PAM_REINITIALIZE_CRED as isize,

    /// Extend lifetime of user credentials
    /// (used for pam_setcred())
    REFRESH_CRED = pam_sys::PAM_REFRESH_CRED as isize,

    /// The password service should only update those passwords that have aged.
    /// If this flag is not passed, the password service should update all passwords.
    /// (used by pam_chauthtok)
    CHANGE_EXPIRED_AUTHTOK = pam_sys::PAM_CHANGE_EXPIRED_AUTHTOK as isize,

    // TODO: check if there is some native constant for this
    NONE = 0,
}

impl std::fmt::Display for PamFlag {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> Result<(), std::fmt::Error> {
        f.write_str(&format!("{:?} ({})", self, *self as i32))
    }
}

/// The Linux-PAM item types
///
/// These defines are used by `pam_set_item()` `and pam_get_item()`.
/// Please check the spec which are allowed for use by applications
/// and which are only allowed for use by modules.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum PamItemType {
    /// The service name
    SERVICE = 1,

    /// The user name
    USER = 2,

    /// The tty name
    TTY = 3,

    /// The remote host name
    RHOST = 4,

    /// The pam_conv structure
    CONV = 5,

    /// The authentication token (password)
    AUTHTOK = 6,

    /// The old authentication token
    OLDAUTHTOK = 7,

    /// The remote user name
    RUSER = 8,

    /// the prompt for getting a username Linux-PAM extensions
    USER_PROMPT = 9,

    /// app supplied function to override failure delays
    FAIL_DELAY = 10,

    /// X display name
    XDISPLAY = 11,

    /// X server authentication data
    XAUTHDATA = 12,

    /// The type for pam_get_authtok
    AUTHTOK_TYPE = 13,
}

impl std::fmt::Display for PamItemType {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> Result<(), std::fmt::Error> {
        f.write_str(&format!("{:?} ({})", self, *self as i32))
    }
}

/// The Linux-PAM message styles
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum PamMessageStyle {
    PROMPT_ECHO_OFF = 1,
    PROMPT_ECHO_ON = 2,
    ERROR_MSG = 3,
    TEXT_INFO = 4,
}

impl std::fmt::Display for PamMessageStyle {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> Result<(), std::fmt::Error> {
        f.write_str(&format!("{:?} ({})", self, *self as i32))
    }
}

impl From<i32> for PamMessageStyle {
    fn from(style: i32) -> PamMessageStyle {
        match style {
            1 => PamMessageStyle::PROMPT_ECHO_OFF,
            2 => PamMessageStyle::PROMPT_ECHO_ON,
            3 => PamMessageStyle::ERROR_MSG,
            4 => PamMessageStyle::TEXT_INFO,
            _ => PamMessageStyle::ERROR_MSG,
        }
    }
}
