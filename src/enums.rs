//! Types defined by Linux-PAM
//!
//! This modules contains struct and enum definitions used by `pam-sys`.

use pam_macros::pam_enum;

/// The Linux-PAM return values
#[pam_enum]
pub enum PamReturnCode {
    /// System error
    System_Err,

    /// Successful function return
    Success,

    /// dlopen() failure when dynamically loading a service module
    Open_Err,

    /// Symbol not found
    Symbol_Err,

    /// Error in service module
    Service_Err,

    /// Memory buffer error
    Buf_Err,

    /// Permission denied
    Perm_Denied,

    /// Authentication failure
    Auth_Err,

    /// Can not access authentication data due to insufficient credentials
    Cred_Insufficient,

    /// Underlying authentication service can not retrieve authentication information
    Authinfo_Unavail,

    /// User not known to the underlying authentication module
    User_Unknown,

    /// An authentication service has maintained a retry count which has been reached.
    /// No further retries should be attempted
    MaxTries,

    /// New authentication token required.
    /// This is normally returned if the machine security policies require
    /// that the password should be changed beccause the password is NULL or it has aged
    New_Authtok_Reqd,

    /// User account has expired
    Acct_Expired,

    /// Can not make/remove an entry for the specified session
    Session_Err,

    /// Underlying authentication service can not retrieve user credentials unavailable
    Cred_Unavail,

    /// User credentials expired
    Cred_Expired,

    /// Failure setting user credentials
    Cred_Err,

    /// No module specific data is present
    No_Module_Data,

    /// Conversation error
    Conv_Err,

    /// Authentication token manipulation error
    AuthTok_Err,

    /// Authentication information cannot be recovered
    AuthTok_Recovery_Err,

    /// Authentication token lock busy
    AuthTok_Lock_Busy,

    /// Authentication token aging disabled
    AuthTok_Disable_Aging,

    /// Preliminary check by password service
    Try_Again,

    /// Ignore underlying account module regardless of whether
    /// the control flag is required, optional, or sufficient
    Ignore,

    /// Critical error (?module fail now request)
    AuthTok_Expired,

    /// user's authentication token has expired
    Abort,

    /// module is not known
    Module_Unknown,

    /// Bad item passed to pam_*_item()
    Bad_Item,

    /// conversation function is event driven and data is not available yet
    Conv_Again,

    /// please call this function again to complete authentication stack.
    /// Before calling again as isize, verify that conversation is completed
    Incomplete,
}

impl std::fmt::Display for PamReturnCode {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> Result<(), std::fmt::Error> {
        f.write_str(&format!("{:?} ({})", self, *self as i32))
    }
}

/// PAM flags for pam_setcred
#[pam_enum]
pub enum PamSetCredFlag {
    /// Set user credentials for an authentication service
    /// (used for pam_setcred())
    Establish_Cred,

    /// Delete user credentials associated with an authentication service
    /// (used for pam_setcred())
    Delete_Cred,

    /// Reinitialize user credentials
    /// (used for pam_setcred())
    Reinitialize_Cred,

    /// Extend lifetime of user credentials
    /// (used for pam_setcred())
    Refresh_Cred,
}

impl std::fmt::Display for PamSetCredFlag {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> Result<(), std::fmt::Error> {
        f.write_str(&format!("{:?} ({})", self, *self as i32))
    }
}

/// PAM flags for pam_authenticate
#[pam_enum]
pub enum PamAuthenticateFlag {
    /// Default value, if no specific flags should be passed
    None = 0,

    /// The authentication service should return AUTH_ERROR
    /// if the user has a null authentication token
    /// (used by pam_authenticate{,_secondary}())
    Disallow_Null_AuthTok,
}

impl std::fmt::Display for PamAuthenticateFlag {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> Result<(), std::fmt::Error> {
        f.write_str(&format!("{:?} ({})", self, *self as i32))
    }
}

/// PAM flags for pam_ch_authtok and pam_sm_chauthtok
#[pam_enum]
pub enum PamAuthTokFlag {
    /// Default value, if no specific flags should be passed
    None = 0,

    /// The following two flags are for use across the Linux-PAM/module
    /// interface only. The Application is not permitted to use these
    /// tokens.
    ///
    /// The password service should only perform preliminary checks.  No
    /// passwords should be updated.
    Prelim_Check,

    /// The password service should only update those passwords that have aged.
    /// If this flag is not passed, the password service should update all passwords.
    /// (used by pam_chauthtok)
    Change_Expired_AuthTok,

    /// The password service should update passwords Note: PAM_PRELIM_CHECK
    /// and PAM_UPDATE_AUTHTOK cannot both be set simultaneously!
    Update_AuthTok,
}

impl std::fmt::Display for PamAuthTokFlag {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> Result<(), std::fmt::Error> {
        f.write_str(&format!("{:?} ({})", self, *self as i32))
    }
}

/// The general PAM flags
#[pam_enum]
pub enum PamFlag {
    /// Default value, if no specific flags should be passed
    None = 0,

    /// Authentication service should not generate any messages
    Silent,
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
#[pam_enum]
pub enum PamItemType {
    /// The service name
    Service,

    /// The user name
    User,

    /// The tty name
    TTY,

    /// The remote host name
    RHost,

    /// The pam_conv structure
    Conv,

    /// The authentication token (password)
    AuthTok,

    /// The old authentication token
    OldAuthTok,

    /// The remote user name
    RUser,

    /// the prompt for getting a username Linux-PAM extensions
    User_Prompt,

    /// app supplied function to override failure delays
    Fail_Delay,

    /// X display name
    XDisplay,

    /// X server authentication data
    XAuthData,

    /// The type for pam_get_authtok
    AuthTok_Type,
}

impl std::fmt::Display for PamItemType {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> Result<(), std::fmt::Error> {
        f.write_str(&format!("{:?} ({})", self, *self as i32))
    }
}

/// The Linux-PAM message styles
#[pam_enum]
pub enum PamMessageStyle {
    Prompt_Echo_On,
    Prompt_Echo_Off,
    Error_Msg,
    Text_Info,
}

impl std::fmt::Display for PamMessageStyle {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> Result<(), std::fmt::Error> {
        f.write_str(&format!("{:?} ({})", self, *self as i32))
    }
}
