use std::ffi::{CStr, CString, NulError};
use std::ops::{Deref, DerefMut};

use libc::c_void;
use pam_sys::{set_item, PamHandle, PamItemType};

use crate::{PamError, PamReturnCode};

pub trait ConversationHandler<'a, C>: std::ops::Deref<Target = C> + DerefMut<Target = C> {
    fn create(conversation: Box<C>, handle: &'a mut PamHandle) -> Self;
    fn handle_mut(this: &mut Self) -> &mut PamHandle;
    fn handle(this: &Self) -> &PamHandle;
}

pub struct DefaultHandler<'a, C> {
    conv: Box<C>,
    handle: &'a mut PamHandle,
}

impl<C> Deref for DefaultHandler<'_, C> {
    type Target = C;

    fn deref(&self) -> &C {
        &self.conv
    }
}

impl<C> DerefMut for DefaultHandler<'_, C> {
    fn deref_mut(&mut self) -> &mut C {
        &mut self.conv
    }
}

impl<'a, C> ConversationHandler<'a, C> for DefaultHandler<'a, C> {
    fn create(conversation: Box<C>, handle: &'a mut PamHandle) -> Self {
        Self {
            conv: conversation,
            handle,
        }
    }

    fn handle(this: &Self) -> &PamHandle {
        &this.handle
    }

    fn handle_mut(this: &mut Self) -> &mut PamHandle {
        &mut this.handle
    }
}

/// A trait representing the PAM authentification conversation
///
/// PAM authentification is done as a conversation mechanism, in which PAM
/// asks several questions and the client (your code) answers them. This trait
/// is a representation of such a conversation, which one method for each message
/// PAM can send you.
///
/// This is the trait to implement if you want to customize the conversation with
/// PAM. If you just want a simple login/password authentication, you can use the
/// `PasswordConv` implementation provided by this crate.
pub trait Converse<'a>: Sized {
    type Handler: ConversationHandler<'a, Self>;

    /// PAM requests a value that should be echoed to the user as they type it
    ///
    /// This would typically be the username. The exact question is provided as the
    /// `msg` argument if you wish to display it to your user.
    fn prompt_echo(&mut self, msg: &CStr) -> ::std::result::Result<CString, ()>;
    /// PAM requests a value that should be typed blindly by the user
    ///
    /// This would typically be the password. The exact question is provided as the
    /// `msg` argument if you wish to display it to your user.
    fn prompt_blind(&mut self, msg: &CStr) -> ::std::result::Result<CString, ()>;
    /// This is an informational message from PAM
    fn info(&mut self, msg: &CStr);
    /// This is an error message from PAM
    fn error(&mut self, msg: &CStr);
    /// Get the username that is being authenticated
    ///
    /// This method is not a PAM callback, but is rather used by the `Authenticator` to
    /// setup the environment when opening a session.
    fn username(&self) -> &str;
}

/// A minimalistic conversation handler, that uses given login and password
///
/// This conversation handler is not really interactive, but simply returns to
/// PAM the value that have been set using the `set_credentials` method.
pub struct PasswordConv {
    login: CString,
    passwd: CString,
}

impl PasswordConv {
    /// Create a new `PasswordConv` handler
    pub(crate) fn new() -> PasswordConv {
        PasswordConv {
            login: CString::new("").unwrap(),
            passwd: CString::new("").unwrap(),
        }
    }
}

#[derive(Debug)]
pub enum SetCredentialsError {
    PamError(PamError),
    InvalidUsername(NulError),
}

impl From<NulError> for SetCredentialsError {
    fn from(err: NulError) -> Self {
        SetCredentialsError::InvalidUsername(err)
    }
}

impl DefaultHandler<'_, PasswordConv> {
    /// Set the credentials that this handler will provide to PAM
    pub fn set_credentials<U: Into<Vec<u8>>, V: Into<Vec<u8>>>(
        &mut self,
        login: U,
        password: V,
    ) -> Result<(), SetCredentialsError> {
        let login_string = CString::new(login)?;
        let password_string = CString::new(password)?;

        match set_item(self.handle, PamItemType::USER, unsafe {
            &*(login_string.as_ptr() as *const c_void)
        }) {
            PamReturnCode::SUCCESS => {}
            code => return Err(SetCredentialsError::PamError(From::from(code))),
        }

        self.conv.login = login_string;
        self.conv.passwd = password_string;
        Ok(())
    }
}

impl<'a> Converse<'a> for PasswordConv {
    type Handler = DefaultHandler<'a, Self>;

    fn prompt_echo(&mut self, _msg: &CStr) -> Result<CString, ()> {
        Ok(self.login.clone())
    }
    fn prompt_blind(&mut self, _msg: &CStr) -> Result<CString, ()> {
        Ok(self.passwd.clone())
    }
    fn info(&mut self, _msg: &CStr) {}
    fn error(&mut self, msg: &CStr) {
        eprintln!("[PAM ERROR] {}", msg.to_string_lossy());
    }
    fn username(&self) -> &str {
        &self.login.to_str().expect("Username to be valid UTF-8")
    }
}
