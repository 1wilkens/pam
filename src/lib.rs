#![allow(non_camel_case_types)]
// We want to pass PamHandles by ref as they are opaque
#![allow(clippy::trivially_copy_pass_by_ref)]

//! Rustified API to the Linux-PAM authentication libary

// Reexport pam_sys so downstream users don't need to depend on it
pub use pam_sys;

mod conv;
mod enums;
mod functions;
mod types;

pub use crate::{enums::*, functions::*, types::*};

#[cfg(feature = "auth")]
pub mod auth;
#[cfg(feature = "module")]
pub mod module;

pub use crate::{conv::Conversation, enums::*};

#[cfg(feature = "auth")]
pub use auth::Authenticator;
