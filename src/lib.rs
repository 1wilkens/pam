#![allow(non_camel_case_types)]
// We want to pass PamHandles by ref as they are opaque
#![allow(clippy::trivially_copy_pass_by_ref)]

//! Rustified API to the Linux-PAM authentication libary
//!
//! This library supports both PAM clients and modules through the respective
//! cargo features. If you do not want to use any high-level API, wrappers
//! for the raw PAM related functions from `pam_sys` are also exported at crate
//! root.

// Reexport pam_sys so downstream users don't need to depend on it
pub use pam_sys;

mod conv;
mod enums;
mod functions;
mod types;
mod env;

pub use crate::{enums::*, functions::*, types::*};

#[cfg(feature = "client")]
pub mod client;
#[cfg(feature = "module")]
pub mod module;

pub use crate::{conv::Conversation, enums::*};

#[cfg(feature = "client")]
pub use client::Client;

#[cfg(feature = "module")]
pub use module::PamModule;
