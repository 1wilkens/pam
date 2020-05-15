//! Functions and structures that can be used to implement a PAM module
//!
//! Inspired by anowell/pam-rs

use crate::{PamHandle, PamReturnCode};
use std::ffi::CStr;
use std::os::raw::c_uint;

// FIXME: Find a solution for the flags containing ORed integers
#[allow(unused_variables)]
/// Trait representing a PAM module.
///
/// Modules should override the desired functions and call the macro `impl_pam_module`.
/// This exports the respective functions at the expected symbols prefixed with `pam_sm_`.
///
/// ```no_run
/// use pam::{PamModule, export_pam_module};
///
/// pub struct MyModule;
/// impl PamModule for MyModule {}
///
/// // FIXME: Currently gets E0433: failed to resolve for `MyModule`
/// //export_pam_module!(MyModule);
/// ```
pub trait PamModule {
    fn account_management(handle: &PamHandle, args: Vec<&CStr>, flags: c_uint) -> PamReturnCode {
        PamReturnCode::Ignore
    }
    fn authenticate(handle: &PamHandle, args: Vec<&CStr>, flags: c_uint) -> PamReturnCode {
        PamReturnCode::Ignore
    }
    fn change_auth_token(handle: &PamHandle, args: Vec<&CStr>, flags: c_uint) -> PamReturnCode {
        PamReturnCode::Ignore
    }
    fn close_session(handle: &PamHandle, args: Vec<&CStr>, flags: c_uint) -> PamReturnCode {
        PamReturnCode::Ignore
    }
    fn open_session(handle: &PamHandle, args: Vec<&CStr>, flags: c_uint) -> PamReturnCode {
        PamReturnCode::Ignore
    }
    fn set_credentials(handle: &PamHandle, args: Vec<&CStr>, flags: c_uint) -> PamReturnCode {
        PamReturnCode::Ignore
    }
}

#[macro_export]
/// Export the given struct as a PAM module by wiring up the respective extern "C" functions
macro_rules! export_pam_module {
    ($struct:ident) => {
        pub use _pam_module_::*;
        mod _pam_module_ {
            use std::ffi::CStr;
            use std::os::raw::{c_char, c_int, c_uint};
            use $crate::{PamHandle, PamModule, PamReturnCode};

            fn convert_args<'a>(argc: c_int, argv: *const *const c_char) -> Vec<&'a CStr> {
                (0..argc)
                    .map(|i| unsafe { CStr::from_ptr(*argv.offset(i as isize)) })
                    .collect()
            }

            #[no_mangle]
            pub extern "C" fn pam_sm_acct_mgmt(
                handle: &PamHandle,
                flags: c_uint,
                argc: c_int,
                argv: *const *const c_char,
            ) -> PamReturnCode {
                let args = convert_args(argc, argv);
                super::$struct::account_management(handle, args, flags)
            }
            #[no_mangle]
            pub extern "C" fn pam_sm_authenticate(
                handle: &PamHandle,
                flags: c_uint,
                argc: c_int,
                argv: *const *const c_char,
            ) -> PamReturnCode {
                let args = convert_args(argc, argv);
                super::$struct::authenticate(handle, args, flags)
            }
            #[no_mangle]
            pub extern "C" fn pam_sm_chauthtok(
                handle: &PamHandle,
                flags: c_uint,
                argc: c_int,
                argv: *const *const c_char,
            ) -> PamReturnCode {
                let args = convert_args(argc, argv);
                super::$struct::change_auth_token(handle, args, flags)
            }
            #[no_mangle]
            pub extern "C" fn pam_sm_close_session(
                handle: &PamHandle,
                flags: c_uint,
                argc: c_int,
                argv: *const *const c_char,
            ) -> PamReturnCode {
                let args = convert_args(argc, argv);
                super::$struct::close_session(handle, args, flags)
            }
            #[no_mangle]
            pub extern "C" fn pam_sm_open_session(
                handle: &PamHandle,
                flags: c_uint,
                argc: c_int,
                argv: *const *const c_char,
            ) -> PamReturnCode {
                let args = convert_args(argc, argv);
                super::$struct::open_session(handle, args, flags)
            }
            #[no_mangle]
            pub extern "C" fn pam_sm_setcred(
                handle: &PamHandle,
                flags: c_uint,
                argc: c_int,
                argv: *const *const c_char,
            ) -> PamReturnCode {
                let args = convert_args(argc, argv);
                super::$struct::set_credentials(handle, args, flags)
            }
        }
    };
}

#[cfg(test)]
pub mod test {
    use super::PamModule;
    use crate::export_pam_module;

    pub struct TestModule;
    impl PamModule for TestModule {}

    export_pam_module!(TestModule);
}
