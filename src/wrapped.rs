//! Wrapped FFI bindings to Linux-PAM
//!
//! This module provides wrapped versions of some of the functions from
//! the [`raw`](../raw/index.html) module which use the appropriate enums
//! instead of `c_int`. These wrappers should always be preferred as one
//! can safely match on their return types and prevent illegal arguments
//! from beeing passed to the native library.
//!
//! Note: These wrappers get added as I need them. Feel free to open an issue
//! or PR for the ones that you require which haven't been added yet.
use libc::{c_char, c_int, c_void};

use std::ffi::{CStr, CString};
use std::ptr::null;

use pam_sys as ffi;

use crate::{PamFlag, PamItemType, PamReturnCode};

/* ------------------------ ffi::pam_appl.h -------------------------- */
#[inline]
pub fn start(
    service: &str,
    user: Option<&str>,
    conversation: &ffi::pam_conv,
    handle: *mut *mut ffi::pam_handle_t,
) -> PamReturnCode {
    if let Ok(service) = CString::new(service) {
        if let Some(usr) = user {
            if let Ok(user) = CString::new(usr) {
                unsafe {
                    From::from(ffi::pam_start(
                        service.as_ptr(),
                        user.as_ptr(),
                        conversation,
                        handle as *mut *mut ffi::pam_handle_t,
                    ))
                }
            } else {
                PamReturnCode::BUF_ERR
            }
        } else {
            unsafe {
                From::from(ffi::pam_start(
                    service.as_ptr(),
                    null(),
                    conversation,
                    handle as *mut *mut ffi::pam_handle_t,
                ))
            }
        }
    } else {
        PamReturnCode::SERVICE_ERR
    }
}

#[inline]
pub fn end(handle: &mut ffi::pam_handle_t, status: PamReturnCode) -> PamReturnCode {
    From::from(unsafe { ffi::pam_end(handle, status as c_int) })
}

#[inline]
pub fn authenticate(handle: &mut ffi::pam_handle_t, flags: PamFlag) -> PamReturnCode {
    From::from(unsafe { ffi::pam_authenticate(handle, flags as c_int) })
}

#[inline]
pub fn setcred(handle: &mut ffi::pam_handle_t, flags: PamFlag) -> PamReturnCode {
    From::from(unsafe { ffi::pam_setcred(handle, flags as c_int) })
}

#[inline]
pub fn acct_mgmt(handle: &mut ffi::pam_handle_t, flags: PamFlag) -> PamReturnCode {
    From::from(unsafe { ffi::pam_acct_mgmt(handle, flags as c_int) })
}

#[inline]
pub fn open_session(handle: &mut ffi::pam_handle_t, flags: PamFlag) -> PamReturnCode {
    From::from(unsafe { ffi::pam_open_session(handle, flags as c_int) })
}

#[inline]
pub fn close_session(handle: &mut ffi::pam_handle_t, flags: PamFlag) -> PamReturnCode {
    From::from(unsafe { ffi::pam_close_session(handle, flags as c_int) })
}

#[inline]
pub fn chauthtok(handle: &mut ffi::pam_handle_t, flags: PamFlag) -> PamReturnCode {
    From::from(unsafe { ffi::pam_chauthtok(handle, flags as c_int) })
}
/* ------------------------ ffi::pam_appl.h -------------------------- */

/* ----------------------- _pam_types.h ------------------------- */
#[inline]
pub fn set_item(
    handle: &mut ffi::pam_handle_t,
    item_type: PamItemType,
    item: &c_void,
) -> PamReturnCode {
    From::from(unsafe { ffi::pam_set_item(handle, item_type as c_int, item) })
}

#[inline]
pub fn get_item(
    handle: &ffi::pam_handle_t,
    item_type: PamItemType,
    item: &mut *const c_void,
) -> PamReturnCode {
    From::from(unsafe { ffi::pam_get_item(handle, item_type as c_int, item) })
}

#[inline]
pub fn strerror(handle: &mut ffi::pam_handle_t, errnum: PamReturnCode) -> Option<&str> {
    unsafe { CStr::from_ptr(ffi::pam_strerror(handle, errnum as c_int)) }
        .to_str()
        .ok()
}

#[inline]
pub fn putenv(handle: &mut ffi::pam_handle_t, name_value: &str) -> PamReturnCode {
    if let Ok(name_value) = CString::new(name_value) {
        From::from(unsafe { ffi::pam_putenv(handle, name_value.as_ptr()) })
    } else {
        // Not sure whether this is the correct return value
        PamReturnCode::BUF_ERR
    }
}

#[inline]
pub fn getenv<'a>(handle: &'a mut ffi::pam_handle_t, name: &str) -> Option<&'a str> {
    if let Ok(name) = CString::new(name) {
        let env = unsafe { ffi::pam_getenv(handle, name.as_ptr()) };
        if !env.is_null() {
            unsafe { CStr::from_ptr(env) }.to_str().ok()
        } else {
            None
        }
    } else {
        None
    }
}

/*#[inline]
pub fn getenvlist(handle: &mut ffi::pam_handle_t) -> *const *const c_char {
    //TODO: find a convenient way to handle this with Rust types
    unsafe { ffi::pam_getenvlist(handle) }
}*/
/* ----------------------- _pam_types.h ------------------------- */

/* ----------------------- ffi::pam_misc.h --------------------------- */
#[inline]
#[cfg(target_os = "linux")]
pub fn misc_paste_env(handle: &mut ffi::pam_handle_t, user_env: &[&str]) -> PamReturnCode {
    // Taken from: https://github.com/rust-lang/rust/issues/9564#issuecomment-95354558
    let user_env: Vec<_> = user_env
        .iter()
        .map(|&env| CString::new(env).unwrap())
        .collect();
    let env_ptrs: Vec<_> = user_env
        .iter()
        .map(|env| env.as_ptr())
        .chain(Some(null()))
        .collect();
    From::from(unsafe { ffi::pam_misc_paste_env(handle, env_ptrs.as_ptr()) })
}

/*#[inline]
#[cfg(target_os = "linux")]
pub fn misc_drop_env(env: &mut *mut c_char) -> PamReturnCode {
    From::from(unsafe { ffi::pam_misc_drop_env(env) })
}*/

#[inline]
#[cfg(target_os = "linux")]
pub fn misc_setenv(
    handle: &mut ffi::pam_handle_t,
    name: &str,
    value: &str,
    readonly: bool,
) -> PamReturnCode {
    if let (Ok(name), Ok(value)) = (CString::new(name), CString::new(value)) {
        From::from(unsafe {
            ffi::pam_misc_setenv(
                handle,
                name.as_ptr(),
                value.as_ptr(),
                if readonly { 0 } else { 1 },
            )
        })
    } else {
        PamReturnCode::BUF_ERR
    }
}
/* ----------------------- ffi::pam_misc.h --------------------------- */

/* ----------------------- ffi::pam_modules.h ------------------------ */
#[inline]
pub fn set_data(
    handle: &mut ffi::pam_handle_t,
    module_data_name: &str,
    data: &mut c_void,
    cleanup: Option<unsafe extern "C" fn(*mut ffi::pam_handle_t, *mut c_void, c_int)>,
) -> PamReturnCode {
    if let Ok(module_data_name) = CString::new(module_data_name) {
        From::from(unsafe { ffi::pam_set_data(handle, module_data_name.as_ptr(), data, cleanup) })
    } else {
        PamReturnCode::BUF_ERR
    }
}

//pub fn get_data(handle: *const ffi::pam_handle_t, module_data_name: *const c_char, data: *const *const c_void);

pub fn get_user(
    handle: &ffi::pam_handle_t,
    user: &mut *const c_char,
    prompt: Option<&CStr>,
) -> PamReturnCode {
    From::from(unsafe {
        ffi::pam_get_user(
            // Bindgen generates *mut pam_handle_t but it should be *pam_handle_t
            std::mem::transmute(handle),
            user,
            prompt.map(|str| str.as_ptr()).unwrap_or(std::ptr::null()),
        )
    })
}

/* ----------------------- ffi::pam_modules.h ------------------------ */
