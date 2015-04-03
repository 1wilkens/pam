extern crate libc;
extern crate pam_sys as ffi;

use libc::{calloc, free, c_char, c_int, c_void, size_t};

use std::mem;
use std::slice;
use std::ptr;
use std::ffi::{CStr, CString};

extern "C" fn converse(num_msg: c_int, msg: *mut *mut ffi::PamMessage,
    resp: *mut *mut ffi::PamResponse, appdata_ptr: *mut c_void) -> c_int {
    unsafe {
        // allocate space for responses
        *resp = calloc(num_msg as u64, mem::size_of::<ffi::PamResponse>() as size_t) as *mut ffi::PamResponse;
        if (*resp).is_null() {
            return ffi::PamReturnCode::BUF_ERR as c_int;
        }
    }

    // wrap function arguments for easier access //TODO: might want to keep these for when CVec can be used in stable?
    //let messages    : CVec<*mut ffi::PamMessage> = unsafe { CVec::new(Unique::new(msg), num_msg as usize) };
    //let mut responses   : CVec<ffi::PamResponse> = unsafe { CVec::new(Unique::new(*resp), num_msg as usize) };
    let data            : &[&str]                = unsafe { slice::from_raw_parts(appdata_ptr as *const &str, 2) };

    let mut result: ffi::PamReturnCode = ffi::PamReturnCode::SUCCESS;
    for i in 0..num_msg as isize {
        unsafe {
            // get indexed values
            let m: &mut ffi::PamMessage = &mut **(msg.offset(i));
            let r: &mut ffi::PamResponse = &mut *((*resp).offset(i));
            // match on msg_style
            match ffi::PamMessageStyle::from_i32(m.msg_style) {
                // assume username is requested
                ffi::PamMessageStyle::PROMPT_ECHO_ON => {
                    strdup(data[0], &mut r.resp);
                }
                // assume password is requested
                ffi::PamMessageStyle::PROMPT_ECHO_OFF => {
                    strdup(data[1], &mut r.resp);
                }
                // an error occured
                ffi::PamMessageStyle::ERROR_MSG => {
                    println!("PAM_ERROR_MSG: {}", String::from_utf8_lossy(CStr::from_ptr(m.msg).to_bytes())); //TODO: simplify this?
                    result = ffi::PamReturnCode::CONV_ERR;
                }
                // print the message to stdout
                ffi::PamMessageStyle::TEXT_INFO => {
                    println!("PAM_TEXT_INFO: {}", String::from_utf8_lossy(CStr::from_ptr(m.msg).to_bytes()));
                }
            }
        }
        if result != ffi::PamReturnCode::SUCCESS {
            break;
        }
    }

    // free allocated memory if an error occured
    if result != ffi::PamReturnCode::SUCCESS {
        unsafe { free(*resp as *mut c_void) };
    }

    result as c_int
}

fn strdup(inp: &str, outp: &mut *mut c_char) {
    if !outp.is_null() {
        panic!("Cannot copy &str to non null ptr!");
    }
    let len_with_nul: usize = inp.bytes().len() + 1;
    unsafe {
        *outp = calloc(mem::size_of::<c_char>() as u64, len_with_nul as u64) as *mut c_char;  // allocate memory
        ptr::copy_nonoverlapping(inp.as_ptr() as *const c_char, *outp, len_with_nul - 1); // copy string bytes
    }
}

pub fn login(service: &str, user: &str, password: &str) -> bool {
    let creds: [&str; 2] = [user, password];
    let conv = ffi::PamConversation{
        conv: Some(converse),
        data_ptr: creds.as_ptr() as *mut c_void
    };
    let mut handle: *mut ffi::PamHandle = ptr::null_mut();

    let success = ffi::PamReturnCode::SUCCESS;
    let mut res = unsafe { ffi::start(CString::new(service).unwrap().as_ptr(), ptr::null(), &conv, &mut handle) };
    if res != success {
        return pam_fail(handle, "pam_start", res);
    }
    res = unsafe { ffi::authenticate(handle, ffi::PamFlag::NONE) };
    if res != success {
        return pam_fail(handle, "pam_authenticate", res);
    }
    res = unsafe { ffi::acct_mgmt(handle, ffi::PamFlag::NONE) };
    if res != success {
        return pam_fail(handle, "pam_acct_mgmt", res);
    }
    res = unsafe { ffi::setcred(handle, ffi::PamFlag::ESTABLISH_CRED) };
    if res != success {
        return pam_fail(handle, "pam_setcred", res);
    }
    res = unsafe { ffi::open_session(handle, ffi::PamFlag::NONE) };
    if res != success {
        return pam_fail(handle, "pam_open_session", res);
    }
    true
}

fn pam_fail(handle: *mut ffi::PamHandle, func: &str, res: ffi::PamReturnCode) -> bool {
    println!("{} returned: {:?}", func, res);
    unsafe {
        ffi::setcred(handle, ffi::PamFlag::DELETE_CRED);
        ffi::end(handle, 0);
    }
    false
}
