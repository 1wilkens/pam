// Copyright 2015-2017 pam-auth Developers
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use libc::{calloc, free, strdup, c_char, c_int, c_void, size_t};
use pam::{PamMessage, PamMessageStyle, PamResponse, PamReturnCode};

use std::ffi::CStr;
use std::mem;
use std::slice;

pub extern "C" fn converse(num_msg: c_int,
                           msg: *mut *mut PamMessage,
                           resp: *mut *mut PamResponse,
                           appdata_ptr: *mut c_void)
                           -> c_int {
    use std::ffi::CStr;
    use std::mem;
    use std::slice;

    unsafe {
        // allocate space for responses
        *resp = calloc(num_msg as usize, mem::size_of::<PamResponse>() as size_t) as
                *mut PamResponse;
        if (*resp).is_null() {
            return PamReturnCode::BUF_ERR as c_int;
        }
    }

    let data: &[&str] = unsafe { slice::from_raw_parts(appdata_ptr as *const &str, 2) };

    let mut result: PamReturnCode = PamReturnCode::SUCCESS;
    for i in 0..num_msg as isize {
        unsafe {
            // get indexed values
            let m: &mut PamMessage = &mut **(msg.offset(i));
            let r: &mut PamResponse = &mut *((*resp).offset(i));
            // match on msg_style
            match PamMessageStyle::from(m.msg_style) {
                // assume username is requested
                PamMessageStyle::PROMPT_ECHO_ON => {
                    r.resp = strdup(data[0].as_ptr() as *const c_char);
                }
                // assume password is requested
                PamMessageStyle::PROMPT_ECHO_OFF => {
                    r.resp = strdup(data[1].as_ptr() as *const c_char);
                }
                // an error occured
                PamMessageStyle::ERROR_MSG => {
                    result = PamReturnCode::CONV_ERR;
                }
                // print the message to stdout
                PamMessageStyle::TEXT_INFO => {
                    println!("PAM_TEXT_INFO: {}",
                             String::from_utf8_lossy(CStr::from_ptr(m.msg).to_bytes()));
                }
            }
        }
        if result != PamReturnCode::SUCCESS {
            break;
        }
    }

    // free allocated memory if an error occured
    if result != PamReturnCode::SUCCESS {
        unsafe { free(*resp as *mut c_void) };
    }

    result as c_int
}
