// Copyright (C) 2015 Florian Wilkens
//
// Permission is hereby granted, free of charge, to any person obtaining a copy of this software and
// associated documentation files (the "Software"), to deal in the Software without restriction,
// including without limitation the rights to use, copy, modify, merge, publish, distribute,
// sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all copies or substantial
// portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT
// NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
// NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES
// OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
// CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

use libc::{calloc, free, c_char, c_int, c_void, size_t};
use pam::{PamMessage, PamMessageStyle, PamResponse, PamReturnCode};

pub extern "C" fn converse(num_msg: c_int, msg: *mut *mut PamMessage,
    resp: *mut *mut PamResponse, appdata_ptr: *mut c_void) -> c_int {
    use std::ffi::CStr;
    use std::mem;
    use std::slice;

    unsafe {
        // allocate space for responses
        *resp = calloc(num_msg as u64, mem::size_of::<PamResponse>() as size_t) as *mut PamResponse;
        if (*resp).is_null() {
            return PamReturnCode::BUF_ERR as c_int;
        }
    }

    let data : &[&str] = unsafe { slice::from_raw_parts(appdata_ptr as *const &str, 2) };

    let mut result: PamReturnCode = PamReturnCode::SUCCESS;
    for i in 0..num_msg as isize {
        unsafe {
            // get indexed values
            let m: &mut PamMessage = &mut **(msg.offset(i));
            let r: &mut PamResponse = &mut *((*resp).offset(i));
            // match on msg_style
            match PamMessageStyle::from_i32(m.msg_style) {
                // assume username is requested
                PamMessageStyle::PROMPT_ECHO_ON => {
                    strdup(data[0], &mut r.resp);
                }
                // assume password is requested
                PamMessageStyle::PROMPT_ECHO_OFF => {
                    strdup(data[1], &mut r.resp);
                }
                // an error occured
                PamMessageStyle::ERROR_MSG => {
                    println!("PAM_ERROR_MSG: {}", String::from_utf8_lossy(CStr::from_ptr(m.msg).to_bytes())); //TODO: simplify this?
                    result = PamReturnCode::CONV_ERR;
                }
                // print the message to stdout
                PamMessageStyle::TEXT_INFO => {
                    println!("PAM_TEXT_INFO: {}", String::from_utf8_lossy(CStr::from_ptr(m.msg).to_bytes()));
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

/// Dumb utility function mirroring glibc's strdup
fn strdup(inp: &str, outp: &mut *mut c_char) {
    use std::mem;
    use std::ptr;

    if !outp.is_null() {
        panic!("Cannot copy &str to non null ptr!");
    }
    let len_with_nul: usize = inp.bytes().len() + 1;
    unsafe {
        *outp = calloc(mem::size_of::<c_char>() as u64, len_with_nul as u64) as *mut c_char;  // allocate memory
        ptr::copy_nonoverlapping(inp.as_ptr() as *const c_char, *outp, len_with_nul - 1); // copy string bytes
    }
}
