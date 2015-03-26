#![feature(unique)]

extern crate libc;
extern crate c_vec;

extern crate pam_sys as ffi;

use libc::{calloc, free, c_char, c_int, c_void, size_t};
use c_vec::{CVec};

use std::mem;
use std::ptr::{self, Unique};
use std::ffi::{CStr, CString};

extern "C" fn conv(num_msg: c_int, msg: *mut *mut ffi::PamMessage,
    resp: *mut *mut ffi::PamResponse, appdata_ptr: *mut c_void) -> c_int {

    unsafe {
        // allocate space for responses
        *resp = calloc(num_msg as u64, mem::size_of::<ffi::PamResponse>() as size_t) as *mut ffi::PamResponse;
        if (*resp).is_null() {
            return ffi::PamReturnCode::BUF_ERR as c_int;
        }
    }

    // wrap function arguments for easier access
    let messages    : CVec<*mut ffi::PamMessage> = unsafe { CVec::new(Unique::new(msg), num_msg as usize) };
    let responses   : CVec<ffi::PamResponse>     = unsafe { CVec::new(Unique::new(*resp), num_msg as usize) };
    let data        : CVec<*const c_char>        = unsafe { CVec::new(Unique::new(appdata_ptr as *mut *const c_char), 2) };

    let mut result: ffi::PamReturnCode = ffi::PamReturnCode::SUCCESS;
    for i in 0..num_msg as usize {
        unsafe {
            // get indexed values
            let m: *mut ffi::PamMessage = match messages.get(i) {
                Some(m) => *m,
                None    => { result = ffi::PamReturnCode::CONV_ERR; break; }
            };
            let r: ffi::PamResponse = match responses.get(i) {
                Some(r) => *r,
                None    => { result = ffi::PamReturnCode::CONV_ERR; break; }
            };

            // match on msg_style
            match ffi::PamMessageStyle::from_i32((*m).msg_style) {
                // assume username is requested
                ffi::PamMessageStyle::PROMPT_ECHO_ON => {
                    let user_bytes = match data.get(0) {
                        Some(b) => CStr::from_ptr(*b).to_bytes_with_nul(),
                        None    => { result = ffi::PamReturnCode::CONV_ERR; break; }
                    };
                    ptr::copy(r.resp, user_bytes.as_ptr() as *const c_char, user_bytes.len());
                }
                // assume password is requested
                ffi::PamMessageStyle::PROMPT_ECHO_OFF => {
                    let password_bytes = match data.get(1) {
                        Some(b) => CStr::from_ptr(*b).to_bytes_with_nul(),
                        None    => { result = ffi::PamReturnCode::CONV_ERR; break; }
                    };
                    ptr::copy(r.resp, password_bytes.as_ptr() as *const c_char, password_bytes.len());
                }
                // an error occured
                ffi::PamMessageStyle::ERROR_MSG => {
                    //println!("Err: {}", CStr::from_ptr((*m).msg));    //TODO: print m->msg to stderr
                    result = ffi::PamReturnCode::CONV_ERR;
                }
                // print the message to stdout
                ffi::PamMessageStyle::TEXT_INFO => println!("{}", /*m.msg*/ "")
            }
        }
        if result != ffi::PamReturnCode::SUCCESS {
            break;
        }
    }

    // free allocated memory if an error occured
    if result != ffi::PamReturnCode::SUCCESS {
        unsafe { free(*resp as *mut c_void) };
        //*resp = ptr::null_mut() as *mut ffi::PamResponse;
    }

    result as c_int
}

pub fn login(service: &str, user: &str, password: &str) -> bool {
    let service = CString::new(service).unwrap();
    let user = CString::new(user).unwrap();
    let password = CString::new(password).unwrap();
    let mut creds: [*const c_char; 2] = [ptr::null(); 2];
    creds[0] = user.as_ptr();
    creds[1] = password.as_ptr();

    let conv = ffi::PamConversation{
        conv: Some(conv),
        data_ptr: creds.as_ptr() as *mut c_void
    };
    let mut handle: *mut ffi::PamHandle = ptr::null_mut();

    let mut res = unsafe { ffi::start(service.as_ptr(), user.as_ptr(), &conv, &mut handle) };
    println!("pam_start returned: {:?}", res);
    res = unsafe { ffi::authenticate(handle, ffi::PamFlag::NONE) };
    println!("pam_authenticate returned: {:?}", res);
    res = unsafe { ffi::acct_mgmt(handle, ffi::PamFlag::NONE) };
    println!("pam_acct_mgmt returned: {:?}", res);
    res = unsafe { ffi::setcred(handle, ffi::PamFlag::ESTABLISH_CRED) };
    println!("pam_setcred returned: {:?}", res);
    res = unsafe { ffi::open_session(handle, ffi::PamFlag::NONE) };
    println!("pam_setcred returned: {:?}", res);

    if res != ffi::PamReturnCode::SUCCESS {
        unsafe { ffi::setcred(handle, ffi::PamFlag::DELETE_CRED) };
        false
    }
    else {
        true
    }
}

#[test]
fn test() {
    use std::io;

    let service = "rdm".to_string();
    let user = "florian".to_string();
    let pa = Authenticator::new(&service, &user);
    let mut pa = match pa {
        Some(a) => {
            println!("Got Authenticator!");
            a
        },
        None    => panic!("failed to get Authenticator")
    };
    let res = pa.authenticate();
    println!("pam_authenticate returned: {}", res);
    /*let mut pw = String::new();
    match io::stdin().read_line(&mut pw) {
        Ok(_)   => println!("Got pw: {}", pw),
        Err(_)  => panic!("Failed to get pw!")
    };*/
}
