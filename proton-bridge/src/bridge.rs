//! Buteo plugin FFI: one opaque sync session per run, driven by JSON
//! messages (see `proton_sync::device::session` for the protocol). The C++
//! shim only executes the requests it gets back.

use crate::ffi_utils::{cstr_to_string, into_c_string};
use proton_sync::device::session::{Kind, Session};
use std::os::raw::c_char;
use std::sync::Mutex;

pub struct ProtonSync {
    session: Mutex<Session>,
}

/// `kind` is `"contacts"` or `"calendar"`; null on anything else.
#[no_mangle]
pub extern "C" fn proton_sync_new(
    kind: *const c_char,
    account_id: *const c_char,
) -> *mut ProtonSync {
    let kind = unsafe { cstr_to_string(kind) };
    let account = unsafe { cstr_to_string(account_id) };
    match Kind::parse(&kind) {
        Some(kind) if !account.is_empty() => Box::into_raw(Box::new(ProtonSync {
            session: Mutex::new(Session::new(kind, &account)),
        })),
        _ => std::ptr::null_mut(),
    }
}

/// Feed one input message, get the next outcome (JSON, free with
/// `proton_string_free`). Never null for a valid session.
#[no_mangle]
pub extern "C" fn proton_sync_step(
    sync: *mut ProtonSync,
    input_json: *const c_char,
) -> *mut c_char {
    if sync.is_null() {
        return std::ptr::null_mut();
    }
    let input = unsafe { cstr_to_string(input_json) };
    let sync = unsafe { &*sync };
    let outcome = sync
        .session
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .step(&input);
    into_c_string(serde_json::to_string(&outcome).unwrap_or_else(|_| "{}".into()))
}

/// A running engine thread keeps its own handles and finishes on its own.
#[no_mangle]
pub extern "C" fn proton_sync_free(sync: *mut ProtonSync) {
    if !sync.is_null() {
        unsafe {
            drop(Box::from_raw(sync));
        }
    }
}

#[no_mangle]
pub extern "C" fn proton_string_free(s: *mut c_char) {
    if !s.is_null() {
        unsafe {
            drop(std::ffi::CString::from_raw(s));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::{CStr, CString};

    #[test]
    fn test_ffi_round_trip() {
        let kind = CString::new("contacts").unwrap();
        let account = CString::new("7").unwrap();
        assert!(
            proton_sync_new(CString::new("mail").unwrap().as_ptr(), account.as_ptr()).is_null()
        );
        let sync = proton_sync_new(kind.as_ptr(), account.as_ptr());
        assert!(!sync.is_null());
        let input = CString::new(r#"{"begin":{"credentials":{"CaptchaRequired":true}}}"#).unwrap();
        let out = proton_sync_step(sync, input.as_ptr());
        let text = unsafe { CStr::from_ptr(out) }
            .to_string_lossy()
            .into_owned();
        assert!(text.contains("\"auth_failure\":true"), "{text}");
        proton_string_free(out);
        proton_sync_free(sync);
    }
}
