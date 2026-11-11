use std::ffi::{CStr, CString};
use std::os::raw::c_char;

pub unsafe fn cstr_to_string(ptr: *const c_char) -> String {
    if ptr.is_null() {
        return String::new();
    }
    CStr::from_ptr(ptr).to_string_lossy().into_owned()
}

/// Heap C string for the caller to free with `proton_string_free`
/// (interior NULs, which JSON never contains unescaped, are dropped).
pub fn into_c_string(s: String) -> *mut c_char {
    CString::new(s.replace('\0', ""))
        .unwrap_or_default()
        .into_raw()
}
