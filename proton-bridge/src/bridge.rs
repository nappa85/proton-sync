use crate::ffi_utils::cstr_to_string;
use proton_sync::{calendar::CalendarSyncEngine, SyncConfig, SyncEngine, SyncStatus};
use std::ffi::CString;
use std::os::raw::c_char;
use std::sync::{Arc, Mutex};

fn lock_or_recover<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|e| e.into_inner())
}

pub struct ProtonSyncEngine {
    inner: Arc<Mutex<Option<SyncEngine>>>,
    synced_contacts_json: Arc<Mutex<Option<String>>>,
}

#[repr(C)]
pub struct ProtonBridgeStatus {
    pub state: [u8; 16],
    pub state_truncated: bool,
    pub progress: f32,
    pub total_contacts: u32,
    pub synced_contacts: u32,
    pub error: [u8; 256],
    pub error_truncated: bool,
}

impl Default for ProtonBridgeStatus {
    fn default() -> Self {
        Self {
            state: [0; 16],
            state_truncated: false,
            progress: 0.0,
            total_contacts: 0,
            synced_contacts: 0,
            error: [0; 256],
            error_truncated: false,
        }
    }
}

impl ProtonBridgeStatus {
    fn from_sync_status(s: &SyncStatus) -> Self {
        let mut status = Self::default();
        let state_bytes = s.state.as_bytes();
        status.state_truncated = state_bytes.len() >= status.state.len();
        let copy_len = state_bytes.len().min(status.state.len() - 1);
        status.state[..copy_len].copy_from_slice(&state_bytes[..copy_len]);
        status.progress = s.progress;
        status.total_contacts = s.total_contacts;
        status.synced_contacts = s.synced_contacts;
        if let Some(ref err) = s.error {
            let err_bytes = err.as_bytes();
            status.error_truncated = err_bytes.len() >= status.error.len();
            let copy_len = err_bytes.len().min(status.error.len() - 1);
            status.error[..copy_len].copy_from_slice(&err_bytes[..copy_len]);
        }
        status
    }
}

#[no_mangle]
pub extern "C" fn proton_bridge_create_engine(
    username: *const c_char,
    password: *const c_char,
    access_token: *const c_char,
    refresh_token: *const c_char,
    uid: *const c_char,
    totp_code: *const c_char,
) -> *mut ProtonSyncEngine {
    proton_bridge_create_engine_with_derived(
        username,
        password,
        access_token,
        refresh_token,
        uid,
        totp_code,
        std::ptr::null(),
    )
}

#[no_mangle]
pub extern "C" fn proton_bridge_create_engine_with_derived(
    username: *const c_char,
    password: *const c_char,
    access_token: *const c_char,
    refresh_token: *const c_char,
    uid: *const c_char,
    totp_code: *const c_char,
    derived_passwords_json: *const c_char,
) -> *mut ProtonSyncEngine {
    let username = unsafe { cstr_to_string(username) };
    let password = unsafe { cstr_to_string(password) };
    let access_token_str = unsafe { cstr_to_string(access_token) };
    let refresh_token_str = unsafe { cstr_to_string(refresh_token) };
    let uid_str = unsafe { cstr_to_string(uid) };
    let totp_code_str = unsafe { cstr_to_string(totp_code) };
    let derived_json_str = unsafe { cstr_to_string(derived_passwords_json) };

    let derived_passwords = if derived_json_str.is_empty() {
        None
    } else {
        serde_json::from_str(&derived_json_str).ok()
    };

    let config = SyncConfig {
        username,
        password,
        derived_passwords,
        access_token: if access_token_str.is_empty() {
            None
        } else {
            Some(access_token_str)
        },
        refresh_token: if refresh_token_str.is_empty() {
            None
        } else {
            Some(refresh_token_str)
        },
        uid: if uid_str.is_empty() {
            None
        } else {
            Some(uid_str)
        },
        totp_code: if totp_code_str.is_empty() {
            None
        } else {
            Some(totp_code_str)
        },
        ..Default::default()
    };

    let engine = SyncEngine::new(config);
    Box::into_raw(Box::new(ProtonSyncEngine {
        inner: Arc::new(Mutex::new(Some(engine))),
        synced_contacts_json: Arc::new(Mutex::new(None)),
    }))
}

/// Full constructor for the wired contacts upsync cycle: inventory (shim
/// local-inventory JSON array), known UIDs (persisted ID-map keys JSON
/// array) and anchors (map JSON) feed the planner; empty/invalid strings
/// safely degrade to download-only.
#[no_mangle]
#[allow(clippy::too_many_arguments)]
pub extern "C" fn proton_bridge_create_engine_with_inventory(
    username: *const c_char,
    password: *const c_char,
    access_token: *const c_char,
    refresh_token: *const c_char,
    uid: *const c_char,
    totp_code: *const c_char,
    derived_passwords_json: *const c_char,
    inventory_json: *const c_char,
    known_uids_json: *const c_char,
    anchors_json: *const c_char,
) -> *mut ProtonSyncEngine {
    let username = unsafe { cstr_to_string(username) };
    let password = unsafe { cstr_to_string(password) };
    let access_token_str = unsafe { cstr_to_string(access_token) };
    let refresh_token_str = unsafe { cstr_to_string(refresh_token) };
    let uid_str = unsafe { cstr_to_string(uid) };
    let totp_code_str = unsafe { cstr_to_string(totp_code) };
    let derived_json_str = unsafe { cstr_to_string(derived_passwords_json) };
    let inventory_str = unsafe { cstr_to_string(inventory_json) };
    let known_str = unsafe { cstr_to_string(known_uids_json) };
    let anchors_str = unsafe { cstr_to_string(anchors_json) };

    let derived_passwords = if derived_json_str.is_empty() {
        None
    } else {
        serde_json::from_str(&derived_json_str).ok()
    };
    // Malformed inventory/anchors degrade to download-only (None), never
    // to a half-fed plan.
    let contact_inventory = if inventory_str.is_empty() {
        None
    } else {
        serde_json::from_str(&inventory_str).ok()
    };
    let contact_known_uids = if known_str.is_empty() {
        None
    } else {
        serde_json::from_str(&known_str).ok()
    };
    let contact_anchors = if anchors_str.is_empty() {
        None
    } else {
        serde_json::from_str(&anchors_str).ok()
    };

    let config = SyncConfig {
        username,
        password,
        derived_passwords,
        access_token: if access_token_str.is_empty() {
            None
        } else {
            Some(access_token_str)
        },
        refresh_token: if refresh_token_str.is_empty() {
            None
        } else {
            Some(refresh_token_str)
        },
        uid: if uid_str.is_empty() {
            None
        } else {
            Some(uid_str)
        },
        totp_code: if totp_code_str.is_empty() {
            None
        } else {
            Some(totp_code_str)
        },
        contact_inventory,
        contact_known_uids,
        contact_anchors,
        ..Default::default()
    };

    let engine = SyncEngine::new(config);
    Box::into_raw(Box::new(ProtonSyncEngine {
        inner: Arc::new(Mutex::new(Some(engine))),
        synced_contacts_json: Arc::new(Mutex::new(None)),
    }))
}

#[no_mangle]
pub extern "C" fn proton_bridge_destroy_engine(engine: *mut ProtonSyncEngine) {
    if !engine.is_null() {
        unsafe {
            drop(Box::from_raw(engine));
        }
    }
}

#[no_mangle]
pub extern "C" fn proton_bridge_start_sync(engine: *mut ProtonSyncEngine) -> bool {
    if engine.is_null() {
        return false;
    }
    let engine_ref = unsafe { &*engine };

    if let Some(mut inner_engine) = lock_or_recover(&engine_ref.inner).take() {
        let config = inner_engine.config().clone();
        let json_arc = Arc::clone(&engine_ref.synced_contacts_json);
        let inner_arc = Arc::clone(&engine_ref.inner);

        std::thread::spawn(move || {
            inner_engine.start_sync(config);
            let status = inner_engine.status();
            if status.state == "complete" {
                let json = inner_engine.get_contacts_json();
                *lock_or_recover(&json_arc) = Some(json);
            }
            *lock_or_recover(&inner_arc) = Some(inner_engine);
        });

        true
    } else {
        false
    }
}

#[no_mangle]
pub extern "C" fn proton_bridge_abort_sync(engine: *mut ProtonSyncEngine) {
    if engine.is_null() {
        return;
    }
    let engine_ref = unsafe { &*engine };
    if let Some(mut inner_engine) = lock_or_recover(&engine_ref.inner).take() {
        inner_engine.abort();
        *lock_or_recover(&engine_ref.inner) = Some(inner_engine);
    }
}

#[no_mangle]
pub extern "C" fn proton_bridge_get_status(
    engine: *mut ProtonSyncEngine,
    status: *mut ProtonBridgeStatus,
) {
    if engine.is_null() || status.is_null() {
        return;
    }
    let engine_ref = unsafe { &*engine };
    let s = lock_or_recover(&engine_ref.inner)
        .as_ref()
        .map(|e| e.status())
        .unwrap_or_default();

    let bridge_status = ProtonBridgeStatus::from_sync_status(&s);
    unsafe {
        *status = bridge_status;
    }
}

#[no_mangle]
pub extern "C" fn proton_bridge_get_synced_contacts_json(
    engine: *mut ProtonSyncEngine,
) -> *mut c_char {
    if engine.is_null() {
        return std::ptr::null_mut();
    }
    let engine_ref = unsafe { &*engine };
    let json = lock_or_recover(&engine_ref.synced_contacts_json).clone();
    match json {
        Some(s) => CString::new(s).unwrap().into_raw(),
        None => std::ptr::null_mut(),
    }
}

#[no_mangle]
pub extern "C" fn proton_bridge_free_string(s: *mut c_char) {
    if !s.is_null() {
        unsafe {
            drop(CString::from_raw(s));
        }
    }
}

#[no_mangle]
pub extern "C" fn proton_bridge_get_refresh_token(engine: *mut ProtonSyncEngine) -> *mut c_char {
    if engine.is_null() {
        return std::ptr::null_mut();
    }
    let engine_ref = unsafe { &*engine };
    let guard = lock_or_recover(&engine_ref.inner);
    match guard.as_ref() {
        Some(e) => match e.get_refresh_token() {
            Some(s) => CString::new(s).unwrap().into_raw(),
            None => std::ptr::null_mut(),
        },
        None => std::ptr::null_mut(),
    }
}

#[no_mangle]
pub extern "C" fn proton_bridge_get_uid(engine: *mut ProtonSyncEngine) -> *mut c_char {
    if engine.is_null() {
        return std::ptr::null_mut();
    }
    let engine_ref = unsafe { &*engine };
    let guard = lock_or_recover(&engine_ref.inner);
    match guard.as_ref() {
        Some(e) => match e.get_uid() {
            Some(s) => CString::new(s).unwrap().into_raw(),
            None => std::ptr::null_mut(),
        },
        None => std::ptr::null_mut(),
    }
}

#[no_mangle]
pub extern "C" fn proton_bridge_get_derived_passwords_json(
    engine: *mut ProtonSyncEngine,
) -> *mut c_char {
    if engine.is_null() {
        return std::ptr::null_mut();
    }
    let engine_ref = unsafe { &*engine };
    let guard = lock_or_recover(&engine_ref.inner);
    match guard.as_ref() {
        Some(e) => match e.get_derived_passwords_json() {
            Some(s) => CString::new(s).unwrap().into_raw(),
            None => std::ptr::null_mut(),
        },
        None => std::ptr::null_mut(),
    }
}

#[no_mangle]
pub extern "C" fn proton_bridge_get_keys_debug(engine: *mut ProtonSyncEngine) -> *mut c_char {
    if engine.is_null() {
        return std::ptr::null_mut();
    }
    let engine_ref = unsafe { &*engine };
    let guard = lock_or_recover(&engine_ref.inner);
    match guard.as_ref() {
        Some(e) => match e.get_keys_debug() {
            Some(s) => CString::new(s).unwrap().into_raw(),
            None => std::ptr::null_mut(),
        },
        None => std::ptr::null_mut(),
    }
}

/// Contacts upsync outputs (valid after `complete`): server-wins
/// conflicts (`[]` JSON, shim notifies) and merged anchors (null when
/// nothing known — caller must not overwrite a good cache with that).
#[no_mangle]
pub extern "C" fn proton_bridge_get_contact_conflicts_json(
    engine: *mut ProtonSyncEngine,
) -> *mut c_char {
    if engine.is_null() {
        return std::ptr::null_mut();
    }
    let engine_ref = unsafe { &*engine };
    let guard = lock_or_recover(&engine_ref.inner);
    match guard.as_ref() {
        Some(e) => CString::new(e.get_contact_conflicts_json())
            .unwrap()
            .into_raw(),
        None => std::ptr::null_mut(),
    }
}

/// Skipped uploads this run (`[]` JSON — IDs and reason codes only).
/// The shim appends the count to the sync notification and logs the
/// full list to the file log.
#[no_mangle]
pub extern "C" fn proton_bridge_get_contact_deferred_json(
    engine: *mut ProtonSyncEngine,
) -> *mut c_char {
    if engine.is_null() {
        return std::ptr::null_mut();
    }
    let engine_ref = unsafe { &*engine };
    let guard = lock_or_recover(&engine_ref.inner);
    match guard.as_ref() {
        Some(e) => CString::new(e.get_contact_deferred_json())
            .unwrap()
            .into_raw(),
        None => std::ptr::null_mut(),
    }
}

#[no_mangle]
pub extern "C" fn proton_bridge_get_contact_anchors_json(
    engine: *mut ProtonSyncEngine,
) -> *mut c_char {
    if engine.is_null() {
        return std::ptr::null_mut();
    }
    let engine_ref = unsafe { &*engine };
    let guard = lock_or_recover(&engine_ref.inner);
    match guard.as_ref() {
        Some(e) => {
            let s = e.get_contact_anchors_json();
            if s.is_empty() {
                std::ptr::null_mut()
            } else {
                CString::new(s).unwrap().into_raw()
            }
        }
        None => std::ptr::null_mut(),
    }
}

/// Posted-but-unconfirmed creates (`{qcontact_id: stable_uid}` JSON, null
/// when none). Valid after ANY run outcome — especially errors, where the
/// shim must still persist it wholesale as `contacts_pending` (never
/// merge: an empty return clears stale entries).
#[no_mangle]
pub extern "C" fn proton_bridge_get_contact_pending_json(
    engine: *mut ProtonSyncEngine,
) -> *mut c_char {
    if engine.is_null() {
        return std::ptr::null_mut();
    }
    let engine_ref = unsafe { &*engine };
    let guard = lock_or_recover(&engine_ref.inner);
    match guard.as_ref() {
        Some(e) => {
            let s = e.get_contact_pending_json();
            if s.is_empty() {
                std::ptr::null_mut()
            } else {
                CString::new(s).unwrap().into_raw()
            }
        }
        None => std::ptr::null_mut(),
    }
}

// ---- Calendar engine FFI (single .so, separate engine) ----
// Mirrors the contacts engine: derived passwords in, events JSON out.
pub struct ProtonCalendarEngine {
    inner: Arc<Mutex<Option<CalendarSyncEngine>>>,
    synced_events_json: Arc<Mutex<Option<String>>>,
}

/// FFI boundary unpacking: one String per C pointer by construction.
#[allow(clippy::too_many_arguments)]
fn calendar_config_from_parts(
    username: String,
    access_token: String,
    refresh_token: String,
    uid: String,
    derived_json: String,
    defaults_json: String,
    inventory_json: String,
    anchors_json: String,
) -> SyncConfig {
    let derived_passwords = if derived_json.is_empty() {
        None
    } else {
        serde_json::from_str(&derived_json).ok()
    };
    let calendar_defaults = if defaults_json.is_empty() {
        None
    } else {
        serde_json::from_str(&defaults_json).ok()
    };
    // Malformed inventory/anchors degrade to download-only (None), never
    // to a half-fed plan: a corrupt inventory must not drive uploads.
    let local_inventory = if inventory_json.is_empty() {
        None
    } else {
        serde_json::from_str(&inventory_json).ok()
    };
    let anchor_map = if anchors_json.is_empty() {
        None
    } else {
        serde_json::from_str(&anchors_json).ok()
    };
    SyncConfig {
        username,
        password: String::new(),
        derived_passwords,
        access_token: if access_token.is_empty() {
            None
        } else {
            Some(access_token)
        },
        refresh_token: if refresh_token.is_empty() {
            None
        } else {
            Some(refresh_token)
        },
        uid: if uid.is_empty() { None } else { Some(uid) },
        calendar_defaults,
        local_inventory,
        anchor_map,
        ..Default::default()
    }
}

#[no_mangle]
pub extern "C" fn proton_calendar_create_engine(
    username: *const c_char,
    access_token: *const c_char,
    refresh_token: *const c_char,
    uid: *const c_char,
) -> *mut ProtonCalendarEngine {
    proton_calendar_create_engine_with_derived(
        username,
        access_token,
        refresh_token,
        uid,
        std::ptr::null(),
    )
}
#[no_mangle]
pub extern "C" fn proton_calendar_create_engine_with_derived(
    username: *const c_char,
    access_token: *const c_char,
    refresh_token: *const c_char,
    uid: *const c_char,
    derived_passwords_json: *const c_char,
) -> *mut ProtonCalendarEngine {
    let username = unsafe { cstr_to_string(username) };
    let access_token = unsafe { cstr_to_string(access_token) };
    let refresh_token = unsafe { cstr_to_string(refresh_token) };
    let uid = unsafe { cstr_to_string(uid) };
    let derived_json = unsafe { cstr_to_string(derived_passwords_json) };
    let config = calendar_config_from_parts(
        username,
        access_token,
        refresh_token,
        uid,
        derived_json,
        String::new(),
        String::new(),
        String::new(),
    );
    let engine = CalendarSyncEngine::new(config);
    Box::into_raw(Box::new(ProtonCalendarEngine {
        inner: Arc::new(Mutex::new(Some(engine))),
        synced_events_json: Arc::new(Mutex::new(None)),
    }))
}
#[no_mangle]
pub extern "C" fn proton_calendar_create_engine_with_derived_and_defaults(
    username: *const c_char,
    access_token: *const c_char,
    refresh_token: *const c_char,
    uid: *const c_char,
    derived_passwords_json: *const c_char,
    defaults_json: *const c_char,
) -> *mut ProtonCalendarEngine {
    let username = unsafe { cstr_to_string(username) };
    let access_token = unsafe { cstr_to_string(access_token) };
    let refresh_token = unsafe { cstr_to_string(refresh_token) };
    let uid = unsafe { cstr_to_string(uid) };
    let derived_json = unsafe { cstr_to_string(derived_passwords_json) };
    let defaults_json = unsafe { cstr_to_string(defaults_json) };
    let config = calendar_config_from_parts(
        username,
        access_token,
        refresh_token,
        uid,
        derived_json,
        defaults_json,
        String::new(),
        String::new(),
    );
    let engine = CalendarSyncEngine::new(config);
    Box::into_raw(Box::new(ProtonCalendarEngine {
        inner: Arc::new(Mutex::new(Some(engine))),
        synced_events_json: Arc::new(Mutex::new(None)),
    }))
}
/// Full constructor for the wired upsync cycle: inventory (shim
/// `exportLocalInventory` JSON array) + anchors (persisted map JSON) feed
/// the planner; empty/invalid strings safely degrade to download-only.
#[no_mangle]
pub extern "C" fn proton_calendar_create_engine_with_inventory(
    username: *const c_char,
    access_token: *const c_char,
    refresh_token: *const c_char,
    uid: *const c_char,
    derived_passwords_json: *const c_char,
    defaults_json: *const c_char,
    inventory_json: *const c_char,
    anchors_json: *const c_char,
) -> *mut ProtonCalendarEngine {
    let username = unsafe { cstr_to_string(username) };
    let access_token = unsafe { cstr_to_string(access_token) };
    let refresh_token = unsafe { cstr_to_string(refresh_token) };
    let uid = unsafe { cstr_to_string(uid) };
    let derived_json = unsafe { cstr_to_string(derived_passwords_json) };
    let defaults_json = unsafe { cstr_to_string(defaults_json) };
    let inventory_json = unsafe { cstr_to_string(inventory_json) };
    let anchors_json = unsafe { cstr_to_string(anchors_json) };
    let config = calendar_config_from_parts(
        username,
        access_token,
        refresh_token,
        uid,
        derived_json,
        defaults_json,
        inventory_json,
        anchors_json,
    );
    let engine = CalendarSyncEngine::new(config);
    Box::into_raw(Box::new(ProtonCalendarEngine {
        inner: Arc::new(Mutex::new(Some(engine))),
        synced_events_json: Arc::new(Mutex::new(None)),
    }))
}
/// Restore an encrypted snapshot before start_sync. Invalid input is ignored,
/// forcing a full refresh rather than applying a partial cache.
#[no_mangle]
pub extern "C" fn proton_calendar_restore_snapshot(
    e: *mut ProtonCalendarEngine,
    json: *const c_char,
) {
    if e.is_null() {
        return;
    }
    let json = unsafe { cstr_to_string(json) };
    let eref = unsafe { &*e };
    if let Some(engine) = lock_or_recover(&eref.inner).as_mut() {
        engine.restore_snapshot(&json);
    }
}

#[no_mangle]
pub extern "C" fn proton_calendar_destroy_engine(e: *mut ProtonCalendarEngine) {
    if !e.is_null() {
        unsafe {
            drop(Box::from_raw(e));
        }
    }
}

/// Truncate-rotate a debug log file once it exceeds 1 MiB, keeping the
/// last 256 KiB (see `proton_api::diag::rotate_log_if_needed`). Retained
/// for compatibility; persistent daily logs do not call this helper.
/// Returns true only when a rotation happened; null/empty path is false.
#[no_mangle]
pub extern "C" fn proton_bridge_rotate_log(path: *const c_char) -> bool {
    let p = unsafe { cstr_to_string(path) };
    if p.is_empty() {
        return false;
    }
    proton_api::diag::rotate_log_if_needed(std::path::Path::new(&p), 1024 * 1024, 256 * 1024)
        .unwrap_or(false)
}
#[no_mangle]
pub extern "C" fn proton_calendar_start_sync(e: *mut ProtonCalendarEngine) -> bool {
    if e.is_null() {
        return false;
    }
    let eref = unsafe { &*e };
    if let Some(mut eng) = lock_or_recover(&eref.inner).take() {
        let config = eng.config();
        let json_arc = Arc::clone(&eref.synced_events_json);
        let inner = Arc::clone(&eref.inner);
        std::thread::spawn(move || {
            eng.start_sync(config);
            let status = eng.status();
            if status.state == "complete" {
                *lock_or_recover(&json_arc) = Some(eng.get_events_json());
            }
            *lock_or_recover(&inner) = Some(eng);
        });
        true
    } else {
        false
    }
}
#[no_mangle]
pub extern "C" fn proton_calendar_get_status(
    e: *mut ProtonCalendarEngine,
    s: *mut ProtonBridgeStatus,
) {
    if e.is_null() || s.is_null() {
        return;
    }
    let eref = unsafe { &*e };
    let st = eref
        .inner
        .lock()
        .unwrap()
        .as_ref()
        .map(|x| x.status())
        .unwrap_or_default();
    unsafe {
        *s = ProtonBridgeStatus::from_sync_status(&st);
    }
}

#[no_mangle]
pub extern "C" fn proton_calendar_get_events_json(e: *mut ProtonCalendarEngine) -> *mut c_char {
    if e.is_null() {
        return std::ptr::null_mut();
    }
    let eref = unsafe { &*e };
    // Prefer the snapshot taken at completion; fall back to the live engine.
    if let Some(s) = lock_or_recover(&eref.synced_events_json).clone() {
        return CString::new(s).unwrap().into_raw();
    }
    let guard = lock_or_recover(&eref.inner);
    match guard.as_ref() {
        Some(eng) => CString::new(eng.get_events_json()).unwrap().into_raw(),
        None => std::ptr::null_mut(),
    }
}

#[no_mangle]
pub extern "C" fn proton_calendar_get_keys_debug(e: *mut ProtonCalendarEngine) -> *mut c_char {
    if e.is_null() {
        return std::ptr::null_mut();
    }
    let eref = unsafe { &*e };
    let guard = lock_or_recover(&eref.inner);
    match guard.as_ref() {
        Some(eng) => match eng.get_keys_debug() {
            Some(s) => CString::new(s).unwrap().into_raw(),
            None => std::ptr::null_mut(),
        },
        None => std::ptr::null_mut(),
    }
}

#[no_mangle]
pub extern "C" fn proton_calendar_get_refresh_token(e: *mut ProtonCalendarEngine) -> *mut c_char {
    if e.is_null() {
        return std::ptr::null_mut();
    }
    let eref = unsafe { &*e };
    let guard = lock_or_recover(&eref.inner);
    match guard.as_ref().and_then(|eng| eng.get_refresh_token()) {
        Some(s) => CString::new(s).unwrap().into_raw(),
        None => std::ptr::null_mut(),
    }
}

#[no_mangle]
pub extern "C" fn proton_calendar_get_uid(e: *mut ProtonCalendarEngine) -> *mut c_char {
    if e.is_null() {
        return std::ptr::null_mut();
    }
    let eref = unsafe { &*e };
    let guard = lock_or_recover(&eref.inner);
    match guard.as_ref().and_then(|eng| eng.get_uid()) {
        Some(s) => CString::new(s).unwrap().into_raw(),
        None => std::ptr::null_mut(),
    }
}

/// Last-seen non-empty per-calendar reminder defaults as JSON, or null when
/// this run saw none (caller must not overwrite a good cache with that).
#[no_mangle]
pub extern "C" fn proton_calendar_get_defaults_json(e: *mut ProtonCalendarEngine) -> *mut c_char {
    if e.is_null() {
        return std::ptr::null_mut();
    }
    let eref = unsafe { &*e };
    let guard = lock_or_recover(&eref.inner);
    match guard.as_ref() {
        Some(eng) => {
            let s = eng.defaults_json();
            if s.is_empty() {
                std::ptr::null_mut()
            } else {
                CString::new(s).unwrap().into_raw()
            }
        }
        None => std::ptr::null_mut(),
    }
}

/// Upsync cycle outputs (valid after `complete`; `[]`/`{}`-shaped JSON, or
/// null when the engine is gone — never null-on-empty, so the shim can
/// distinguish "no data" from "engine missing").
fn calendar_engine_json(
    e: *mut ProtonCalendarEngine,
    pick: fn(&CalendarSyncEngine) -> String,
) -> *mut c_char {
    if e.is_null() {
        return std::ptr::null_mut();
    }
    let eref = unsafe { &*e };
    let guard = lock_or_recover(&eref.inner);
    match guard.as_ref() {
        Some(eng) => CString::new(pick(eng)).unwrap().into_raw(),
        None => std::ptr::null_mut(),
    }
}

/// mKCal UIDs whose tombstones may be purged (purge ONLY after their
/// deletes uploaded OK — the engine returns Err otherwise and this stays
/// stale from a previous run; the shim must only consume it on `complete`).
#[no_mangle]
pub extern "C" fn proton_calendar_get_purgeable_json(e: *mut ProtonCalendarEngine) -> *mut c_char {
    calendar_engine_json(e, CalendarSyncEngine::purgeable_json)
}

/// Commit only after the matching phone calendar save succeeds.
#[no_mangle]
pub extern "C" fn proton_calendar_get_snapshot_json(e: *mut ProtonCalendarEngine) -> *mut c_char {
    calendar_engine_json(e, CalendarSyncEngine::snapshot_json)
}

/// Server-wins conflicts this run (shim notifies; download overwrote them).
#[no_mangle]
pub extern "C" fn proton_calendar_get_conflicts_json(e: *mut ProtonCalendarEngine) -> *mut c_char {
    calendar_engine_json(e, CalendarSyncEngine::conflicts_json)
}

/// Merged anchor map, or null when nothing known (caller must not
/// overwrite a good cache with that — mirrors defaults_json).
#[no_mangle]
pub extern "C" fn proton_calendar_get_anchors_json(e: *mut ProtonCalendarEngine) -> *mut c_char {
    if e.is_null() {
        return std::ptr::null_mut();
    }
    let eref = unsafe { &*e };
    let guard = lock_or_recover(&eref.inner);
    match guard.as_ref() {
        Some(eng) => {
            let s = eng.anchors_json();
            if s.is_empty() {
                std::ptr::null_mut()
            } else {
                CString::new(s).unwrap().into_raw()
            }
        }
        None => std::ptr::null_mut(),
    }
}

/// Posted-but-unconfirmed creates (`{mKCal UID: stable event UID}` JSON,
/// null when none). Valid after ANY run outcome — especially errors, where
/// the shim must still persist it wholesale as `calendar_pending` (never
/// merge: an empty return clears stale entries).
#[no_mangle]
pub extern "C" fn proton_calendar_get_pending_json(e: *mut ProtonCalendarEngine) -> *mut c_char {
    if e.is_null() {
        return std::ptr::null_mut();
    }
    let eref = unsafe { &*e };
    let guard = lock_or_recover(&eref.inner);
    match guard.as_ref() {
        Some(eng) => {
            let s = eng.pending_json();
            if s.is_empty() {
                std::ptr::null_mut()
            } else {
                CString::new(s).unwrap().into_raw()
            }
        }
        None => std::ptr::null_mut(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn decode_state(status: &ProtonBridgeStatus) -> String {
        let len = status
            .state
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(status.state.len());
        String::from_utf8_lossy(&status.state[..len]).into_owned()
    }

    fn decode_error(status: &ProtonBridgeStatus) -> String {
        let len = status
            .error
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(status.error.len());
        String::from_utf8_lossy(&status.error[..len]).into_owned()
    }

    #[test]
    fn test_status_needs_2fa_round_trips_over_ffi() {
        let sync = SyncStatus {
            state: "needs_2fa".into(),
            error: Some("2FA verification required".into()),
            ..Default::default()
        };
        let bridge = ProtonBridgeStatus::from_sync_status(&sync);
        assert_eq!(decode_state(&bridge), "needs_2fa");
        assert!(!bridge.state_truncated);
        assert_eq!(decode_error(&bridge), "2FA verification required");
        assert!(!bridge.error_truncated);
    }

    #[test]
    fn test_status_error_round_trips_over_ffi() {
        let sync = SyncStatus {
            state: "error".into(),
            error: Some("Auth failed: bad password".into()),
            ..Default::default()
        };
        let bridge = ProtonBridgeStatus::from_sync_status(&sync);
        assert_eq!(decode_state(&bridge), "error");
        assert!(decode_error(&bridge).contains("bad password"));
    }

    #[test]
    fn test_status_truncation_detected() {
        let long_state = "a".repeat(20);
        let long_error = "e".repeat(300);
        let sync = SyncStatus {
            state: long_state,
            error: Some(long_error),
            ..Default::default()
        };
        let bridge = ProtonBridgeStatus::from_sync_status(&sync);
        assert!(bridge.state_truncated);
        assert!(bridge.error_truncated);
    }

    #[test]
    fn test_inventory_config_parses_and_degrades() {
        // Valid inventory + anchors feed the planner; malformed JSON
        // degrades to download-only (None) instead of a half-fed plan.
        let good = calendar_config_from_parts(
            "u".into(),
            String::new(),
            String::new(),
            String::new(),
            String::new(),
            String::new(),
            r#"[{"mkcal_uid":"n1","proton_id":"e1","deleted":false,"modified":false,"last_synced_mtime":100}]"#.into(),
            r#"{"e1":100}"#.into(),
        );
        let inv = good.local_inventory.expect("inventory parsed");
        assert_eq!(inv.len(), 1);
        assert_eq!(inv[0].mkcal_uid, "n1");
        assert_eq!(
            good.anchor_map.expect("anchors parsed").get("e1"),
            Some(&100)
        );
        let bad = calendar_config_from_parts(
            "u".into(),
            String::new(),
            String::new(),
            String::new(),
            String::new(),
            String::new(),
            "not-json".into(),
            "also-not-json".into(),
        );
        assert!(bad.local_inventory.is_none());
        assert!(bad.anchor_map.is_none());
    }
}
