//! SignOn plugin logic (method "proton", mechanism "password").
//!
//! signond merges the identity secret (UserName/Secret) and the previously
//! stored method blob (tokens) into the session data before invoking the
//! plugin, so the flow is fully driven by the input map:
//!
//! - TwoFactorPassword + locked tokens → complete the 2FA login.
//! - RefreshToken + Uid (and no fresh Password) → refresh, never prompt.
//! - Otherwise full SRP login with UserName/Password; a TOTP account returns
//!   `TwoFARequired` + locked-session tokens WITHOUT storing anything, and
//!   the caller re-invokes with `TwoFactorPassword`.
//! - Human verification (API 9001) returns `CaptchaRequired` + challenge.
//!
//! Tokens are persisted through `store`: signond keeps every property except
//! UserName/Secret in the per-identity blob, so later sessions (the sync
//! plugin) receive them. The raw password is never stored or echoed back;
//! when present it derives the mailbox passwords (DerivedPasswords), also
//! written to the settings groups of the Uid and username because signond
//! may drop unknown blob keys.
//!
//! The C++ plugin forwards the session map as JSON to
//! [`proton_signon_process`] and emits what comes back.

use crate::ffi_utils::{cstr_to_string, into_c_string};
use proton_api::{AuthClient, AuthTokens, LoginState, ProtonError};
use proton_sync::device::settings::SettingsPatch;
use serde::Serialize;
use serde_json::{Map, Value};
use std::os::raw::c_char;

/// Network side, swappable in tests.
pub trait Auth {
    fn login(
        &self,
        username: &str,
        password: &str,
        hv: Option<&str>,
    ) -> Result<LoginState, ProtonError>;
    fn submit_2fa(
        &self,
        code: &str,
        access: &str,
        refresh: &str,
        uid: &str,
        hv: Option<&str>,
    ) -> Result<AuthTokens, ProtonError>;
    fn refresh(&self, refresh: &str, uid: &str) -> Result<AuthTokens, ProtonError>;
    /// `{key id: base64 passphrase}`, empty on failure.
    fn derive(&self, password: &str, access: &str, uid: &str) -> Map<String, Value>;
}

impl Auth for AuthClient {
    fn login(
        &self,
        username: &str,
        password: &str,
        hv: Option<&str>,
    ) -> Result<LoginState, ProtonError> {
        AuthClient::login(self, username, password, hv)
    }
    fn submit_2fa(
        &self,
        code: &str,
        access: &str,
        refresh: &str,
        uid: &str,
        hv: Option<&str>,
    ) -> Result<AuthTokens, ProtonError> {
        AuthClient::submit_2fa(self, code, access, refresh, uid, hv)
    }
    fn refresh(&self, refresh: &str, uid: &str) -> Result<AuthTokens, ProtonError> {
        AuthClient::refresh(self, refresh, uid)
    }
    fn derive(&self, password: &str, access: &str, uid: &str) -> Map<String, Value> {
        match proton_api::keys::derive_all_passwords(password, access, uid) {
            Ok(map) => map
                .into_iter()
                .map(|(k, v)| (k, Value::String(v)))
                .collect(),
            Err(e) => {
                eprintln!("derive_all_passwords failed: {e}");
                Map::new()
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SignonError {
    /// `not_authorized` or `missing_data` (SignOn::Error type).
    pub code: &'static str,
    pub message: String,
}

#[derive(Debug, Default, Serialize)]
pub struct SignonOutcome {
    /// Properties to persist in the identity blob (`store` signal).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub store: Option<Map<String, Value>>,
    /// Session result (`result` signal).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Map<String, Value>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<SignonError>,
    #[serde(skip_serializing_if = "SettingsPatch::is_empty")]
    pub settings: SettingsPatch,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub log: Vec<String>,
}

impl SignonOutcome {
    fn error(code: &'static str, message: impl Into<String>) -> Self {
        SignonOutcome {
            error: Some(SignonError {
                code,
                message: message.into(),
            }),
            ..SignonOutcome::default()
        }
    }

    fn result(map: Map<String, Value>) -> Self {
        SignonOutcome {
            result: Some(map),
            ..SignonOutcome::default()
        }
    }
}

fn text(data: &Map<String, Value>, key: &str) -> String {
    match data.get(key) {
        Some(Value::String(s)) => s.clone(),
        _ => String::new(),
    }
}

fn put(map: &mut Map<String, Value>, key: &str, value: &str) {
    if !value.is_empty() {
        map.insert(key.into(), Value::String(value.into()));
    }
}

/// Human-verification challenge; `locked` adds the locked-session tokens
/// so the retry can go straight to the 2FA submit.
fn captcha(err: &ProtonError, locked: Option<(&str, &str, &str)>) -> Option<SignonOutcome> {
    let ProtonError::Captcha(c) = err else {
        return None;
    };
    let mut map = Map::new();
    map.insert("CaptchaRequired".into(), Value::Bool(true));
    map.insert("CaptchaUrl".into(), Value::String(c.web_url.clone()));
    map.insert("CaptchaMethods".into(), Value::String(c.methods_display()));
    map.insert("CaptchaToken".into(), Value::String(c.token.clone()));
    if let Some((access, refresh, uid)) = locked {
        map.insert("AccessToken".into(), Value::String(access.into()));
        map.insert("RefreshToken".into(), Value::String(refresh.into()));
        map.insert("Uid".into(), Value::String(uid.into()));
        map.insert("TwoFARequired".into(), Value::Bool(true));
    }
    let mut out = SignonOutcome::result(map);
    out.log.push("CAPTCHA required".into());
    Some(out)
}

fn authenticated(
    auth: &dyn Auth,
    tokens: &AuthTokens,
    username: &str,
    password: &str,
) -> SignonOutcome {
    let mut out = SignonOutcome::default();
    let mut map = Map::new();
    put(&mut map, "UserName", username);
    put(&mut map, "AccessToken", &tokens.access_token);
    put(&mut map, "RefreshToken", &tokens.refresh_token);
    put(&mut map, "Uid", &tokens.uid);
    // With the raw password at hand (creation / credentials update), derive
    // the mailbox passwords now so later syncs unlock keys without it.
    if !password.is_empty() && !tokens.access_token.is_empty() && !tokens.uid.is_empty() {
        let derived = auth.derive(password, &tokens.access_token, &tokens.uid);
        if derived.is_empty() {
            out.log.push("derive returned no keys".into());
        } else {
            let json = Value::Object(derived.clone()).to_string();
            out.log.push(format!("derived {} keys", derived.len()));
            map.insert("DerivedPasswords".into(), Value::String(json.clone()));
            for group in [&tokens.uid, &username.to_string()] {
                if !group.is_empty() {
                    out.settings.set(group, "derived_passwords", json.clone());
                }
            }
        }
    }
    out.store = Some(map.clone());
    out.result = Some(map);
    out
}

fn submit_2fa(
    auth: &dyn Auth,
    data: &Map<String, Value>,
    locked: (&str, &str, &str),
    code: &str,
    hv: Option<&str>,
) -> SignonOutcome {
    let (access, refresh, uid) = locked;
    match auth.submit_2fa(code, access, refresh, uid, hv) {
        Ok(tokens) => {
            let mut out = authenticated(auth, &tokens, &text(data, "UserName"), &password(data));
            out.log.push("2FA verified, session upgraded".into());
            out
        }
        Err(e) => captcha(&e, Some(locked))
            .unwrap_or_else(|| SignonOutcome::error("not_authorized", e.to_string())),
    }
}

/// Transient `Password` (creation/update) wins over the identity Secret,
/// which normally holds the dummy "x".
fn password(data: &Map<String, Value>) -> String {
    let param = text(data, "Password");
    if param.is_empty() {
        text(data, "Secret")
    } else {
        param
    }
}

pub fn process(auth: &dyn Auth, data: &Map<String, Value>) -> SignonOutcome {
    let username = text(data, "UserName");
    let fresh_password = !text(data, "Password").is_empty();
    let password = password(data);
    let refresh_token = text(data, "RefreshToken");
    let uid = text(data, "Uid");
    let code = text(data, "TwoFactorPassword").trim().to_string();
    let hv_token = text(data, "HumanVerificationToken").trim().to_string();
    let hv = (!hv_token.is_empty()).then_some(hv_token.as_str());
    let trace = format!(
        "process username={username} pw_len={} rt_present={} uid={uid} totp_len={} fresh_password={fresh_password} hv_token={}",
        password.chars().count(),
        !refresh_token.is_empty(),
        code.len(),
        hv.is_some()
    );

    let mut out = (|| {
        // 1) Second factor: complete the locked-session login.
        if !code.is_empty() && !refresh_token.is_empty() && !uid.is_empty() {
            let access = text(data, "AccessToken");
            if access.is_empty() {
                return SignonOutcome::error(
                    "missing_data",
                    "2FA code provided but no locked-session access token",
                );
            }
            return submit_2fa(auth, data, (&access, &refresh_token, &uid), &code, hv);
        }
        // 2) Stored tokens: refresh, never prompt — unless a fresh password
        //    came in (a refresh would hide a changed password / new 2FA).
        if !fresh_password && !refresh_token.is_empty() && !uid.is_empty() {
            match auth.refresh(&refresh_token, &uid) {
                Ok(tokens) => {
                    let mut out = authenticated(auth, &tokens, &username, &password);
                    out.log.push(format!("refreshed session for uid {uid}"));
                    return out;
                }
                // Never SRP with the dummy identity secret: that produces
                // misleading CAPTCHA challenges and needless logins.
                Err(e) if password.is_empty() || password == "x" => {
                    return SignonOutcome::error(
                        "not_authorized",
                        format!("Session refresh failed: {e}"),
                    );
                }
                Err(_) => {}
            }
        }
        // 3) Full SRP login.
        if username.is_empty() || password.is_empty() {
            return SignonOutcome::error("missing_data", "Username and password are required");
        }
        match auth.login(&username, &password, hv) {
            Ok(LoginState::Authenticated { tokens, .. }) => {
                authenticated(auth, &tokens, &username, &password)
            }
            Ok(LoginState::Requires2FA {
                access_token,
                refresh_token,
                uid,
                ..
            }) => {
                let locked = (access_token.as_str(), refresh_token.as_str(), uid.as_str());
                if !code.is_empty() {
                    return submit_2fa(auth, data, locked, &code, hv);
                }
                // Not stored: the session is unusable until the second
                // factor is verified; the UI asks for the code and retries.
                let mut map = Map::new();
                map.insert("TwoFARequired".into(), Value::Bool(true));
                map.insert("AccessToken".into(), Value::String(access_token.clone()));
                map.insert("RefreshToken".into(), Value::String(refresh_token.clone()));
                map.insert("Uid".into(), Value::String(uid.clone()));
                let mut out = SignonOutcome::result(map);
                out.log
                    .push("2FA required, returning locked session".into());
                out
            }
            Err(e) => captcha(&e, None)
                .unwrap_or_else(|| SignonOutcome::error("not_authorized", e.to_string())),
        }
    })();
    out.log.insert(0, trace);
    out
}

/// signond `refresh()`: stored tokens only.
pub fn refresh(auth: &dyn Auth, data: &Map<String, Value>) -> SignonOutcome {
    let refresh_token = text(data, "RefreshToken");
    let uid = text(data, "Uid");
    if refresh_token.is_empty() || uid.is_empty() {
        return SignonOutcome::error("missing_data", "No stored tokens to refresh");
    }
    match auth.refresh(&refresh_token, &uid) {
        Ok(tokens) => authenticated(auth, &tokens, &text(data, "UserName"), ""),
        Err(e) => SignonOutcome::error("not_authorized", e.to_string()),
    }
}

/// `input_json`: `{"mode": "process"|"refresh", "data": {session map}}`.
/// Returns the [`SignonOutcome`] JSON (free with `proton_string_free`).
#[no_mangle]
pub extern "C" fn proton_signon_process(input_json: *const c_char) -> *mut c_char {
    let input: Value =
        serde_json::from_str(&unsafe { cstr_to_string(input_json) }).unwrap_or_default();
    let data = input
        .get("data")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    let client = AuthClient::new();
    let out = if input.get("mode").and_then(Value::as_str) == Some("refresh") {
        refresh(&client, &data)
    } else {
        process(&client, &data)
    };
    into_c_string(serde_json::to_string(&out).unwrap_or_else(|_| "{}".into()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::cell::RefCell;

    #[derive(Default)]
    struct Fake {
        calls: RefCell<Vec<String>>,
        login_2fa: bool,
        login_captcha: bool,
        refresh_fails: bool,
    }

    fn tokens(tag: &str) -> AuthTokens {
        AuthTokens {
            access_token: format!("at-{tag}"),
            refresh_token: format!("rt-{tag}"),
            uid: format!("uid-{tag}"),
        }
    }

    fn hv_error() -> ProtonError {
        ProtonError::Captcha(proton_api::CaptchaChallenge {
            methods: vec!["captcha".into(), "email".into()],
            token: "secret-token".into(),
            web_url: "https://verify.proton.me/?token=secret-token".into(),
        })
    }

    impl Auth for Fake {
        fn login(&self, _: &str, _: &str, _: Option<&str>) -> Result<LoginState, ProtonError> {
            self.calls.borrow_mut().push("login".into());
            if self.login_captcha {
                return Err(hv_error());
            }
            let t = tokens("login");
            Ok(if self.login_2fa {
                LoginState::Requires2FA {
                    access_token: t.access_token,
                    refresh_token: t.refresh_token,
                    uid: t.uid,
                    scopes: vec![],
                }
            } else {
                LoginState::Authenticated {
                    tokens: t,
                    scopes: vec![],
                }
            })
        }
        fn submit_2fa(
            &self,
            code: &str,
            access: &str,
            _: &str,
            _: &str,
            _: Option<&str>,
        ) -> Result<AuthTokens, ProtonError> {
            self.calls.borrow_mut().push(format!("2fa:{code}:{access}"));
            Ok(tokens("2fa"))
        }
        fn refresh(&self, _: &str, _: &str) -> Result<AuthTokens, ProtonError> {
            self.calls.borrow_mut().push("refresh".into());
            if self.refresh_fails {
                Err(ProtonError::Auth("expired".into()))
            } else {
                Ok(tokens("refresh"))
            }
        }
        fn derive(&self, _: &str, _: &str, _: &str) -> Map<String, Value> {
            json!({"k": "p"}).as_object().unwrap().clone()
        }
    }

    fn data(v: Value) -> Map<String, Value> {
        v.as_object().unwrap().clone()
    }

    #[test]
    fn test_refresh_with_dummy_secret_never_logs_in() {
        let fake = Fake {
            refresh_fails: true,
            ..Fake::default()
        };
        let out = process(
            &fake,
            &data(json!({"UserName": "u", "Secret": "x", "RefreshToken": "r", "Uid": "i"})),
        );
        assert_eq!(out.error.unwrap().code, "not_authorized");
        assert_eq!(*fake.calls.borrow(), vec!["refresh"]);
    }

    #[test]
    fn test_fresh_password_logs_in_and_derives() {
        let fake = Fake::default();
        let out = process(
            &fake,
            &data(json!({"UserName": "u", "Password": "pw", "RefreshToken": "r", "Uid": "i"})),
        );
        assert_eq!(*fake.calls.borrow(), vec!["login"]);
        let store = out.store.unwrap();
        assert_eq!(store["AccessToken"], "at-login");
        assert!(store.contains_key("DerivedPasswords"));
        assert!(!store.contains_key("Password"));
        let settings = serde_json::to_value(&out.settings).unwrap();
        assert!(settings["uid-login"]["derived_passwords"].is_string());
        assert!(settings["u"]["derived_passwords"].is_string());
    }

    #[test]
    fn test_2fa_locked_session_then_code() {
        let fake = Fake {
            login_2fa: true,
            ..Fake::default()
        };
        let out = process(&fake, &data(json!({"UserName": "u", "Password": "pw"})));
        let result = out.result.unwrap();
        assert_eq!(result["TwoFARequired"], true);
        assert!(out.store.is_none());
        let out = process(
            &fake,
            &data(
                json!({"TwoFactorPassword": " 123456 ", "AccessToken": "locked", "RefreshToken": "r", "Uid": "i"}),
            ),
        );
        assert!(out.store.is_some());
        assert_eq!(fake.calls.borrow().last().unwrap(), "2fa:123456:locked");
        let out = process(
            &fake,
            &data(json!({"TwoFactorPassword": "1", "RefreshToken": "r", "Uid": "i"})),
        );
        assert_eq!(out.error.unwrap().code, "missing_data");
    }

    #[test]
    fn test_captcha_carries_challenge() {
        let fake = Fake {
            login_captcha: true,
            ..Fake::default()
        };
        let out = process(&fake, &data(json!({"UserName": "u", "Password": "pw"})));
        let result = out.result.unwrap();
        assert_eq!(result["CaptchaRequired"], true);
        assert_eq!(result["CaptchaMethods"], "captcha, email");
        assert_eq!(result["CaptchaToken"], "secret-token");
        assert!(out.store.is_none());
    }

    #[test]
    fn test_refresh_mode_needs_tokens() {
        let fake = Fake::default();
        assert_eq!(
            refresh(&fake, &Map::new()).error.unwrap().code,
            "missing_data"
        );
        let out = refresh(&fake, &data(json!({"RefreshToken": "r", "Uid": "i"})));
        assert_eq!(out.result.unwrap()["AccessToken"], "at-refresh");
    }
}
