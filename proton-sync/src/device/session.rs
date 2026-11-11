//! One sync run as a request/response state machine the shim drives.
//!
//! The shim feeds [`Input`]s (credentials + settings, local dumps, avatar
//! conversions, write results, polls) and executes the [`Request`] of each
//! [`Outcome`] (dump local data, convert avatars, apply a write plan, poll
//! later), applying settings patches, writing log lines and showing
//! notices along the way, until an outcome carries a [`Finish`].

use super::calendar as cal;
use super::contacts as con;
use super::settings::{Settings, SettingsPatch};
use crate::calendar::CalendarSyncEngine;
use crate::{SyncConfig, SyncEngine};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::{Arc, Mutex};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Contacts,
    Calendar,
}

impl Kind {
    pub fn parse(s: &str) -> Option<Kind> {
        match s {
            "contacts" => Some(Kind::Contacts),
            "calendar" => Some(Kind::Calendar),
            _ => None,
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Input {
    /// SignOn session properties and every settings group.
    Begin {
        credentials: Map<String, Value>,
        #[serde(default)]
        settings: Settings,
    },
    /// Local dump (contacts: array; calendar: `{notebooks, events}`).
    Local {
        ok: bool,
        #[serde(default)]
        error: String,
        #[serde(default)]
        data: Value,
    },
    /// Avatar source → data URI (`""` when unreadable).
    Avatars {
        data: BTreeMap<String, String>,
    },
    Poll {},
    /// Write plan result (contacts: `{saved: [...]}`; calendar:
    /// `{last_modified: {uid: msecs}}`).
    Written {
        ok: bool,
        #[serde(default)]
        error: String,
        #[serde(default)]
        data: Value,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Request {
    /// Dump local data and answer with [`Input::Local`].
    Local,
    /// Convert these avatar files to data URIs ([`Input::Avatars`]).
    Avatars { sources: Vec<String> },
    /// Answer with [`Input::Poll`] after this delay.
    Poll { after_ms: u32 },
    /// Apply the plan and answer with [`Input::Written`].
    Write { plan: Value },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Notice {
    pub summary: String,
    pub body: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Finish {
    pub ok: bool,
    pub message: String,
    /// Report as an authentication failure (Settings then offers to update
    /// the credentials) instead of an internal error.
    pub auth_failure: bool,
}

#[derive(Debug, Default, Serialize)]
pub struct Outcome {
    #[serde(skip_serializing_if = "SettingsPatch::is_empty")]
    pub settings: SettingsPatch,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub log: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub notices: Vec<Notice>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request: Option<Request>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Finish>,
}

impl Outcome {
    fn notice(&mut self, summary: &str, body: impl Into<String>) {
        let body = body.into();
        self.log.push(format!("Notification: {summary} – {body}"));
        self.notices.push(Notice {
            summary: summary.into(),
            body,
        });
    }

    fn finish(&mut self, ok: bool, message: impl Into<String>, auth_failure: bool) {
        self.result = Some(Finish {
            ok,
            message: message.into(),
            auth_failure,
        });
    }
}

enum EngineBox {
    Contacts(SyncEngine),
    Calendar(CalendarSyncEngine),
}

/// Engine outputs the write phase needs.
#[derive(Default)]
struct Done {
    rows: String,
    confirmed: BTreeMap<String, String>,
    /// Engine retry UIDs (persisted alone once the write succeeded).
    pending: String,
    purgeable: BTreeSet<String>,
    snapshot: String,
}

enum Stage {
    Fresh,
    StartLocal(Box<SyncConfig>),
    Avatars(Box<SyncConfig>, Vec<con::LocalContact>),
    Running(Arc<Mutex<Option<EngineBox>>>),
    WriteLocal(Done),
    ContactsWritten(con::WriteContext, Done),
    CalendarWritten(cal::WriteContext, Done),
    Finished,
}

pub struct Session {
    kind: Kind,
    account: String,
    settings: Settings,
    stage: Stage,
    api_base_url: Option<String>,
}

const POLL_MS: u32 = 500;

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn json_map(raw: &str) -> BTreeMap<String, String> {
    serde_json::from_str::<BTreeMap<String, Value>>(raw)
        .unwrap_or_default()
        .into_iter()
        .filter_map(|(k, v)| v.as_str().map(|s| (k, s.to_string())))
        .collect()
}

fn array_len(raw: &str) -> usize {
    serde_json::from_str::<Vec<Value>>(raw).map_or(0, |a| a.len())
}

impl Session {
    pub fn new(kind: Kind, account: &str) -> Self {
        Session {
            kind,
            account: account.to_string(),
            settings: Settings::default(),
            stage: Stage::Fresh,
            api_base_url: None,
        }
    }

    /// Point the engines at another API host (tests).
    pub fn set_api_base_url(&mut self, url: &str) {
        self.api_base_url = Some(url.to_string());
    }

    fn label(&self) -> &'static str {
        match self.kind {
            Kind::Contacts => "Contacts",
            Kind::Calendar => "Calendar",
        }
    }

    /// Feed one input; never panics on malformed input (the run fails).
    pub fn step(&mut self, input: &str) -> Outcome {
        let mut out = match serde_json::from_str::<Input>(input) {
            Ok(input) => self.handle(input),
            Err(e) => {
                let mut out = Outcome::default();
                out.log.push(format!("Malformed shim input: {e}"));
                out.finish(false, "Internal error", false);
                out
            }
        };
        if out.result.is_some() {
            self.stage = Stage::Finished;
        }
        self.settings.apply(&out.settings);
        // Keep the log readable even for big traces.
        for line in &mut out.log {
            if line.len() > 8000 {
                *line = con::truncate(line, 8000);
            }
        }
        out
    }

    fn handle(&mut self, input: Input) -> Outcome {
        let stage = std::mem::replace(&mut self.stage, Stage::Finished);
        match (stage, input) {
            (
                Stage::Fresh,
                Input::Begin {
                    credentials,
                    settings,
                },
            ) => {
                self.settings = settings;
                self.begin(&credentials)
            }
            (Stage::StartLocal(config), Input::Local { ok, error, data }) => {
                self.start_local(*config, ok, &error, data)
            }
            (Stage::Avatars(config, local), Input::Avatars { data }) => {
                let mut out = Outcome::default();
                self.start_contacts(*config, Some(&local), &data, &mut out);
                out
            }
            (Stage::Running(slot), Input::Poll {}) => self.poll(slot),
            (Stage::WriteLocal(done), Input::Local { ok, error, data }) => {
                self.write_local(done, ok, &error, data)
            }
            (Stage::ContactsWritten(ctx, done), Input::Written { ok, error, data }) => {
                self.contacts_written(&ctx, &done, ok, &error, &data)
            }
            (Stage::CalendarWritten(ctx, done), Input::Written { ok, error, data }) => {
                self.calendar_written(&ctx, &done, ok, &error, &data)
            }
            (stage, _) => {
                let mut out = Outcome::default();
                if let Stage::Running(slot) = stage {
                    // Keep the engine; the shim may just poll again.
                    self.stage = Stage::Running(slot);
                    out.request = Some(Request::Poll { after_ms: POLL_MS });
                    return out;
                }
                out.log
                    .push("Unexpected shim input for this sync stage".into());
                out.finish(false, "Internal error", false);
                out
            }
        }
    }

    // ---- credentials ----

    fn begin(&mut self, creds: &Map<String, Value>) -> Outcome {
        let mut out = Outcome::default();
        let text = |k: &str| match creds.get(k) {
            Some(Value::String(s)) => s.clone(),
            _ => String::new(),
        };
        let flag = |k: &str| match creds.get(k) {
            Some(Value::Bool(b)) => *b,
            Some(Value::String(s)) => s == "true",
            _ => false,
        };
        if flag("CaptchaRequired") {
            let msg = "Proton human verification required – please update credentials in Settings → Proton";
            out.log.push(msg.into());
            out.finish(false, msg, true);
            return out;
        }
        // The sync plugin runs without UI: a locked 2FA session needs the
        // user to update credentials (and enter the OTP) in Settings.
        if flag("TwoFARequired") {
            out.log
                .push("2FA required but no UI allowed in sync session".into());
            out.finish(
                false,
                "Two-factor authentication required – please update credentials in Settings → Proton and enter OTP code",
                true,
            );
            return out;
        }
        let account = self.account.clone();
        let username = text("UserName");
        let mut password = text("Secret");
        if password.is_empty() {
            password = text("Password");
        }
        let access_token = text("AccessToken");
        let mut refresh_token = text("RefreshToken");
        let mut uid = text("Uid");
        if refresh_token.is_empty() {
            refresh_token = self.settings.get(&account, "refresh_token").to_string();
        }
        if uid.is_empty() {
            uid = self.settings.get(&account, "uid").to_string();
        }
        let blob = text("DerivedPasswords");
        let derived = self.merged_derived(&username, &uid, &blob, &mut out.log);
        let present = |s: &str| if s.is_empty() { "(none)" } else { "(present)" };
        out.log.push(format!(
            "{} credentials: username={} pw_len={} access_token={} refresh_token={} uid={} derived={}",
            self.label(),
            username,
            password.chars().count(),
            present(&access_token),
            present(&refresh_token),
            if uid.is_empty() { "(none)" } else { &uid },
            if derived.is_empty() {
                "(none)".to_string()
            } else {
                format!("{} keys", derived.len())
            },
        ));
        if access_token.is_empty() && refresh_token.is_empty() {
            out.finish(false, "No auth tokens received", true);
            return out;
        }
        let non_empty = |s: String| (!s.is_empty()).then_some(s);
        let mut config = SyncConfig {
            account_id: account.clone(),
            username,
            password: if self.kind == Kind::Contacts {
                password
            } else {
                String::new()
            },
            derived_passwords: (!derived.is_empty()).then(|| derived.into_iter().collect()),
            access_token: non_empty(access_token),
            refresh_token: non_empty(refresh_token),
            uid: non_empty(uid),
            api_base_url: self.api_base_url.clone(),
            ..SyncConfig::default()
        };
        if self.kind == Kind::Calendar {
            let defaults = self.settings.get(&account, cal::DEFAULTS);
            if !defaults.is_empty() {
                config.calendar_defaults = serde_json::from_str(defaults).ok();
            }
        }
        self.stage = Stage::StartLocal(Box::new(config));
        out.request = Some(Request::Local);
        out
    }

    /// DerivedPasswords from every known source. Different logins stored
    /// single-key maps in different groups (account / username / Uid), and
    /// the SignOn blob is wiped to tokens-only on every refresh: first-hit-
    /// wins shadowed keys, so union them (every entry was verified by
    /// trial-unlock at login). Later sources win on conflict.
    fn merged_derived(
        &self,
        username: &str,
        uid: &str,
        blob: &str,
        log: &mut Vec<String>,
    ) -> BTreeMap<String, String> {
        let mut merged = BTreeMap::new();
        let mut used = Vec::new();
        let sources = [
            (
                "accountId",
                self.settings.get(&self.account, "derived_passwords"),
            ),
            ("username", self.settings.get(username, "derived_passwords")),
            ("Uid", self.settings.get(uid, "derived_passwords")),
            ("blob", blob),
        ];
        for (name, raw) in sources {
            if (name == "username" && username.is_empty()) || (name == "Uid" && uid.is_empty()) {
                continue;
            }
            let map = json_map(raw);
            if map.is_empty() {
                continue;
            }
            used.push(format!("{name}({})", map.len()));
            merged.extend(map);
        }
        if !used.is_empty() {
            log.push(format!("Merged DerivedPasswords from {}", used.join("+")));
        }
        merged
    }

    // ---- start ----

    fn start_local(&mut self, config: SyncConfig, ok: bool, error: &str, data: Value) -> Outcome {
        let mut out = Outcome::default();
        if !ok {
            // Unreadable local store: download-only (no uploads, no deletes).
            out.log.push(format!(
                "{} local store unreadable ({error}); download only",
                self.label()
            ));
        }
        match self.kind {
            Kind::Contacts => {
                let local: Option<Vec<con::LocalContact>> = if ok {
                    match serde_json::from_value(data) {
                        Ok(local) => Some(local),
                        Err(e) => {
                            out.log
                                .push(format!("Contacts dump malformed ({e}); download only"));
                            None
                        }
                    }
                } else {
                    None
                };
                if let Some(local) = &local {
                    let sources = con::avatars_needed(&self.settings, &self.account, local);
                    if !sources.is_empty() {
                        self.stage = Stage::Avatars(Box::new(config), local.clone());
                        out.request = Some(Request::Avatars { sources });
                        return out;
                    }
                }
                self.start_contacts(config, local.as_deref(), &BTreeMap::new(), &mut out);
            }
            Kind::Calendar => {
                let local: Option<cal::LocalCalendar> = if ok {
                    match serde_json::from_value(data) {
                        Ok(local) => Some(local),
                        Err(e) => {
                            out.log
                                .push(format!("Calendar dump malformed ({e}); download only"));
                            None
                        }
                    }
                } else {
                    None
                };
                self.start_calendar(config, local.as_ref(), &mut out);
            }
        }
        out
    }

    fn start_contacts(
        &mut self,
        mut config: SyncConfig,
        local: Option<&[con::LocalContact]>,
        avatars: &BTreeMap<String, String>,
        out: &mut Outcome,
    ) {
        if let Some(local) = local {
            let inv = con::inventory(&self.settings, &self.account, local, avatars);
            out.log.extend(inv.log);
            config.contact_inventory = Some(inv.items);
            config.contact_known_uids = Some(inv.known_uids);
            if !self.settings.get(&self.account, con::ANCHORS).is_empty() {
                config.contact_anchors = Some(inv.anchors);
            }
        }
        let engine = SyncEngine::new(config.clone());
        self.spawn(EngineBox::Contacts(engine), config, out);
    }

    fn start_calendar(
        &mut self,
        mut config: SyncConfig,
        local: Option<&cal::LocalCalendar>,
        out: &mut Outcome,
    ) {
        if let Some(local) = local {
            let inv = cal::inventory(&self.settings, &self.account, &local.events);
            out.log.push(format!(
                "Calendar inventory: {} live/tombstone rows",
                inv.len()
            ));
            config.local_inventory = Some(inv);
            if !self.settings.get(&self.account, cal::ANCHORS).is_empty() {
                config.anchor_map = Some(
                    self.settings
                        .int_map(&self.account, cal::ANCHORS)
                        .into_iter()
                        .collect::<HashMap<_, _>>(),
                );
            }
        }
        let mut engine = CalendarSyncEngine::new(config.clone());
        engine.restore_snapshot(self.settings.get(&self.account, cal::SNAPSHOT));
        let config = engine.config();
        self.spawn(EngineBox::Calendar(engine), config, out);
    }

    fn spawn(&mut self, engine: EngineBox, config: SyncConfig, out: &mut Outcome) {
        let slot = Arc::new(Mutex::new(None));
        let back = Arc::clone(&slot);
        std::thread::spawn(move || {
            let engine = match engine {
                EngineBox::Contacts(mut e) => {
                    e.start_sync(config);
                    EngineBox::Contacts(e)
                }
                EngineBox::Calendar(mut e) => {
                    e.start_sync(config);
                    EngineBox::Calendar(e)
                }
            };
            *lock(&back) = Some(engine);
        });
        self.stage = Stage::Running(slot);
        out.request = Some(Request::Poll { after_ms: POLL_MS });
    }

    // ---- engine finished ----

    fn poll(&mut self, slot: Arc<Mutex<Option<EngineBox>>>) -> Outcome {
        let mut out = Outcome::default();
        let Some(engine) = lock(&slot).take() else {
            self.stage = Stage::Running(slot);
            out.request = Some(Request::Poll { after_ms: POLL_MS });
            return out;
        };
        match engine {
            EngineBox::Contacts(e) => self.contacts_done(&e, &mut out),
            EngineBox::Calendar(e) => self.calendar_done(&e, &mut out),
        }
        out
    }

    fn persist_tokens(&self, rt: Option<String>, uid: Option<String>, out: &mut Outcome) {
        if let (Some(rt), Some(uid)) = (rt, uid) {
            if !rt.is_empty() && !uid.is_empty() {
                out.settings.set(&self.account, "refresh_token", rt);
                out.settings.set(&self.account, "uid", uid);
                out.log
                    .push(format!("Persisted tokens for account {}", self.account));
            }
        }
    }

    /// Retry UIDs persisted wholesale (never merged: empty clears stale
    /// entries).
    fn persist_pending(&self, key: &str, map: &BTreeMap<String, String>, out: &mut Outcome) {
        let value = if map.is_empty() {
            String::new()
        } else {
            serde_json::to_string(map).unwrap_or_default()
        };
        if !value.is_empty() {
            out.log.push(format!(
                "Persisted {} pending: {}",
                self.label().to_lowercase(),
                con::truncate(&value, 2000)
            ));
        }
        out.settings.set(&self.account, key, value);
    }

    fn contacts_done(&mut self, e: &SyncEngine, out: &mut Outcome) {
        let status = e.status();
        let pending = json_map(&e.get_contact_pending_json());
        self.persist_tokens(e.get_refresh_token(), e.get_uid(), out);
        let keys_debug = e.get_keys_debug().unwrap_or_default();
        let error = status.error.clone().unwrap_or_default();
        match status.state.as_str() {
            "complete" => {
                if let Some(derived) = e.get_derived_passwords_json() {
                    if !derived.is_empty() && derived != "null" {
                        out.settings
                            .set(&self.account, "derived_passwords", derived);
                        out.log.push(format!(
                            "Persisted derived passwords for account {}",
                            self.account
                        ));
                    }
                }
                out.log.push(format!("Keys debug: {keys_debug}"));
                let anchors = e.get_contact_anchors_json();
                if !anchors.is_empty() {
                    out.log.push(format!(
                        "Persisted contacts anchors: {}",
                        con::truncate(&anchors, 2000)
                    ));
                    out.settings.set(&self.account, con::ANCHORS, anchors);
                }
                // Confirmed uploads of phone-only rows stay retry UIDs until
                // the local write succeeds: if it fails, the next cycle
                // re-posts under the same UID and adopts (never a second
                // server copy).
                let confirmed = json_map(&e.get_contact_confirmed_json());
                let mut retry = pending.clone();
                retry.extend(confirmed.clone());
                self.persist_pending(con::PENDING, &retry, out);
                let mut parts = Vec::new();
                let conflicts = array_len(&e.get_contact_conflicts_json());
                if conflicts > 0 {
                    parts.push(format!(
                        "{conflicts} contacts changed on both sides; server version kept"
                    ));
                }
                let deferred_json = e.get_contact_deferred_json();
                let deferred = array_len(&deferred_json);
                if deferred > 0 {
                    out.log.push(format!(
                        "Contacts deferred uploads: {}",
                        con::truncate(&deferred_json, 2000)
                    ));
                    parts.push(format!(
                        "{deferred} local changes could not be uploaded yet; kept on the phone, retrying next sync"
                    ));
                }
                if !parts.is_empty() {
                    out.notice("Proton Contacts sync conflicts", parts.join("; "));
                }
                self.stage = Stage::WriteLocal(Done {
                    rows: e.get_contacts_json(),
                    confirmed,
                    pending: serde_json::to_string(&pending).unwrap_or_default(),
                    ..Done::default()
                });
                out.request = Some(Request::Local);
            }
            "needs_2fa" => {
                // Distinct from a generic auth failure: the account needs a
                // fresh OTP code (Settings → Proton → Update credentials).
                let msg = if error.is_empty() {
                    "Two-factor authentication required".to_string()
                } else {
                    error
                };
                out.log.push(format!("Sync needs 2FA: {msg}"));
                out.notice(
                    "Proton Contacts needs verification",
                    format!("{msg} – open Settings → Accounts → Proton, update credentials and enter your one-time code"),
                );
                out.finish(false, msg, true);
            }
            state => {
                let msg = if error.is_empty() {
                    format!("Sync ended in state {state}")
                } else {
                    error
                };
                out.log.push(format!("Sync error: {msg}"));
                out.log.push(format!("Keys debug on error: {keys_debug}"));
                // The error path is exactly when posted-but-unconfirmed
                // creates exist (re-list failed after successful POSTs).
                self.persist_pending(con::PENDING, &pending, out);
                out.notice("Proton Contacts sync failed", msg.clone());
                out.finish(false, msg, true);
            }
        }
    }

    fn calendar_done(&mut self, e: &CalendarSyncEngine, out: &mut Outcome) {
        let status = e.status();
        let pending = json_map(&e.pending_json());
        // A successful token refresh can precede a failed download: keep
        // the rotated token either way.
        self.persist_tokens(e.get_refresh_token(), e.get_uid(), out);
        let error = status.error.clone().unwrap_or_default();
        match status.state.as_str() {
            "complete" => {
                if let Some(keys) = e.get_keys_debug() {
                    out.log.push(format!("Calendar keys debug: {keys}"));
                }
                let defaults = e.defaults_json();
                if !defaults.is_empty() {
                    out.settings.set(&self.account, cal::DEFAULTS, defaults);
                    out.log.push(format!(
                        "Persisted calendar defaults for account {}",
                        self.account
                    ));
                }
                let anchors = e.anchors_json();
                if !anchors.is_empty() {
                    out.settings.set(&self.account, cal::ANCHORS, anchors);
                }
                let confirmed = json_map(&e.confirmed_json());
                let mut retry = pending.clone();
                retry.extend(confirmed.clone());
                self.persist_pending(cal::PENDING, &retry, out);
                let conflicts = array_len(&e.conflicts_json());
                if conflicts > 0 {
                    out.notice(
                        "Proton Calendar sync conflicts",
                        format!("{conflicts} events changed on both sides; server version kept"),
                    );
                }
                self.stage = Stage::WriteLocal(Done {
                    rows: e.get_events_json(),
                    confirmed,
                    pending: serde_json::to_string(&pending).unwrap_or_default(),
                    purgeable: serde_json::from_str(&e.purgeable_json()).unwrap_or_default(),
                    snapshot: e.snapshot_json(),
                });
                out.request = Some(Request::Local);
            }
            state => {
                let msg = if error.is_empty() {
                    format!("Sync ended in state {state}")
                } else {
                    error
                };
                out.log.push(format!("Calendar sync error: {msg}"));
                self.persist_pending(cal::PENDING, &pending, out);
                out.notice("Proton Calendar sync failed", msg.clone());
                out.finish(false, msg, true);
            }
        }
    }

    // ---- write ----

    fn write_failed(&self, out: &mut Outcome) {
        match self.kind {
            Kind::Contacts => {
                out.notice(
                    "Proton Contacts sync failed",
                    "Failed to write contacts to phone",
                );
                out.finish(false, "Failed to write contacts", false);
            }
            Kind::Calendar => {
                out.notice(
                    "Proton Calendar sync failed",
                    "Failed to write events to phone",
                );
                out.finish(false, "Failed to write calendar events", false);
            }
        }
    }

    fn write_local(&mut self, done: Done, ok: bool, error: &str, data: Value) -> Outcome {
        let mut out = Outcome::default();
        if !ok {
            out.log
                .push(format!("{} local store unreadable: {error}", self.label()));
            self.write_failed(&mut out);
            return out;
        }
        let planned = match self.kind {
            Kind::Contacts => serde_json::from_value::<Vec<con::LocalContact>>(data)
                .map_err(|e| format!("Contacts dump malformed: {e}"))
                .and_then(|local| {
                    con::write_plan(
                        &self.settings,
                        &self.account,
                        &done.rows,
                        &done.confirmed,
                        &local,
                    )
                })
                .and_then(|(plan, ctx, log)| {
                    let plan = serde_json::to_value(plan).map_err(|e| e.to_string())?;
                    Ok((plan, log, Stage::ContactsWritten(ctx, Done::default())))
                }),
            Kind::Calendar => serde_json::from_value::<cal::LocalCalendar>(data)
                .map_err(|e| format!("Calendar dump malformed: {e}"))
                .and_then(|local| {
                    cal::write_plan(
                        &self.settings,
                        &self.account,
                        &done.rows,
                        &done.confirmed,
                        &done.purgeable,
                        &local,
                        chrono::Utc::now().timestamp(),
                    )
                })
                .and_then(|(plan, ctx, log)| {
                    let plan = serde_json::to_value(plan).map_err(|e| e.to_string())?;
                    Ok((plan, log, Stage::CalendarWritten(ctx, Done::default())))
                }),
        };
        match planned {
            Ok((plan, log, stage)) => {
                out.log.extend(log);
                self.stage = match stage {
                    Stage::ContactsWritten(ctx, _) => Stage::ContactsWritten(ctx, done),
                    Stage::CalendarWritten(ctx, _) => Stage::CalendarWritten(ctx, done),
                    other => other,
                };
                out.request = Some(Request::Write { plan });
            }
            Err(msg) => {
                out.log.extend(msg.lines().map(str::to_string));
                self.write_failed(&mut out);
            }
        }
        out
    }

    fn contacts_written(
        &mut self,
        ctx: &con::WriteContext,
        done: &Done,
        ok: bool,
        error: &str,
        data: &Value,
    ) -> Outcome {
        let mut out = Outcome::default();
        if !ok {
            out.log.push(format!("Contacts write failed: {error}"));
            self.write_failed(&mut out);
            return out;
        }
        let saved: Vec<con::Saved> = data
            .get("saved")
            .cloned()
            .and_then(|v| serde_json::from_value(v).ok())
            .unwrap_or_default();
        let (patch, log) = con::commit(&self.settings, &self.account, ctx, &saved);
        out.settings.merge(patch);
        out.log.extend(log);
        self.persist_pending(con::PENDING, &json_map(&done.pending), &mut out);
        out.finish(true, "Sync completed", false);
        out
    }

    fn calendar_written(
        &mut self,
        ctx: &cal::WriteContext,
        done: &Done,
        ok: bool,
        error: &str,
        data: &Value,
    ) -> Outcome {
        let mut out = Outcome::default();
        if !ok {
            out.log.push(format!("Calendar write failed: {error}"));
            self.write_failed(&mut out);
            return out;
        }
        let reported: BTreeMap<String, i64> = data
            .get("last_modified")
            .and_then(Value::as_object)
            .map(|m| {
                m.iter()
                    .filter_map(|(k, v)| super::settings::as_i64(v).map(|n| (k.clone(), n)))
                    .collect()
            })
            .unwrap_or_default();
        let (patch, log) = cal::commit(&self.settings, &self.account, ctx, &reported);
        out.settings.merge(patch);
        out.log.extend(log);
        self.persist_pending(cal::PENDING, &json_map(&done.pending), &mut out);
        // Commit the encrypted cache only after the matching phone save.
        if !done.snapshot.is_empty() {
            out.settings
                .set(&self.account, cal::SNAPSHOT, done.snapshot.clone());
        }
        out.finish(true, "Calendar sync completed", false);
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn begin(session: &mut Session, creds: Value, settings: Value) -> Value {
        let input = json!({"begin": {"credentials": creds, "settings": settings}});
        serde_json::to_value(session.step(&input.to_string())).unwrap()
    }

    #[test]
    fn test_captcha_and_2fa_fail_without_engine() {
        let mut s = Session::new(Kind::Contacts, "1");
        let out = begin(&mut s, json!({"CaptchaRequired": true}), json!({}));
        assert_eq!(out["result"]["auth_failure"], true);
        let mut s = Session::new(Kind::Calendar, "1");
        let out = begin(&mut s, json!({"TwoFARequired": "true"}), json!({}));
        assert!(out["result"]["message"]
            .as_str()
            .unwrap()
            .contains("Two-factor"));
    }

    #[test]
    fn test_no_tokens_is_auth_failure() {
        let mut s = Session::new(Kind::Contacts, "1");
        let out = begin(&mut s, json!({"UserName": "u"}), json!({}));
        assert_eq!(out["result"]["message"], "No auth tokens received");
    }

    #[test]
    fn test_persisted_tokens_and_derived_union() {
        let mut s = Session::new(Kind::Contacts, "1");
        let settings = json!({
            "1": {"refresh_token": "rt", "uid": "U", "derived_passwords": "{\"k1\":\"a\",\"k2\":\"a\"}"},
            "U": {"derived_passwords": "{\"k2\":\"b\"}"},
            "me@x": {"derived_passwords": "not json"}
        });
        let out = begin(
            &mut s,
            json!({"UserName": "me@x", "DerivedPasswords": "{\"k3\":\"c\"}"}),
            settings,
        );
        assert_eq!(out["request"]["kind"], "local");
        assert!(out["log"][0]
            .as_str()
            .unwrap()
            .contains("accountId(2)+Uid(1)+blob(1)"));
        let Stage::StartLocal(config) = &s.stage else {
            panic!("expected local request");
        };
        let derived = config.derived_passwords.as_ref().unwrap();
        assert_eq!(derived.get("k2").map(String::as_str), Some("b"));
        assert_eq!(derived.len(), 3);
        assert_eq!(config.refresh_token.as_deref(), Some("rt"));
        assert_eq!(config.uid.as_deref(), Some("U"));
    }

    #[test]
    fn test_unexpected_input_fails_cleanly() {
        let mut s = Session::new(Kind::Calendar, "1");
        let out = serde_json::to_value(s.step(r#"{"poll":{}}"#)).unwrap();
        assert_eq!(out["result"]["ok"], false);
        let out = serde_json::to_value(s.step("garbage")).unwrap();
        assert_eq!(out["result"]["ok"], false);
    }

    fn step(s: &mut Session, input: Value) -> Value {
        serde_json::to_value(s.step(&input.to_string())).unwrap()
    }

    /// Full run against a mock server: begin → local dump → engine →
    /// write plan → written → settings, exactly as the shim drives it.
    #[test]
    fn test_calendar_run_end_to_end_mock() {
        let mut server = mockito::Server::new();
        let mut guards = Vec::new();
        let now = chrono::Utc::now().timestamp();
        let events = format!(
            "{{\"Code\":1000,\"Events\":[{{\"ID\":\"e1\",\"UID\":\"u1\",\"StartTime\":{now},\"EndTime\":{},\"LastEditTime\":100,\"FullDay\":0,\"SharedEvents\":[{{\"Type\":2,\"Data\":\"BEGIN:VEVENT\\nUID:u1\\nSUMMARY:Keep\\nEND:VEVENT\",\"Signature\":\"s\"}}]}}],\"More\":0}}",
            now + 3600
        );
        for (re, body) in [
            (
                r"/core/v4/users.*",
                r#"{"User":{"ID":"u","Name":"t","Keys":[]}}"#.to_string(),
            ),
            (r"/core/v4/keys/salts.*", r#"{"KeySalts":[]}"#.into()),
            (r"/core/v4/addresses.*", r#"{"Addresses":[]}"#.into()),
            (
                r"/calendar/v1$",
                r#"{"Code":1000,"Calendars":[{"ID":"cal1","Name":"C"}]}"#.into(),
            ),
            (r"/calendar/v1/cal1/events.*", events),
            (
                r"/calendar/v1/cal1/members.*",
                r#"{"Members":[{"ID":"m1","Email":"t@x","Name":"T"}]}"#.into(),
            ),
            (r"/calendar/v1/cal1/keys.*", r#"{"Keys":[]}"#.into()),
            (
                r"/calendar/v1/cal1/passphrase.*",
                r#"{"Passphrase":null}"#.into(),
            ),
            (
                r"/calendar/v1/cal1/settings.*",
                r#"{"Code":1000,"CalendarSettings":{}}"#.into(),
            ),
        ] {
            guards.push(
                server
                    .mock("GET", mockito::Matcher::Regex(re.into()))
                    .with_status(200)
                    .with_header("content-type", "application/json")
                    .with_body(body)
                    .create(),
            );
        }
        guards.push(
            server
                .mock(
                    "GET",
                    mockito::Matcher::Regex(r"/calendar/v2/cal1/bootstrap.*".into()),
                )
                .with_status(404)
                .with_body("{}")
                .create(),
        );

        let mut s = Session::new(Kind::Calendar, "1");
        s.set_api_base_url(&server.url());
        let out = step(
            &mut s,
            json!({"begin": {"credentials": {"AccessToken": "at", "RefreshToken": "rt", "Uid": "uid"}}}),
        );
        assert_eq!(out["request"]["kind"], "local");
        let nb = "proton-calendar-1-cal1";
        let out = step(
            &mut s,
            json!({"local": {"ok": true, "data": {"notebooks": [nb], "events": []}}}),
        );
        assert_eq!(out["request"]["kind"], "poll");
        let mut out = out;
        for _ in 0..200 {
            if out["request"]["kind"] != "poll" {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
            out = step(&mut s, json!({"poll": {}}));
        }
        assert_eq!(out["request"]["kind"], "local", "{out}");

        // Write phase: a stale synced event goes, a phone-made one stays.
        let stale = crate::device::calendar_identity::stored_uid("1", "cal1", "gone", 0);
        let out = step(
            &mut s,
            json!({"local": {"ok": true, "data": {"notebooks": [nb], "events": [
                {"notebook": nb, "uid": stale, "event_id": "old"},
                {"notebook": nb, "uid": "phone-made"}
            ]}}}),
        );
        let plan = &out["request"]["plan"];
        assert_eq!(out["request"]["kind"], "write", "{out}");
        assert_eq!(plan["delete"], json!([0]));
        assert_eq!(plan["add"].as_array().unwrap().len(), 1);
        assert_eq!(plan["add"][0]["notebook"], nb);
        assert_eq!(plan["add"][0]["summary"], "Keep");
        let added = plan["add"][0]["uid"].as_str().unwrap().to_string();

        let out = step(
            &mut s,
            json!({"written": {"ok": true, "data": {"last_modified": {added.clone(): 1234}}}}),
        );
        assert_eq!(out["result"]["ok"], true, "{out}");
        assert_eq!(
            s.settings
                .string_map("1", cal::ID_MAP)
                .get(&added)
                .map(String::as_str),
            Some("e1")
        );
        assert_eq!(
            s.settings.int_map("1", cal::LAST_MODIFIED).get(&added),
            Some(&1234)
        );
        assert_eq!(s.settings.get("1", "refresh_token"), "rt");
        assert!(!s.settings.get("1", cal::SNAPSHOT).is_empty());
        let _held = guards;
    }

    #[test]
    fn test_avatar_request_round_trip() {
        let mut s = Session::new(Kind::Contacts, "1");
        let settings = json!({"1": {"contacts_last_modified": "{\"q\":1}"}});
        begin(&mut s, json!({"AccessToken": "at"}), settings);
        let local = json!({"local": {"ok": true, "data": [
            {"id": "q", "guid": "u", "last_modified": 2, "avatars": ["file:///a.jpg"]}
        ]}});
        let out = serde_json::to_value(s.step(&local.to_string())).unwrap();
        assert_eq!(out["request"]["kind"], "avatars");
        assert_eq!(out["request"]["sources"][0], "file:///a.jpg");
    }
}
