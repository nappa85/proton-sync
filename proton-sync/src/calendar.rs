use crate::{config::SyncConfig, status::SyncStatus};
use base64::Engine;
use proton_api::{
    calendar as cal_api, CalendarClient, CalendarEvent, KeysClient, TokenManager, UnlockedKey,
};
use serde::Serialize;
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};

fn lock_or_recover<T>(mutex: &std::sync::Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|e| e.into_inner())
}

/// JSON shape consumed by the C++ mKCal shim.
///
/// New fields are `#[serde(default)]` so old phone builds ignore them and
/// new builds accept old cached JSON: `organizer` stays the bare email,
/// `organizer_name` carries CN; `attendees` stays the legacy email list,
/// `attendees_full` carries CN/RSVP/PARTSTAT/ROLE; `recurrence_id_ical`
/// is the in-fragment RECURRENCE-ID value (row `recurrence_id` unix stays
/// authoritative for exception linkage).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(non_snake_case)]
pub struct CalEventJson {
    pub id: String,
    pub uid: String,
    pub calendar_id: String,
    pub calendar_name: String,
    pub summary: String,
    pub description: String,
    pub location: String,
    pub dtstart: String,
    pub dtend: String,
    pub dtstamp: String,
    pub rrule: String,
    pub exdates: Vec<String>,
    pub sequence: String,
    pub status: String,
    pub transp: String,
    pub organizer: String,
    pub attendees: Vec<String>,
    pub start_time: i64,
    pub end_time: i64,
    pub start_timezone: String,
    pub end_timezone: String,
    pub full_day: bool,
    pub color: Option<String>,
    pub recurrence_id: Option<i64>,
    pub notifications: Vec<proton_api::CalNotification>,
    #[serde(default)]
    pub organizer_name: String,
    #[serde(default)]
    pub attendees_full: Vec<proton_api::CalAttendee>,
    #[serde(default)]
    pub recurrence_id_ical: String,
    #[serde(default)]
    pub recurrence_id_range: String,
    /// Server row `LastEditTime` (unix): per-row sync anchor for upsync
    /// conflict detection (`upsync::merge_anchors`). Not displayed.
    #[serde(default)]
    pub mtime: i64,
}

use serde::Deserialize;

pub struct CalendarSyncEngine {
    config: Arc<Mutex<SyncConfig>>,
    status: Arc<Mutex<SyncStatus>>,
    token_manager: Arc<Mutex<TokenManager>>,
    events_json: Arc<Mutex<Option<String>>>,
    keys_debug: Arc<Mutex<Option<String>>>,
    // Last-seen non-empty per-calendar reminder defaults (this run). The
    // shim persists them via get_defaults_json so restored sessions (whose
    // live settings come back empty) can seed the same fallbacks.
    last_defaults: Arc<Mutex<HashMap<String, crate::config::CalendarDefaults>>>,
    // Upsync cycle outputs (this run): tombstone UIDs safe to purge (only
    // after their deletes uploaded OK), server-wins conflicts, and the
    // merged anchor map. Read by the shim via *_json getters.
    last_purgeable: Arc<Mutex<Vec<String>>>,
    last_conflicts: Arc<Mutex<Vec<crate::upsync::SyncConflict>>>,
    last_anchors: Arc<Mutex<HashMap<String, i64>>>,
    // Posted-but-unconfirmed creates (mKCal UID → stable event UID) for
    // retry idempotency. Read by the shim via `pending_json` on EVERY
    // outcome (complete clears it, error keeps it).
    last_pending: Arc<Mutex<HashMap<String, String>>>,
}

impl CalendarSyncEngine {
    pub fn new(config: SyncConfig) -> Self {
        let mut tm = TokenManager::new();
        if let (Some(rt), Some(uid)) = (&config.refresh_token, &config.uid) {
            if !rt.is_empty() && !uid.is_empty() {
                let at = config.access_token.as_deref().unwrap_or("");
                tm.restore_tokens(proton_api::AuthTokens {
                    access_token: at.to_string(),
                    refresh_token: rt.clone(),
                    uid: uid.clone(),
                });
                if !at.is_empty() {
                    tm.set_expiry(3600);
                }
            }
        }
        Self {
            config: Arc::new(Mutex::new(config)),
            status: Arc::new(Mutex::new(SyncStatus::default())),
            token_manager: Arc::new(Mutex::new(tm)),
            events_json: Arc::new(Mutex::new(None)),
            keys_debug: Arc::new(Mutex::new(None)),
            last_defaults: Arc::new(Mutex::new(HashMap::new())),
            last_purgeable: Arc::new(Mutex::new(Vec::new())),
            last_conflicts: Arc::new(Mutex::new(Vec::new())),
            last_anchors: Arc::new(Mutex::new(HashMap::new())),
            last_pending: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Serialized last-seen non-empty per-calendar defaults (`{}` when none
    /// this run — caller must not overwrite a good cache with it).
    pub fn defaults_json(&self) -> String {
        let map = lock_or_recover(&self.last_defaults);
        if map.is_empty() {
            return String::new();
        }
        serde_json::to_string(&*map).unwrap_or_default()
    }

    /// mKCal UIDs whose tombstones may be purged (`[]` when none — the shim
    /// unions these with its replacement-phase removals for selective
    /// purge; ONLY valid after a `complete` status).
    pub fn purgeable_json(&self) -> String {
        serde_json::to_string(&*lock_or_recover(&self.last_purgeable)).unwrap_or_default()
    }

    /// Server-wins conflicts this run (`[]` when none — the shim notifies).
    pub fn conflicts_json(&self) -> String {
        serde_json::to_string(&*lock_or_recover(&self.last_conflicts)).unwrap_or_default()
    }

    /// Merged anchor map (`{}` when nothing known — caller must not
    /// overwrite a good cache with it).
    pub fn anchors_json(&self) -> String {
        let map = lock_or_recover(&self.last_anchors);
        if map.is_empty() {
            return String::new();
        }
        serde_json::to_string(&*map).unwrap_or_default()
    }

    /// Posted-but-unconfirmed creates (`{mKCal UID: stable event UID}`)
    /// for the shim to persist (`calendar_pending`) and feed back as
    /// `pending_uid` next cycle. Empty (this getter returns `""`) when
    /// nothing is unconfirmed — the shim must overwrite its cache
    /// wholesale, never merge, so stale entries vanish.
    pub fn pending_json(&self) -> String {
        let map = lock_or_recover(&self.last_pending);
        if map.is_empty() {
            return String::new();
        }
        serde_json::to_string(&*map).unwrap_or_default()
    }

    fn calendar_client(config: &SyncConfig, access_token: &str, uid: &str) -> CalendarClient {
        match &config.api_base_url {
            Some(base) if !base.is_empty() => {
                CalendarClient::new_with_base_url(base.clone(), access_token.into(), uid.into())
            }
            _ => CalendarClient::new(access_token.into(), uid.into()),
        }
    }

    pub fn config(&self) -> SyncConfig {
        lock_or_recover(&self.config).clone()
    }

    pub fn start_sync(&mut self, config: SyncConfig) {
        *lock_or_recover(&self.config) = config.clone();
        *lock_or_recover(&self.events_json) = None;
        self.set_status(SyncStatus {
            state: "syncing".into(),
            progress: 0.0,
            ..Default::default()
        });
        match self.run_sync(&config) {
            Ok(evts) => {
                let json = serde_json::to_string(&evts).unwrap_or_else(|_| "[]".into());
                *lock_or_recover(&self.events_json) = Some(json);
                self.set_status(SyncStatus {
                    state: "complete".into(),
                    progress: 1.0,
                    total_contacts: evts.len() as u32,
                    synced_contacts: evts.len() as u32,
                    ..Default::default()
                });
            }
            Err(e) => {
                self.set_status(SyncStatus {
                    state: "error".into(),
                    error: Some(format!("Calendar sync failed: {e}")),
                    ..Default::default()
                });
            }
        }
    }

    fn run_sync(&self, config: &SyncConfig) -> Result<Vec<CalEventJson>, proton_api::ProtonError> {
        let mut tm = lock_or_recover(&self.token_manager);
        if tm.refresh_token().is_none()
            && config.password.is_empty()
            && config.derived_passwords.is_none()
        {
            return Err(proton_api::ProtonError::Auth("No auth".into()));
        }
        let access_token = if tm.refresh_token().is_some() {
            tm.access_token()?
        } else {
            return Err(proton_api::ProtonError::Auth(
                "Calendar needs refresh token".into(),
            ));
        };
        let uid = tm.uid().unwrap_or(&config.username).to_string();
        let refresh_scopes = tm.last_refresh_scopes();
        drop(tm);
        if let Some(rs) = refresh_scopes {
            self.set_debug(format!("refresh_scopes={rs}"));
        }
        if std::env::var("LIVE_TRACE").is_ok() {
            eprintln!(
                "engine token={} uid={uid}",
                &access_token[..6.min(access_token.len())]
            );
        }

        // Phase 1: fetch event rows FIRST, before any key/salt/bootstrap
        // calls. Live-verified 2026-09-06 (FINDINGS_CALENDAR.md §7): in a
        // session, untyped listing returns rows when called before
        // get_user/get_key_salts/get_addresses/bootstrap, and null Events
        // afterwards — same token, same params. Cause unknown (server-side
        // read-state); ordering around it is the reliable path.
        let cal_client = Self::calendar_client(config, &access_token, &uid);
        let cals = cal_client.list_calendars()?;
        let mut out = Vec::new();
        let mut query_errors: Vec<String> = Vec::new();
        let mut fetched: Vec<(proton_api::Calendar, Vec<CalendarEvent>)> = Vec::new();
        for cal in &cals {
            match cal_client.list_all_events(&cal.ID) {
                Ok(evs) => {
                    // Head-to-head listing diagnostic (env-gated, read-only,
                    // zero behavior change): the same ±45d window through
                    // the typed 4-Type sweep, compared as ID sets against
                    // the untyped result filtered to that window. Answers
                    // the FINDINGS §7 anomaly (identical typed queries
                    // intermittently 200-empty on host): a `typed=0` line
                    // next to a populated untyped set reproduces it live;
                    // matching sets exonerate the typed path. Narrow window
                    // keeps it to 4 extra queries per calendar (the full
                    // 3y sweep would be ~50, near the rate limit).
                    if std::env::var("PROTON_CAL_DIAG").is_ok() {
                        let diag_end = chrono::Utc::now().timestamp() + 45 * 86400;
                        let diag_start = diag_end - 90 * 86400;
                        match cal_client
                            .list_all_events_windowed(&cal.ID, diag_start, diag_end, "UTC")
                        {
                            Ok(typed) => {
                                let untyped_ids: HashSet<&str> = evs
                                    .iter()
                                    .filter(|e| {
                                        !e.RRule.as_deref().unwrap_or("").is_empty()
                                            || (e.StartTime < diag_end && e.EndTime > diag_start)
                                    })
                                    .map(|e| e.ID.as_str())
                                    .collect();
                                let typed_ids: HashSet<&str> =
                                    typed.iter().map(|e| e.ID.as_str()).collect();
                                let mut only_typed: Vec<&str> = typed_ids
                                    .difference(&untyped_ids)
                                    .take(10)
                                    .copied()
                                    .collect();
                                let mut only_untyped: Vec<&str> = untyped_ids
                                    .difference(&typed_ids)
                                    .take(10)
                                    .copied()
                                    .collect();
                                only_typed.sort_unstable();
                                only_untyped.sort_unstable();
                                // Row shapes for the diff only (plaintext
                                // columns: recurrence + window position tell
                                // expected boundary/master divergences apart
                                // from genuine mistypings).
                                let by_id: std::collections::HashMap<
                                    &str,
                                    &proton_api::CalendarEvent,
                                > = evs
                                    .iter()
                                    .chain(typed.iter())
                                    .map(|e| (e.ID.as_str(), e))
                                    .collect();
                                let describe = |id: &&str| -> String {
                                    match by_id.get(id) {
                                        Some(e) => format!(
                                            "{}:rr={}rec={}fd={}st={}et={}",
                                            &e.ID[..8.min(e.ID.len())],
                                            e.RRule.as_deref().unwrap_or("-"),
                                            e.RecurrenceID.unwrap_or(-1),
                                            e.FullDay.unwrap_or(false) as u8,
                                            e.StartTime,
                                            e.EndTime,
                                        ),
                                        None => format!("{id}:gone"),
                                    }
                                };
                                let only_typed_shapes: Vec<String> =
                                    only_typed.iter().map(describe).collect();
                                let only_untyped_shapes: Vec<String> =
                                    only_untyped.iter().map(describe).collect();
                                self.set_debug(format!(
                                    "cal_diag cal={} typed={} untyped={} only_typed={:?} only_untyped={:?}",
                                    &cal.ID[..8.min(cal.ID.len())],
                                    typed_ids.len(),
                                    untyped_ids.len(),
                                    only_typed_shapes,
                                    only_untyped_shapes,
                                ));
                            }
                            Err(e) => {
                                let msg = format!("{e}");
                                let short: String = msg.chars().take(120).collect();
                                self.set_debug(format!(
                                    "cal_diag cal={} typed_err:{short}",
                                    &cal.ID[..8.min(cal.ID.len())]
                                ));
                            }
                        }
                    }
                    fetched.push((cal.clone(), evs));
                }
                Err(e) => {
                    query_errors.push(format!("{}:{e}", &cal.ID[..8.min(cal.ID.len())]));
                }
            }
        }
        // The shim replaces all account notebooks. A partial snapshot would
        // erase events from calendars whose query failed, even if others worked.
        if !query_errors.is_empty() {
            return Err(proton_api::ProtonError::Api {
                code: 0,
                message: format!("Calendar event queries failed: {}", query_errors.join("; ")),
            });
        }
        // Unlock user + address keys (same Token-aware logic as contacts engine).
        let mut keys = self.unlock_address_keys(&access_token, &uid, config)?;
        // Upsync phase 1 (uploads) before the download/decrypt loop below.
        // Fail-closed: Err aborts before any download/apply (start_sync
        // reports it; local state untouched; uploads retry next cycle).
        self.run_upload_phase(config, &cal_client, &mut keys, &uid, &mut fetched)?;
        for (cal, events) in &fetched {
            // Bootstrap: members + keys + passphrase in one call (v2, fallback v1).
            let mut bootstrap =
                cal_client
                    .get_bootstrap(&cal.ID)
                    .unwrap_or(proton_api::CalendarBootstrap {
                        Members: Vec::new(),
                        Keys: Vec::new(),
                        Passphrase: None,
                        Settings: None,
                    });
            // Standalone settings top-up with visible outcome: a single
            // fetch whose shape is always reported, so empty results stay
            // attributable (server-sent-nothing vs unparsed-shape).
            if bootstrap.Settings.as_ref().is_none_or(|s| s.is_empty()) {
                match cal_client.get_settings_verbose(&cal.ID) {
                    Ok((s, _)) if !s.is_empty() => {
                        bootstrap.Settings = Some(s);
                    }
                    Ok((_, shape)) => {
                        self.set_debug(format!(
                            "cal={} settings_empty {shape}",
                            &cal.ID[..8.min(cal.ID.len())]
                        ));
                    }
                    Err(e) => {
                        let msg = format!("{e}");
                        let short: String = msg.chars().take(90).collect();
                        self.set_debug(format!(
                            "cal={} settings_err:{short}",
                            &cal.ID[..8.min(cal.ID.len())]
                        ));
                    }
                }
            }
            // Remember non-empty live defaults so the shim can cache them
            // for restored sessions (whose live settings come back empty).
            if let Some(s) = bootstrap.Settings.as_ref().filter(|s| !s.is_empty()) {
                let part = s
                    .DefaultPartDayNotifications
                    .as_deref()
                    .map_or_else(Vec::new, Self::parse_notification_list);
                let full = s
                    .DefaultFullDayNotifications
                    .as_deref()
                    .map_or_else(Vec::new, Self::parse_notification_list);
                if !part.is_empty() || !full.is_empty() {
                    lock_or_recover(&self.last_defaults).insert(
                        cal.ID.clone(),
                        crate::config::CalendarDefaults { part, full },
                    );
                }
            }
            // Display metadata lives on the member entry (api.md drift),
            // top-level Name is a legacy fallback.
            let cal_name = bootstrap
                .Members
                .first()
                .map(|m| {
                    if m.Name.is_empty() {
                        m.Email.clone()
                    } else {
                        m.Name.clone()
                    }
                })
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| {
                    if cal.Name.is_empty() {
                        cal.ID.clone()
                    } else {
                        cal.Name.clone()
                    }
                });
            let member_id = pick_member_id(&bootstrap.Members, &config.username);
            let mut cal_keys = Self::unlock_calendar_keys(&bootstrap, &member_id, keys.combined());
            self.set_debug(format!(
                "cal={} members={} calkeys={} addrkeys={} settings={}",
                &cal.ID[..8.min(cal.ID.len())],
                bootstrap.Members.len(),
                cal_keys.len(),
                keys.combined().len(),
                if bootstrap.Settings.is_some() {
                    "1"
                } else {
                    "0"
                }
            ));
            for ev in events {
                let cached = config
                    .calendar_defaults
                    .as_ref()
                    .and_then(|m| m.get(&cal.ID));
                if let Some(json) = Self::process_event(
                    ev,
                    &cal.ID,
                    &cal_name,
                    &mut cal_keys,
                    keys.combined(),
                    bootstrap.Settings.as_ref(),
                    cached,
                ) {
                    out.push(json);
                } else {
                    return Err(proton_api::ProtonError::Api {
                        code: 0,
                        message: format!(
                            "Calendar event {} could not be decoded; local events preserved",
                            ev.ID
                        ),
                    });
                }
            }
        }
        // Account-level calendar settings in full (default reminder sets
        // may live here rather than per-calendar — one small call/sync).
        match cal_client.fetch_account_calendar_settings_raw() {
            Ok((v, status)) => self.set_debug(format!(
                "account_calendar_settings http{status} {}",
                proton_api::diag::diag_body(&v)
            )),
            Err(e) => {
                let msg = format!("{e}");
                self.set_debug(format!(
                    "account_calendar_settings err:{}",
                    msg.chars().take(80).collect::<String>()
                ));
            }
        }
        Ok(out)
    }

    /// Unlock calendar keys for one bootstrap: picked member first, then
    /// any-member fallback (shared calendars, email mismatch).
    fn unlock_calendar_keys(
        bootstrap: &proton_api::CalendarBootstrap,
        member_id: &Option<String>,
        address_keys: &mut [UnlockedKey],
    ) -> Vec<UnlockedKey> {
        let mut cal_keys: Vec<UnlockedKey> = Vec::new();
        if let (Some(pp), Some(mid)) = (bootstrap.Passphrase.as_ref(), member_id.as_ref()) {
            if let Ok(uks) = cal_api::decrypt_calendar_keys(&bootstrap.Keys, pp, address_keys, mid)
            {
                cal_keys = uks;
            }
        }
        if cal_keys.is_empty() {
            if let Some(pp) = bootstrap.Passphrase.as_ref() {
                for mp in &pp.MemberPassphrases {
                    if let Ok(uks) = cal_api::decrypt_calendar_keys(
                        &bootstrap.Keys,
                        pp,
                        address_keys,
                        &mp.MemberID,
                    ) {
                        cal_keys = uks;
                        break;
                    }
                }
            }
        }
        cal_keys
    }

    /// Resolve reminder/color overrides for one update from phone fields.
    /// Returns `None` when the phone sent neither (verbatim re-send).
    /// - color: validated palette hex; `""` reverts to the calendar's own
    ///   member color (web-client behavior); off-palette keeps server.
    /// - notifications: phone display alarms merged with the row's
    ///   server-sent (Type 0) entries; when the merged set equals the
    ///   effective calendar defaults, force inherit (`null`) instead of
    ///   materializing copies. Unknown defaults (no live, no cache) fall
    ///   back to verbatim — never alter what we can't evaluate.
    fn update_overrides(
        row: &CalendarEvent,
        fields: &proton_api::LocalFields,
        live_settings: Option<&proton_api::CalendarSettings>,
        cached: Option<&crate::config::CalendarDefaults>,
        member_color: &str,
    ) -> Option<proton_api::calendar_write::UpdateOverrides> {
        use proton_api::calendar_write::UpdateOverrides;
        let color = match fields.color.as_deref() {
            None => None,
            Some("") => proton_api::resolve_color(member_color).ok(),
            Some(hex) => proton_api::resolve_color(hex).ok(),
        };
        let notifications: Option<Option<Vec<serde_json::Value>>> =
            match fields.notifications.as_ref() {
                None => None,
                Some(phone) => {
                    let display: Vec<serde_json::Value> = phone
                        .iter()
                        .filter(|v| v.get("Type").and_then(|t| t.as_i64()) != Some(0))
                        .cloned()
                        .collect();
                    let email: Vec<serde_json::Value> = row
                        .Notifications
                        .as_deref()
                        .unwrap_or(&[])
                        .iter()
                        .filter(|v| v.get("Type").and_then(|t| t.as_i64()) == Some(0))
                        .cloned()
                        .collect();
                    let full_day = row.FullDay.unwrap_or(false);
                    let live_list = live_settings.and_then(|s| {
                        if full_day {
                            s.DefaultFullDayNotifications.as_ref()
                        } else {
                            s.DefaultPartDayNotifications.as_ref()
                        }
                    });
                    let cached_list: Option<&[proton_api::CalNotification]> = cached.map(|c| {
                        if full_day {
                            c.full.as_slice()
                        } else {
                            c.part.as_slice()
                        }
                    });
                    let known = live_list.is_some() || cached_list.is_some_and(|l| !l.is_empty());
                    if !known {
                        return color.map(|color| UpdateOverrides {
                            notifications: None,
                            color: Some(color),
                        });
                    }
                    let mut default_offsets = std::collections::HashSet::new();
                    if let Some(list) = live_list {
                        default_offsets.extend(
                            Self::parse_notification_list(list)
                                .into_iter()
                                .map(|n| n.offset_secs),
                        );
                    } else if let Some(list) = cached_list {
                        default_offsets.extend(list.iter().map(|n| n.offset_secs));
                    }
                    let phone_offsets: std::collections::HashSet<i64> = display
                        .iter()
                        .filter_map(|v| v.get("Trigger").and_then(|t| t.as_str()))
                        .filter_map(proton_api::parse_notification_trigger)
                        .collect();
                    Some(if phone_offsets == default_offsets {
                        None
                    } else {
                        let mut merged = email;
                        merged.extend(display);
                        Some(merged)
                    })
                }
            };
        match (notifications, color) {
            (None, None) => None,
            (notifications, color) => Some(UpdateOverrides {
                notifications,
                color,
            }),
        }
    }
    /// PUT one batch, mapping transport + per-op failures to a fail-closed
    /// engine error (the caller aborts before any download/apply).
    fn put_batch(
        &self,
        cal_client: &CalendarClient,
        cal_id: &str,
        batch: &proton_api::SyncBatchRequest,
        what: &str,
    ) -> Result<(), proton_api::ProtonError> {
        let resp =
            cal_client
                .put_sync(cal_id, batch)
                .map_err(|e| proton_api::ProtonError::Api {
                    code: 0,
                    message: format!("upsync {what} upload failed: {e}"),
                })?;
        if let Some(err) = resp.first_error() {
            // Failure-only structure log (scrubbed: no Data/Signatures,
            // no plaintext) — the next debug step for server rejections.
            self.set_debug(format!(
                "upsync_{what}_rejected cal={} {} msg={err}",
                &cal_id[..8.min(cal_id.len())],
                crate::upsync::scrub_batch(batch),
            ));
            return Err(proton_api::ProtonError::Api {
                code: 0,
                message: format!("upsync {what} upload failed: {err}"),
            });
        }
        Ok(())
    }

    /// Upsync upload phase (phase 1 of `SyncCycle::ORDER`). Plans from the
    /// shim-fed inventory + listed rows, executes create/update/delete
    /// batches per calendar (fail-closed), reconciles `fetched` (deletes
    /// filter locally; creates/updates re-list for fresh server truth),
    /// and records purgeable/conflicts/anchors for the shim getters.
    /// Unsealable rows defer (log + skip, never fail the phase). Without
    /// a fed inventory the plan is empty and this is a no-op.
    fn run_upload_phase(
        &self,
        config: &SyncConfig,
        cal_client: &CalendarClient,
        keys: &mut UnlockedAddressKeys,
        uid: &str,
        fetched: &mut [(proton_api::Calendar, Vec<CalendarEvent>)],
    ) -> Result<(), proton_api::ProtonError> {
        let inventory = config.local_inventory.clone().unwrap_or_default();
        // Drop stale retry UIDs: rows deleted locally since the error cycle
        // have no job anymore (only guid-less rows can carry pending_uid).
        lock_or_recover(&self.last_pending).retain(|qid, _| {
            inventory
                .iter()
                .any(|i| &i.mkcal_uid == qid && i.proton_id.is_none())
        });
        // Out-of-window tombstone resolution: the windowed listing only
        // covers 2 years, so a tombstone whose ID is missing may still
        // exist server-side. UID-list it (server-side filter, no window)
        // and merge hits into `fetched` so the planner below sees them.
        // Tombstones WITHOUT a Proton ID (id-map entry lost) resolve the
        // same way: a UID hit proves the user deleted something real (the
        // planner turns it into a series delete); no hit keeps the orphan
        // path. Merged hits dedupe by row ID — a UID query can return rows
        // the window already listed (partially in-window series).
        if !inventory.is_empty() {
            let listed: HashSet<String> = fetched
                .iter()
                .flat_map(|(_, evs)| evs.iter().map(|e| e.ID.clone()))
                .collect();
            for item in inventory.iter().filter(|i| {
                i.deleted
                    && i.uid.as_deref().is_some_and(|u| !u.is_empty())
                    && i.proton_id
                        .as_deref()
                        .is_none_or(|pid| !listed.contains(pid))
            }) {
                let ruid = item.uid.clone().unwrap_or_default();
                if ruid.is_empty() {
                    continue;
                }
                let pid = item.proton_id.clone();
                for (cal, events) in fetched.iter_mut() {
                    if let Some(pid) = pid.as_deref() {
                        if events.iter().any(|e| e.ID == pid) {
                            break;
                        }
                    }
                    match cal_client.list_by_uid(&cal.ID, &ruid) {
                        Ok(found) if !found.is_empty() => {
                            let fresh: Vec<proton_api::CalendarEvent> = found
                                .into_iter()
                                .filter(|e| !events.iter().any(|x| x.ID == e.ID))
                                .collect();
                            if fresh.is_empty() {
                                continue;
                            }
                            self.set_debug(format!(
                                "upsync_uid cal={} uid-rows={}",
                                &cal.ID[..8.min(cal.ID.len())],
                                fresh.len()
                            ));
                            events.extend(fresh);
                            break;
                        }
                        _ => {}
                    }
                }
            }
        }
        let all_rows: Vec<CalendarEvent> = fetched
            .iter()
            .flat_map(|(_, evs)| evs.iter().cloned())
            .collect();
        let local_ids: HashSet<String> = inventory
            .iter()
            .filter_map(|item| item.proton_id.clone())
            .collect();
        *lock_or_recover(&self.last_anchors) = crate::upsync::merge_anchors(
            config.anchor_map.as_ref().unwrap_or(&HashMap::new()),
            &all_rows,
            &local_ids,
        );
        if inventory.is_empty() {
            return Ok(());
        }
        let plan = crate::upsync::plan_sync(&all_rows, &inventory);
        *lock_or_recover(&self.last_purgeable) = plan.purgeable_tombstones.clone();
        *lock_or_recover(&self.last_conflicts) = plan.conflicts.clone();
        if plan.uploads.is_empty() {
            return Ok(());
        }
        let items: HashMap<&str, &crate::upsync::LocalItem> = inventory
            .iter()
            .map(|item| (item.mkcal_uid.as_str(), item))
            .collect();
        let row_cal: HashMap<&str, &str> = all_rows
            .iter()
            .map(|row| (row.ID.as_str(), row.CalendarID.as_str()))
            .collect();
        let mut uploaded: HashSet<String> = HashSet::new();
        let mut relist: HashSet<String> = HashSet::new();
        let mut deferred = 0u32;
        // Per-calendar batches (endpoint is per-calID). One extra bootstrap
        // per affected calendar for member ID + calendar keys (the decrypt
        // loop below re-bootstraps; accepted duplicate on this rare path).
        for (cal, events) in fetched.iter() {
            let ops: Vec<&crate::upsync::UploadOp> = plan
                .uploads
                .iter()
                .filter(|op| match op {
                    crate::upsync::UploadOp::Delete { proton_id } => {
                        events.iter().any(|e| &e.ID == proton_id)
                    }
                    crate::upsync::UploadOp::Update { proton_id, .. } => {
                        row_cal.get(proton_id.as_str()) == Some(&cal.ID.as_str())
                    }
                    crate::upsync::UploadOp::Create { mkcal_uid } => items
                        .get(mkcal_uid.as_str())
                        .is_some_and(|item| item.calendar_id.as_deref() == Some(cal.ID.as_str())),
                })
                .collect();
            if ops.is_empty() {
                continue;
            }
            let bootstrap =
                cal_client
                    .get_bootstrap(&cal.ID)
                    .unwrap_or(proton_api::CalendarBootstrap {
                        Members: Vec::new(),
                        Keys: Vec::new(),
                        Passphrase: None,
                        Settings: None,
                    });
            let Some(member_id) = pick_member_id(&bootstrap.Members, &config.username) else {
                self.set_debug(format!(
                    "upsync_skip cal={} no-member",
                    &cal.ID[..8.min(cal.ID.len())]
                ));
                continue;
            };
            let mut cal_keys =
                Self::unlock_calendar_keys(&bootstrap, &Some(member_id.clone()), keys.combined());
            // Creates: seal fresh bodies (missing fields/calendar or
            // unserializable recurrence defers with a log line). Each job
            // seals under a STABLE event UID: `pending_uid` carried from
            // the previous cycle when the last attempt posted but never
            // confirmed (re-list failure), else a fresh
            // `proton-sync-{account}-{nanos}` UID. Stable UIDs make
            // retries idempotent: a retry succeeds, upserts, or
            // UID-conflicts into adoption below — never duplicates.
            let mut created = Vec::new();
            let mut created_meta: Vec<(String, String)> = Vec::new();
            for op in ops.iter().filter_map(|op| match op {
                crate::upsync::UploadOp::Create { mkcal_uid } => Some(mkcal_uid),
                _ => None,
            }) {
                let item = items.get(op.as_str());
                let fields = item.and_then(|item| item.fields.as_ref());
                match fields {
                    Some(fields) => {
                        let stable_uid = item
                            .and_then(|item| item.pending_uid.clone())
                            .filter(|u| !u.is_empty())
                            .unwrap_or_else(|| {
                                let safe_uid: String = uid
                                    .chars()
                                    .filter(|c| c.is_ascii_alphanumeric())
                                    .take(16)
                                    .collect();
                                let nanos = std::time::SystemTime::now()
                                    .duration_since(std::time::UNIX_EPOCH)
                                    .map(|d| d.as_nanos())
                                    .unwrap_or(0);
                                format!("proton-sync-{safe_uid}-{nanos}")
                            });
                        match proton_api::calendar_seal::build_create_body(
                            fields,
                            &stable_uid,
                            &mut cal_keys,
                            keys.address_only(),
                        ) {
                            Ok(Some(body)) => {
                                created_meta.push((op.clone(), stable_uid));
                                created.push(body);
                            }
                            Ok(None) => {
                                deferred += 1;
                                self.set_debug(format!("upsync_deferred create {op} unsealable"));
                            }
                            Err(e) => {
                                deferred += 1;
                                self.set_debug(format!("upsync_deferred create {op}: {e}"));
                            }
                        }
                    }
                    None => {
                        deferred += 1;
                        self.set_debug(format!("upsync_deferred create {op} no-fields"));
                    }
                }
            }
            if !created.is_empty() {
                let batch = proton_api::SyncBatchRequest {
                    MemberID: member_id.clone(),
                    IsImport: Some(0),
                    Events: created
                        .into_iter()
                        .map(proton_api::SyncEventOp::create)
                        .collect(),
                };
                // Per-op partition (not put_batch's all-or-nothing): Code
                // 1000 confirms (pending re-list); anything else is a
                // UID-conflict candidate for adoption; a missing Index is
                // a protocol violation and fails closed.
                let resp = cal_client.put_sync(&cal.ID, &batch).map_err(|e| {
                    proton_api::ProtonError::Api {
                        code: 0,
                        message: format!("upsync create upload failed: {e}"),
                    }
                })?;
                let mut adopted_here = 0u32;
                for (i, (mkcal_uid, stable_uid)) in created_meta.iter().enumerate() {
                    match resp.Responses.iter().find(|r| r.Index == i as i64) {
                        Some(entry) if entry.Response.Code == 1000 => {
                            lock_or_recover(&self.last_pending)
                                .insert(mkcal_uid.clone(), stable_uid.clone());
                        }
                        Some(entry) => {
                            // Conflict (or any per-op error): UID-list the
                            // stable UID — a hit proves an earlier POST
                            // landed and is adopted; a miss fails closed
                            // (the old first_error behavior for real
                            // validation errors).
                            match cal_client.list_by_uid(&cal.ID, stable_uid) {
                                Ok(found) if !found.is_empty() => {
                                    adopted_here += 1;
                                    // Adopted rows need anchor refresh like
                                    // fresh creates: re-list below.
                                    relist.insert(cal.ID.clone());
                                    lock_or_recover(&self.last_pending).remove(mkcal_uid);
                                    self.set_debug(format!(
                                        "upsync_adopted cal={} uid-conflict",
                                        &cal.ID[..8.min(cal.ID.len())]
                                    ));
                                }
                                _ => {
                                    self.set_debug(format!(
                                        "upsync_create_rejected cal={} {} msg=code {} {}",
                                        &cal.ID[..8.min(cal.ID.len())],
                                        crate::upsync::scrub_batch(&batch),
                                        entry.Response.Code,
                                        entry.Response.Error,
                                    ));
                                    return Err(proton_api::ProtonError::Api {
                                        code: 0,
                                        message: format!(
                                            "upsync create upload failed: code {} {} \
                                             (uid unresolvable, failing closed)",
                                            entry.Response.Code, entry.Response.Error,
                                        ),
                                    });
                                }
                            }
                        }
                        None => {
                            return Err(proton_api::ProtonError::Api {
                                code: 0,
                                message: format!(
                                    "upsync create upload failed: \
                                     response missing Index {i}"
                                ),
                            });
                        }
                    }
                }
                relist.insert(cal.ID.clone());
                self.set_debug(format!(
                    "upsync_created cal={} n={} adopted={adopted_here}",
                    &cal.ID[..8.min(cal.ID.len())],
                    batch.Events.len(),
                ));
            }
            // Updates: GET-fresh row → patch → reseal (per-op defer on
            // unsealable rows; never fail the phase for one bad row).
            let mut sealed = Vec::new();
            for (proton_id, mkcal_uid) in ops.iter().filter_map(|op| match op {
                crate::upsync::UploadOp::Update {
                    proton_id,
                    mkcal_uid,
                } => Some((proton_id, mkcal_uid)),
                _ => None,
            }) {
                let fields = items
                    .get(mkcal_uid.as_str())
                    .and_then(|item| item.fields.as_ref());
                let Some(fields) = fields else {
                    deferred += 1;
                    self.set_debug(format!("upsync_deferred update {proton_id} no-fields"));
                    continue;
                };
                let fresh = match cal_client.get_event(&cal.ID, proton_id) {
                    Ok(row) => row,
                    Err(e) => {
                        deferred += 1;
                        self.set_debug(format!("upsync_deferred update {proton_id} refetch: {e}"));
                        continue;
                    }
                };
                let live_settings = bootstrap.Settings.as_ref();
                let cached = config
                    .calendar_defaults
                    .as_ref()
                    .and_then(|m| m.get(&cal.ID));
                let member_color = bootstrap
                    .Members
                    .iter()
                    .find_map(|m| (!m.Color.is_empty()).then(|| m.Color.clone()))
                    .unwrap_or_default();
                let overrides =
                    Self::update_overrides(&fresh, fields, live_settings, cached, &member_color);
                // Author-matched signing key (multi-address refinement);
                // falls back to the whole address range. The narrowed slice
                // also scopes decrypt-fallback to the author's key — the
                // common case for passphrase-encrypted member cards.
                let sign_range = signing_index(&keys.address_emails, &fresh.Author)
                    .filter(|i| *i < keys.address_only().len())
                    .map(|i| (i, i + 1));
                let addr_all = keys.address_only();
                let (lo, hi) = sign_range.unwrap_or((0, addr_all.len()));
                let sign_keys = &mut addr_all[lo..hi];
                // Reminder-only fast path: identical content + a real
                // notification change → personal PUT (no reseal, no
                // SEQUENCE churn, no 2001/2011 surface). Anything else
                // falls through to the whole-object replace below.
                let personal_override = overrides.as_ref().filter(|o| o.notifications.is_some());
                if let Some(o) = personal_override {
                    if proton_api::calendar_seal::content_matches_except_notifications(
                        &fresh,
                        fields,
                        &mut cal_keys,
                        sign_keys,
                    ) {
                        let (notifications, color) =
                            proton_api::calendar_write::marshal_notif_color(
                                fresh.Notifications.as_deref(),
                                fresh.Color.as_deref().unwrap_or(""),
                                o,
                            );
                        match cal_client.put_personal(
                            &cal.ID,
                            proton_id,
                            &proton_api::calendar_write::PersonalEventBody {
                                Notifications: notifications,
                                Color: color,
                            },
                        ) {
                            Ok(_) => {
                                relist.insert(cal.ID.clone());
                                self.set_debug(format!(
                                    "upsync_personal cal={} id={proton_id}",
                                    &cal.ID[..8.min(cal.ID.len())]
                                ));
                            }
                            Err(e) => {
                                deferred += 1;
                                self.set_debug(format!(
                                    "upsync_deferred update {proton_id} personal: {e}"
                                ));
                            }
                        }
                        continue;
                    }
                }
                match proton_api::calendar_seal::build_update_body(
                    &fresh,
                    fields,
                    overrides.as_ref(),
                    &mut cal_keys,
                    sign_keys,
                ) {
                    Ok(Some(body)) => sealed.push((proton_id.clone(), body)),
                    Ok(None) => {
                        deferred += 1;
                        self.set_debug(format!("upsync_deferred update {proton_id} unsealable"));
                    }
                    Err(e) => {
                        deferred += 1;
                        self.set_debug(format!("upsync_deferred update {proton_id}: {e}"));
                    }
                }
            }
            if let Some(batch) = crate::upsync::assemble_update_batch(&member_id, sealed) {
                let n = batch.Events.len();
                self.put_batch(cal_client, &cal.ID, &batch, "update")?;
                relist.insert(cal.ID.clone());
                self.set_debug(format!(
                    "upsync_updated cal={} n={n}",
                    &cal.ID[..8.min(cal.ID.len())]
                ));
            }
            // Deletes (unchanged path).
            let cal_plan = crate::upsync::SyncPlan {
                uploads: ops
                    .iter()
                    .filter(|op| matches!(op, crate::upsync::UploadOp::Delete { .. }))
                    .map(|op| (*op).clone())
                    .collect(),
                ..Default::default()
            };
            if cal_plan.uploads.is_empty() {
                continue;
            }
            let Some(batch) = crate::upsync::assemble_delete_batch(&member_id, &cal_plan, events)
            else {
                continue;
            };
            let n = batch.Events.len();
            self.put_batch(cal_client, &cal.ID, &batch, "delete")?;
            for op in &cal_plan.uploads {
                if let crate::upsync::UploadOp::Delete { proton_id } = op {
                    uploaded.insert(proton_id.clone());
                }
            }
            self.set_debug(format!(
                "upsync_deleted cal={} n={n}",
                &cal.ID[..8.min(cal.ID.len())]
            ));
        }
        if deferred > 0 {
            self.set_debug(format!("upsync_deferred total={deferred}"));
        }
        // Reconcile `fetched` with the uploads: drop deleted rows locally
        // (no resurrection), re-list calendars with creates/updates (fresh
        // server truth incl. new IDs; fail-closed on error).
        if !uploaded.is_empty() {
            for (_, events) in fetched.iter_mut() {
                events.retain(|e| !uploaded.contains(&e.ID));
            }
        }
        for cal_id in &relist {
            let fresh =
                cal_client
                    .list_all_events(cal_id)
                    .map_err(|e| proton_api::ProtonError::Api {
                        code: 0,
                        message: format!("upsync re-list failed: {e}"),
                    })?;
            if let Some(entry) = fetched.iter_mut().find(|(cal, _)| &cal.ID == cal_id) {
                entry.1 = fresh;
            }
        }
        // Drain confirmed retry UIDs: a posted UID present anywhere in
        // the reconciled listing is confirmed (drop it). Anything else
        // stays pending — e.g. an out-of-window create the windowed
        // re-list cannot see yet retries with the SAME uid next cycle
        // (convergent when the server dedupes, never worse than a fresh
        // UID otherwise). Any re-list failure above aborts (Err) with the
        // whole map intact for the shim to persist.
        let confirmed: std::collections::HashSet<&str> = fetched
            .iter()
            .flat_map(|(_, evs)| evs.iter().map(|e| e.UID.as_str()))
            .collect();
        lock_or_recover(&self.last_pending).retain(|_, uid| !confirmed.contains(uid.as_str()));
        Ok(())
    }

    fn process_event(
        ev: &CalendarEvent,
        cal_id: &str,
        cal_name: &str,
        cal_keys: &mut [UnlockedKey],
        addr_keys: &mut [UnlockedKey],
        settings: Option<&proton_api::CalendarSettings>,
        cached: Option<&crate::config::CalendarDefaults>,
    ) -> Option<CalEventJson> {
        let mut fragments: Vec<String> = Vec::new();
        // Shared-signed first (structural wins in merge), then shared-encrypted,
        // calendar parts, attendees. Key packets per Go Decode: shared cards use
        // SharedKeyPacket, calendar cards use CalendarKeyPacket.
        for part in &ev.SharedEvents {
            let kp = if ev.SharedKeyPacket.is_empty() {
                None
            } else {
                Some(ev.SharedKeyPacket.as_str())
            };
            if let Ok(plain) = cal_api::decrypt_calendar_part(part, cal_keys, addr_keys, kp) {
                fragments.push(plain);
            } else if (part.Type & 1) == 0 {
                fragments.push(part.Data.clone());
            } else {
                return None;
            }
        }
        for part in &ev.CalendarEvents {
            let kp = if ev.CalendarKeyPacket.is_empty() {
                None
            } else {
                Some(ev.CalendarKeyPacket.as_str())
            };
            if let Ok(plain) = cal_api::decrypt_calendar_part(part, cal_keys, addr_keys, kp) {
                fragments.push(plain);
            } else if (part.Type & 1) == 0 {
                fragments.push(part.Data.clone());
            } else {
                return None;
            }
        }
        for part in &ev.AttendeesEvents {
            let kp = if ev.SharedKeyPacket.is_empty() {
                None
            } else {
                Some(ev.SharedKeyPacket.as_str())
            };
            if let Ok(plain) = cal_api::decrypt_calendar_part(part, cal_keys, addr_keys, kp) {
                fragments.push(plain);
            } else {
                return None;
            }
        }
        // PersonalEvents carry member reminders; Notifications row is source of
        // truth (api.md) – skip decrypt, do not fail on them.
        let parsed = if fragments.is_empty() {
            cal_api::ParsedCalendarEvent::default()
        } else {
            cal_api::merge_ical_fragments(&fragments).ok()?
        };
        // UID fallback to row UID (signed-only rows still listable).
        let uid = if parsed.uid.is_empty() {
            ev.UID.clone()
        } else {
            parsed.uid.clone()
        };
        if uid.is_empty() && parsed.summary.is_empty() {
            return None;
        }
        Some(CalEventJson {
            id: ev.ID.clone(),
            uid,
            calendar_id: cal_id.to_string(),
            calendar_name: cal_name.to_string(),
            summary: parsed.summary.clone(),
            description: parsed.description.clone(),
            location: parsed.location.clone(),
            dtstart: parsed.dtstart.clone(),
            dtend: parsed.dtend.clone(),
            dtstamp: parsed.dtstamp.clone(),
            rrule: parsed.rrule.clone(),
            exdates: parsed.exdates.clone(),
            sequence: parsed.sequence.clone(),
            status: parsed.status.clone(),
            transp: parsed.transp.clone(),
            organizer: parsed.organizer.clone(),
            attendees: parsed.attendees.clone(),
            start_time: ev.StartTime,
            end_time: ev.EndTime,
            start_timezone: ev.StartTimezone.clone(),
            end_timezone: ev.EndTimezone.clone(),
            full_day: ev.FullDay.unwrap_or(false),
            color: ev.Color.clone(),
            recurrence_id: ev.RecurrenceID,
            notifications: Self::resolve_notifications(ev, settings, cached),
            organizer_name: parsed.organizer_name.clone(),
            attendees_full: parsed.attendee_details.clone(),
            recurrence_id_ical: parsed.recurrence_id.clone(),
            recurrence_id_range: parsed.recurrence_id_range.clone(),
            mtime: ev.LastEditTime,
        })
    }

    /// Effective reminders for one event: explicit array (even empty =
    /// none) wins; `null`/absent falls back to live calendar defaults, then
    /// to cached defaults (same precedence); nothing anywhere means none.
    fn resolve_notifications(
        ev: &CalendarEvent,
        settings: Option<&proton_api::CalendarSettings>,
        cached: Option<&crate::config::CalendarDefaults>,
    ) -> Vec<proton_api::CalNotification> {
        if let Some(list) = ev.Notifications.as_ref() {
            return Self::parse_notification_list(list);
        }
        let live = settings.and_then(|s| {
            if ev.FullDay.unwrap_or(false) {
                s.DefaultFullDayNotifications.as_ref()
            } else {
                s.DefaultPartDayNotifications.as_ref()
            }
        });
        if let Some(list) = live {
            if !list.is_empty() {
                return Self::parse_notification_list(list);
            }
        }
        let fallback = cached.map(|c| {
            if ev.FullDay.unwrap_or(false) {
                &c.full
            } else {
                &c.part
            }
        });
        fallback.cloned().unwrap_or_default()
    }

    fn parse_notification_list(list: &[serde_json::Value]) -> Vec<proton_api::CalNotification> {
        list.iter()
            .filter_map(|n| {
                let kind = n.get("Type").and_then(|v| v.as_i64()).unwrap_or(1);
                // Email reminders (Type 0) are sent by the Proton server —
                // only on-device (display) alarms belong in mKCal.
                if kind == 0 {
                    return None;
                }
                let trigger = n.get("Trigger").and_then(|v| v.as_str())?;
                let offset_secs = proton_api::parse_notification_trigger(trigger)?;
                Some(proton_api::CalNotification {
                    action: "display".into(),
                    offset_secs,
                })
            })
            .collect()
    }

    /// Unlock user keys via derived/salted passphrase, then address keys via
    /// Token (go-proton-api) with salt fallback. Returns address-capable keys
    /// (user keys + unlocked address keys – both can decrypt passphrase cards
    /// since passphrase may be encrypted to any account address key).
    fn unlock_address_keys(
        &self,
        access_token: &str,
        uid: &str,
        config: &SyncConfig,
    ) -> Result<UnlockedAddressKeys, proton_api::ProtonError> {
        let keys_client = match &config.api_base_url {
            Some(base) if !base.is_empty() => KeysClient::new_with_base_url(
                base.clone(),
                access_token.to_string(),
                uid.to_string(),
            ),
            _ => KeysClient::new(access_token.to_string(), uid.to_string()),
        };
        let user = keys_client.get_user()?;
        // Best-effort: restored sessions lack the elevated ("locked") scope
        // for /keys/salts (403/9101, verified live). Derived passwords and
        // Token-decrypt paths don't need salts, so continue without them.
        let salts = match keys_client.get_key_salts() {
            Ok(s) => s,
            Err(e) => {
                let msg = format!("{e}");
                let short: String = msg.chars().take(80).collect();
                self.set_debug(format!("salts_unavailable:{short}"));
                Vec::new()
            }
        };
        let addresses = keys_client.get_addresses().unwrap_or_default();
        let mut unlocked: Vec<UnlockedKey> = Vec::new();
        let mut address_emails: Vec<String> = Vec::new();
        let mut debug_parts: Vec<String> = Vec::new();
        debug_parts.push(format!(
            "derived_keys={}",
            config
                .derived_passwords
                .as_ref()
                .map(|m| m.len())
                .unwrap_or(0)
        ));
        // User keys.
        for key in &user.Keys {
            if key.PrivateKey.is_empty() {
                continue;
            }
            match Self::passphrase_for(
                &key.ID,
                &config.password,
                config.derived_passwords.as_ref(),
                salts.iter().find(|s| s.ID == key.ID),
            ) {
                Some((pp, src)) => match UnlockedKey::from_armored(&key.PrivateKey, &pp) {
                    Ok(uk) => {
                        debug_parts.push(format!("u_{}_{src}", &key.ID[..8.min(key.ID.len())]));
                        unlocked.push(uk);
                    }
                    Err(_) => {
                        debug_parts.push(format!(
                            "u_{}_unlock_err_{src}",
                            &key.ID[..8.min(key.ID.len())]
                        ));
                    }
                },
                None => {
                    debug_parts.push(format!("u_{}_no_pp", &key.ID[..8.min(key.ID.len())]));
                }
            }
        }
        // Address keys: Token first, then salt fallback. Everything from
        // here on is address (not user) material — the sync write path
        // MUST sign with these (server rejects user-key signatures on
        // event data: "Provide data signed using the address key").
        let address_start = unlocked.len();
        for addr in &addresses {
            for key in &addr.Keys {
                if key.PrivateKey.is_empty() {
                    continue;
                }
                if !key.Token.is_empty() && !unlocked.is_empty() {
                    let mut found: Option<Vec<u8>> = None;
                    for uk in unlocked.iter_mut() {
                        if let Ok(secret) = proton_api::crypto::decrypt_raw_with_key(&key.Token, uk)
                        {
                            if !secret.is_empty() {
                                found = Some(secret);
                                break;
                            }
                        }
                    }
                    if let Some(secret) = found {
                        if let Ok(ak) = UnlockedKey::from_armored(&key.PrivateKey, &secret) {
                            debug_parts
                                .push(format!("a_{}_tok_ok", &key.ID[..8.min(key.ID.len())]));
                            unlocked.push(ak);
                            address_emails.push(addr.Email.clone());
                            continue;
                        }
                    }
                }
                match Self::passphrase_for(
                    &key.ID,
                    &config.password,
                    config.derived_passwords.as_ref(),
                    salts.iter().find(|s| s.ID == key.ID),
                ) {
                    Some((pp, src)) => match UnlockedKey::from_armored(&key.PrivateKey, &pp) {
                        Ok(ak) => {
                            debug_parts.push(format!("a_{}_{src}", &key.ID[..8.min(key.ID.len())]));
                            unlocked.push(ak);
                            address_emails.push(addr.Email.clone());
                        }
                        Err(_) => {
                            debug_parts.push(format!(
                                "a_{}_unlock_err_{src}",
                                &key.ID[..8.min(key.ID.len())]
                            ));
                        }
                    },
                    None => {
                        debug_parts.push(format!("a_{}_no_pp", &key.ID[..8.min(key.ID.len())]));
                    }
                }
            }
        }
        debug_parts.push(format!("total={}", unlocked.len()));
        self.set_debug(debug_parts.join(";"));
        Ok(UnlockedAddressKeys {
            keys: unlocked,
            address_start,
            address_emails,
        })
    }

    fn passphrase_for(
        key_id: &str,
        password: &str,
        derived: Option<&std::collections::HashMap<String, String>>,
        salt: Option<&proton_api::KeySalt>,
    ) -> Option<(Vec<u8>, &'static str)> {
        if let Some(map) = derived {
            if let Some(b64) = map.get(key_id) {
                if let Ok(bytes) = base64::engine::general_purpose::STANDARD.decode(b64) {
                    return Some((bytes, "derived"));
                }
            }
        }
        if password.is_empty() {
            return None;
        }
        let salt = salt?;
        let ks = salt.KeySalt.as_ref()?;
        if ks.is_empty() {
            return Some((password.as_bytes().to_vec(), "plain"));
        }
        proton_api::derive_mailbox_password(password.as_bytes(), ks)
            .ok()
            .map(|pp| (pp, "salt"))
    }

    fn set_debug(&self, s: String) {
        let mut prev = lock_or_recover(&self.keys_debug);
        let combined = match prev.clone() {
            Some(p) if !p.is_empty() => format!("{p}|{s}"),
            _ => s,
        };
        *prev = Some(combined);
    }

    pub fn status(&self) -> SyncStatus {
        lock_or_recover(&self.status).clone()
    }

    pub fn get_events_json(&self) -> String {
        lock_or_recover(&self.events_json)
            .clone()
            .unwrap_or_else(|| "[]".into())
    }

    pub fn get_keys_debug(&self) -> Option<String> {
        lock_or_recover(&self.keys_debug).clone()
    }

    pub fn get_refresh_token(&self) -> Option<String> {
        lock_or_recover(&self.token_manager)
            .refresh_token()
            .map(str::to_string)
    }

    pub fn get_uid(&self) -> Option<String> {
        lock_or_recover(&self.token_manager)
            .uid()
            .map(str::to_string)
    }

    fn set_status(&self, s: SyncStatus) {
        *lock_or_recover(&self.status) = s;
    }
}

/// Unlocked keys with the user/address split point. Decryption tries the
/// whole `combined` set (passphrase cards may be encrypted to any account
/// key); SEALING (event signatures, key packets) uses `address_only`
/// exclusively — the server verifies event data against address keys.
pub struct UnlockedAddressKeys {
    keys: Vec<UnlockedKey>,
    address_start: usize,
    /// Account address emails parallel to `address_only` (one entry per
    /// pushed address key) for author-matched signing.
    address_emails: Vec<String>,
}

impl UnlockedAddressKeys {
    pub fn combined(&mut self) -> &mut [UnlockedKey] {
        &mut self.keys
    }

    pub fn address_only(&mut self) -> &mut [UnlockedKey] {
        let start = self.address_start.min(self.keys.len());
        &mut self.keys[start..]
    }
}

/// Signing-key index into the address-only slice for `author` (a row
/// `Author` value of undocumented shape — email or display text):
/// case-insensitive exact email match, else contains-match either way,
/// else `None` (caller falls back to the whole range = first address key).
/// Multi-address refinement; single-address accounts always hit index 0.
fn signing_index(address_emails: &[String], author: &str) -> Option<usize> {
    let author = author.trim();
    if author.is_empty() {
        return None;
    }
    if let Some(i) = address_emails
        .iter()
        .position(|e| e.eq_ignore_ascii_case(author))
    {
        return Some(i);
    }
    address_emails.iter().position(|e| {
        let e = e.trim();
        !e.is_empty()
            && (author.to_lowercase().contains(&e.to_lowercase())
                || e.to_lowercase().contains(&author.to_lowercase()))
    })
}

fn pick_member_id(members: &[proton_api::CalendarMember], _username: &str) -> Option<String> {
    // Prefer the first member (list endpoint returns only our own member,
    // api.md response drift). Email matching could refine shared calendars.
    members.first().map(|m| m.ID.clone())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> SyncConfig {
        SyncConfig {
            username: "u".into(),
            ..Default::default()
        }
    }

    #[test]
    fn test_partial_calendar_query_failure_aborts_before_uploads() {
        let mut server = mockito::Server::new();
        let calendars = server
            .mock("GET", "/calendar/v1")
            .with_body(r#"{"Calendars":[{"ID":"good"},{"ID":"bad"}]}"#)
            .create();
        let good = server
            .mock("GET", "/calendar/v1/good/events")
            .match_query(mockito::Matcher::Any)
            .expect_at_least(1)
            .with_body(r#"{"Events":[],"More":0}"#)
            .create();
        let bad = server
            .mock("GET", "/calendar/v1/bad/events")
            .match_query(mockito::Matcher::Any)
            .with_status(503)
            .create();
        let config = SyncConfig {
            api_base_url: Some(server.url()),
            access_token: Some("at".into()),
            refresh_token: Some("rt".into()),
            uid: Some("uid".into()),
            ..cfg()
        };
        let mut engine = CalendarSyncEngine::new(config.clone());
        engine.start_sync(config);
        assert_eq!(engine.status().state, "error");
        assert!(engine
            .status()
            .error
            .unwrap()
            .contains("event queries failed"));
        assert!(lock_or_recover(&engine.events_json).is_none());
        calendars.assert();
        good.assert();
        bad.assert();
    }

    #[test]
    fn test_undecryptable_event_is_not_replaced_with_uid_placeholder() {
        let ev = CalendarEvent {
            UID: "existing-event".into(),
            SharedEvents: vec![proton_api::CalendarEventPart {
                Type: 3,
                Data: "invalid ciphertext".into(),
                ..Default::default()
            }],
            ..Default::default()
        };
        assert!(CalendarSyncEngine::process_event(
            &ev,
            "c1",
            "Calendar",
            &mut [],
            &mut [],
            None,
            None
        )
        .is_none());
    }

    #[test]
    fn test_process_event_signed_only_no_keys() {
        let ev = CalendarEvent {
            ID: "e1".into(),
            UID: "uid-1".into(),
            CalendarID: "c1".into(),
            StartTime: 100,
            EndTime: 200,
            StartTimezone: "UTC".into(),
            EndTimezone: "UTC".into(),
            FullDay: Some(false),
            SharedEvents: vec![proton_api::CalendarEventPart {
                MemberID: String::new(),
                Type: 2,
                Data: "BEGIN:VEVENT\nUID:uid-1\nSUMMARY:Standup\nDTSTART:20260602T090000Z\nDTEND:20260602T093000Z\nEND:VEVENT".into(),
                Signature: "sig".into(),
                Author: String::new(),
            }],
            ..Default::default()
        };
        // Manual Default (CalendarEvent has no Default derive – build via serde).
        let got =
            CalendarSyncEngine::process_event(&ev, "c1", "Work", &mut [], &mut [], None, None);
        assert!(got.is_some());
        let g = got.unwrap();
        assert_eq!(g.uid, "uid-1");
        assert_eq!(g.summary, "Standup");
        assert_eq!(g.dtstart, "20260602T090000Z");
    }

    #[test]
    fn test_process_event_skips_fully_encrypted_without_keys() {
        let ev = CalendarEvent {
            ID: "e2".into(),
            UID: String::new(),
            CalendarID: "c1".into(),
            SharedEvents: vec![proton_api::CalendarEventPart {
                MemberID: String::new(),
                Type: 3,
                Data: "-----BEGIN PGP MESSAGE-----".into(),
                Signature: String::new(),
                Author: String::new(),
            }],
            ..Default::default()
        };
        let got =
            CalendarSyncEngine::process_event(&ev, "c1", "Work", &mut [], &mut [], None, None);
        assert!(got.is_none());
    }

    fn notif_json() -> serde_json::Value {
        serde_json::from_str(
            r#"[{"Type":1,"Trigger":"-PT15M"},{"Type":0,"Trigger":"-P1D"},{"Type":9,"Trigger":"garbage"}]"#,
        )
        .unwrap()
    }

    #[test]
    fn test_resolve_notifications_explicit_wins() {
        let ev = CalendarEvent {
            Notifications: Some(notif_json().as_array().unwrap().clone()),
            ..Default::default()
        };
        let out = CalendarSyncEngine::resolve_notifications(&ev, None, None);
        // Garbage entry skipped, email entry skipped (server-sent), no
        // defaults consulted.
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].action, "display");
        assert_eq!(out[0].offset_secs, -900);
    }

    #[test]
    fn test_calendar_settings_is_empty() {
        assert!(proton_api::CalendarSettings::default().is_empty());
        let empty_obj = proton_api::CalendarSettings {
            DefaultPartDayNotifications: Some(vec![]),
            ..Default::default()
        };
        assert!(empty_obj.is_empty());
        let full = proton_api::CalendarSettings {
            DefaultPartDayNotifications: Some(
                serde_json::from_str::<Vec<serde_json::Value>>(
                    r#"[{"Type":1,"Trigger":"-PT15M"}]"#,
                )
                .unwrap(),
            ),
            ..Default::default()
        };
        assert!(!full.is_empty());
    }

    #[test]
    fn test_resolve_notifications_explicit_empty_means_none() {
        let ev = CalendarEvent {
            Notifications: Some(vec![]),
            ..Default::default()
        };
        let settings = proton_api::CalendarSettings {
            DefaultPartDayNotifications: Some(notif_json().as_array().unwrap().clone()),
            ..Default::default()
        };
        assert!(CalendarSyncEngine::resolve_notifications(&ev, Some(&settings), None).is_empty());
    }

    #[test]
    fn test_resolve_notifications_inherits_calendar_defaults() {
        let timed = CalendarEvent {
            FullDay: Some(false),
            ..Default::default()
        };
        let allday = CalendarEvent {
            FullDay: Some(true),
            ..Default::default()
        };
        let settings = proton_api::CalendarSettings {
            DefaultPartDayNotifications: Some(
                serde_json::from_str::<Vec<serde_json::Value>>(
                    r#"[{"Type":1,"Trigger":"-PT15M"}]"#,
                )
                .unwrap(),
            ),
            DefaultFullDayNotifications: Some(
                serde_json::from_str::<Vec<serde_json::Value>>(r#"[{"Type":1,"Trigger":"-P1D"}]"#)
                    .unwrap(),
            ),
            ..Default::default()
        };
        let t = CalendarSyncEngine::resolve_notifications(&timed, Some(&settings), None);
        assert_eq!(t.len(), 1);
        assert_eq!(t[0].offset_secs, -900);
        let a = CalendarSyncEngine::resolve_notifications(&allday, Some(&settings), None);
        assert_eq!(a.len(), 1);
        assert_eq!(a[0].offset_secs, -86400);
        // No settings at all: nothing.
        let n = CalendarSyncEngine::resolve_notifications(&timed, None, None);
        assert!(n.is_empty());
    }

    #[test]
    fn test_resolve_notifications_cached_fallback() {
        use crate::config::CalendarDefaults;
        // Live settings empty (v2 `{}` on restored sessions) + cache hit.
        let timed = CalendarEvent {
            FullDay: Some(false),
            ..Default::default()
        };
        let empty_live = proton_api::CalendarSettings::default();
        let cached = CalendarDefaults {
            part: vec![proton_api::CalNotification {
                action: "display".into(),
                offset_secs: -900,
            }],
            full: vec![],
        };
        let out =
            CalendarSyncEngine::resolve_notifications(&timed, Some(&empty_live), Some(&cached));
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].offset_secs, -900);
        // Live non-empty wins over cache.
        let live = proton_api::CalendarSettings {
            DefaultPartDayNotifications: Some(
                serde_json::from_str::<Vec<serde_json::Value>>(r#"[{"Type":1,"Trigger":"-PT1H"}]"#)
                    .unwrap(),
            ),
            ..Default::default()
        };
        let out2 = CalendarSyncEngine::resolve_notifications(&timed, Some(&live), Some(&cached));
        assert_eq!(out2.len(), 1);
        assert_eq!(out2[0].offset_secs, -3600);
    }

    #[test]
    fn test_pick_member_id_first() {
        let m = vec![
            proton_api::CalendarMember {
                ID: "m1".into(),
                ..Default::default()
            },
            proton_api::CalendarMember {
                ID: "m2".into(),
                ..Default::default()
            },
        ];
        assert_eq!(pick_member_id(&m, "u"), Some("m1".into()));
        let empty: Vec<proton_api::CalendarMember> = Vec::new();
        assert_eq!(pick_member_id(&empty, "u"), None);
    }

    #[test]
    fn test_engine_new_restores_tokens() {
        let mut c = cfg();
        c.refresh_token = Some("rt".into());
        c.uid = Some("uid".into());
        c.access_token = Some("at".into());
        let e = CalendarSyncEngine::new(c);
        assert_eq!(e.get_uid(), Some("uid".into()));
        assert_eq!(e.get_refresh_token(), Some("rt".into()));
        assert_eq!(e.get_events_json(), "[]");
    }

    #[test]
    fn test_process_event_carries_attendee_details_and_rrule() {
        let ev = CalendarEvent {
            ID: "e9".into(),
            UID: "uid-9".into(),
            CalendarID: "c1".into(),
            StartTime: 100,
            EndTime: 200,
            StartTimezone: "Europe/Rome".into(),
            EndTimezone: "Europe/Rome".into(),
            FullDay: Some(false),
            SharedEvents: vec![proton_api::CalendarEventPart {
                MemberID: String::new(),
                Type: 2,
                Data: "BEGIN:VEVENT\nUID:uid-9\nSUMMARY:Sync\nORGANIZER;CN=Boss:mailto:boss@example.com\nATTENDEE;CN=Alice;RSVP=TRUE;PARTSTAT=ACCEPTED:mailto:alice@example.com\nRRULE:FREQ=WEEKLY;INTERVAL=2;BYDAY=TU,TH\nRECURRENCE-ID:20260915T200000Z\nEND:VEVENT"
                    .into(),
                Signature: "sig".into(),
                Author: String::new(),
            }],
            ..Default::default()
        };
        let got =
            CalendarSyncEngine::process_event(&ev, "c1", "Work", &mut [], &mut [], None, None)
                .expect("signed-only event processes");
        assert_eq!(got.organizer, "boss@example.com");
        assert_eq!(got.organizer_name, "Boss");
        assert_eq!(got.attendees_full.len(), 1);
        assert_eq!(got.attendees_full[0].email, "alice@example.com");
        assert!(got.attendees_full[0].rsvp);
        assert_eq!(got.attendees_full[0].partstat, "ACCEPTED");
        assert_eq!(got.rrule, "FREQ=WEEKLY;INTERVAL=2;BYDAY=TU,TH");
        assert_eq!(got.recurrence_id_ical, "20260915T200000Z");
        // JSON round-trips the new fields (shim contract) and stays
        // backward compatible with old JSON missing them.
        let json = serde_json::to_string(&vec![got]).unwrap();
        assert!(json.contains("attendees_full"));
        assert!(json.contains("organizer_name"));
        let old: Vec<CalEventJson> =
            serde_json::from_str(r#"[{"id":"x","uid":"u","calendar_id":"c","calendar_name":"n","summary":"s","description":"","location":"","dtstart":"","dtend":"","dtstamp":"","rrule":"","exdates":[],"sequence":"","status":"","transp":"","organizer":"a@b","attendees":[],"start_time":0,"end_time":0,"start_timezone":"","end_timezone":"","full_day":false,"color":null,"recurrence_id":null,"notifications":[]}]"#)
                .unwrap();
        assert!(old[0].attendees_full.is_empty());
        assert!(old[0].organizer_name.is_empty());
    }

    #[test]
    fn test_upload_delete_cycle_end_to_end_mock() {
        // Full offline cycle (mockito, no live server): inventory tombstone
        // for a listed row → plan → PUT delete batch (exact wire shape) →
        // 1001 → filtered download (e9 gone from output) + purgeable +
        // anchors getters.
        let mut server = mockito::Server::new();
        // In-window unix times (the untyped listing filters by overlap
        // with [now-1y, now+1y]; 1970-era constants would drop).
        let now = chrono::Utc::now().timestamp();
        let row = |id: &str, uid: &str, mtime: i64| {
            format!(
                r#"{{"ID":"{id}","UID":"{uid}","StartTime":{now},"EndTime":{end},"LastEditTime":{mtime},"FullDay":0,
                "SharedEvents":[{{"Type":2,"Data":"BEGIN:VEVENT\nUID:{uid}\nSUMMARY:Keep {id}\nEND:VEVENT","Signature":"s"}}]}}"#,
                end = now + 3600,
            )
        };
        // Mock guards must stay alive for the whole test.
        let mut guards = Vec::new();
        macro_rules! mock_get {
            ($re:expr, $code:expr, $body:expr) => {
                guards.push(
                    server
                        .mock("GET", mockito::Matcher::Regex($re.into()))
                        .with_status($code)
                        .with_header("content-type", "application/json")
                        .with_body($body)
                        .create(),
                );
            };
        }
        mock_get!(
            r"/core/v4/users.*",
            200,
            r#"{"User":{"ID":"u","Name":"t","Keys":[]}}"#
        );
        mock_get!(r"/core/v4/keys/salts.*", 200, r#"{"KeySalts":[]}"#);
        mock_get!(r"/core/v4/addresses.*", 200, r#"{"Addresses":[]}"#);
        mock_get!(
            r"/calendar/v1$",
            200,
            r#"{"Code":1000,"Calendars":[{"ID":"cal1","Name":"C"}]}"#
        );
        guards.push(
            server
                .mock(
                    "GET",
                    mockito::Matcher::Regex(r"/calendar/v1/cal1/events.*".into()),
                )
                .with_status(200)
                .with_header("content-type", "application/json")
                .with_body(format!(
                    "{{\"Code\":1000,\"Events\":[{},{}],\"More\":0}}",
                    row("e1", "u1", 100),
                    row("e9", "u9", 50)
                ))
                .create(),
        );
        mock_get!(r"/calendar/v2/cal1/bootstrap.*", 404, "{}");
        mock_get!(
            r"/calendar/v1/cal1/members.*",
            200,
            r#"{"Members":[{"ID":"m1","Email":"t@x","Name":"T"}]}"#
        );
        mock_get!(r"/calendar/v1/cal1/keys.*", 200, r#"{"Keys":[]}"#);
        mock_get!(
            r"/calendar/v1/cal1/passphrase.*",
            200,
            r#"{"Passphrase":null}"#
        );
        mock_get!(
            r"/calendar/v1/cal1/settings.*",
            200,
            r#"{"Code":1000,"CalendarSettings":{}}"#
        );
        let put = server
            .mock(
                "PUT",
                mockito::Matcher::Regex(r"/calendar/v1/cal1/events/sync.*".into()),
            )
            .match_body(mockito::Matcher::JsonString(
                r#"{"MemberID":"m1","Events":[{"ID":"e9"}]}"#.into(),
            ))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"Code":1001,"Responses":[]}"#)
            .create();

        let mut c = cfg();
        c.refresh_token = Some("rt".into());
        c.uid = Some("uid".into());
        c.access_token = Some("at".into());
        c.api_base_url = Some(server.url());
        c.local_inventory = Some(vec![
            crate::upsync::LocalItem {
                mkcal_uid: "n1".into(),
                proton_id: Some("e1".into()),
                deleted: false,
                modified: false,
                last_synced_mtime: Some(100),
                fields: None,
                calendar_id: None,
                uid: None,
                pending_uid: None,
            },
            crate::upsync::LocalItem {
                mkcal_uid: "n9".into(),
                proton_id: Some("e9".into()),
                deleted: true,
                modified: false,
                last_synced_mtime: Some(50),
                fields: None,
                calendar_id: None,
                uid: None,
                pending_uid: None,
            },
        ]);
        let mut anchors = std::collections::HashMap::new();
        anchors.insert("e1".to_string(), 100);
        anchors.insert("e9".to_string(), 50);
        c.anchor_map = Some(anchors);

        let mut engine = CalendarSyncEngine::new(c.clone());
        engine.start_sync(c);
        assert_eq!(engine.status().state, "complete");
        put.assert(); // the delete batch really went out
                      // Download filtered: e9 uploaded away, e1 kept with its mtime.
        let events: Vec<CalEventJson> = serde_json::from_str(&engine.get_events_json()).unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].id, "e1");
        assert_eq!(events[0].mtime, 100);
        // Shim outputs: purgeable tombstone, no conflicts, merged anchors.
        let purgeable: Vec<String> = serde_json::from_str(&engine.purgeable_json()).unwrap();
        assert_eq!(purgeable, vec!["n9".to_string()]);
        let conflicts: Vec<crate::upsync::SyncConflict> =
            serde_json::from_str(&engine.conflicts_json()).unwrap();
        assert!(conflicts.is_empty());
        let out_anchors: std::collections::HashMap<String, i64> =
            serde_json::from_str(&engine.anchors_json()).unwrap();
        assert_eq!(out_anchors.get("e1"), Some(&100));
    }

    /// Fresh unlocked test identity as armored TSK JSON-escaped for mocks.
    /// Keys are unencrypted, so `from_armored` unlocks with any passphrase
    /// input — paired with empty-salt `KeySalt` entries the engine's
    /// password path unlocks them exactly like production derived keys.
    fn armored_tsk() -> String {
        use sequoia_openpgp::{cert::CertBuilder, serialize::Serialize};
        let (cert, _) = CertBuilder::new()
            .add_signing_subkey()
            .add_transport_encryption_subkey()
            .generate()
            .expect("test key generation");
        let mut buf = Vec::new();
        cert.as_tsk()
            .armored()
            .export(&mut buf)
            .expect("test cert armor");
        String::from_utf8(buf).unwrap().replace('\n', "\\n")
    }

    #[test]
    fn test_update_text_edit_uploads_mock() {
        // Update path with REAL keys (generated, unencrypted + empty salts
        // + password): modified row with fields → GET-fresh → patch →
        // reseal → PUT update batch (op ID asserted; body blobs are
        // randomized signatures/ciphertext — content proven decrypt-back in
        // proton-api seal tests). Tombstone e9 still deletes in the same
        // cycle (update-before-delete order preserved across batches).
        let user_armored = armored_tsk();
        let addr_armored = armored_tsk();
        let mut server = mockito::Server::new();
        let mut guards = Vec::new();
        macro_rules! mock_get {
            ($re:expr, $code:expr, $body:expr) => {
                guards.push(
                    server
                        .mock("GET", mockito::Matcher::Regex($re.into()))
                        .with_status($code)
                        .with_header("content-type", "application/json")
                        .with_body($body)
                        .create(),
                );
            };
        }
        mock_get!(
            r"/core/v4/users.*",
            200,
            format!(
                r#"{{"User":{{"ID":"u","Name":"t","Keys":[{{"ID":"k1","PrivateKey":"{user_armored}","Token":"","Signature":""}}]}}}}"#
            )
        );
        mock_get!(
            r"/core/v4/keys/salts.*",
            200,
            r#"{"KeySalts":[{"ID":"k1","KeySalt":""},{"ID":"ak1","KeySalt":""}]}"#
        );
        mock_get!(
            r"/core/v4/addresses.*",
            200,
            format!(
                r#"{{"Addresses":[{{"ID":"a1","Email":"t@x","Keys":[{{"ID":"ak1","PrivateKey":"{addr_armored}","Token":"","Signature":""}}]}}]}}"#
            )
        );
        mock_get!(
            r"/calendar/v1$",
            200,
            r#"{"Code":1000,"Calendars":[{"ID":"cal1","Name":"C"}]}"#
        );
        let now = chrono::Utc::now().timestamp();
        let row_e1 = format!(
            r#"{{"ID":"e1","UID":"u1","CalendarID":"cal1","StartTime":{now},"EndTime":{end},"LastEditTime":100,"FullDay":0,
            "SharedEvents":[{{"Type":2,"Data":"BEGIN:VEVENT\nUID:u1\nSUMMARY:Old\nSEQUENCE:2\nEND:VEVENT","Signature":"s"}}]}}"#,
            end = now + 3600,
        );
        let row_e9 = format!(
            r#"{{"ID":"e9","UID":"u9","CalendarID":"cal1","StartTime":{now},"EndTime":{end},"LastEditTime":50,"FullDay":0,
            "SharedEvents":[{{"Type":2,"Data":"BEGIN:VEVENT\nUID:u9\nSUMMARY:Gone\nEND:VEVENT","Signature":"s"}}]}}"#,
            end = now + 3600,
        );
        guards.push(
            server
                .mock(
                    "GET",
                    mockito::Matcher::Regex(r"/calendar/v1/cal1/events.*".into()),
                )
                .with_status(200)
                .with_header("content-type", "application/json")
                .with_body(format!(
                    "{{\"Code\":1000,\"Events\":[{row_e1},{row_e9}],\"More\":0}}"
                ))
                .create(),
        );
        // Fresh GET for the update row (engine refetches to avoid TOCTOU).
        guards.push(
            server
                .mock(
                    "GET",
                    mockito::Matcher::Regex(r"/calendar/v1/cal1/events/e1.*".into()),
                )
                .with_status(200)
                .with_header("content-type", "application/json")
                .with_body(format!("{{\"Event\":{row_e1}}}"))
                .create(),
        );
        mock_get!(r"/calendar/v2/cal1/bootstrap.*", 404, "{}");
        mock_get!(
            r"/calendar/v1/cal1/members.*",
            200,
            r#"{"Members":[{"ID":"m1","Email":"t@x","Name":"T"}]}"#
        );
        mock_get!(r"/calendar/v1/cal1/keys.*", 200, r#"{"Keys":[]}"#);
        mock_get!(
            r"/calendar/v1/cal1/passphrase.*",
            200,
            r#"{"Passphrase":null}"#
        );
        mock_get!(
            r"/calendar/v1/cal1/settings.*",
            200,
            r#"{"Code":1000,"CalendarSettings":{}}"#
        );
        // Update batch carries the e1 op (body blobs randomized — match ID).
        let put_update = server
            .mock(
                "PUT",
                mockito::Matcher::Regex(r"/calendar/v1/cal1/events/sync.*".into()),
            )
            .match_body(mockito::Matcher::Regex(r#""ID":"e1""#.into()))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"Code":1001,"Responses":[]}"#)
            .create();
        // Delete batch carries the e9 ID-only op (exact shape).
        let put_delete = server
            .mock(
                "PUT",
                mockito::Matcher::Regex(r"/calendar/v1/cal1/events/sync.*".into()),
            )
            .match_body(mockito::Matcher::JsonString(
                r#"{"MemberID":"m1","Events":[{"ID":"e9"}]}"#.into(),
            ))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"Code":1001,"Responses":[]}"#)
            .create();

        let mut c = cfg();
        c.refresh_token = Some("rt".into());
        c.uid = Some("uid".into());
        c.access_token = Some("at".into());
        c.password = "testpw".into();
        c.api_base_url = Some(server.url());
        c.local_inventory = Some(vec![
            crate::upsync::LocalItem {
                mkcal_uid: "n1".into(),
                proton_id: Some("e1".into()),
                deleted: false,
                modified: true,
                last_synced_mtime: Some(100),
                fields: Some(proton_api::LocalFields {
                    summary: Some("Edited".into()),
                    ..Default::default()
                }),
                calendar_id: Some("cal1".into()),
                uid: None,
                pending_uid: None,
            },
            crate::upsync::LocalItem {
                mkcal_uid: "n9".into(),
                proton_id: Some("e9".into()),
                deleted: true,
                modified: false,
                last_synced_mtime: Some(50),
                fields: None,
                calendar_id: Some("cal1".into()),
                uid: None,
                pending_uid: None,
            },
        ]);
        let mut anchors = std::collections::HashMap::new();
        anchors.insert("e1".to_string(), 100);
        anchors.insert("e9".to_string(), 50);
        c.anchor_map = Some(anchors);

        let mut engine = CalendarSyncEngine::new(c.clone());
        engine.start_sync(c);
        assert_eq!(engine.status().state, "complete");
        put_update.assert();
        put_delete.assert();
        // e1 present. (The static mock re-list returns pre-delete rows,
        // so e9 reappears in the download here — delete-filtering itself
        // is proven by the delete-cycle test, which has no re-list to
        // resurrect it. Live, the re-list would no longer contain e9.)
        let events: Vec<CalEventJson> = serde_json::from_str(&engine.get_events_json()).unwrap();
        assert!(events.iter().any(|e| e.id == "e1"));
        let purgeable: Vec<String> = serde_json::from_str(&engine.purgeable_json()).unwrap();
        assert_eq!(purgeable, vec!["n9".to_string()]);
        let purgeable: Vec<String> = serde_json::from_str(&engine.purgeable_json()).unwrap();
        assert_eq!(purgeable, vec!["n9".to_string()]);
        let _held = guards;
    }

    #[test]
    fn test_update_reminder_only_uses_personal_route_mock() {
        // Reminder-only phone edit: identical content + changed alarms →
        // personal PUT (exact two-field body), and NO whole-object reseal
        // (expect-zero on events/sync). REAL keys through the password
        // unlock path (decrypt-for-compare is read-only).
        let user_armored = armored_tsk();
        let addr_armored = armored_tsk();
        let mut server = mockito::Server::new();
        let mut guards = Vec::new();
        macro_rules! mock_get {
            ($re:expr, $code:expr, $body:expr) => {
                guards.push(
                    server
                        .mock("GET", mockito::Matcher::Regex($re.into()))
                        .with_status($code)
                        .with_header("content-type", "application/json")
                        .with_body($body)
                        .create(),
                );
            };
        }
        mock_get!(
            r"/core/v4/users.*",
            200,
            format!(
                r#"{{"User":{{"ID":"u","Name":"t","Keys":[{{"ID":"k1","PrivateKey":"{user_armored}","Token":"","Signature":""}}]}}}}"#
            )
        );
        mock_get!(
            r"/core/v4/keys/salts.*",
            200,
            r#"{"KeySalts":[{"ID":"k1","KeySalt":""},{"ID":"ak1","KeySalt":""}]}"#
        );
        mock_get!(
            r"/core/v4/addresses.*",
            200,
            format!(
                r#"{{"Addresses":[{{"ID":"a1","Email":"t@x","Keys":[{{"ID":"ak1","PrivateKey":"{addr_armored}","Token":"","Signature":""}}]}}]}}"#
            )
        );
        mock_get!(
            r"/calendar/v1$",
            200,
            r#"{"Code":1000,"Calendars":[{"ID":"cal1","Name":"C"}]}"#
        );
        let now = chrono::Utc::now().timestamp();
        let row_e1 = format!(
            r#"{{"ID":"e1","UID":"u1","CalendarID":"cal1","StartTime":{now},"EndTime":{end},"LastEditTime":100,"FullDay":0,"Notifications":null,
            "SharedEvents":[{{"Type":2,"Data":"BEGIN:VEVENT\nUID:u1\nSUMMARY:Same\nDESCRIPTION:Same desc\nLOCATION:Same loc\nDTSTART:20300101T100000Z\nDTEND:20300101T110000Z\nEND:VEVENT","Signature":"s"}}]}}"#,
            end = now + 3600,
        );
        guards.push(
            server
                .mock(
                    "GET",
                    mockito::Matcher::Regex(r"/calendar/v1/cal1/events.*".into()),
                )
                .with_status(200)
                .with_header("content-type", "application/json")
                .with_body(format!(
                    "{{\"Code\":1000,\"Events\":[{row_e1}],\"More\":0}}"
                ))
                .create(),
        );
        // Fresh GET for the update row (engine refetches to avoid TOCTOU).
        guards.push(
            server
                .mock(
                    "GET",
                    mockito::Matcher::Regex(r"/calendar/v1/cal1/events/e1.*".into()),
                )
                .with_status(200)
                .with_header("content-type", "application/json")
                .with_body(format!("{{\"Event\":{row_e1}}}"))
                .create(),
        );
        mock_get!(r"/calendar/v2/cal1/bootstrap.*", 404, "{}");
        mock_get!(
            r"/calendar/v1/cal1/members.*",
            200,
            r#"{"Members":[{"ID":"m1","Email":"t@x","Name":"T"}]}"#
        );
        mock_get!(r"/calendar/v1/cal1/keys.*", 200, r#"{"Keys":[]}"#);
        mock_get!(
            r"/calendar/v1/cal1/passphrase.*",
            200,
            r#"{"Passphrase":null}"#
        );
        // Real (non-empty) calendar defaults: the -PT1H phone alarm
        // differs from the inherited -PT15M → genuine notification change.
        mock_get!(
            r"/calendar/v1/cal1/settings.*",
            200,
            r#"{"Code":1000,"CalendarSettings":{"DefaultPartDayNotifications":[{"Trigger":"-PT15M","Type":1}],"DefaultFullDayNotifications":[]}}"#
        );
        // The personal PUT — exact two-field body, no cards involved.
        let put_personal = server
            .mock(
                "PUT",
                mockito::Matcher::Regex(r"/calendar/v1/cal1/events/e1/personal".into()),
            )
            .match_body(mockito::Matcher::JsonString(
                r#"{"Notifications":[{"Trigger":"-PT1H","Type":1}],"Color":null}"#.into(),
            ))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                "{\"Code\":1000,\"Event\":{\"ID\":\"e1\",\"UID\":\"u1\",\"LastEditTime\":101}}",
            )
            .create();
        // Any whole-object reseal fails the test (expect-zero + assert).
        let no_reseal = server
            .mock(
                "PUT",
                mockito::Matcher::Regex(r"/calendar/v1/cal1/events/sync.*".into()),
            )
            .expect(0)
            .create();
        guards.push(no_reseal);

        let mut c = cfg();
        c.refresh_token = Some("rt".into());
        c.uid = Some("uid".into());
        c.access_token = Some("at".into());
        c.password = "testpw".into();
        c.api_base_url = Some(server.url());
        c.local_inventory = Some(vec![crate::upsync::LocalItem {
            mkcal_uid: "n1".into(),
            proton_id: Some("e1".into()),
            deleted: false,
            modified: true,
            last_synced_mtime: Some(100),
            fields: Some(proton_api::LocalFields {
                summary: Some("Same".into()),
                description: Some("Same desc".into()),
                location: Some("Same loc".into()),
                start_unix: Some(now),
                end_unix: Some(now + 3600),
                all_day: Some(false),
                notifications: Some(vec![serde_json::json!({"Trigger": "-PT1H", "Type": 1})]),
                ..Default::default()
            }),
            calendar_id: Some("cal1".into()),
            uid: None,
            pending_uid: None,
        }]);
        let mut anchors = std::collections::HashMap::new();
        anchors.insert("e1".to_string(), 100);
        c.anchor_map = Some(anchors);

        let mut engine = CalendarSyncEngine::new(c.clone());
        engine.start_sync(c);
        assert_eq!(engine.status().state, "complete");
        put_personal.assert();
        let dbg = engine.get_keys_debug().unwrap_or_default();
        assert!(dbg.contains("upsync_personal"), "{dbg}");
        let _held = guards;
    }

    #[test]
    fn test_cal_diag_head_to_head_mock() {
        // The PROTON_CAL_DIAG comparison runs inside the normal listing
        // (before unlock, so no keys are needed) and reports typed vs
        // untyped ID sets for the same window. Env save/restore keeps
        // parallel tests hermetic.
        let prev = std::env::var("PROTON_CAL_DIAG").ok();
        std::env::set_var("PROTON_CAL_DIAG", "1");
        let mut server = mockito::Server::new();
        let mut guards = Vec::new();
        macro_rules! mock_get {
            ($re:expr, $code:expr, $body:expr) => {
                guards.push(
                    server
                        .mock("GET", mockito::Matcher::Regex($re.into()))
                        .with_status($code)
                        .with_header("content-type", "application/json")
                        .with_body($body)
                        .create(),
                );
            };
        }
        mock_get!(
            r"/calendar/v1$",
            200,
            r#"{"Code":1000,"Calendars":[{"ID":"cal1","Name":"C"}]}"#
        );
        let now = chrono::Utc::now().timestamp();
        guards.push(
            server
                .mock(
                    "GET",
                    mockito::Matcher::Regex(r"/calendar/v1/cal1/events.*".into()),
                )
                .with_status(200)
                .with_header("content-type", "application/json")
                .with_body(format!(
                    "{{\"Code\":1000,\"Events\":[{{\"ID\":\"e1\",\"UID\":\"u1\",\"StartTime\":{now},\"EndTime\":{},\"LastEditTime\":100,\"FullDay\":0,\"SharedEvents\":[]}}],\"More\":0}}",
                    now + 3600
                ))
                .create(),
        );
        let mut c = cfg();
        c.refresh_token = Some("rt".into());
        c.uid = Some("uid".into());
        c.access_token = Some("at".into());
        c.api_base_url = Some(server.url());
        let mut engine = CalendarSyncEngine::new(c.clone());
        engine.start_sync(c);
        let dbg = engine.get_keys_debug().unwrap_or_default();
        assert!(dbg.contains("cal_diag cal=cal1"), "{dbg}");
        assert!(dbg.contains("typed=1 untyped=1"), "{dbg}");
        assert!(dbg.contains("only_typed=[]"), "{dbg}");
        assert!(dbg.contains("only_untyped=[]"), "{dbg}");
        match prev {
            Some(v) => std::env::set_var("PROTON_CAL_DIAG", v),
            None => std::env::remove_var("PROTON_CAL_DIAG"),
        }
        let _held = guards;
    }

    #[test]
    fn test_unlock_splits_user_and_address_keys() {
        // Regression test for the live 2001 "Provide data signed using the
        // address key" rejection: the sealer signs with keys
        // [address_start..] (address material), never the user keys pushed
        // first. Locks the construction order the signing path depends on.
        let user_armored = armored_tsk();
        let addr_armored = armored_tsk();
        let mut server = mockito::Server::new();
        let mut guards = Vec::new();
        macro_rules! mock_get {
            ($re:expr, $code:expr, $body:expr) => {
                guards.push(
                    server
                        .mock("GET", mockito::Matcher::Regex($re.into()))
                        .with_status($code)
                        .with_header("content-type", "application/json")
                        .with_body($body)
                        .create(),
                );
            };
        }
        mock_get!(
            r"/core/v4/users.*",
            200,
            format!(
                r#"{{"User":{{"ID":"u","Name":"t","Keys":[{{"ID":"k1","PrivateKey":"{user_armored}","Token":"","Signature":""}}]}}}}"#
            )
        );
        mock_get!(
            r"/core/v4/keys/salts.*",
            200,
            r#"{"KeySalts":[{"ID":"k1","KeySalt":""},{"ID":"ak1","KeySalt":""}]}"#
        );
        mock_get!(
            r"/core/v4/addresses.*",
            200,
            format!(
                r#"{{"Addresses":[{{"ID":"a1","Email":"t@x","Keys":[{{"ID":"ak1","PrivateKey":"{addr_armored}","Token":"","Signature":""}}]}}]}}"#
            )
        );
        let mut c = cfg();
        c.password = "testpw".into();
        c.api_base_url = Some(server.url());
        let engine = CalendarSyncEngine::new(c.clone());
        let keys = engine.unlock_address_keys("at", "uid", &c).unwrap();
        assert_eq!(keys.keys.len(), 2);
        assert_eq!(keys.address_start, 1);
        assert_eq!(keys.keys.len() - keys.address_start, 1);
        let _held = guards;
    }

    #[test]
    fn test_signing_index_matches_author() {
        let emails = vec!["a@x.y".to_string(), "b@x.y".to_string()];
        assert_eq!(signing_index(&emails, "b@x.y"), Some(1));
        assert_eq!(signing_index(&emails, "B@X.Y"), Some(1));
        assert_eq!(signing_index(&emails, "Bob <b@x.y>"), Some(1));
        assert_eq!(signing_index(&emails, "nobody@z"), None);
        assert_eq!(signing_index(&emails, ""), None);
        assert_eq!(signing_index(&[], "b@x.y"), None);
    }

    fn timed_settings() -> proton_api::CalendarSettings {
        proton_api::CalendarSettings {
            DefaultPartDayNotifications: Some(
                serde_json::from_str::<Vec<serde_json::Value>>(
                    r#"[{"Type":1,"Trigger":"-PT15M"}]"#,
                )
                .unwrap(),
            ),
            ..Default::default()
        }
    }

    #[test]
    fn test_overrides_defaults_to_verbatim() {
        let row = CalendarEvent {
            ..Default::default()
        };
        let fields = proton_api::LocalFields::default();
        assert!(CalendarSyncEngine::update_overrides(&row, &fields, None, None, "").is_none());
    }

    #[test]
    fn test_overrides_inherit_when_matching_defaults() {
        // Phone shows materialized defaults after a title-only edit →
        // force inherit (null) instead of persisting copies.
        let row = CalendarEvent {
            FullDay: Some(false),
            ..Default::default()
        };
        let fields = proton_api::LocalFields {
            notifications: Some(vec![serde_json::json!({"Trigger": "-PT15M", "Type": 1})]),
            ..Default::default()
        };
        let out =
            CalendarSyncEngine::update_overrides(&row, &fields, Some(&timed_settings()), None, "")
                .expect("override computed");
        assert_eq!(out.notifications, Some(None));
        assert_eq!(out.color, None);
    }

    #[test]
    fn test_overrides_merge_email_and_explicit() {
        // Custom phone alarm + server-sent email entry merge; color validates.
        let row = CalendarEvent {
            FullDay: Some(false),
            Notifications: Some(vec![serde_json::json!({"Trigger": "-P1D", "Type": 0})]),
            ..Default::default()
        };
        let fields = proton_api::LocalFields {
            notifications: Some(vec![serde_json::json!({"Trigger": "-PT1H", "Type": 1})]),
            color: Some("#EC3E7C".into()),
            ..Default::default()
        };
        let out =
            CalendarSyncEngine::update_overrides(&row, &fields, Some(&timed_settings()), None, "")
                .expect("override computed");
        let list = out.notifications.expect("array").expect("not null");
        assert_eq!(list.len(), 2); // email kept + custom display
        assert_eq!(out.color.as_deref(), Some("#EC3E7C"));
    }

    #[test]
    fn test_overrides_unknown_defaults_stay_verbatim() {
        // No live settings, no cache: never alter what we can't evaluate.
        let row = CalendarEvent {
            ..Default::default()
        };
        let fields = proton_api::LocalFields {
            notifications: Some(vec![serde_json::json!({"Trigger": "-PT1H", "Type": 1})]),
            color: Some("not-a-color".into()),
            ..Default::default()
        };
        // Unknown defaults + invalid color: nothing resolvable → None
        // (verbatim re-send of the row values).
        assert!(CalendarSyncEngine::update_overrides(&row, &fields, None, None, "").is_none());
    }

    #[test]
    fn test_overrides_empty_color_reverts_to_member() {
        let row = CalendarEvent {
            ..Default::default()
        };
        let fields = proton_api::LocalFields {
            color: Some(String::new()),
            ..Default::default()
        };
        let out = CalendarSyncEngine::update_overrides(&row, &fields, None, None, "#EC3E7C")
            .expect("override computed");
        assert_eq!(out.color.as_deref(), Some("#EC3E7C"));
    }

    #[test]
    fn test_uid_augment_resolves_out_of_window_tombstone() {
        // Tombstone whose ID missed the windowed listing but carries a UID:
        // the engine UID-lists it, merges the hit, and the delete PUT fires.
        // Without the UID query the planner would (safely) skip the upload.
        let mut server = mockito::Server::new();
        let mut guards = Vec::new();
        macro_rules! mock_get {
            ($re:expr, $code:expr, $body:expr) => {
                guards.push(
                    server
                        .mock("GET", mockito::Matcher::Regex($re.into()))
                        .with_status($code)
                        .with_header("content-type", "application/json")
                        .with_body($body)
                        .create(),
                );
            };
        }
        mock_get!(
            r"/core/v4/users.*",
            200,
            r#"{"User":{"ID":"u","Name":"t","Keys":[]}}"#
        );
        mock_get!(r"/core/v4/keys/salts.*", 200, r#"{"KeySalts":[]}"#);
        mock_get!(r"/core/v4/addresses.*", 200, r#"{"Addresses":[]}"#);
        mock_get!(
            r"/calendar/v1$",
            200,
            r#"{"Code":1000,"Calendars":[{"ID":"cal1","Name":"C"}]}"#
        );
        let now = chrono::Utc::now().timestamp();
        guards.push(
            server
                .mock(
                    "GET",
                    mockito::Matcher::Regex(r"/calendar/v1/cal1/events.*".into()),
                )
                .with_status(200)
                .with_header("content-type", "application/json")
                .with_body(format!(
                    "{{\"Code\":1000,\"Events\":[{{\"ID\":\"e1\",\"UID\":\"u1\",\"CalendarID\":\"cal1\",\"StartTime\":{now},\"EndTime\":{},\"LastEditTime\":100,\"FullDay\":0,\"SharedEvents\":[{{\"Type\":2,\"Data\":\"BEGIN:VEVENT\\nUID:u1\\nSUMMARY:Keep\\nEND:VEVENT\",\"Signature\":\"s\"}}]}}],\"More\":0}}",
                    now + 3600
                ))
                .create(),
        );
        // UID fallback route returns the missing row.
        guards.push(
            server
                .mock(
                    "GET",
                    mockito::Matcher::Regex(r"/calendar/v1/cal1/events.*".into()),
                )
                .match_query(mockito::Matcher::UrlEncoded("UID".into(), "u9".into()))
                .with_status(200)
                .with_header("content-type", "application/json")
                .with_body(format!(
                    "{{\"Code\":1000,\"Events\":[{{\"ID\":\"e9\",\"UID\":\"u9\",\"CalendarID\":\"cal1\",\"StartTime\":{now},\"EndTime\":{},\"LastEditTime\":50,\"FullDay\":0,\"SharedEvents\":[{{\"Type\":2,\"Data\":\"BEGIN:VEVENT\\nUID:u9\\nSUMMARY:Gone\\nEND:VEVENT\",\"Signature\":\"s\"}}]}}],\"More\":0}}",
                    now + 3600
                ))
                .create(),
        );
        mock_get!(r"/calendar/v2/cal1/bootstrap.*", 404, "{}");
        mock_get!(
            r"/calendar/v1/cal1/members.*",
            200,
            r#"{"Members":[{"ID":"m1","Email":"t@x","Name":"T"}]}"#
        );
        mock_get!(r"/calendar/v1/cal1/keys.*", 200, r#"{"Keys":[]}"#);
        mock_get!(
            r"/calendar/v1/cal1/passphrase.*",
            200,
            r#"{"Passphrase":null}"#
        );
        mock_get!(
            r"/calendar/v1/cal1/settings.*",
            200,
            r#"{"Code":1000,"CalendarSettings":{}}"#
        );
        let put = server
            .mock(
                "PUT",
                mockito::Matcher::Regex(r"/calendar/v1/cal1/events/sync.*".into()),
            )
            .match_body(mockito::Matcher::JsonString(
                r#"{"MemberID":"m1","Events":[{"ID":"e9"}]}"#.into(),
            ))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"Code":1001,"Responses":[]}"#)
            .create();

        let mut c = cfg();
        c.refresh_token = Some("rt".into());
        c.uid = Some("uid".into());
        c.access_token = Some("at".into());
        c.api_base_url = Some(server.url());
        c.local_inventory = Some(vec![crate::upsync::LocalItem {
            mkcal_uid: "n9".into(),
            proton_id: Some("e9".into()),
            deleted: true,
            modified: false,
            last_synced_mtime: Some(50),
            fields: None,
            calendar_id: Some("cal1".into()),
            uid: Some("u9".into()),
            pending_uid: None,
        }]);
        let mut engine = CalendarSyncEngine::new(c.clone());
        engine.start_sync(c);
        assert_eq!(engine.status().state, "complete");
        put.assert(); // UID hit merged → delete uploaded
        let purgeable: Vec<String> = serde_json::from_str(&engine.purgeable_json()).unwrap();
        assert_eq!(purgeable, vec!["n9".to_string()]);
        let _held = guards;
    }

    #[test]
    fn test_uid_augment_resolves_pidless_tombstone() {
        // Id-map entry lost (proton_id None) but raw UID present: the
        // extended augment still UID-lists the hit, the planner resolves
        // the delete from the merged rows, and the same PUT fires. Without
        // the extension this tombstone would purge as a silent orphan
        // while e9 survived server-side.
        let mut server = mockito::Server::new();
        let mut guards = Vec::new();
        macro_rules! mock_get {
            ($re:expr, $code:expr, $body:expr) => {
                guards.push(
                    server
                        .mock("GET", mockito::Matcher::Regex($re.into()))
                        .with_status($code)
                        .with_header("content-type", "application/json")
                        .with_body($body)
                        .create(),
                );
            };
        }
        mock_get!(
            r"/core/v4/users.*",
            200,
            r#"{"User":{"ID":"u","Name":"t","Keys":[]}}"#
        );
        mock_get!(r"/core/v4/keys/salts.*", 200, r#"{"KeySalts":[]}"#);
        mock_get!(r"/core/v4/addresses.*", 200, r#"{"Addresses":[]}"#);
        mock_get!(
            r"/calendar/v1$",
            200,
            r#"{"Code":1000,"Calendars":[{"ID":"cal1","Name":"C"}]}"#
        );
        let now = chrono::Utc::now().timestamp();
        guards.push(
            server
                .mock(
                    "GET",
                    mockito::Matcher::Regex(r"/calendar/v1/cal1/events.*".into()),
                )
                .with_status(200)
                .with_header("content-type", "application/json")
                .with_body(format!(
                    "{{\"Code\":1000,\"Events\":[{{\"ID\":\"e1\",\"UID\":\"u1\",\"CalendarID\":\"cal1\",\"StartTime\":{now},\"EndTime\":{},\"LastEditTime\":100,\"FullDay\":0,\"SharedEvents\":[{{\"Type\":2,\"Data\":\"BEGIN:VEVENT\\nUID:u1\\nSUMMARY:Keep\\nEND:VEVENT\",\"Signature\":\"s\"}}]}}],\"More\":0}}",
                    now + 3600
                ))
                .create(),
        );
        // UID fallback route returns the missing row (out-of-window hit).
        guards.push(
            server
                .mock(
                    "GET",
                    mockito::Matcher::Regex(r"/calendar/v1/cal1/events.*".into()),
                )
                .match_query(mockito::Matcher::UrlEncoded("UID".into(), "u9".into()))
                .with_status(200)
                .with_header("content-type", "application/json")
                .with_body(format!(
                    "{{\"Code\":1000,\"Events\":[{{\"ID\":\"e9\",\"UID\":\"u9\",\"CalendarID\":\"cal1\",\"StartTime\":{now},\"EndTime\":{},\"LastEditTime\":50,\"FullDay\":0,\"SharedEvents\":[{{\"Type\":2,\"Data\":\"BEGIN:VEVENT\\nUID:u9\\nSUMMARY:Gone\\nEND:VEVENT\",\"Signature\":\"s\"}}]}}],\"More\":0}}",
                    now + 3600
                ))
                .create(),
        );
        mock_get!(r"/calendar/v2/cal1/bootstrap.*", 404, "{}");
        mock_get!(
            r"/calendar/v1/cal1/members.*",
            200,
            r#"{"Members":[{"ID":"m1","Email":"t@x","Name":"T"}]}"#
        );
        mock_get!(r"/calendar/v1/cal1/keys.*", 200, r#"{"Keys":[]}"#);
        mock_get!(
            r"/calendar/v1/cal1/passphrase.*",
            200,
            r#"{"Passphrase":null}"#
        );
        mock_get!(
            r"/calendar/v1/cal1/settings.*",
            200,
            r#"{"Code":1000,"CalendarSettings":{}}"#
        );
        let put = server
            .mock(
                "PUT",
                mockito::Matcher::Regex(r"/calendar/v1/cal1/events/sync.*".into()),
            )
            .match_body(mockito::Matcher::JsonString(
                r#"{"MemberID":"m1","Events":[{"ID":"e9"}]}"#.into(),
            ))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"Code":1001,"Responses":[]}"#)
            .create();

        let mut c = cfg();
        c.refresh_token = Some("rt".into());
        c.uid = Some("uid".into());
        c.access_token = Some("at".into());
        c.api_base_url = Some(server.url());
        c.local_inventory = Some(vec![crate::upsync::LocalItem {
            mkcal_uid: "n9".into(),
            proton_id: None,
            deleted: true,
            modified: false,
            last_synced_mtime: None,
            fields: None,
            calendar_id: Some("cal1".into()),
            uid: Some("u9".into()),
            pending_uid: None,
        }]);
        let mut engine = CalendarSyncEngine::new(c.clone());
        engine.start_sync(c);
        assert_eq!(engine.status().state, "complete");
        put.assert(); // pid-less UID hit merged → delete uploaded
        let purgeable: Vec<String> = serde_json::from_str(&engine.purgeable_json()).unwrap();
        assert_eq!(purgeable, vec!["n9".to_string()]);
        let _held = guards;
    }

    /// Working key hierarchy for create-path tests: address key (direct
    /// use) + calendar key (via a member passphrase sealed to the address
    /// key, exactly like the live bootstrap). JSON-escaped variants suit
    /// mock bodies; raw variants suit direct unlock.
    struct KeyMaterial {
        addr_raw: String,
        cal_esc: String,
        pp_esc: String,
    }

    fn make_key_material() -> KeyMaterial {
        let addr_raw = armored_tsk().replace("\\n", "\n");
        let mut addr =
            proton_api::UnlockedKey::from_armored(&addr_raw, b"").expect("test key unlocks");
        let cal_raw = armored_tsk().replace("\\n", "\n");
        let (pp_data, _) = proton_api::contact_seal::seal_contact_card(
            "test-cal-pp",
            std::slice::from_mut(&mut addr),
        )
        .expect("passphrase seals");
        KeyMaterial {
            addr_raw,
            cal_esc: cal_raw.replace('\n', "\\n"),
            pp_esc: pp_data.replace('\n', "\\n"),
        }
    }

    fn material_address_keys(mat: &KeyMaterial) -> UnlockedAddressKeys {
        let key =
            proton_api::UnlockedKey::from_armored(&mat.addr_raw, b"").expect("test key unlocks");
        UnlockedAddressKeys {
            keys: vec![key],
            address_start: 0,
            address_emails: vec!["t@x".into()],
        }
    }

    fn test_calendar() -> proton_api::Calendar {
        proton_api::Calendar {
            ID: "cal1".into(),
            Name: "C".into(),
            Description: String::new(),
            Color: String::new(),
            Display: None,
            Type: 0,
            Flags: 0,
        }
    }

    fn create_fields() -> proton_api::LocalFields {
        let now = chrono::Utc::now().timestamp();
        proton_api::LocalFields {
            summary: Some("Fresh".into()),
            description: Some("d".into()),
            location: Some("l".into()),
            start_unix: Some(now),
            end_unix: Some(now + 3600),
            all_day: Some(false),
            notifications: None,
            ..Default::default()
        }
    }

    fn create_item(pending_uid: Option<&str>) -> crate::upsync::LocalItem {
        crate::upsync::LocalItem {
            mkcal_uid: "n1".into(),
            proton_id: None,
            deleted: false,
            modified: true,
            last_synced_mtime: None,
            fields: Some(create_fields()),
            calendar_id: Some("cal1".into()),
            uid: None,
            pending_uid: pending_uid.map(str::to_string),
        }
    }

    fn phase_config(server_url: String, inventory: Vec<crate::upsync::LocalItem>) -> SyncConfig {
        let mut c = cfg();
        c.refresh_token = Some("rt".into());
        c.uid = Some("uid".into());
        c.access_token = Some("at".into());
        c.api_base_url = Some(server_url);
        c.local_inventory = Some(inventory);
        c
    }

    /// Bootstrap chain the create path needs (member ID + working
    /// calendar keys via a sealed member passphrase). Static key mocks
    /// (`Keys:[]`) suffice for update/delete-only cycles, never creates.
    fn mock_bootstrap(
        server: &mut mockito::Server,
        guards: &mut Vec<mockito::Mock>,
        mat: &KeyMaterial,
    ) {
        macro_rules! mock_get {
            ($re:expr, $code:expr, $body:expr) => {
                guards.push(
                    server
                        .mock("GET", mockito::Matcher::Regex($re.into()))
                        .with_status($code)
                        .with_header("content-type", "application/json")
                        .with_body($body)
                        .create(),
                );
            };
        }
        mock_get!(r"/calendar/v2/cal1/bootstrap.*", 404, "{}");
        mock_get!(
            r"/calendar/v1/cal1/members.*",
            200,
            r#"{"Members":[{"ID":"m1","Email":"t@x","Name":"T"}]}"#
        );
        mock_get!(
            r"/calendar/v1/cal1/keys.*",
            200,
            format!(
                r#"{{"Keys":[{{"ID":"k1","CalendarID":"cal1","PassphraseID":"p1","PrivateKey":"{}","Flags":0}}]}}"#,
                mat.cal_esc,
            )
        );
        mock_get!(
            r"/calendar/v1/cal1/passphrase.*",
            200,
            format!(
                r#"{{"Passphrase":{{"ID":"p1","Flags":0,"MemberPassphrases":[{{"MemberID":"m1","Passphrase":"{}","Signature":""}}]}}}}"#,
                mat.pp_esc,
            )
        );
        mock_get!(
            r"/calendar/v1/cal1/settings.*",
            200,
            r#"{"Code":1000,"CalendarSettings":{}}"#
        );
    }

    #[test]
    fn test_create_retry_reuses_stable_uid_mock() {
        // POST lands but re-list fails → Err + pending {n1: U}. Next cycle
        // feeds pending_uid=U → the re-POST seals the SAME UID (asserted on
        // the plaintext signed fragment) instead of minting a fresh one.
        let mut server1 = mockito::Server::new();
        let mut guards1 = Vec::new();
        let mat = make_key_material();
        mock_bootstrap(&mut server1, &mut guards1, &mat);
        server1
            .mock(
                "PUT",
                mockito::Matcher::Regex(r"/calendar/v1/cal1/events/sync.*".into()),
            )
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"Code":1001,"Responses":[{"Index":0,"Response":{"Code":1000}}]}"#)
            .create();
        server1
            .mock(
                "GET",
                mockito::Matcher::Regex(r"/calendar/v1/cal1/events.*".into()),
            )
            .with_status(500)
            .with_body("{}")
            .create();

        let engine = CalendarSyncEngine::new(phase_config(server1.url(), vec![create_item(None)]));
        let client = CalendarClient::new_with_base_url(server1.url(), "at".into(), "uid".into());
        let mut keys = material_address_keys(&mat);
        let mut fetched = vec![(test_calendar(), Vec::new())];
        let config = phase_config(server1.url(), vec![create_item(None)]);
        let err = engine
            .run_upload_phase(&config, &client, &mut keys, "uid", &mut fetched)
            .expect_err("re-list must fail");
        assert!(format!("{err}").contains("re-list"), "{err}");
        let pending: std::collections::HashMap<String, String> =
            serde_json::from_str(&engine.pending_json()).expect("pending parses");
        assert_eq!(pending.len(), 1);
        let uid = pending["n1"].clone();
        assert!(uid.starts_with("proton-sync-"), "{uid}");
        let _held = guards1;

        // Cycle 2 (fresh server = fresh mocks): the POST must carry U.
        let mut server2 = mockito::Server::new();
        let mut guards2 = Vec::new();
        mock_bootstrap(&mut server2, &mut guards2, &mat);
        let post2 = server2
            .mock(
                "PUT",
                mockito::Matcher::Regex(r"/calendar/v1/cal1/events/sync.*".into()),
            )
            .match_body(mockito::Matcher::Regex(format!("UID:{uid}")))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"Code":1001,"Responses":[{"Index":0,"Response":{"Code":1000}}]}"#)
            .create();
        server2
            .mock("GET", mockito::Matcher::Regex(r"/calendar/v1/cal1/events.*".into()))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body({
                let now = chrono::Utc::now().timestamp();
                format!(
                    "{{\"Code\":1000,\"Events\":[{{\"ID\":\"c1\",\"UID\":\"{uid}\",\"CalendarID\":\"cal1\",\"StartTime\":{now},\"EndTime\":{},\"LastEditTime\":101,\"FullDay\":0,\"SharedEvents\":[]}}],\"More\":0}}",
                    now + 3600
                )
            })
            .create();
        let engine2 =
            CalendarSyncEngine::new(phase_config(server2.url(), vec![create_item(Some(&uid))]));
        let client2 = CalendarClient::new_with_base_url(server2.url(), "at".into(), "uid".into());
        let mut keys2 = material_address_keys(&mat);
        let mut fetched2 = vec![(test_calendar(), Vec::new())];
        let config2 = phase_config(server2.url(), vec![create_item(Some(&uid))]);
        engine2
            .run_upload_phase(&config2, &client2, &mut keys2, "uid", &mut fetched2)
            .expect("retry completes");
        post2.assert(); // same UID re-POSTed, not a fresh one
        assert_eq!(engine2.pending_json(), String::new(), "re-list drains");
        let _held = guards2;
    }

    #[test]
    fn test_create_conflict_adopts_uid_listed_row_mock() {
        // Non-1000 per-op code + UID-list hit → adopted (no error, no
        // duplicate); the pending entry for it drops.
        let mut server = mockito::Server::new();
        let mut guards = Vec::new();
        let mat = make_key_material();
        mock_bootstrap(&mut server, &mut guards, &mat);
        server
            .mock(
                "PUT",
                mockito::Matcher::Regex(r"/calendar/v1/cal1/events/sync.*".into()),
            )
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"Code":1001,"Responses":[{"Index":0,"Response":{"Code":2200,"Error":"UID conflict"}}]}"#)
            .create();
        let now = chrono::Utc::now().timestamp();
        // NOTE (mockito 1.7 priority): a never-hit mock wins over hit
        // ones, so this catch-all would shadow the UID mock below for
        // UID queries. `.expect(0)` marks it satisfied from the start
        // (it still serves the re-list; its count is just unasserted).
        server
            .mock(
                "GET",
                mockito::Matcher::Regex(r"/calendar/v1/cal1/events.*".into()),
            )
            .expect(0)
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"Code":1000,"Events":[],"More":0}"#)
            .create();
        server
            .mock("GET", mockito::Matcher::Regex(r"/calendar/v1/cal1/events.*".into()))
            .match_query(mockito::Matcher::UrlEncoded("UID".into(), "u-adopt-1".into()))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(format!(
                "{{\"Code\":1000,\"Events\":[{{\"ID\":\"e9\",\"UID\":\"u-adopt-1\",\"CalendarID\":\"cal1\",\"StartTime\":{now},\"EndTime\":{},\"LastEditTime\":50,\"FullDay\":0,\"SharedEvents\":[]}}],\"More\":0}}",
                now + 3600
            ))
            .create();
        let engine = CalendarSyncEngine::new(phase_config(
            server.url(),
            vec![create_item(Some("u-adopt-1"))],
        ));
        let client = CalendarClient::new_with_base_url(server.url(), "at".into(), "uid".into());
        let mut keys = material_address_keys(&mat);
        let mut fetched = vec![(test_calendar(), Vec::new())];
        let config = phase_config(server.url(), vec![create_item(Some("u-adopt-1"))]);
        engine
            .run_upload_phase(&config, &client, &mut keys, "uid", &mut fetched)
            .expect("conflict adopts");
        assert!(engine.pending_json().is_empty());
        let _held = guards;
    }

    #[test]
    fn test_create_conflict_unresolvable_fails_closed_mock() {
        // Non-1000 per-op code + UID-list miss → fail closed (the old
        // first_error behavior for real validation errors).
        let mut server = mockito::Server::new();
        let mut guards = Vec::new();
        let mat = make_key_material();
        mock_bootstrap(&mut server, &mut guards, &mat);
        server
            .mock(
                "PUT",
                mockito::Matcher::Regex(r"/calendar/v1/cal1/events/sync.*".into()),
            )
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"Code":1001,"Responses":[{"Index":0,"Response":{"Code":2011,"Error":"Not a valid Proton color"}}]}"#)
            .create();
        server
            .mock(
                "GET",
                mockito::Matcher::Regex(r"/calendar/v1/cal1/events.*".into()),
            )
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"Code":1000,"Events":[],"More":0}"#)
            .create();
        let engine = CalendarSyncEngine::new(phase_config(
            server.url(),
            vec![create_item(Some("u-ghost-1"))],
        ));
        let client = CalendarClient::new_with_base_url(server.url(), "at".into(), "uid".into());
        let mut keys = material_address_keys(&mat);
        let mut fetched = vec![(test_calendar(), Vec::new())];
        let config = phase_config(server.url(), vec![create_item(Some("u-ghost-1"))]);
        let err = engine
            .run_upload_phase(&config, &client, &mut keys, "uid", &mut fetched)
            .expect_err("unresolvable conflict must fail");
        assert!(format!("{err}").contains("unresolvable"), "{err}");
        let _held = guards;
    }

    #[test]
    fn test_no_inventory_stays_download_only() {
        // Without a fed inventory the upload phase is a no-op: the SAME
        // mocks as above must complete with both rows present and zero PUTs
        // (today's behavior, byte-identical downloads).
        let mut server = mockito::Server::new();
        let mut guards = Vec::new();
        macro_rules! mock_get {
            ($re:expr, $code:expr, $body:expr) => {
                guards.push(
                    server
                        .mock("GET", mockito::Matcher::Regex($re.into()))
                        .with_status($code)
                        .with_header("content-type", "application/json")
                        .with_body($body)
                        .create(),
                );
            };
        }
        mock_get!(
            r"/core/v4/users.*",
            200,
            r#"{"User":{"ID":"u","Name":"t","Keys":[]}}"#
        );
        mock_get!(r"/core/v4/keys/salts.*", 200, r#"{"KeySalts":[]}"#);
        mock_get!(r"/core/v4/addresses.*", 200, r#"{"Addresses":[]}"#);
        mock_get!(
            r"/calendar/v1$",
            200,
            r#"{"Code":1000,"Calendars":[{"ID":"cal1","Name":"C"}]}"#
        );
        let now = chrono::Utc::now().timestamp();
        guards.push(
            server
                .mock(
                    "GET",
                    mockito::Matcher::Regex(r"/calendar/v1/cal1/events.*".into()),
                )
                .with_status(200)
                .with_header("content-type", "application/json")
                .with_body(format!(
                    "{{\"Code\":1000,\"Events\":[{{\"ID\":\"e1\",\"UID\":\"u1\",\"StartTime\":{now},\"EndTime\":{},\"LastEditTime\":100,\"FullDay\":0,\"SharedEvents\":[{{\"Type\":2,\"Data\":\"BEGIN:VEVENT\\nUID:u1\\nSUMMARY:Keep\\nEND:VEVENT\",\"Signature\":\"s\"}}]}}],\"More\":0}}",
                    now + 3600
                ))
                .create(),
        );
        mock_get!(r"/calendar/v2/cal1/bootstrap.*", 404, "{}");
        mock_get!(
            r"/calendar/v1/cal1/members.*",
            200,
            r#"{"Members":[{"ID":"m1","Email":"t@x","Name":"T"}]}"#
        );
        mock_get!(r"/calendar/v1/cal1/keys.*", 200, r#"{"Keys":[]}"#);
        mock_get!(
            r"/calendar/v1/cal1/passphrase.*",
            200,
            r#"{"Passphrase":null}"#
        );
        mock_get!(
            r"/calendar/v1/cal1/settings.*",
            200,
            r#"{"Code":1000,"CalendarSettings":{}}"#
        );
        // Any PUT would 501 (no mock) and fail the phase — plus assert zero.
        let put = server
            .mock(
                "PUT",
                mockito::Matcher::Regex(r"/calendar/v1/cal1/events/sync.*".into()),
            )
            .expect(0)
            .create();
        guards.push(put);

        let mut c = cfg();
        c.refresh_token = Some("rt".into());
        c.uid = Some("uid".into());
        c.access_token = Some("at".into());
        c.api_base_url = Some(server.url());
        assert!(c.local_inventory.is_none());

        let mut engine = CalendarSyncEngine::new(c.clone());
        engine.start_sync(c);
        assert_eq!(engine.status().state, "complete");
        let events: Vec<CalEventJson> = serde_json::from_str(&engine.get_events_json()).unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].id, "e1");
        let purgeable: Vec<String> = serde_json::from_str(&engine.purgeable_json()).unwrap();
        assert!(purgeable.is_empty());
        let _held = guards;
    }
}
