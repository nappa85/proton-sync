// proton-api/src/calendar.rs — Proton Calendar REST client (contacts analog)
// Endpoints documented in go-proton-api calendar*.go and WebClients api/calendars.ts
// Crypto model per cheeseandcereal/proton-cal docs/crypto.md + api.md (June 2026,
// verified live) and proton.me/blog/protoncalendar-security-model:
//   user key -> address key (Token) -> calendar passphrase (per-member armored)
//   -> calendar keys -> per-event session keys (SharedKeyPacket/CalendarKeyPacket).
use crate::client::{build_client, API_BASE, APP_VERSION};
use crate::{crypto::UnlockedKey, models::*, ProtonError, Result};
use base64::Engine;
use serde::{Deserialize, Serialize};
use std::time::Duration;

pub const CALENDAR_MAX_WINDOW_SECS: i64 = 93 * 86400;
pub const CALENDAR_PAGE_SIZE: u32 = 100;

pub struct CalendarModelChanges {
    pub cursor: String,
    pub more: bool,
    pub refresh: bool,
    pub events: Vec<(String, u8)>,
}

pub struct CalendarClient {
    client: reqwest::blocking::Client,
    base_url: String,
    access_token: String,
    uid: String,
    pacer: crate::client::RequestPacer,
}

impl CalendarClient {
    pub fn new(access_token: String, uid: String) -> Self {
        Self {
            client: build_client(Duration::from_secs(60)),
            base_url: API_BASE.to_string(),
            access_token,
            uid,
            pacer: Default::default(),
        }
    }

    pub fn new_with_base_url(base_url: String, access_token: String, uid: String) -> Self {
        Self {
            client: build_client(Duration::from_secs(60)),
            base_url,
            access_token,
            uid,
            pacer: Default::default(),
        }
    }

    fn auth_header(&self) -> String {
        format!("Bearer {}", self.access_token)
    }

    pub fn list_calendars(&self) -> Result<Vec<Calendar>> {
        self.pacer.wait();
        let resp = self
            .client
            .get(format!("{}/calendar/v1", self.base_url))
            .header("Authorization", self.auth_header())
            .header("x-pm-uid", &self.uid)
            .header("x-pm-appversion", APP_VERSION)
            .send()?
            .error_for_status()?;
        let text = resp.text()?;
        let v: serde_json::Value = serde_json::from_str(&text)?;
        if v.get("Code")
            .and_then(|c| c.as_i64())
            .is_some_and(|c| c != 1000)
        {
            return Err(ProtonError::Api {
                code: 0,
                message: "Calendar listing rejected".into(),
            });
        }
        let cals: Vec<Calendar> = serde_json::from_value(v["Calendars"].clone())?;
        if cals.iter().any(|cal| cal.ID.is_empty()) {
            return Err(ProtonError::Api {
                code: 0,
                message: "Calendar list contains an empty ID".into(),
            });
        }
        Ok(cals)
    }

    fn fetch_model(&self, cal_id: &str, cursor: &str) -> Result<Option<serde_json::Value>> {
        self.pacer.wait();
        let response = self
            .client
            .get(format!(
                "{}/calendar/v1/{cal_id}/modelevents/{cursor}",
                self.base_url
            ))
            .header("Authorization", self.auth_header())
            .header("x-pm-uid", &self.uid)
            .header("x-pm-appversion", APP_VERSION)
            .send()?;
        if matches!(response.status().as_u16(), 404 | 410 | 501) {
            return Ok(None); // Unsupported or expired cursor: full refresh.
        }
        if response.status().as_u16() == 400 {
            let value: serde_json::Value = response.json()?;
            if cursor != "latest" && value.get("Code").and_then(|c| c.as_i64()) == Some(2061) {
                return Ok(None); // Proton INVALID_ID_ERROR, not auth/rate limiting.
            }
            return Err(ProtonError::Api {
                code: 0,
                message: "Calendar change feed rejected with HTTP 400".into(),
            });
        }
        let response = response.error_for_status()?;
        let value: serde_json::Value = response.json()?;
        if value
            .get("Code")
            .and_then(|c| c.as_i64())
            .is_some_and(|c| c != 1000)
        {
            return Err(ProtonError::Api {
                code: 0,
                message: "Calendar change feed rejected".into(),
            });
        }
        Ok(Some(value))
    }

    pub fn latest_model_event_id(&self, cal_id: &str) -> Result<Option<String>> {
        self.fetch_model(cal_id, "latest")?
            .map(|value| {
                value
                    .get("CalendarModelEventID")
                    .and_then(|v| v.as_str())
                    .filter(|s| !s.is_empty())
                    .map(str::to_owned)
                    .ok_or_else(|| ProtonError::Api {
                        code: 0,
                        message: "Calendar change feed has no cursor".into(),
                    })
            })
            .transpose()
    }

    pub fn model_changes(
        &self,
        cal_id: &str,
        cursor: &str,
    ) -> Result<Option<CalendarModelChanges>> {
        let Some(value) = self.fetch_model(cal_id, cursor)? else {
            return Ok(None);
        };
        let flag = |key: &str, optional: bool| -> Result<bool> {
            match value.get(key) {
                Some(serde_json::Value::Bool(v)) => Ok(*v),
                Some(serde_json::Value::Number(v)) => {
                    v.as_u64().map(|n| n != 0).ok_or_else(|| ProtonError::Api {
                        code: 0,
                        message: format!("Invalid calendar {key} flag"),
                    })
                }
                None if optional => Ok(false),
                _ => Err(ProtonError::Api {
                    code: 0,
                    message: format!("Missing calendar {key} flag"),
                }),
            }
        };
        let next = value
            .get("CalendarModelEventID")
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .ok_or_else(|| ProtonError::Api {
                code: 0,
                message: "Calendar change feed has no cursor".into(),
            })?;
        let mut events = Vec::new();
        match value.get("CalendarEvents") {
            Some(serde_json::Value::Array(rows)) => {
                for row in rows {
                    let id = row
                        .get("ID")
                        .and_then(|v| v.as_str())
                        .filter(|s| !s.is_empty());
                    let action = row
                        .get("Action")
                        .and_then(|v| v.as_u64())
                        .filter(|n| *n <= 2);
                    match (id, action) {
                        (Some(id), Some(action)) => events.push((id.to_owned(), action as u8)),
                        _ => {
                            return Err(ProtonError::Api {
                                code: 0,
                                message: "Invalid calendar change record".into(),
                            })
                        }
                    }
                }
            }
            None | Some(serde_json::Value::Null) => {}
            _ => {
                return Err(ProtonError::Api {
                    code: 0,
                    message: "Invalid calendar change array".into(),
                })
            }
        }
        Ok(Some(CalendarModelChanges {
            cursor: next.to_owned(),
            more: flag("More", false)?,
            refresh: flag("Refresh", true)?,
            events,
        }))
    }

    pub fn get_calendar_keys(&self, cal_id: &str) -> Result<Vec<CalendarKey>> {
        self.pacer.wait();
        let resp = self
            .client
            .get(format!("{}/calendar/v1/{}/keys", self.base_url, cal_id))
            .header("Authorization", self.auth_header())
            .header("x-pm-uid", &self.uid)
            .header("x-pm-appversion", APP_VERSION)
            .send()?
            .error_for_status()?;
        let v: serde_json::Value = resp.json()?;
        let keys: Vec<CalendarKey> = serde_json::from_value(v["Keys"].clone()).unwrap_or_default();
        Ok(keys)
    }

    pub fn get_passphrase(&self, cal_id: &str) -> Result<CalendarPassphrase> {
        self.pacer.wait();
        let resp = self
            .client
            .get(format!(
                "{}/calendar/v1/{}/passphrase",
                self.base_url, cal_id
            ))
            .header("Authorization", self.auth_header())
            .header("x-pm-uid", &self.uid)
            .header("x-pm-appversion", APP_VERSION)
            .send()?
            .error_for_status()?;
        let v: serde_json::Value = resp.json()?;
        Ok(serde_json::from_value(v["Passphrase"].clone())?)
    }

    pub fn get_members(&self, cal_id: &str) -> Result<Vec<CalendarMember>> {
        self.pacer.wait();
        let resp = self
            .client
            .get(format!("{}/calendar/v1/{}/members", self.base_url, cal_id))
            .header("Authorization", self.auth_header())
            .header("x-pm-uid", &self.uid)
            .header("x-pm-appversion", APP_VERSION)
            .send()?
            .error_for_status()?;
        let v: serde_json::Value = resp.json()?;
        let members: Vec<CalendarMember> =
            serde_json::from_value(v["Members"].clone()).unwrap_or_default();
        Ok(members)
    }

    /// Consolidated bootstrap (only v2 route, api.md): Keys + Passphrase +
    /// Members in one call. Falls back to three v1 calls if v2 is unavailable.
    pub fn get_bootstrap(&self, cal_id: &str) -> Result<CalendarBootstrap> {
        self.pacer.wait();
        let v2 = self
            .client
            .get(format!(
                "{}/calendar/v2/{}/bootstrap",
                self.base_url, cal_id
            ))
            .header("Authorization", self.auth_header())
            .header("x-pm-uid", &self.uid)
            .header("x-pm-appversion", APP_VERSION)
            .send();
        if let Ok(resp) = v2 {
            if resp.status().is_success() {
                if let Ok(v) = resp.json::<serde_json::Value>() {
                    let members: Vec<CalendarMember> =
                        serde_json::from_value(v["Members"].clone()).unwrap_or_default();
                    let keys: Vec<CalendarKey> =
                        serde_json::from_value(v["Keys"].clone()).unwrap_or_default();
                    let passphrase: Option<CalendarPassphrase> =
                        serde_json::from_value(v["Passphrase"].clone()).unwrap_or(None);
                    let settings: Option<CalendarSettings> =
                        serde_json::from_value(v["CalendarSettings"].clone()).unwrap_or(None);
                    // v2 returns passphrase object directly (not Option-wrapped null issue)
                    if !members.is_empty() || !keys.is_empty() || passphrase.is_some() {
                        let mut boot = CalendarBootstrap {
                            Members: members,
                            Keys: keys,
                            Passphrase: passphrase,
                            Settings: settings,
                        };
                        // v2 omits CalendarSettings on some servers/accounts
                        // (verified live: present via v1, absent via v2) —
                        // fill it from the standalone route when missing.
                        // An empty `{}` counts as missing too.
                        if boot.Settings.as_ref().is_none_or(|s| s.is_empty()) {
                            boot.Settings =
                                self.get_settings(cal_id).ok().filter(|s| !s.is_empty());
                        }
                        return Ok(boot);
                    }
                }
            }
        }
        // Fallback: v1 calls (same shapes per api.md).
        let members = self.get_members(cal_id).unwrap_or_default();
        let keys = self.get_calendar_keys(cal_id).unwrap_or_default();
        let passphrase = self.get_passphrase(cal_id).ok();
        let settings = self.get_settings(cal_id).ok().filter(|s| !s.is_empty());
        Ok(CalendarBootstrap {
            Members: members,
            Keys: keys,
            Passphrase: passphrase,
            Settings: settings,
        })
    }

    /// Standalone calendar settings (v1 route; bootstrap carries the same).
    /// Single-fetch variant also returns the full scrubbed response body,
    /// so an empty result is always attributable: "server sent nothing" vs
    /// "server sent a shape we don't parse". Never silently default.
    pub fn get_settings_verbose(&self, cal_id: &str) -> Result<(CalendarSettings, String)> {
        let (v, status) = self.fetch_settings_raw(cal_id)?;
        let body = format!("http{status} {}", crate::diag::diag_body(&v));
        let inner = v.get("CalendarSettings").unwrap_or(&v);
        let settings: CalendarSettings = serde_json::from_value(inner.clone()).unwrap_or_default();
        Ok((settings, body))
    }

    pub fn get_settings(&self, cal_id: &str) -> Result<CalendarSettings> {
        Ok(self.get_settings_verbose(cal_id)?.0)
    }

    /// Raw settings payloads for diagnostics (v1 + account-level).
    pub fn fetch_settings_raw(&self, cal_id: &str) -> Result<(serde_json::Value, u16)> {
        self.pacer.wait();
        let resp = self
            .client
            .get(format!("{}/calendar/v1/{}/settings", self.base_url, cal_id))
            .header("Authorization", self.auth_header())
            .header("x-pm-uid", &self.uid)
            .header("x-pm-appversion", APP_VERSION)
            .send()?;
        let status = resp.status().as_u16();
        let body = resp.text().unwrap_or_default();
        Ok((
            serde_json::from_str(&body).unwrap_or(serde_json::Value::Null),
            status,
        ))
    }

    /// Raw per-account calendar user settings (`DefaultCalendarID` lives
    /// here; default reminder sets may too — verified live).
    pub fn fetch_account_calendar_settings_raw(&self) -> Result<(serde_json::Value, u16)> {
        self.pacer.wait();
        let resp = self
            .client
            .get(format!("{}/settings/calendar", self.base_url))
            .header("Authorization", self.auth_header())
            .header("x-pm-uid", &self.uid)
            .header("x-pm-appversion", APP_VERSION)
            .send()?;
        let status = resp.status().as_u16();
        let body = resp.text().unwrap_or_default();
        Ok((
            serde_json::from_str(&body).unwrap_or(serde_json::Value::Null),
            status,
        ))
    }

    /// Single Type-scoped page (Type 0..3 required for server-side windowing,
    /// api.md). `Timezone` is REQUIRED by the server (400 Code 2000 without
    /// it, verified live 2026-09-06); "UTC" is the neutral choice. Returns
    /// (events, More cursor).
    pub fn list_events_page(
        &self,
        cal_id: &str,
        query_type: u32,
        start: i64,
        end: i64,
        page: u32,
        timezone: &str,
    ) -> Result<(Vec<CalendarEvent>, bool)> {
        let v = self.fetch_events_page_raw(cal_id, query_type, start, end, page, timezone)?;
        Self::parse_complete_events_envelope(&v, page)
    }

    /// Tolerant envelope parsing shared by typed and untyped listings.
    /// Unknown shapes must not silently drop rows: `More` accepts 0/1 or
    /// bool, falling back to `Total`-based paging.
    pub fn parse_events_envelope(v: &serde_json::Value, page: u32) -> (Vec<CalendarEvent>, bool) {
        // Element-wise: one unparseable row must not drop the whole page.
        // Skips are logged (trace) with the row ID and serde path.
        let events: Vec<CalendarEvent> =
            v.get("Events")
                .and_then(|e| e.as_array())
                .map_or_else(Vec::new, |a| {
                    a.iter()
                        .filter_map(|item| match serde_json::from_value(item.clone()) {
                            Ok(ev) => Some(ev),
                            Err(e) => {
                                if std::env::var("LIVE_TRACE").is_ok() {
                                    eprintln!(
                                        "trace parse-skip ID={} err={e}",
                                        item.get("ID").map_or("?".into(), |m| m.to_string())
                                    );
                                }
                                None
                            }
                        })
                        .collect()
                });
        let more = match v.get("More") {
            Some(serde_json::Value::Bool(b)) => *b,
            Some(serde_json::Value::Number(n)) => n.as_i64().unwrap_or(0) != 0,
            _ => v
                .get("Total")
                .and_then(|t| t.as_u64())
                .is_some_and(|total| (u64::from(page) + 1) * u64::from(CALENDAR_PAGE_SIZE) < total),
        };
        (events, more)
    }

    // Keep tolerant parsing available for diagnostics, but never let a
    // skipped row masquerade as server deletion in a replacement snapshot.
    fn parse_complete_events_envelope(
        v: &serde_json::Value,
        page: u32,
    ) -> Result<(Vec<CalendarEvent>, bool)> {
        let (events, more) = Self::parse_events_envelope(v, page);
        if let Some(rows) = v.get("Events").and_then(|e| e.as_array()) {
            if rows.len() != events.len() {
                return Err(ProtonError::Api {
                    code: 0,
                    message: "Calendar page contains undecodable events; snapshot incomplete"
                        .into(),
                });
            }
        } else {
            return Err(ProtonError::Api {
                code: 0,
                message: "Calendar page has no Events array; snapshot incomplete".into(),
            });
        }
        if events.iter().any(|event| event.ID.is_empty()) || (more && events.is_empty()) {
            return Err(ProtonError::Api {
                code: 0,
                message: "Calendar page has invalid IDs or non-progressing pagination".into(),
            });
        }
        Ok((events, more))
    }

    /// Raw GET for diagnostics: returns (status, body) without status checks.
    pub fn fetch_events_raw(
        &self,
        cal_id: &str,
        params: &[(&str, String)],
    ) -> Result<(u16, String)> {
        self.pacer.wait();
        let pairs: Vec<(String, String)> = params
            .iter()
            .map(|(k, v)| ((*k).to_string(), v.clone()))
            .collect();
        let resp = self
            .client
            .get(format!("{}/calendar/v1/{}/events", self.base_url, cal_id))
            .header("Authorization", self.auth_header())
            .header("x-pm-uid", &self.uid)
            .header("x-pm-appversion", APP_VERSION)
            .query(&pairs)
            .send()?;
        let status = resp.status().as_u16();
        if std::env::var("LIVE_TRACE").is_ok() {
            let hdrs: Vec<String> = resp
                .headers()
                .iter()
                .map(|(k, v)| format!("{}={}", k, v.to_str().unwrap_or("?")))
                .collect();
            eprintln!("trace HEADERS {}", hdrs.join(" "));
        }
        let body = resp.text().unwrap_or_default();
        Ok((status, body))
    }

    /// Diagnostic helper: raw page envelope for one (Type, page) query.
    /// Used by the live-check example to inspect real server shapes.
    pub fn fetch_events_page_raw(
        &self,
        cal_id: &str,
        query_type: u32,
        start: i64,
        end: i64,
        page: u32,
        timezone: &str,
    ) -> Result<serde_json::Value> {
        let resp = self
            .client
            .get(format!("{}/calendar/v1/{}/events", self.base_url, cal_id))
            .header("Authorization", self.auth_header())
            .header("x-pm-uid", &self.uid)
            .header("x-pm-appversion", APP_VERSION)
            .query(&[
                ("Type", query_type.to_string()),
                ("Start", start.to_string()),
                ("End", end.to_string()),
                ("Timezone", timezone.to_string()),
                ("Page", page.to_string()),
                ("PageSize", CALENDAR_PAGE_SIZE.to_string()),
            ])
            .send()?
            .error_for_status()?;
        if std::env::var("LIVE_TRACE").is_ok() {
            eprintln!("trace RESP-URL {}", resp.url());
        }
        Ok(resp.json()?)
    }

    /// Legacy untyped list (kept for compat; server ignores Start/End without
    /// Type and paginates everything – do not use for sync).
    pub fn list_events(&self, cal_id: &str, start: i64, end: i64) -> Result<Vec<CalendarEvent>> {
        let mut out = Vec::new();
        for t in 0..4 {
            let (mut evs, _) = self
                .list_events_page(cal_id, t, start, end, 0, "UTC")
                .unwrap_or_default();
            out.append(&mut evs);
        }
        dedupe_events(&mut out);
        Ok(out)
    }

    /// Windowed sync read (api.md): all 4 Types, ≤93d chunks, ±1d padding,
    /// More-pagination, dedupe by ID. `timezone` is forwarded as the REQUIRED
    /// Timezone query param ("UTC" unless the caller knows better).
    pub fn list_all_events_windowed(
        &self,
        cal_id: &str,
        start: i64,
        end: i64,
        timezone: &str,
    ) -> Result<Vec<CalendarEvent>> {
        let mut out: Vec<CalendarEvent> = Vec::new();
        // ±1d padding keeps boundary rows; content chunks are therefore ≤91d
        // so padded spans never exceed the 93d server cap (400 otherwise).
        let trace = std::env::var("LIVE_TRACE").is_ok();
        for (cs, ce) in split_window(start, end, CALENDAR_MAX_WINDOW_SECS - 2 * 86400) {
            // ±1d padding (server buckets by tz-local start/end).
            let ps = cs.saturating_sub(86400);
            let pe = ce.saturating_add(86400);
            for query_type in 0..4 {
                let mut page = 0u32;
                loop {
                    let (evs, more) =
                        self.list_events_page(cal_id, query_type, ps, pe, page, timezone)?;
                    if trace {
                        eprintln!(
                            "trace cal={} type={query_type} [{ps},{pe}] page={page} rows={} more={more}",
                            &cal_id[..8.min(cal_id.len())],
                            evs.len(),
                        );
                    }
                    out.extend(evs);
                    if !more {
                        break;
                    }
                    page += 1;
                    if page > 100 {
                        break;
                    }
                }
            }
        }
        dedupe_events(&mut out);
        Ok(out)
    }

    /// Batch create/update/delete via the sync write path (api.md — the
    /// ONLY event write route; no standalone POST exists). The caller builds
    /// the batch with `calendar_write` (sealed bodies); this only transports
    /// it. HTTP errors surface as `Err`; per-op failures live in the
    /// response (`first_error`). Untested live — covered by mockito tests.
    pub fn put_sync(
        &self,
        cal_id: &str,
        batch: &crate::calendar_write::SyncBatchRequest,
    ) -> Result<crate::calendar_write::SyncBatchResponse> {
        let resp = self
            .client
            .put(format!(
                "{}/calendar/v1/{}/events/sync",
                self.base_url, cal_id
            ))
            .header("Authorization", self.auth_header())
            .header("x-pm-uid", &self.uid)
            .header("x-pm-appversion", APP_VERSION)
            .json(batch)
            .send()?
            .error_for_status()?;
        Ok(resp.json()?)
    }

    /// Reminder/color-only edit via the personal-part route (WebClients
    /// `updatePersonalEventPart`, `CreateSinglePersonalEventData`): no
    /// cards resealed, no key packets, no SEQUENCE implications — the
    /// server patches just these two row columns. Returns the updated
    /// row; any non-1000 envelope Code fails with the body attached
    /// (contacts 4xx lesson: never blind). Covered by mockito tests;
    /// live verification pending (needs a reminder edit on device).
    pub fn put_personal(
        &self,
        cal_id: &str,
        event_id: &str,
        body: &crate::calendar_write::PersonalEventBody,
    ) -> Result<CalendarEvent> {
        let resp = self
            .client
            .put(format!(
                "{}/calendar/v1/{}/events/{}/personal",
                self.base_url, cal_id, event_id
            ))
            .header("Authorization", self.auth_header())
            .header("x-pm-uid", &self.uid)
            .header("x-pm-appversion", APP_VERSION)
            .json(body)
            .send()?;
        let status = resp.status();
        let text = resp.text().unwrap_or_default();
        if !status.is_success() {
            let short: String = text.chars().take(1000).collect();
            return Err(crate::ProtonError::Api {
                code: 0,
                message: format!("calendar personal PUT failed {status}: {short}"),
            });
        }
        let v: serde_json::Value =
            serde_json::from_str(&text).map_err(crate::ProtonError::Serde)?;
        let code = v.get("Code").and_then(|c| c.as_i64()).unwrap_or(0);
        if code != 1000 && code != 1001 {
            let short: String = text.chars().take(1000).collect();
            return Err(crate::ProtonError::Api {
                code: 0,
                message: format!("calendar personal PUT rejected code {code}: {short}"),
            });
        }
        serde_json::from_value(v["Event"].clone()).map_err(crate::ProtonError::Serde)
    }

    pub fn get_event(&self, cal_id: &str, event_id: &str) -> Result<CalendarEvent> {
        self.pacer.wait();
        let resp = self
            .client
            .get(format!(
                "{}/calendar/v1/{}/events/{}",
                self.base_url, cal_id, event_id
            ))
            .header("Authorization", self.auth_header())
            .header("x-pm-uid", &self.uid)
            .header("x-pm-appversion", APP_VERSION)
            .send()?
            .error_for_status()?;
        let v: serde_json::Value = resp.json()?;
        Ok(serde_json::from_value(v["Event"].clone())?)
    }

    pub fn list_all_events(&self, cal_id: &str) -> Result<Vec<CalendarEvent>> {
        // 2-year window. Live-verified 2026-09-06: untyped paged listing +
        // client-side filtering is reliable, while Type-scoped chunk queries
        // intermittently return 200-empty for covered windows (see
        // FINDINGS_CALENDAR.md §7). Same approach as Nojuza/proton-calendar-cli.
        let end = chrono::Utc::now().timestamp() + 365 * 24 * 3600;
        let start = end - 2 * 365 * 24 * 3600;
        self.list_all_events_untyped(cal_id, start, end)
    }

    /// Server-side UID filter: all rows sharing one iCal UID (master +
    /// exception rows), `More`-paginated (proton-cal `GetByUID`). No window
    /// params — independent of `Type`. Used by upsync to resolve tombstones
    /// the windowed listing missed (out-of-window deletes).
    pub fn list_by_uid(&self, cal_id: &str, uid: &str) -> Result<Vec<CalendarEvent>> {
        let mut out = Vec::new();
        let mut page = 0u32;
        loop {
            let params = vec![
                ("UID", uid.to_string()),
                ("Page", page.to_string()),
                ("PageSize", CALENDAR_PAGE_SIZE.to_string()),
            ];
            let (status, body) = self.fetch_events_raw(cal_id, &params)?;
            if status != 200 {
                return Err(ProtonError::Auth(format!(
                    "UID events query failed {status}: {}",
                    body.chars().take(200).collect::<String>()
                )));
            }
            let v: serde_json::Value = serde_json::from_str(&body)?;
            let (evs, more) = Self::parse_complete_events_envelope(&v, page)?;
            let n = evs.len();
            out.extend(evs);
            if std::env::var("LIVE_TRACE").is_ok() {
                eprintln!("trace uid cal={cal_id} page={page} rows={n} more={more}");
            }
            if !more {
                break;
            }
            page += 1;
            if page > 100 {
                break;
            }
        }
        Ok(out)
    }

    /// Untyped full listing with client-side window filtering.
    /// Recurring masters (RRule present) are always included: per api.md they
    /// must never be window-filtered by their own StartTime/EndTime, which
    /// describe only the first occurrence.
    pub fn list_all_events_untyped(
        &self,
        cal_id: &str,
        start: i64,
        end: i64,
    ) -> Result<Vec<CalendarEvent>> {
        let mut out = Vec::new();
        let mut seen = std::collections::HashSet::new();
        let mut page = 0u32;
        loop {
            let params = vec![
                ("Page", page.to_string()),
                ("PageSize", CALENDAR_PAGE_SIZE.to_string()),
            ];
            let (status, body) = self.fetch_events_raw(cal_id, &params)?;
            if status != 200 {
                return Err(ProtonError::Auth(format!(
                    "Untyped events query failed {status}: {}",
                    body.chars().take(200).collect::<String>()
                )));
            }
            let v: serde_json::Value = serde_json::from_str(&body)?;
            let (evs, more) = Self::parse_complete_events_envelope(&v, page)?;
            let new_ids = evs
                .iter()
                .filter(|event| seen.insert(event.ID.clone()))
                .count();
            if more && new_ids == 0 {
                return Err(ProtonError::Api {
                    code: 0,
                    message: "Calendar listing pagination repeated a page".into(),
                });
            }
            let raw = evs.len();
            let mut kept = 0usize;
            for ev in evs {
                let recurring = ev.RRule.as_ref().is_some_and(|r| !r.is_empty());
                if recurring || (ev.StartTime < end && ev.EndTime > start) {
                    out.push(ev);
                    kept += 1;
                }
            }
            if std::env::var("LIVE_TRACE").is_ok() {
                let keys: Vec<&String> = v.as_object().map_or(Vec::new(), |m| m.keys().collect());
                let snippet: String = body.chars().take(300).collect();
                eprintln!(
                    "trace untyped cal={} page={page} status={status} raw={raw} kept={kept} more={more} MoreRaw={} TotalRaw={} keys={keys:?} body={snippet}",
                    cal_id,
                    v.get("More").map_or("?".into(), |m| m.to_string()),
                    v.get("Total").map_or("?".into(), |m| m.to_string()),
                );
            }
            if !more {
                break;
            }
            page += 1;
            if page > 1000 {
                return Err(ProtonError::Api {
                    code: 0,
                    message: "Calendar listing pagination limit exceeded".into(),
                });
            }
        }
        dedupe_events(&mut out);
        Ok(out)
    }
}

/// Split [start,end) into ≤max_span chunks (api.md 93d cap).
pub fn split_window(start: i64, end: i64, max_span: i64) -> Vec<(i64, i64)> {
    if end <= start || max_span <= 0 {
        return Vec::new();
    }
    let mut out = Vec::new();
    let mut cur = start;
    while cur < end {
        let nxt = (cur.saturating_add(max_span)).min(end);
        out.push((cur, nxt));
        if nxt >= end {
            break;
        }
        cur = nxt;
    }
    out
}

fn dedupe_events(evs: &mut Vec<CalendarEvent>) {
    use std::collections::HashSet;
    let mut seen = HashSet::new();
    evs.retain(|e| seen.insert(e.ID.clone()));
}

/// Lenient signature check (proton-cal `event.Decrypt` + web client behavior:
/// verification is optional in practice; failures must not fail decrypt).
/// Returns Ok(true) when a signature was present (verification attempted),
/// Ok(false) when skipped. Never returns Err.
pub fn verify_signature(
    _data: &str,
    signature: &str,
    _calendar_keys: &[UnlockedKey],
    _address_keys: &[UnlockedKey],
) -> Result<bool> {
    if signature.is_empty() {
        return Ok(false);
    }
    // Full detached-verify via sequoia would need the author's *public* key;
    // UnlockedKey only carries private keypairs, and Proton signs event cards
    // with the author's address key while we may only hold calendar keys.
    // Like proton-cal's lenient read path, we accept the plaintext and let the
    // caller record provenance from row columns (Author). See FINDINGS_CALENDAR.md.
    Ok(true)
}

/// Decrypt one event card.
///
/// Mirrors `go-proton-api` `CalendarEventPart::Decode`:
/// - Encrypted (Type&1) + `key_packet` present → Data is base64 raw SEIPD,
///   key_packet is base64 PKESK; concat binary packets → decrypt with calendar keys.
/// - Encrypted without packet → armored PGP decrypt with calendar keys
///   (fallback: address keys, for passphrase-style cards).
/// - Signed (Type&2) → lenient verify (never fails).
pub fn decrypt_calendar_part(
    part: &CalendarEventPart,
    calendar_keys: &mut [UnlockedKey],
    address_keys: &mut [UnlockedKey],
    key_packet: Option<&str>,
) -> Result<String> {
    let is_encrypted = (part.Type & 1) != 0;
    let is_signed = (part.Type & 2) != 0;
    let mut data = part.Data.clone();
    if is_encrypted {
        let mut found: Option<String> = None;
        // 1) Split-packet path (normal event cards with Shared/CalendarKeyPacket).
        if let Some(kp) = key_packet {
            if !kp.is_empty() && !part.Data.is_empty() {
                let kp_raw = base64::engine::general_purpose::STANDARD.decode(kp).ok();
                let data_raw = base64::engine::general_purpose::STANDARD
                    .decode(&part.Data)
                    .ok();
                if let (Some(kp_raw), Some(data_raw)) = (kp_raw, data_raw) {
                    let mut combined = kp_raw;
                    combined.extend_from_slice(&data_raw);
                    for ak in calendar_keys.iter_mut() {
                        if let Ok(plain) = crate::crypto::decrypt_bytes_with_key(&combined, ak) {
                            found = Some(plain);
                            break;
                        }
                    }
                }
            }
        }
        // 2) Armored fallback (passphrase cards, invites, tests).
        if found.is_none() {
            for ak in calendar_keys.iter_mut().chain(address_keys.iter_mut()) {
                if let Ok(plain) = crate::crypto::decrypt_with_key(&data, ak) {
                    found = Some(plain);
                    break;
                }
            }
        }
        data =
            found.ok_or_else(|| ProtonError::Crypto("calendar decrypt failed: no key".into()))?;
    }
    if is_signed && !part.Signature.is_empty() {
        let _ = verify_signature(&data, &part.Signature, calendar_keys, address_keys);
    }
    Ok(data)
}

// Helper to keep the double-Result let readable under clippy::pedantic.

/// Back-compat wrapper (existing callers pass no key packets).
pub fn decrypt_calendar_event(
    part: &CalendarEventPart,
    calendar_keys: &mut [UnlockedKey],
    address_keys: &mut [UnlockedKey],
) -> Result<String> {
    decrypt_calendar_part(part, calendar_keys, address_keys, None)
}

/// Decrypt the member passphrase with any address key (api.md: passphrase may
/// be encrypted to ANY account address key, not necessarily the member's –
/// try all), then unlock every calendar key that opens with it (keep old
/// generations – old events may use retired keys).
pub fn decrypt_calendar_keys(
    keys: &[CalendarKey],
    passphrase: &CalendarPassphrase,
    address_keys: &mut [UnlockedKey],
    member_id: &str,
) -> Result<Vec<UnlockedKey>> {
    let member_pp = passphrase
        .MemberPassphrases
        .iter()
        .find(|mp| mp.MemberID == member_id)
        .ok_or_else(|| ProtonError::Crypto("No passphrase for member".into()))?;

    let passphrase_plain = crate::crypto::decrypt_contact_card(&member_pp.Passphrase, address_keys)
        .map_err(|e| ProtonError::Crypto(format!("Calendar passphrase decrypt failed: {e}")))?;

    let mut unlocked = Vec::new();
    for key in keys {
        if key.PrivateKey.is_empty() {
            continue;
        }
        match UnlockedKey::from_armored(&key.PrivateKey, passphrase_plain.as_bytes()) {
            Ok(uk) => unlocked.push(uk),
            Err(_) => continue,
        }
    }

    if unlocked.is_empty() {
        return Err(ProtonError::Crypto(
            "No calendar keys could be unlocked".into(),
        ));
    }

    Ok(unlocked)
}

/// Merge decrypted VEVENT fragments into one ParsedCalendarEvent.
///
/// Per proton-cal `ical.MergeFragments`: shared-signed wins structural props,
/// first-seen wins otherwise, multi-valued (EXDATE/ATTENDEE) unioned.
/// Fragments are CRLF, folded at 75 octets, no VERSION/PRODID – unfold first.
pub fn merge_ical_fragments(fragments: &[String]) -> Result<ParsedCalendarEvent> {
    let mut out = ParsedCalendarEvent::default();
    let mut seen_structural = std::collections::HashSet::new();
    for frag in fragments {
        let parsed = parse_ical(frag)?;
        // Structural: shared-signed wins → first non-empty wins in our call
        // order (callers pass shared-signed first).
        macro_rules! first_wins {
            ($field:ident) => {
                if out.$field.is_empty() && !parsed.$field.is_empty() {
                    out.$field = parsed.$field.clone();
                    seen_structural.insert(stringify!($field));
                }
            };
        }
        first_wins!(uid);
        first_wins!(summary);
        first_wins!(description);
        first_wins!(location);
        first_wins!(dtstart);
        first_wins!(dtend);
        first_wins!(dtstamp);
        first_wins!(rrule);
        first_wins!(sequence);
        first_wins!(status);
        first_wins!(transp);
        first_wins!(organizer);
        first_wins!(organizer_name);
        first_wins!(recurrence_id);
        first_wins!(recurrence_id_range);
        let _ = &seen_structural;
        // Multi-valued: union.
        for x in parsed.exdates {
            if !out.exdates.contains(&x) {
                out.exdates.push(x);
            }
        }
        for a in parsed.attendees {
            if !out.attendees.contains(&a) {
                out.attendees.push(a);
            }
        }
        for d in parsed.attendee_details {
            if !d.email.is_empty() && !out.attendee_details.iter().any(|e| e.email == d.email) {
                out.attendee_details.push(d);
            }
        }
        if out.created.is_empty() && !parsed.created.is_empty() {
            out.created = parsed.created.clone();
        }
    }
    Ok(out)
}

fn unescape_ical_text(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c == '\\' {
            match chars.next() {
                Some('n') | Some('N') => out.push('\n'),
                Some(',') => out.push(','),
                Some(';') => out.push(';'),
                Some('\\') => out.push('\\'),
                Some(other) => {
                    out.push('\\');
                    out.push(other);
                }
                None => out.push('\\'),
            }
        } else {
            out.push(c);
        }
    }
    out
}

/// Unfold RFC5545 content lines (CRLF + SP/HTAB continuations) then split.
/// Unfolding removes CRLF plus EXACTLY ONE whitespace char: further spaces
/// are content (verified live 2026-09-06: "ed emoji" folded as "ed \r\n emoji"
/// must not become "edemoji").
fn unfold_ical(s: &str) -> Vec<String> {
    let normalized = s.replace("\r\n", "\n").replace('\r', "\n");
    let mut out: Vec<String> = Vec::new();
    for line in normalized.split('\n') {
        if line.starts_with(' ') || line.starts_with('\t') {
            if let Some(last) = out.last_mut() {
                // SP/HTAB are single-byte in UTF-8: skip exactly one char.
                last.push_str(&line[1..]);
            }
        } else {
            out.push(line.to_string());
        }
    }
    out
}

/// Split `NAME;PARAM=...:value` into (name, value), upper-cased name.
#[allow(dead_code)]
fn split_ical_line(line: &str) -> Option<(String, String)> {
    split_ical_line_full(line).map(|(n, _, v)| (n, v))
}

/// Split `NAME;PARAM=...:value` into (upper-cased name, raw params section,
/// value). The params section excludes the leading `;` ("" when absent).
/// The colon is the first `:` outside a double-quoted param value, so
/// `ATTENDEE;CN="a:b":mailto:x` splits correctly.
fn split_ical_line_full(line: &str) -> Option<(String, String, String)> {
    let bytes = line.as_bytes();
    let mut in_quotes = false;
    let mut colon_at: Option<usize> = None;
    for (i, &b) in bytes.iter().enumerate() {
        if b == b'"' {
            in_quotes = !in_quotes;
        } else if b == b':' && !in_quotes {
            colon_at = Some(i);
            break;
        }
    }
    let colon = colon_at?;
    let (left, value) = line.split_at(colon);
    let value = value[1..].to_string();
    let mut parts = left.splitn(2, ';');
    let name = parts.next().unwrap_or(left).trim().to_uppercase();
    let params = parts.next().unwrap_or("").to_string();
    Some((name, params, value))
}

/// Parse an RFC5545 params section (`CN=Alice;RSVP=TRUE`) into an
/// upper-cased key → raw value map. Quoted values keep inner content
/// (`CN="Doe, John"` → `Doe, John`); `;` inside quotes does not split.
/// Unknown params are kept (caller ignores what it doesn't need).
fn parse_ical_params(params: &str) -> std::collections::HashMap<String, String> {
    let mut out = std::collections::HashMap::new();
    if params.trim().is_empty() {
        return out;
    }
    // Split on ';' outside quotes.
    let mut parts: Vec<String> = Vec::new();
    let mut cur = String::new();
    let mut in_quotes = false;
    for c in params.chars() {
        if c == '"' {
            in_quotes = !in_quotes;
            cur.push(c);
        } else if c == ';' && !in_quotes {
            parts.push(std::mem::take(&mut cur));
        } else {
            cur.push(c);
        }
    }
    parts.push(cur);
    for p in parts {
        let p = p.trim();
        if p.is_empty() {
            continue;
        }
        let (k, v) = match p.find('=') {
            Some(i) => (p[..i].trim().to_uppercase(), p[i + 1..].trim().to_string()),
            None => continue,
        };
        let v = v.strip_prefix('"').map_or_else(
            || v.clone(),
            |rest| rest.strip_suffix('"').unwrap_or(rest).to_string(),
        );
        out.insert(k, v);
    }
    out
}

/// Bare email from an ATTENDEE/ORGANIZER value (`mailto:a@b` → `a@b`,
/// extra `;` suffixes stripped, whitespace trimmed).
fn parse_mailto_email(value: &str) -> String {
    let v = value.trim();
    if let Some(idx) = v.to_lowercase().find("mailto:") {
        v[idx + 7..]
            .split(';')
            .next()
            .unwrap_or("")
            .trim()
            .to_string()
    } else {
        v.split(';').next().unwrap_or("").trim().to_string()
    }
}

/// Structured ATTENDEE identity from one content line's params + value.
fn parse_attendee_identity(params: &str, value: &str) -> CalAttendee {
    let map = parse_ical_params(params);
    CalAttendee {
        email: parse_mailto_email(value),
        name: unescape_ical_text(map.get("CN").map_or("", String::as_str)),
        rsvp: map
            .get("RSVP")
            .is_some_and(|v| v.eq_ignore_ascii_case("TRUE")),
        partstat: map
            .get("PARTSTAT")
            .cloned()
            .unwrap_or_default()
            .to_uppercase(),
        role: map.get("ROLE").cloned().unwrap_or_default().to_uppercase(),
        cutype: map
            .get("CUTYPE")
            .cloned()
            .unwrap_or_default()
            .to_uppercase(),
    }
}

/// Structured ORGANIZER identity from one content line's params + value.
fn parse_organizer_identity(params: &str, value: &str) -> (String, String) {
    let map = parse_ical_params(params);
    (
        parse_mailto_email(value),
        unescape_ical_text(map.get("CN").map_or("", String::as_str)),
    )
}

/// Parse an RRULE value into a [`RecurrenceSpec`] (lenient: invalid parts
/// are skipped; INTERVAL defaults to 1; FREQ upper-cased).
///
/// Reference: RFC5545 §3.3.10 + icalendar.org examples
/// (`FREQ=WEEKLY;COUNT=10;BYDAY=TU,TH`, `BYDAY=1FR`, `BYMONTHDAY=2,15`,
/// `INTERVAL=2`, `WKST=SU`, `UNTIL=...`, `BYSETPOS`, `BYMONTH`, ...).
pub fn parse_rrule(rrule: &str) -> RecurrenceSpec {
    let mut spec = RecurrenceSpec {
        interval: 1,
        ..Default::default()
    };
    for part in rrule.split(';') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        let (k, v) = match part.find('=') {
            Some(i) => (
                part[..i].trim().to_uppercase(),
                part[i + 1..].trim().to_string(),
            ),
            None => continue,
        };
        match k.as_str() {
            "FREQ" => spec.freq = v.to_uppercase(),
            "INTERVAL" => {
                if let Ok(n) = v.parse::<u32>() {
                    if n >= 1 {
                        spec.interval = n;
                    }
                }
            }
            "COUNT" => {
                if let Ok(n) = v.parse::<u32>() {
                    if n >= 1 {
                        spec.count = Some(n);
                    }
                }
            }
            "UNTIL" if !v.is_empty() => {
                spec.until = Some(v);
            }
            "UNTIL" => {}
            "BYDAY" => {
                for entry in v.split(',') {
                    let e = entry.trim().to_uppercase();
                    if e.is_empty() {
                        continue;
                    }
                    // Optional signed numeric prefix + 2-letter weekday
                    // (e.g. MO, 1FR, -1SU). A non-numeric prefix is garbage.
                    let (num, day) = e.split_at(e.len().saturating_sub(2));
                    if !matches!(day, "MO" | "TU" | "WE" | "TH" | "FR" | "SA" | "SU") {
                        continue;
                    }
                    let pos = if num.is_empty() {
                        0
                    } else if let Ok(n) = num.parse::<i32>() {
                        n
                    } else {
                        continue;
                    };
                    // Dedupe identical entries.
                    if !spec.byday.iter().any(|d| d.pos == pos && d.weekday == day) {
                        spec.byday.push(RruleByDay {
                            pos,
                            weekday: day.to_string(),
                        });
                    }
                }
            }
            "BYMONTHDAY" => {
                for entry in v.split(',') {
                    if let Ok(n) = entry.trim().parse::<i32>() {
                        if ((1..=31).contains(&n) || (-31..=-1).contains(&n))
                            && !spec.bymonthday.contains(&n)
                        {
                            spec.bymonthday.push(n);
                        }
                    }
                }
            }
            "BYMONTH" => {
                for entry in v.split(',') {
                    if let Ok(n) = entry.trim().parse::<i32>() {
                        if (1..=12).contains(&n) && !spec.bymonth.contains(&n) {
                            spec.bymonth.push(n);
                        }
                    }
                }
            }
            "BYYEARDAY" => {
                for entry in v.split(',') {
                    if let Ok(n) = entry.trim().parse::<i32>() {
                        if ((1..=366).contains(&n) || (-366..=-1).contains(&n))
                            && !spec.byyearday.contains(&n)
                        {
                            spec.byyearday.push(n);
                        }
                    }
                }
            }
            "BYWEEKNO" => {
                for entry in v.split(',') {
                    if let Ok(n) = entry.trim().parse::<i32>() {
                        if ((1..=53).contains(&n) || (-53..=-1).contains(&n))
                            && !spec.byweekno.contains(&n)
                        {
                            spec.byweekno.push(n);
                        }
                    }
                }
            }
            "BYSETPOS" => {
                for entry in v.split(',') {
                    if let Ok(n) = entry.trim().parse::<i32>() {
                        if ((1..=366).contains(&n) || (-366..=-1).contains(&n))
                            && !spec.bysetpos.contains(&n)
                        {
                            spec.bysetpos.push(n);
                        }
                    }
                }
            }
            "WKST" => {
                let w = v.to_uppercase();
                if matches!(w.as_str(), "MO" | "TU" | "WE" | "TH" | "FR" | "SA" | "SU") {
                    spec.wkst = w;
                }
            }
            // BYHOUR/BYMINUTE/BYSECOND: time comes from DTSTART, nothing to
            // store for mKCal (documented, ignored by design).
            _ => {}
        }
    }
    spec
}

pub fn parse_ical(ical_str: &str) -> Result<ParsedCalendarEvent> {
    let mut out = ParsedCalendarEvent::default();
    for line in unfold_ical(ical_str) {
        let l = line.trim();
        if l.is_empty()
            || l.eq_ignore_ascii_case("BEGIN:VCALENDAR")
            || l.eq_ignore_ascii_case("END:VCALENDAR")
            || l.eq_ignore_ascii_case("BEGIN:VEVENT")
            || l.eq_ignore_ascii_case("END:VEVENT")
            || l.starts_with("VERSION:")
            || l.starts_with("PRODID:")
            || l.starts_with("BEGIN:VALARM")
            || l.starts_with("END:VALARM")
        {
            continue;
        }
        let Some((name, params, raw_value)) = split_ical_line_full(l) else {
            continue;
        };
        let value = unescape_ical_text(raw_value.trim());
        match name.as_str() {
            "UID" if out.uid.is_empty() => out.uid = value,
            "SUMMARY" if out.summary.is_empty() => out.summary = value,
            "DESCRIPTION" if out.description.is_empty() => out.description = value,
            "LOCATION" if out.location.is_empty() => out.location = value,
            "DTSTART" if out.dtstart.is_empty() => out.dtstart = value,
            "DTEND" if out.dtend.is_empty() => out.dtend = value,
            "DTSTAMP" if out.dtstamp.is_empty() => out.dtstamp = value,
            "CREATED" if out.created.is_empty() => out.created = value,
            "RRULE" if out.rrule.is_empty() => out.rrule = value,
            "SEQUENCE" if out.sequence.is_empty() => out.sequence = value,
            "STATUS" if out.status.is_empty() => out.status = value,
            "TRANSP" if out.transp.is_empty() => out.transp = value,
            "ORGANIZER" if out.organizer.is_empty() => {
                let (email, cn) = parse_organizer_identity(&params, &value);
                out.organizer = email;
                out.organizer_name = cn;
            }
            "RECURRENCE-ID" if out.recurrence_id.is_empty() => {
                out.recurrence_id = value;
                let map = parse_ical_params(&params);
                out.recurrence_id_range =
                    map.get("RANGE").cloned().unwrap_or_default().to_uppercase();
            }
            "EXDATE" => {
                for part in value.split(',') {
                    let p = part.trim().to_string();
                    if !p.is_empty() && !out.exdates.contains(&p) {
                        out.exdates.push(p);
                    }
                }
            }
            "ATTENDEE" => {
                if !out.attendees.contains(&value) {
                    out.attendees.push(value.clone());
                }
                let detail = parse_attendee_identity(&params, &value);
                if !detail.email.is_empty()
                    && !out.attendee_details.iter().any(|d| d.email == detail.email)
                {
                    out.attendee_details.push(detail);
                }
            }
            _ => {}
        }
    }
    Ok(out)
}

/// One Proton reminder (`Notifications` row entry) normalized for storage.
/// `action` is `"display"` (device) or `"email"`; `offset_secs` is signed
/// seconds relative to the event start (negative = before).
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct CalNotification {
    pub action: String,
    pub offset_secs: i64,
}

/// Parses Proton reminder Trigger values (`-PT15M`, `-PT1H`, `-P1D`,
/// `-PT0S`, `-P1W`; optional `+`/unsigned). Returns signed seconds.
/// Months are rejected (not exactly representable); garbage returns None
/// so the caller skips that entry instead of failing the event.
pub fn parse_notification_trigger(s: &str) -> Option<i64> {
    let s = s.trim();
    if s.is_empty() {
        return None;
    }
    let (neg, rest) = match s.strip_prefix('-') {
        Some(r) => (true, r),
        None => (false, s.strip_prefix('+').unwrap_or(s)),
    };
    let rest = rest.strip_prefix('P')?;
    let (date_part, time_part) = match rest.find('T') {
        Some(i) => (&rest[..i], &rest[i + 1..]),
        None => (rest, ""),
    };
    let secs = parse_duration_part(date_part, &[('W', 7 * 86400), ('D', 86400)])?.checked_add(
        parse_duration_part(time_part, &[('H', 3600), ('M', 60), ('S', 1)])?,
    )?;
    Some(if neg { -secs } else { secs })
}

fn parse_duration_part(s: &str, units: &[(char, i64)]) -> Option<i64> {
    if s.is_empty() {
        return Some(0);
    }
    let mut total: i64 = 0;
    let mut num = String::new();
    for c in s.chars() {
        if c.is_ascii_digit() {
            num.push(c);
            continue;
        }
        if num.is_empty() {
            return None;
        }
        let v: i64 = num.parse().ok()?;
        let mult = units.iter().find(|(u, _)| *u == c)?.1;
        total = total.checked_add(v.checked_mul(mult)?)?;
        num.clear();
    }
    if num.is_empty() {
        Some(total)
    } else {
        None
    }
}

/// One attendee/organizer identity with RFC5545 params preserved.
///
/// `email` is the bare address (`mailto:` stripped); `name` is CN ("" when
/// absent). `rsvp` tracks RSVP=TRUE; `partstat`/`role`/`cutype` keep the raw
/// upper-cased param values ("" when absent) so the C++ shim can map them to
/// `KCalendarCore::Attendee` without re-parsing iCal params.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct CalAttendee {
    #[serde(default)]
    pub email: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub rsvp: bool,
    #[serde(default)]
    pub partstat: String,
    #[serde(default)]
    pub role: String,
    #[serde(default)]
    pub cutype: String,
}

/// One BYDAY entry: `pos` is the optional numeric prefix (0 = none;
/// only meaningful for MONTHLY/YEARLY per RFC5545 §3.3.10), `weekday` is
/// the two-letter upper-cased code (MO..SU).
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct RruleByDay {
    #[serde(default)]
    pub pos: i32,
    #[serde(default)]
    pub weekday: String,
}

/// Structured RRULE view (RFC5545 §3.3.10) for the subset `mKCal`/
/// `KCalendarCore::RecurrenceRule` can store. Parsing is lenient: unknown
/// or out-of-range parts are skipped, never failing the event. `freq` is
/// upper-cased ("" when absent); `interval` defaults to 1 when unset or
/// invalid; `count`/`until` are None when absent.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct RecurrenceSpec {
    #[serde(default)]
    pub freq: String,
    #[serde(default)]
    pub interval: u32,
    #[serde(default)]
    pub count: Option<u32>,
    #[serde(default)]
    pub until: Option<String>,
    #[serde(default)]
    pub byday: Vec<RruleByDay>,
    #[serde(default)]
    pub bymonthday: Vec<i32>,
    #[serde(default)]
    pub bymonth: Vec<i32>,
    #[serde(default)]
    pub byyearday: Vec<i32>,
    #[serde(default)]
    pub byweekno: Vec<i32>,
    #[serde(default)]
    pub bysetpos: Vec<i32>,
    #[serde(default)]
    pub wkst: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ParsedCalendarEvent {
    pub uid: String,
    pub summary: String,
    pub description: String,
    pub location: String,
    pub dtstart: String,
    pub dtend: String,
    #[serde(default)]
    pub dtstamp: String,
    #[serde(default)]
    pub created: String,
    #[serde(default)]
    pub rrule: String,
    #[serde(default)]
    pub exdates: Vec<String>,
    #[serde(default)]
    pub sequence: String,
    #[serde(default)]
    pub status: String,
    #[serde(default)]
    pub transp: String,
    #[serde(default)]
    pub organizer: String,
    #[serde(default)]
    pub attendees: Vec<String>,
    /// ORGANIZER CN param ("" when absent). `organizer` keeps the bare email
    /// for backward compatibility with the C++ shim.
    #[serde(default)]
    pub organizer_name: String,
    /// Structured attendee identities (parallel to `attendees` email list).
    #[serde(default)]
    pub attendee_details: Vec<CalAttendee>,
    /// RECURRENCE-ID property value ("" for masters). The server row
    /// `RecurrenceID` (unix) stays authoritative for exception linkage;
    /// this is the in-fragment value for completeness / future upsync.
    #[serde(default)]
    pub recurrence_id: String,
    /// RECURRENCE-ID RANGE param ("" or "THISANDFUTURE").
    #[serde(default)]
    pub recurrence_id_range: String,
}

#[cfg(test)]
mod tests {
    #[test]
    fn bootstrap_empty_reminders_do_not_trigger_redundant_settings_requests() {
        let mut server = mockito::Server::new();
        let bootstrap = server.mock("GET", "/calendar/v2/cal/bootstrap")
            .with_body(r#"{"Members":[{"ID":"member"}],"Keys":[],"CalendarSettings":{"DefaultPartDayNotifications":[],"DefaultFullDayNotifications":[]}}"#).create();
        let settings = server
            .mock("GET", "/calendar/v1/cal/settings")
            .expect(0)
            .create();
        let client =
            super::CalendarClient::new_with_base_url(server.url(), "at".into(), "uid".into());
        let result = client.get_bootstrap("cal").unwrap();
        assert!(!result.Settings.unwrap().is_empty());
        bootstrap.assert();
        settings.assert();
    }
    use super::*;

    #[test]
    fn test_split_window_respects_93d_cap() {
        let chunks = split_window(0, 93 * 86400 + 1, CALENDAR_MAX_WINDOW_SECS);
        assert_eq!(chunks.len(), 2);
        assert_eq!(chunks[0], (0, 93 * 86400));
        assert_eq!(chunks[1], (93 * 86400, 93 * 86400 + 1));
        let one = split_window(100, 200, CALENDAR_MAX_WINDOW_SECS);
        assert_eq!(one, vec![(100, 200)]);
        assert!(split_window(5, 5, CALENDAR_MAX_WINDOW_SECS).is_empty());
    }

    #[test]
    fn test_windowed_chunks_stay_within_cap_after_padding() {
        // Regression: ±1d query padding must not push spans over the 93d cap.
        let end = 1_800_000_000;
        let start = end - 2 * 365 * 24 * 3600;
        let chunks = split_window(start, end, CALENDAR_MAX_WINDOW_SECS - 2 * 86400);
        assert!(!chunks.is_empty());
        for (cs, ce) in chunks {
            let padded = ce.saturating_add(86400) - cs.saturating_sub(86400);
            assert!(
                padded <= CALENDAR_MAX_WINDOW_SECS,
                "padded span {padded} exceeds cap"
            );
        }
    }

    #[test]
    fn test_parse_ical_unfolds_and_strips_params() {
        let frag = "BEGIN:VCALENDAR\r\nBEGIN:VEVENT\r\nUID:abc-123\r\nDTSTAMP:20260601T120000Z\r\nDTSTART;TZID=Europe/Rome:20260602T090000\r\nDTEND;TZID=Europe/Rome:20260602T100000\r\nSUMMARY:Long title that is folded \r\n over two lines\r\nDESCRIPTION:line1\\nline2\\, with comma\r\nRRULE:FREQ=WEEKLY;COUNT=10\r\nEXDATE:20260609T090000Z,20260616T090000Z\r\nSEQUENCE:3\r\nSTATUS:CONFIRMED\r\nTRANSP:OPAQUE\r\nORGANIZER;CN=Boss:mailto:boss@example.com\r\nATTENDEE;CN=Alice:mailto:alice@example.com\r\nATTENDEE;CN=Bob:mailto:bob@example.com\r\nEND:VEVENT\r\nEND:VCALENDAR";
        let p = parse_ical(frag).unwrap();
        assert_eq!(p.uid, "abc-123");
        assert_eq!(p.dtstart, "20260602T090000");
        assert_eq!(p.dtend, "20260602T100000");
        assert_eq!(p.summary, "Long title that is folded over two lines");
        assert_eq!(p.description, "line1\nline2, with comma");
        assert_eq!(p.rrule, "FREQ=WEEKLY;COUNT=10");
        assert_eq!(p.exdates.len(), 2);
        assert_eq!(p.sequence, "3");
        assert_eq!(p.status, "CONFIRMED");
        assert_eq!(p.transp, "OPAQUE");
        assert_eq!(p.organizer, "boss@example.com");
        assert_eq!(p.organizer_name, "Boss");
        assert_eq!(p.attendees.len(), 2);
        assert_eq!(p.attendee_details.len(), 2);
        assert_eq!(p.attendee_details[0].email, "alice@example.com");
        assert_eq!(p.attendee_details[0].name, "Alice");
    }

    #[test]
    fn test_unfold_keeps_content_spaces() {
        // Live 2026-09-06 (T05): "ed \r\n emoji" must unfold to "ed emoji",
        // not "edemoji" — exactly one fold char is removed.
        let frag = "BEGIN:VEVENT\r\nUID:x\r\nDESCRIPTION:ed \r\n emoji\r\nEND:VEVENT";
        let p = parse_ical(frag).unwrap();
        assert_eq!(p.description, "ed emoji");
    }

    #[test]
    fn test_parse_ical_all_day_and_utc_forms() {
        // Date/time forms per crypto.md (all accepted, verified live).
        let allday = "BEGIN:VEVENT\nUID:x\nDTSTART;VALUE=DATE:20260709\nDTEND;VALUE=DATE:20260710\nSUMMARY:Holiday\nEND:VEVENT";
        let p = parse_ical(allday).unwrap();
        assert_eq!(p.dtstart, "20260709");
        assert_eq!(p.dtend, "20260710");
        let utc =
            "BEGIN:VEVENT\nUID:y\nDTSTART:20260709T160000Z\nDTEND:20260709T170000Z\nEND:VEVENT";
        let q = parse_ical(utc).unwrap();
        assert_eq!(q.dtstart, "20260709T160000Z");
    }

    #[test]
    fn test_merge_fragments_shared_signed_wins() {
        let signed = "BEGIN:VEVENT\nUID:u1\nDTSTART:20260602T090000Z\nDTEND:20260602T100000Z\nRRULE:FREQ=DAILY\nSUMMARY:signed-title\nEND:VEVENT"
            .to_string();
        let encrypted = "BEGIN:VEVENT\nUID:u1\nDTSTART:SHOULD-NOT-WIN\nSUMMARY:enc-title\nDESCRIPTION:secret\nLOCATION:Room\nEND:VEVENT"
            .to_string();
        let m = merge_ical_fragments(&[signed, encrypted]).unwrap();
        assert_eq!(m.dtstart, "20260602T090000Z");
        // summary already set by signed (first) – first-seen wins otherwise.
        assert_eq!(m.summary, "signed-title");
        assert_eq!(m.description, "secret");
        assert_eq!(m.location, "Room");
        assert_eq!(m.rrule, "FREQ=DAILY");
    }

    #[test]
    fn test_verify_signature_lenient_never_fails() {
        assert!(!verify_signature("data", "", &[], &[]).unwrap());
        assert!(verify_signature("data", "-----BEGIN PGP SIGNATURE-----", &[], &[]).unwrap());
    }

    #[test]
    fn test_decrypt_signed_only_needs_no_keys() {
        let part = CalendarEventPart {
            MemberID: String::new(),
            Type: 2,
            Data: "BEGIN:VEVENT\nUID:plain\nSUMMARY:Hi\nEND:VEVENT".into(),
            Signature: "sig".into(),
            Author: String::new(),
        };
        let out = decrypt_calendar_event(&part, &mut [], &mut []).unwrap();
        assert!(out.contains("UID:plain"));
    }

    #[test]
    fn test_decrypt_encrypted_fails_without_keys() {
        let part = CalendarEventPart {
            MemberID: String::new(),
            Type: 3,
            Data: "-----BEGIN PGP MESSAGE-----".into(),
            Signature: String::new(),
            Author: String::new(),
        };
        assert!(decrypt_calendar_event(&part, &mut [], &mut []).is_err());
    }

    #[test]
    fn test_parse_notification_trigger() {
        assert_eq!(parse_notification_trigger("-PT15M"), Some(-900));
        assert_eq!(parse_notification_trigger("-PT1H"), Some(-3600));
        assert_eq!(parse_notification_trigger("-PT1H30M"), Some(-5400));
        assert_eq!(parse_notification_trigger("-P1D"), Some(-86400));
        assert_eq!(parse_notification_trigger("-P1W"), Some(-604800));
        assert_eq!(parse_notification_trigger("-PT0S"), Some(0));
        assert_eq!(parse_notification_trigger("PT30S"), Some(30));
        assert_eq!(parse_notification_trigger(""), None);
        assert_eq!(parse_notification_trigger("tomorrow"), None);
        assert_eq!(parse_notification_trigger("-P1M"), None); // months rejected
        assert_eq!(parse_notification_trigger("-PT"), Some(0));
        assert_eq!(
            parse_notification_trigger("-P1DT2H3M4S"),
            Some(-(86400 + 7200 + 180 + 4))
        );
    }

    #[test]
    fn test_list_events_page_mock_pagination() {
        let mut server = mockito::Server::new();
        let _m0 = server
            .mock(
                "GET",
                mockito::Matcher::Regex(r"/calendar/v1/cal1/events.*".into()),
            )
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"Events":[{"ID":"e1","UID":"u1"}],"More":0}"#)
            .create();
        let c = CalendarClient::new_with_base_url(server.url(), "at".into(), "uid".into());
        let (evs, more) = c.list_events_page("cal1", 0, 0, 999, 0, "UTC").unwrap();
        assert_eq!(evs.len(), 1);
        assert!(!more);
        assert_eq!(evs[0].ID, "e1");
    }

    #[test]
    fn test_put_personal_mock_success() {
        // Personal-part route: exact path, two-field body, envelope Code
        // 1000 → updated row parsed.
        let mut server = mockito::Server::new();
        let put = server
            .mock(
                "PUT",
                mockito::Matcher::Regex(r"/calendar/v1/cal1/events/e1/personal".into()),
            )
            .match_body(mockito::Matcher::JsonString(
                r#"{"Notifications":[{"Trigger":"-PT1H","Type":1}],"Color":null}"#.into(),
            ))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"Code":1000,"Event":{"ID":"e1","UID":"u1","LastEditTime":200}}"#)
            .create();
        let c = CalendarClient::new_with_base_url(server.url(), "at".into(), "uid".into());
        let body = crate::calendar_write::PersonalEventBody {
            Notifications: serde_json::json!([{"Trigger": "-PT1H", "Type": 1}]),
            Color: serde_json::Value::Null,
        };
        let row = c.put_personal("cal1", "e1", &body).unwrap();
        assert_eq!(row.ID, "e1");
        assert_eq!(row.LastEditTime, 200);
        put.assert();
    }

    #[test]
    fn test_put_personal_mock_rejection_keeps_body() {
        // HTTP and envelope-code rejections both surface the body (never
        // blind — the calendar 2001/2011 lesson).
        for (status, body) in [
            (
                400,
                r#"{"Code":2011,"Error":"These properties are not supported"}"#,
            ),
            (
                200,
                r#"{"Code":2001,"Error":"Provide data signed using the address key"}"#,
            ),
        ] {
            let mut server = mockito::Server::new();
            let _m = server
                .mock(
                    "PUT",
                    mockito::Matcher::Regex(r"/calendar/v1/cal1/events/e1/personal".into()),
                )
                .with_status(status)
                .with_header("content-type", "application/json")
                .with_body(body)
                .create();
            let c = CalendarClient::new_with_base_url(server.url(), "at".into(), "uid".into());
            let payload = crate::calendar_write::PersonalEventBody {
                Notifications: serde_json::Value::Null,
                Color: serde_json::Value::Null,
            };
            let err = c
                .put_personal("cal1", "e1", &payload)
                .expect_err("rejection must err");
            let msg = format!("{err}");
            assert!(msg.contains("2011") || msg.contains("2001"), "{msg}");
        }
    }

    #[test]
    fn test_list_all_events_untyped_filters_window() {
        let mut server = mockito::Server::new();
        let _m = server
            .mock(
                "GET",
                mockito::Matcher::Regex(r"/calendar/v1/cal1/events.*".into()),
            )
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                r#"{"Code":1000,"Events":[
                    {"ID":"in1","UID":"u1","StartTime":150,"EndTime":250},
                    {"ID":"out1","UID":"u2","StartTime":10,"EndTime":20},
                    {"ID":"rec1","UID":"u3","StartTime":1,"EndTime":2,"RRule":"FREQ=YEARLY"}
                ],"More":0}"#,
            )
            .create();
        let c = CalendarClient::new_with_base_url(server.url(), "at".into(), "uid".into());
        let evs = c.list_all_events_untyped("cal1", 100, 200).unwrap();
        let ids: Vec<&str> = evs.iter().map(|e| e.ID.as_str()).collect();
        // Overlapping + recurring-master (never window-filtered) survive.
        assert!(ids.contains(&"in1"), "overlap kept: {ids:?}");
        assert!(ids.contains(&"rec1"), "recurring kept: {ids:?}");
        assert!(!ids.contains(&"out1"), "outside dropped: {ids:?}");
    }

    #[test]
    fn test_live_shaped_row_parses() {
        // Live shape 2026-09-06: int-bool FullDay, null Exdates/RRule/
        // Notifications, VERSION/PRODID in fragments. One bad row must not
        // kill its siblings.
        let v: serde_json::Value = serde_json::from_str(
            r#"{"Code":1000,"Events":[
                {"ID":"good","UID":"u1","StartTime":150,"EndTime":250,
                 "FullDay":0,"Exdates":null,"RRule":null,"Notifications":null,
                 "IsOrganizer":1,"Permissions":3,"RecurrenceID":null,
                 "StartTimezone":null,"EndTimezone":null,"Author":null,
                 "SharedKeyPacket":null,"CalendarKeyPacket":null,
                 "SharedEventID":null,"CreateTime":null,"LastEditTime":null,
                 "IsProtonProtonInvite":0,"AddressKeyPacket":"x",
                 "SharedEvents":[{"Type":2,"Data":"BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//Proton AG//x//EN\r\nBEGIN:VEVENT\r\nUID:u1\r\nSUMMARY:Hi\r\nEND:VEVENT\r\nEND:VCALENDAR","Signature":"s","Author":null}]},
                "not-an-object"
            ],"More":0}"#,
        )
        .unwrap();
        let (evs, more) = CalendarClient::parse_events_envelope(&v, 0);
        assert!(!more);
        assert_eq!(evs.len(), 1, "good row kept, bad row skipped");
        assert_eq!(evs[0].ID, "good");
        assert_eq!(evs[0].FullDay, Some(false));
        assert!(evs[0].Exdates.is_empty());
        assert_eq!(evs[0].StartTimezone, "");
        assert_eq!(evs[0].SharedKeyPacket, "");
        assert_eq!(evs[0].SharedEvents.len(), 1);
        assert!(
            CalendarClient::parse_complete_events_envelope(&v, 0).is_err(),
            "replacement snapshots must reject skipped rows"
        );
    }

    #[test]
    fn test_bootstrap_mock_v2() {
        let mut server = mockito::Server::new();
        let _m = server
            .mock(
                "GET",
                mockito::Matcher::Regex(r"/calendar/v2/cal1/bootstrap.*".into()),
            )
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                r#"{"Members":[{"ID":"m1","Email":"a@b.c"}],"Keys":[],"Passphrase":{"ID":"p1","MemberPassphrases":[]}}"#,
            )
            .create();
        let c = CalendarClient::new_with_base_url(server.url(), "at".into(), "uid".into());
        let b = c.get_bootstrap("cal1").unwrap();
        assert_eq!(b.Members.len(), 1);
        assert_eq!(b.Members[0].ID, "m1");
    }

    #[test]
    fn test_bootstrap_v2_settings_parsed() {
        let mut server = mockito::Server::new();
        let _m = server
            .mock(
                "GET",
                mockito::Matcher::Regex(r"/calendar/v2/cal1/bootstrap.*".into()),
            )
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                r#"{"Members":[{"ID":"m1"}],"Keys":[],
                    "Passphrase":{"ID":"p1","MemberPassphrases":[]},
                    "CalendarSettings":{"DefaultEventDuration":30,
                      "DefaultPartDayNotifications":[{"Trigger":"-PT15M","Type":1}],
                      "DefaultFullDayNotifications":[]}}"#,
            )
            .create();
        let c = CalendarClient::new_with_base_url(server.url(), "at".into(), "uid".into());
        let b = c.get_bootstrap("cal1").unwrap();
        let s = b.Settings.expect("v2 settings parsed");
        assert_eq!(s.DefaultEventDuration, Some(30));
        assert_eq!(s.DefaultPartDayNotifications.unwrap().len(), 1);
        assert!(s.DefaultFullDayNotifications.unwrap().is_empty());
    }

    #[test]
    fn test_settings_live_envelope_with_int_bool() {
        // Exact live shape 2026-09-06: MakesUserBusy arrives as Go int-bool
        // 1, and each default list mixes display (Type 1) + email (Type 0)
        // entries. A strict bool field silently failed the WHOLE struct
        // parse (unwrap_or_default → fake "empty"), hiding real defaults.
        let mut server = mockito::Server::new();
        let _m = server
            .mock(
                "GET",
                mockito::Matcher::Regex(r"/calendar/v1/cal1/settings.*".into()),
            )
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                r#"{"Code":1000,"CalendarSettings":{"CalendarID":"c1",
                    "DefaultEventDuration":30,
                    "DefaultFullDayNotifications":[
                      {"Trigger":"-PT15H","Type":1},{"Trigger":"-PT15H","Type":0}],
                    "DefaultPartDayNotifications":[
                      {"Trigger":"-PT15M","Type":1},{"Trigger":"-PT15M","Type":0}],
                    "ID":"s1","MakesUserBusy":1}}"#,
            )
            .create();
        let c = CalendarClient::new_with_base_url(server.url(), "at".into(), "uid".into());
        let (s, _) = c.get_settings_verbose("cal1").unwrap();
        assert!(!s.is_empty());
        assert_eq!(s.MakesUserBusy, Some(true));
        assert_eq!(s.DefaultPartDayNotifications.unwrap().len(), 2);
    }

    #[test]
    fn test_bootstrap_settings_filled_from_v1() {
        // Live shape 2026-09-06: v2 omits CalendarSettings; the standalone
        // v1 route carries it. get_bootstrap must fill the gap.
        let mut server = mockito::Server::new();
        let _v2 = server
            .mock(
                "GET",
                mockito::Matcher::Regex(r"/calendar/v2/cal1/bootstrap.*".into()),
            )
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"Members":[{"ID":"m1"}],"Keys":[],"Passphrase":null}"#)
            .create();
        let _settings = server
            .mock(
                "GET",
                mockito::Matcher::Regex(r"/calendar/v1/cal1/settings.*".into()),
            )
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                r#"{"CalendarSettings":{"DefaultEventDuration":30,
                    "DefaultPartDayNotifications":[{"Trigger":"-PT15M","Type":1},{"Trigger":"-PT15M","Type":0}]}}"#,
            )
            .create();
        let c = CalendarClient::new_with_base_url(server.url(), "at".into(), "uid".into());
        let b = c.get_bootstrap("cal1").unwrap();
        let s = b.Settings.expect("v1 settings fill the v2 gap");
        assert_eq!(s.DefaultEventDuration, Some(30));
        assert_eq!(s.DefaultPartDayNotifications.unwrap().len(), 2);
        _v2.assert();
        _settings.assert();
    }

    #[test]
    fn test_list_by_uid_pages_and_parses() {
        // Server-side UID filter (master + exception rows, no window
        // params): two pages joined via the More cursor.
        let mut server = mockito::Server::new();
        let _p0 = server
            .mock(
                "GET",
                mockito::Matcher::Regex(r"/calendar/v1/cal1/events.*".into()),
            )
            .match_query(mockito::Matcher::UrlEncoded("UID".into(), "u1".into()))
            .match_query(mockito::Matcher::UrlEncoded("Page".into(), "0".into()))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"Code":1000,"Events":[{"ID":"e1","UID":"u1"}],"More":1}"#)
            .create();
        let _p1 = server
            .mock(
                "GET",
                mockito::Matcher::Regex(r"/calendar/v1/cal1/events.*".into()),
            )
            .match_query(mockito::Matcher::UrlEncoded("UID".into(), "u1".into()))
            .match_query(mockito::Matcher::UrlEncoded("Page".into(), "1".into()))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"Code":1000,"Events":[{"ID":"e2","UID":"u1"}],"More":0}"#)
            .create();
        let c = CalendarClient::new_with_base_url(server.url(), "at".into(), "uid".into());
        let evs = c.list_by_uid("cal1", "u1").unwrap();
        let ids: Vec<&str> = evs.iter().map(|e| e.ID.as_str()).collect();
        assert_eq!(ids, vec!["e1", "e2"]);
        _p0.assert();
        _p1.assert();
    }

    #[test]
    fn test_bootstrap_falls_back_to_v1() {
        let mut server = mockito::Server::new();
        let _v2 = server
            .mock(
                "GET",
                mockito::Matcher::Regex(r"/calendar/v2/cal1/bootstrap.*".into()),
            )
            .with_status(404)
            .with_body("{}")
            .create();
        let _members = server
            .mock(
                "GET",
                mockito::Matcher::Regex(r"/calendar/v1/cal1/members.*".into()),
            )
            .with_status(200)
            .with_body(r#"{"Members":[{"ID":"m9"}]}"#)
            .create();
        let _keys = server
            .mock(
                "GET",
                mockito::Matcher::Regex(r"/calendar/v1/cal1/keys.*".into()),
            )
            .with_status(200)
            .with_body(r#"{"Keys":[]}"#)
            .create();
        let _pp = server
            .mock(
                "GET",
                mockito::Matcher::Regex(r"/calendar/v1/cal1/passphrase.*".into()),
            )
            .with_status(200)
            .with_body(r#"{"Passphrase":{"ID":"p","MemberPassphrases":[]}}"#)
            .create();
        let c = CalendarClient::new_with_base_url(server.url(), "at".into(), "uid".into());
        let b = c.get_bootstrap("cal1").unwrap();
        assert_eq!(b.Members[0].ID, "m9");
    }

    #[test]
    fn test_parse_rrule_weekly_byday_interval() {
        // RFC5545 example: every other week TU+TH, 8 occurrences.
        let s = parse_rrule("FREQ=WEEKLY;INTERVAL=2;COUNT=8;WKST=SU;BYDAY=TU,TH");
        assert_eq!(s.freq, "WEEKLY");
        assert_eq!(s.interval, 2);
        assert_eq!(s.count, Some(8));
        assert_eq!(s.wkst, "SU");
        assert_eq!(s.byday.len(), 2);
        assert!(s.byday.iter().any(|d| d.weekday == "TU" && d.pos == 0));
        assert!(s.byday.iter().any(|d| d.weekday == "TH" && d.pos == 0));
    }

    #[test]
    fn test_parse_rrule_monthly_numeric_byday_and_monthday() {
        // Monthly first-Friday + month-day list (RFC5545 §3.8.5.3 examples).
        let s = parse_rrule("FREQ=MONTHLY;COUNT=10;BYDAY=1FR");
        assert_eq!(s.freq, "MONTHLY");
        assert_eq!(s.byday.len(), 1);
        assert_eq!(s.byday[0].weekday, "FR");
        assert_eq!(s.byday[0].pos, 1);
        let t = parse_rrule("FREQ=MONTHLY;COUNT=10;BYMONTHDAY=2,15");
        assert_eq!(t.bymonthday, vec![2, 15]);
        let u = parse_rrule("FREQ=MONTHLY;INTERVAL=18;COUNT=10;BYMONTHDAY=10,11,12,13,14,15");
        assert_eq!(u.interval, 18);
        assert_eq!(u.bymonthday.len(), 6);
    }

    #[test]
    fn test_parse_rrule_yearly_bymonth_until_and_bysetpos() {
        let s = parse_rrule("FREQ=YEARLY;BYMONTH=3;BYDAY=TH");
        assert_eq!(s.freq, "YEARLY");
        assert_eq!(s.bymonth, vec![3]);
        assert_eq!(s.byday.len(), 1);
        let t = parse_rrule("FREQ=YEARLY;UNTIL=20000131T140000Z;BYMONTH=1;BYDAY=SU");
        assert_eq!(t.until, Some("20000131T140000Z".into()));
        assert_eq!(t.bymonth, vec![1]);
        let u = parse_rrule("FREQ=MONTHLY;BYDAY=MO,TU,WE,TH,FR;BYSETPOS=-1");
        assert_eq!(u.bysetpos, vec![-1]);
        assert_eq!(u.byday.len(), 5);
    }

    #[test]
    fn test_parse_rrule_lenient_skips_garbage() {
        // Invalid INTERVAL/COUNT fall back to defaults; bad BYDAY/BYMONTHDAY
        // entries are skipped without failing the whole rule.
        let s = parse_rrule(
            "FREQ=DAILY;INTERVAL=0;COUNT=xx;BYDAY=XX,MO;BYMONTHDAY=99,15;BYMONTH=13,6;WKST=XX",
        );
        assert_eq!(s.freq, "DAILY");
        assert_eq!(s.interval, 1);
        assert_eq!(s.count, None);
        assert_eq!(s.byday.len(), 1);
        assert_eq!(s.byday[0].weekday, "MO");
        assert_eq!(s.bymonthday, vec![15]);
        assert_eq!(s.bymonth, vec![6]);
        assert!(s.wkst.is_empty());
        // Empty rule: freq empty, interval default.
        let e = parse_rrule("");
        assert!(e.freq.is_empty());
        assert_eq!(e.interval, 1);
    }

    #[test]
    fn test_parse_ical_attendee_params_rsvp_partstat_role() {
        let frag = "BEGIN:VEVENT\nUID:x\nORGANIZER;CN=Big Boss:mailto:boss@example.com\nATTENDEE;CN=Alice;RSVP=TRUE;PARTSTAT=ACCEPTED;ROLE=REQ-PARTICIPANT:mailto:alice@example.com\nATTENDEE;CN=Bob;PARTSTAT=TENTATIVE;ROLE=OPT-PARTICIPANT;CUTYPE=INDIVIDUAL:mailto:bob@example.com\nATTENDEE:mailto:plain@example.com\nEND:VEVENT";
        let p = parse_ical(frag).unwrap();
        assert_eq!(p.organizer, "boss@example.com");
        assert_eq!(p.organizer_name, "Big Boss");
        assert_eq!(p.attendees.len(), 3);
        assert_eq!(p.attendee_details.len(), 3);
        let a = &p.attendee_details[0];
        assert_eq!(a.email, "alice@example.com");
        assert_eq!(a.name, "Alice");
        assert!(a.rsvp);
        assert_eq!(a.partstat, "ACCEPTED");
        assert_eq!(a.role, "REQ-PARTICIPANT");
        let b = &p.attendee_details[1];
        assert_eq!(b.name, "Bob");
        assert!(!b.rsvp);
        assert_eq!(b.partstat, "TENTATIVE");
        assert_eq!(b.role, "OPT-PARTICIPANT");
        assert_eq!(b.cutype, "INDIVIDUAL");
        assert_eq!(p.attendee_details[2].email, "plain@example.com");
    }

    #[test]
    fn test_parse_ical_attendee_quoted_cn_with_comma() {
        // CN may be quoted and contain commas/semicolons (RFC5545 params).
        let frag =
            "BEGIN:VEVENT\nUID:x\nATTENDEE;CN=\"Doe, John\":mailto:john@example.com\nEND:VEVENT";
        let p = parse_ical(frag).unwrap();
        assert_eq!(p.attendee_details.len(), 1);
        assert_eq!(p.attendee_details[0].name, "Doe, John");
        assert_eq!(p.attendee_details[0].email, "john@example.com");
    }

    #[test]
    fn test_parse_ical_recurrence_id_and_range() {
        let master =
            "BEGIN:VEVENT\nUID:u1\nDTSTART:20260914T200000Z\nRRULE:FREQ=DAILY;COUNT=5\nEND:VEVENT";
        let m = parse_ical(master).unwrap();
        assert!(m.recurrence_id.is_empty());
        let exc = "BEGIN:VEVENT\nUID:u1\nRECURRENCE-ID:20260915T200000Z\nDTSTART:20260915T223000Z\nEND:VEVENT";
        let e = parse_ical(exc).unwrap();
        assert_eq!(e.recurrence_id, "20260915T200000Z");
        assert!(e.recurrence_id_range.is_empty());
        let exc2 =
            "BEGIN:VEVENT\nUID:u1\nRECURRENCE-ID;RANGE=THISANDFUTURE:20260915T200000Z\nEND:VEVENT";
        let f = parse_ical(exc2).unwrap();
        assert_eq!(f.recurrence_id_range, "THISANDFUTURE");
    }

    #[test]
    fn test_parse_ical_exdate_tzid_and_merge_union() {
        // EXDATE with TZID strips params but keeps floating values; merge
        // unions multi-valued EXDATE/ATTENDEE across fragments.
        let a = "BEGIN:VEVENT\nUID:u1\nEXDATE:20260909T090000Z,20260916T090000Z\nEND:VEVENT"
            .to_string();
        let b = "BEGIN:VEVENT\nUID:u1\nEXDATE;TZID=Europe/Rome:20260923T090000\nATTENDEE;CN=Alice:mailto:alice@example.com\nEND:VEVENT".to_string();
        let m = merge_ical_fragments(&[a, b]).unwrap();
        assert_eq!(m.exdates.len(), 3);
        assert!(m.exdates.contains(&"20260923T090000".to_string()));
        assert_eq!(m.attendee_details.len(), 1);
        assert_eq!(m.attendee_details[0].email, "alice@example.com");
    }

    #[test]
    fn test_split_full_handles_colon_in_quoted_param() {
        let (name, params, value) =
            split_ical_line_full("ATTENDEE;CN=\"a:b\":mailto:x@example.com").unwrap();
        assert_eq!(name, "ATTENDEE");
        assert!(params.contains("CN="));
        assert_eq!(value, "mailto:x@example.com");
        let map = parse_ical_params(&params);
        assert_eq!(map.get("CN").map(String::as_str), Some("a:b"));
    }
}
