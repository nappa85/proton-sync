//! Calendar on the phone (mKCal): what the shim dumps, the upload inventory
//! built from it, the reconciling write plan for the downloaded rows, and
//! the bookkeeping persisted after the write.
//!
//! Persisted keys (account group):
//! - `proton_id_map`: `{stored UID: Proton event ID}` — tombstone fallback
//!   when a deleted incidence lost its custom property.
//! - `proton_anchors`: `{Proton event ID: server LastEditTime}`.
//! - `proton_last_modified`: `{stored UID: msecs}` — dirt baseline
//!   (missing entry = clean, never mass-upload).
//! - `calendar_pending`: `{stored UID: stable event UID}` — retry UIDs.
//! - `calendar_row_hashes`: `{series key: fingerprint}` — reconcile input.
//! - `calendar_defaults`, `calendar_snapshot`: engine caches.

use super::calendar_identity as identity;
use super::caltime::{self, CalTime};
use super::reconcile::{self, Local};
use super::settings::{as_i64, Settings, SettingsPatch};
use crate::upsync::LocalItem;
use proton_api::calendar_write::LocalFields;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};

pub const ID_MAP: &str = "proton_id_map";
pub const ANCHORS: &str = "proton_anchors";
pub const LAST_MODIFIED: &str = "proton_last_modified";
pub const PENDING: &str = "calendar_pending";
pub const ROW_HASHES: &str = "calendar_row_hashes";
pub const DEFAULTS: &str = "calendar_defaults";
pub const SNAPSHOT: &str = "calendar_snapshot";

/// First recurrence rule of a phone event, as KCalendarCore holds it.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(default)]
pub struct LocalRule {
    /// `DAILY`/`WEEKLY`/`MONTHLY`/`YEARLY`, `SUBDAILY`, or `NONE`.
    pub freq: String,
    pub interval: i64,
    /// COUNT (>0), 0 = until/forever.
    pub count: i64,
    /// UNTIL as unix seconds.
    pub until: Option<i64>,
    /// `[pos, weekday 1=Mon..7=Sun]`.
    pub by_day: Vec<(i64, i64)>,
    pub by_month_day: Vec<i64>,
    pub by_month: Vec<i64>,
    pub by_set_pos: Vec<i64>,
    pub wkst: i64,
    /// BYHOUR/BYMINUTE/BYSECOND/BYYEARDAY/BYWEEKNO present.
    pub unsupported_parts: bool,
}

/// The shim's dump: our notebooks (per-calendar and the retired one) and
/// every incidence in them.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(default)]
pub struct LocalCalendar {
    pub notebooks: Vec<String>,
    pub events: Vec<LocalEvent>,
}

/// One incidence of one of our notebooks (live or tombstone).
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(default)]
pub struct LocalEvent {
    pub notebook: String,
    pub uid: String,
    pub deleted: bool,
    /// Phone-made occurrence exception (unix seconds of its recurrence-id).
    pub recurrence_id: Option<i64>,
    pub last_modified: Option<i64>,
    /// `X-PROTON-EVENT-ID` / `X-PROTON-ICAL-UID` custom properties.
    pub event_id: String,
    pub ical_uid: String,
    pub summary: String,
    pub description: String,
    pub location: String,
    pub start: Option<i64>,
    pub end: Option<i64>,
    pub all_day: bool,
    pub recurs: bool,
    pub rule: Option<LocalRule>,
    /// Start offsets (seconds) of alarms relative to the start.
    pub alarms: Vec<i64>,
    pub color: String,
}

fn weekday_code(day: i64) -> Option<&'static str> {
    ["MO", "TU", "WE", "TH", "FR", "SA", "SU"]
        .get(usize::try_from(day).ok()?.checked_sub(1)?)
        .copied()
}

fn weekday_number(code: &str) -> Option<i64> {
    (1..=7).find(|d| weekday_code(*d) == Some(code))
}

fn int_list(nums: &[i64]) -> String {
    nums.iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(",")
}

/// RFC5545 RRULE for the upsync inventory (common subset: FREQ D/W/M/Y +
/// INTERVAL + COUNT/UNTIL + BYDAY/BYMONTHDAY/BYMONTH/BYSETPOS + WKST).
/// Returns `(has_recurrence, rule)`; anything else (sub-daily, BYHOUR…,
/// COUNT+UNTIL) is unserializable: `(true, "")`, so the engine keeps the
/// server rule on update and defers creates (never flattens a series).
fn serialize_rrule(rule: Option<&LocalRule>) -> (bool, String) {
    let Some(rule) = rule.filter(|r| r.freq != "NONE" && !r.freq.is_empty()) else {
        return (false, String::new());
    };
    if !["DAILY", "WEEKLY", "MONTHLY", "YEARLY"].contains(&rule.freq.as_str())
        || rule.unsupported_parts
        || (rule.count > 0 && rule.until.is_some())
    {
        return (true, String::new());
    }
    let mut out = format!("FREQ={}", rule.freq);
    if rule.interval > 1 {
        out.push_str(&format!(";INTERVAL={}", rule.interval));
    }
    if rule.count > 0 {
        out.push_str(&format!(";COUNT={}", rule.count));
    } else if let Some(until) = rule.until {
        let Some(dt) = chrono::DateTime::from_timestamp(until, 0) else {
            return (true, String::new());
        };
        out.push_str(&format!(";UNTIL={}", dt.format("%Y%m%dT%H%M%SZ")));
    }
    if !rule.by_day.is_empty() {
        let mut days = Vec::new();
        for (pos, day) in &rule.by_day {
            let Some(code) = weekday_code(*day) else {
                return (true, String::new());
            };
            days.push(if *pos == 0 {
                code.to_string()
            } else {
                format!("{pos}{code}")
            });
        }
        out.push_str(&format!(";BYDAY={}", days.join(",")));
    }
    for (name, list) in [
        ("BYMONTHDAY", &rule.by_month_day),
        ("BYMONTH", &rule.by_month),
        ("BYSETPOS", &rule.by_set_pos),
    ] {
        if !list.is_empty() {
            out.push_str(&format!(";{name}={}", int_list(list)));
        }
    }
    if let Some(code) = weekday_code(rule.wkst) {
        out.push_str(&format!(";WKST={code}"));
    }
    (true, out)
}

/// Signed offset seconds → Proton ISO8601 duration trigger (`-PT15M`).
fn duration_trigger(offset: i64) -> String {
    let sign = if offset < 0 { "-" } else { "" };
    let mut mag = offset.unsigned_abs();
    let mut weeks = mag / 604_800;
    mag %= 604_800;
    let mut days = mag / 86_400;
    mag %= 86_400;
    let (hours, minutes, seconds) = (mag / 3600, mag % 3600 / 60, mag % 60);
    // ISO8601 forbids mixing W with other units.
    if weeks > 0 && (days > 0 || hours > 0 || minutes > 0 || seconds > 0) {
        days += weeks * 7;
        weeks = 0;
    }
    if weeks > 0 {
        return format!("{sign}P{weeks}W");
    }
    let mut out = String::from("P");
    if days > 0 {
        out.push_str(&format!("{days}D"));
    }
    let mut time = String::new();
    if hours > 0 {
        time.push_str(&format!("{hours}H"));
    }
    if minutes > 0 {
        time.push_str(&format!("{minutes}M"));
    }
    if seconds > 0 || (days == 0 && hours == 0 && minutes == 0) {
        time.push_str(&format!("{seconds}S"));
    }
    if !time.is_empty() {
        out.push('T');
        out.push_str(&time);
    }
    format!("{sign}{out}")
}

/// Local inventory for the upsync planner (`upsync::LocalItem`): every live
/// incidence of the per-calendar notebooks plus tombstones. Tombstones
/// shadowing a live row (replacement artifact of a crashed cycle) are
/// dropped instead of uploading a spurious server delete.
pub fn inventory(settings: &Settings, account: &str, local: &[LocalEvent]) -> Vec<LocalItem> {
    let id_map = settings.string_map(account, ID_MAP);
    let anchors = settings.int_map(account, ANCHORS);
    let last_mod = settings.int_map(account, LAST_MODIFIED);
    let pending = settings.string_map(account, PENDING);
    let prefix = identity::notebook_prefix(account);
    let live: BTreeSet<(&str, &str)> = local
        .iter()
        .filter(|e| !e.deleted)
        .map(|e| (e.notebook.as_str(), e.uid.as_str()))
        .collect();
    let mut out = Vec::new();
    for ev in local {
        let Some(cal_id) = ev.notebook.strip_prefix(&prefix) else {
            continue;
        };
        let calendar_id = (!cal_id.is_empty()).then(|| cal_id.to_string());
        let proton_id = if ev.event_id.is_empty() {
            id_map.get(&ev.uid).cloned().unwrap_or_default()
        } else {
            ev.event_id.clone()
        };
        let anchor = (!proton_id.is_empty())
            .then(|| anchors.get(&proton_id).copied())
            .flatten();
        if ev.deleted {
            if live.contains(&(ev.notebook.as_str(), ev.uid.as_str())) {
                continue;
            }
            let raw = if ev.ical_uid.is_empty() {
                identity::raw_uid(&ev.uid, account, cal_id)
            } else {
                ev.ical_uid.clone()
            };
            out.push(LocalItem {
                mkcal_uid: ev.uid.clone(),
                proton_id: (!proton_id.is_empty()).then_some(proton_id),
                deleted: true,
                modified: false,
                last_synced_mtime: anchor,
                fields: None,
                calendar_id,
                uid: (!raw.is_empty()).then_some(raw),
                pending_uid: None,
            });
            continue;
        }
        let dirty = match (ev.last_modified, last_mod.get(&ev.uid)) {
            (Some(now), Some(base)) => now != *base,
            _ => false,
        };
        let fields = match (ev.start, ev.end) {
            (Some(start), Some(end))
                if calendar_id.is_some() && (dirty || proton_id.is_empty()) =>
            {
                let (has, rrule) = if ev.recurs {
                    serialize_rrule(ev.rule.as_ref())
                } else {
                    (false, String::new())
                };
                // No rule: key absent (keep on update); serializable: set
                // it; unserializable: has_recurrence (keep/defer).
                let (rrule, has_recurrence) = match (has, rrule.is_empty()) {
                    (true, false) => (Some(Some(rrule)), false),
                    (true, true) => (None, true),
                    _ => (None, false),
                };
                Some(LocalFields {
                    summary: Some(ev.summary.clone()),
                    description: Some(ev.description.clone()),
                    location: Some(ev.location.clone()),
                    start_unix: Some(start),
                    end_unix: Some(end),
                    all_day: Some(ev.all_day),
                    rrule,
                    has_recurrence,
                    notifications: Some(
                        ev.alarms
                            .iter()
                            .map(|o| json!({"Trigger": duration_trigger(*o), "Type": 1}))
                            .collect(),
                    ),
                    color: Some(ev.color.clone()),
                })
            }
            _ => None,
        };
        out.push(LocalItem {
            mkcal_uid: ev.uid.clone(),
            pending_uid: proton_id
                .is_empty()
                .then(|| pending.get(&ev.uid).cloned())
                .flatten(),
            proton_id: (!proton_id.is_empty()).then_some(proton_id),
            deleted: false,
            modified: dirty,
            last_synced_mtime: anchor,
            fields,
            calendar_id,
            uid: None,
        });
    }
    out
}

// ---- download side ----

fn s<'a>(row: &'a Value, key: &str) -> &'a str {
    row.get(key).and_then(Value::as_str).unwrap_or("")
}

fn int(row: &Value, key: &str) -> i64 {
    row.get(key).and_then(as_i64).unwrap_or(0)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Rule {
    pub freq: String,
    pub interval: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub count: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub until: Option<CalTime>,
    pub by_day: Vec<(i64, i64)>,
    pub by_month_day: Vec<i64>,
    pub by_month: Vec<i64>,
    pub by_year_day: Vec<i64>,
    pub by_week_no: Vec<i64>,
    pub by_set_pos: Vec<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub wkst: Option<i64>,
    /// Original text, stored on the rule for reference.
    pub text: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Attendee {
    pub name: String,
    pub email: String,
    pub rsvp: bool,
    pub partstat: String,
    pub role: String,
    pub cutype: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Alarm {
    pub offset_secs: i64,
    pub email: bool,
}

/// One phone event to add, fully resolved: the shim only maps fields.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct EventSpec {
    pub uid: String,
    pub notebook: String,
    pub summary: String,
    pub description: String,
    pub location: String,
    pub all_day: bool,
    pub start: CalTime,
    pub end: CalTime,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rrule: Option<Rule>,
    pub exdates: Vec<CalTime>,
    pub attendees: Vec<Attendee>,
    pub organizer_email: String,
    pub organizer_name: String,
    /// `CONFIRMED`/`CANCELLED`/`TENTATIVE` or empty.
    pub status: String,
    pub transparent: bool,
    pub color: String,
    pub alarms: Vec<Alarm>,
    /// `X-PROTON-*` custom properties.
    pub properties: BTreeMap<String, String>,
}

fn strip_mailto(value: &str) -> String {
    let email = value.trim();
    match email.to_ascii_lowercase().find("mailto:") {
        Some(i) => email[i + 7..]
            .split(';')
            .next()
            .unwrap_or("")
            .trim()
            .to_string(),
        None => email.to_string(),
    }
}

fn parse_list(value: &str, lo: i64, hi: i64, drop_zero: bool) -> Vec<i64> {
    let mut out = Vec::new();
    for entry in value.split(',') {
        if let Ok(n) = entry.trim().parse::<i64>() {
            if n >= lo && n <= hi && !(drop_zero && n == 0) && !out.contains(&n) {
                out.push(n);
            }
        }
    }
    out
}

/// `MO`, `1FR`, `-1SU`, `+2TU` → (pos, weekday).
fn parse_by_day(entry: &str) -> Option<(i64, i64)> {
    let e = entry.trim().to_uppercase();
    if e.len() < 2 || !e.is_char_boundary(e.len() - 2) {
        return None;
    }
    let (num, day) = e.split_at(e.len() - 2);
    let day = weekday_number(day)?;
    if num.is_empty() {
        return Some((0, day));
    }
    Some((num.parse().ok()?, day))
}

/// RRULE text → rule (FREQ + INTERVAL + COUNT/UNTIL + BYxxx + WKST; COUNT
/// wins over UNTIL). BYHOUR/BYMINUTE/BYSECOND are ignored (time comes from
/// DTSTART); invalid parts are skipped, never failing the event.
fn parse_rrule(text: &str, start_tz: &str) -> Option<Rule> {
    let rrule = text.to_uppercase();
    if !rrule.contains("FREQ=") {
        return None;
    }
    let freq = [
        "DAILY", "WEEKLY", "MONTHLY", "YEARLY", "HOURLY", "MINUTELY", "SECONDLY",
    ]
    .into_iter()
    .find(|f| rrule.contains(&format!("FREQ={f}")))?;
    let mut rule = Rule {
        freq: freq.into(),
        interval: 1,
        count: None,
        until: None,
        by_day: Vec::new(),
        by_month_day: Vec::new(),
        by_month: Vec::new(),
        by_year_day: Vec::new(),
        by_week_no: Vec::new(),
        by_set_pos: Vec::new(),
        wkst: None,
        text: rrule.clone(),
    };
    let mut until = None;
    for part in rrule.split(';') {
        let Some((name, value)) = part.split_once('=') else {
            continue;
        };
        match name {
            "COUNT" => rule.count = value.parse().ok().filter(|n: &i64| *n > 0).or(rule.count),
            "UNTIL" => until = caltime::parse(value, 0, start_tz).or(until),
            "INTERVAL" => {
                if let Some(n) = value.parse().ok().filter(|n: &i64| *n >= 1) {
                    rule.interval = n;
                }
            }
            "BYDAY" => {
                for entry in value.split(',') {
                    if let Some(wp) = parse_by_day(entry) {
                        if !rule.by_day.contains(&wp) {
                            rule.by_day.push(wp);
                        }
                    }
                }
            }
            "BYMONTHDAY" => rule.by_month_day = parse_list(value, -31, 31, true),
            "BYMONTH" => rule.by_month = parse_list(value, 1, 12, false),
            "BYYEARDAY" => rule.by_year_day = parse_list(value, -366, 366, true),
            "BYWEEKNO" => rule.by_week_no = parse_list(value, -53, 53, true),
            "BYSETPOS" => rule.by_set_pos = parse_list(value, -366, 366, true),
            "WKST" => rule.wkst = weekday_number(value),
            _ => {}
        }
    }
    if rule.count.is_none() {
        rule.until = until;
    }
    Some(rule)
}

/// Start/end with the unix fallback, default durations and the all-day
/// end fix (Proton DTEND is exclusive, the Calendar app reads it inclusive).
fn event_times(row: &Value, now: i64) -> (CalTime, CalTime, bool) {
    let all_day = row
        .get("full_day")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let start = caltime::parse(
        s(row, "dtstart"),
        int(row, "start_time"),
        s(row, "start_timezone"),
    )
    .unwrap_or(CalTime::Utc { utc: now });
    let fallback = if all_day { 86_400 } else { 3600 };
    let mut end = match caltime::parse(
        s(row, "dtend"),
        int(row, "end_time"),
        s(row, "end_timezone"),
    ) {
        Some(end) if end.before(&start) != Some(true) => end,
        _ => start.add_secs(fallback),
    };
    if all_day {
        end = end.add_secs(-86_400);
        if end.before(&start) == Some(true) {
            end = start.clone();
        }
    }
    (start, end, all_day)
}

fn event_spec(row: &Value, uid: String, notebook: &str, display_uid: &str, now: i64) -> EventSpec {
    let (start, end, all_day) = event_times(row, now);
    let start_tz = match s(row, "start_timezone") {
        "" => "UTC",
        tz => tz,
    };
    let attendees = match row.get("attendees_full").and_then(Value::as_array) {
        Some(full) if !full.is_empty() => full
            .iter()
            .filter_map(|a| {
                let email = strip_mailto(s(a, "email"));
                (!email.is_empty()).then(|| Attendee {
                    name: s(a, "name").to_string(),
                    email,
                    rsvp: a.get("rsvp").and_then(Value::as_bool).unwrap_or(false),
                    partstat: s(a, "partstat").to_uppercase(),
                    role: s(a, "role").to_uppercase(),
                    cutype: s(a, "cutype").to_uppercase(),
                })
            })
            .collect(),
        _ => row
            .get("attendees")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(|a| {
                let email = strip_mailto(a.as_str().unwrap_or(""));
                (!email.is_empty()).then(|| Attendee {
                    name: String::new(),
                    email,
                    rsvp: false,
                    partstat: String::new(),
                    role: String::new(),
                    cutype: String::new(),
                })
            })
            .collect(),
    };
    let mut properties = BTreeMap::new();
    if !s(row, "id").is_empty() {
        properties.insert("EVENT-ID".to_string(), s(row, "id").to_string());
    }
    properties.insert("ICAL-UID".to_string(), s(row, "uid").to_string());
    let summary = match s(row, "summary") {
        "" => display_uid.to_string(),
        text => text.to_string(),
    };
    let status = s(row, "status").to_uppercase();
    EventSpec {
        uid,
        notebook: notebook.to_string(),
        summary,
        description: s(row, "description").to_string(),
        location: s(row, "location").to_string(),
        all_day,
        rrule: parse_rrule(s(row, "rrule"), start_tz),
        exdates: row
            .get("exdates")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(|x| caltime::parse(x.as_str().unwrap_or(""), 0, start_tz))
            .collect(),
        start,
        end,
        attendees,
        organizer_email: strip_mailto(s(row, "organizer")),
        organizer_name: s(row, "organizer_name").to_string(),
        status: if ["CONFIRMED", "CANCELLED", "TENTATIVE"].contains(&status.as_str()) {
            status
        } else {
            String::new()
        },
        transparent: s(row, "transp").eq_ignore_ascii_case("TRANSPARENT"),
        color: s(row, "color").to_string(),
        alarms: row
            .get("notifications")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .map(|n| Alarm {
                offset_secs: int(n, "offset_secs"),
                email: s(n, "action") == "email",
            })
            .collect(),
        properties,
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Notebook {
    pub uid: String,
    pub name: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Purge {
    pub notebook: String,
    /// Purge every tombstone (retired notebook) instead of only `uids`.
    pub all: bool,
    pub uids: Vec<String>,
}

/// What the shim executes, in order: delete (indexes into the dumped
/// events; exceptions before their master), ensure notebooks, add, save
/// (purging the deletions just made), delete retired notebooks, report
/// `lastModified` of `report` UIDs, purge tombstones.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct WritePlan {
    pub delete: Vec<usize>,
    pub notebooks: Vec<Notebook>,
    pub add: Vec<EventSpec>,
    pub delete_notebooks: Vec<String>,
    pub report: Vec<String>,
    pub purge: Vec<Purge>,
}

/// Bookkeeping carried from the plan to the commit.
#[derive(Debug, Clone, Default)]
pub struct WriteContext {
    /// (stored UID, Proton event ID, server mtime, untouched series).
    rows: Vec<(String, String, Option<i64>, bool)>,
    hashes: BTreeMap<String, String>,
    saved: usize,
    unchanged: usize,
}

/// Reconciling write (see `reconcile`). Rows are grouped per series
/// (namespaced master UID + its standalone exception rows) and matched
/// against the local events of our notebooks. Events created on the phone
/// and not uploaded yet are kept; once the engine confirms their upload
/// (`confirmed`, keyed by the phone UID) the local copy is dropped in favour
/// of the server row. `purgeable`: tombstones whose server delete uploaded.
pub fn write_plan(
    settings: &Settings,
    account: &str,
    rows_json: &str,
    confirmed: &BTreeMap<String, String>,
    purgeable: &BTreeSet<String>,
    dump: &LocalCalendar,
    now: i64,
) -> Result<(WritePlan, WriteContext, Vec<String>), String> {
    let local = &dump.events;
    let rows: Vec<Value> =
        serde_json::from_str(rows_json).map_err(|_| "Expected JSON array of events")?;
    let mut log = Vec::new();
    let identity_details = |row: &Value, index: usize| {
        json!({
            "row": index, "id": row.get("id"), "uid": row.get("uid"),
            "calendar_id": row.get("calendar_id"), "calendar_name": row.get("calendar_name"),
            "recurrence_id": row.get("recurrence_id"),
        })
        .to_string()
    };

    // Identities first: duplicate/empty UIDs cannot be inserted reliably and
    // must not turn into deletions.
    let mut stored_of = Vec::with_capacity(rows.len());
    let mut seen: BTreeMap<String, usize> = BTreeMap::new();
    for (i, row) in rows.iter().enumerate() {
        let uid = s(row, "uid");
        let stored = identity::stored_uid(
            account,
            s(row, "calendar_id"),
            uid,
            int(row, "recurrence_id"),
        );
        if uid.is_empty() || seen.contains_key(&stored) {
            log.push("Invalid or duplicate calendar event UID; import aborted".into());
            log.push(format!(
                "Calendar identity failure: reason={} incoming={}",
                if uid.is_empty() {
                    "empty_uid"
                } else {
                    "duplicate_uid"
                },
                identity_details(row, i)
            ));
            if let Some(prev) = seen.get(&stored) {
                log.push(format!(
                    "Calendar identity conflict: previous={}",
                    identity_details(&rows[*prev], *prev)
                ));
            }
            return Err(log.join("\n"));
        }
        seen.insert(stored.clone(), i);
        stored_of.push(stored);
    }

    // Server side, grouped per series.
    let prefix = identity::notebook_prefix(account);
    let mut cal_names: BTreeMap<String, String> = BTreeMap::new();
    let mut series_rows: BTreeMap<String, Vec<usize>> = BTreeMap::new();
    let mut series_calendar: BTreeMap<String, String> = BTreeMap::new();
    let mut series_parts: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for (i, row) in rows.iter().enumerate() {
        let cid = identity::calendar_id(s(row, "calendar_id")).to_string();
        cal_names
            .entry(cid.clone())
            .or_insert_with(|| s(row, "calendar_name").to_string());
        let key = identity::stored_uid(account, &cid, s(row, "uid"), 0);
        series_rows.entry(key.clone()).or_default().push(i);
        series_calendar.insert(key.clone(), cid);
        series_parts
            .entry(key)
            .or_default()
            .push(reconcile::row_hash(row, &[]));
    }
    let incoming: BTreeMap<String, String> = series_parts
        .iter()
        .map(|(k, parts)| (k.clone(), reconcile::group_hash(parts)))
        .collect();

    let id_map = settings.string_map(account, ID_MAP);
    let previous_mod = settings.int_map(account, LAST_MODIFIED);
    let previous_hashes = settings.string_map(account, ROW_HASHES);
    let stored_prefix = identity::stored_prefix(account);
    let legacy = identity::legacy_notebook(account);

    // Local side: every live event in our notebooks, grouped the same way.
    let mut local_parts: BTreeMap<String, Vec<usize>> = BTreeMap::new();
    let mut local_notebook: BTreeMap<String, String> = BTreeMap::new();
    let mut local_state: BTreeMap<String, Local> = BTreeMap::new();
    let has_legacy = dump.notebooks.contains(&legacy);
    for (index, ev) in local.iter().enumerate() {
        if ev.deleted || !ev.notebook.starts_with(&prefix) {
            continue;
        }
        let key = identity::series_key(&ev.uid).to_string();
        let synced = ev.uid.starts_with(&stored_prefix)
            || !ev.event_id.is_empty()
            || id_map.contains_key(&ev.uid)
            || confirmed.contains_key(&ev.uid);
        let state = local_state.entry(key.clone()).or_insert(Local {
            synced: false,
            intact: true,
        });
        state.synced |= synced;
        // A phone-made occurrence exception is not something the last
        // write produced: rewrite the series.
        if ev.recurrence_id.is_some() {
            state.intact = false;
        }
        if local_notebook
            .get(&key)
            .is_some_and(|nb| *nb != ev.notebook)
        {
            state.intact = false;
        }
        local_notebook.insert(key.clone(), ev.notebook.clone());
        local_parts.entry(key).or_default().push(index);
    }
    for (key, state) in &mut local_state {
        let Some(cid) = series_calendar.get(key) else {
            continue;
        };
        // Moved to another notebook on the phone, or parts missing/extra.
        if local_notebook.get(key) != Some(&format!("{prefix}{cid}"))
            || local_parts.get(key).map_or(0, Vec::len) != series_rows[key].len()
        {
            state.intact = false;
        }
    }

    let plan = reconcile::plan(&incoming, &previous_hashes, &local_state, &BTreeSet::new());
    log.push(format!(
        "Calendar reconcile (series): {} confirmed={}",
        plan.summary(),
        confirmed.len()
    ));

    let mut write = WritePlan::default();
    let mut deleted_uids = BTreeSet::new();
    for key in plan.rewrite.iter().chain(&plan.remove) {
        let mut parts = local_parts.get(key).cloned().unwrap_or_default();
        // Exceptions go before their master (deleting a master may take
        // its exceptions with it).
        parts.sort_by_key(|i| local[*i].recurrence_id.is_none());
        for i in parts {
            deleted_uids.insert(local[i].uid.clone());
            write.delete.push(i);
        }
    }

    for (cid, name) in &cal_names {
        write.notebooks.push(Notebook {
            uid: format!("{prefix}{cid}"),
            name: if name.is_empty() {
                format!("Proton Calendar ({account})")
            } else {
                name.clone()
            },
        });
    }

    for key in plan.add.iter().chain(&plan.rewrite) {
        let cid = &series_calendar[key];
        let notebook = format!("{prefix}{cid}");
        let indexes = &series_rows[key];
        let master = indexes
            .iter()
            .copied()
            .find(|i| int(&rows[*i], "recurrence_id") <= 0);
        let mut specs = Vec::new();
        if let Some(m) = master {
            specs.push(event_spec(
                &rows[m],
                key.clone(),
                &notebook,
                s(&rows[m], "uid"),
                now,
            ));
        }
        for &i in indexes {
            let row = &rows[i];
            let rid = int(row, "recurrence_id");
            if rid <= 0 {
                continue;
            }
            // Exception occurrence: mKCal never persisted real exception
            // incidences, so decompose into an EXDATE on the master plus a
            // standalone event with a stable suffixed UID.
            match specs.first_mut().filter(|_| master.is_some()) {
                Some(master_spec) => master_spec.exdates.push(CalTime::Utc { utc: rid }),
                None => log.push(format!(
                    "exception without master, standalone uid={}",
                    contacts_truncate(s(row, "uid"), 64)
                )),
            }
            let display = format!("{}#{rid}", s(row, "uid"));
            specs.push(event_spec(
                row,
                stored_of[i].clone(),
                &notebook,
                &display,
                now,
            ));
        }
        write.add.extend(specs);
    }

    let untouched: BTreeSet<&String> = plan.unchanged.iter().collect();
    let mut ctx = WriteContext {
        hashes: plan.hashes.clone(),
        saved: write.add.len(),
        unchanged: plan.unchanged.len(),
        rows: Vec::new(),
    };
    for (i, row) in rows.iter().enumerate() {
        let series = identity::stored_uid(account, s(row, "calendar_id"), s(row, "uid"), 0);
        let keep = untouched.contains(&series);
        let stored = stored_of[i].clone();
        // Rows whose baseline is carried need no fresh timestamp.
        if !(keep && previous_mod.contains_key(&stored)) {
            write.report.push(stored.clone());
        }
        let mtime = row.get("mtime").and_then(as_i64);
        ctx.rows
            .push((stored, s(row, "id").to_string(), mtime, keep));
    }

    if has_legacy {
        write.delete_notebooks.push(legacy.clone());
    }
    // Tombstones: the retired notebook is purged wholesale; ours only for
    // uploaded deletes, rows replaced here, and stale tombstones shadowing
    // a live server row. Un-uploaded user deletes survive for next cycle.
    write.purge.push(Purge {
        notebook: legacy,
        all: true,
        uids: Vec::new(),
    });
    let mut purge_uids: BTreeSet<String> = purgeable.clone();
    purge_uids.extend(deleted_uids);
    purge_uids.extend(stored_of.iter().cloned());
    for nb in &write.notebooks {
        write.purge.push(Purge {
            notebook: nb.uid.clone(),
            all: false,
            uids: purge_uids.iter().cloned().collect(),
        });
    }
    Ok((write, ctx, log))
}

fn contacts_truncate(s: &str, n: usize) -> String {
    super::contacts::truncate(s, n)
}

/// Settings after a successful write: per-row Proton IDs, anchors and
/// lastModified baselines (untouched series keep their previous baseline,
/// so a local edit that has not uploaded yet stays dirty) plus fingerprints.
pub fn commit(
    settings: &Settings,
    account: &str,
    ctx: &WriteContext,
    reported: &BTreeMap<String, i64>,
) -> (SettingsPatch, Vec<String>) {
    let previous_mod = settings.int_map(account, LAST_MODIFIED);
    let mut id_map = BTreeMap::new();
    let mut anchors = BTreeMap::new();
    let mut modified = BTreeMap::new();
    for (stored, proton_id, mtime, keep) in &ctx.rows {
        if proton_id.is_empty() {
            continue;
        }
        id_map.insert(stored.clone(), proton_id.clone());
        if let Some(m) = mtime {
            anchors.insert(proton_id.clone(), *m);
        }
        let baseline = if *keep {
            previous_mod.get(stored).or_else(|| reported.get(stored))
        } else {
            reported.get(stored)
        };
        if let Some(ms) = baseline {
            modified.insert(stored.clone(), *ms);
        }
    }
    let mut patch = SettingsPatch::default();
    patch.set_json(account, ID_MAP, &id_map);
    patch.set_json(account, ANCHORS, &anchors);
    patch.set_json(account, LAST_MODIFIED, &modified);
    patch.set_json(account, ROW_HASHES, &ctx.hashes);
    let log = vec![format!(
        "Saved {} calendar events to mkcal ({} series unchanged)",
        ctx.saved, ctx.unchanged
    )];
    (patch, log)
}

#[cfg(test)]
mod tests {
    use super::*;

    const ACC: &str = "143";

    fn nb(cid: &str) -> String {
        format!("proton-calendar-{ACC}-{cid}")
    }

    fn row(uid: &str, cal: &str, rid: i64, summary: &str) -> Value {
        json!({"id": format!("id-{uid}-{rid}"), "uid": uid, "calendar_id": cal,
               "calendar_name": "Personal", "recurrence_id": rid, "summary": summary,
               "start_time": 1000, "end_time": 4600, "mtime": 9})
    }

    fn local(uid: &str, notebook: &str) -> LocalEvent {
        LocalEvent {
            notebook: notebook.into(),
            uid: uid.into(),
            last_modified: Some(1),
            start: Some(1000),
            end: Some(2000),
            ..LocalEvent::default()
        }
    }

    #[test]
    fn test_rrule_round_trips() {
        let rule = LocalRule {
            freq: "WEEKLY".into(),
            interval: 2,
            count: 0,
            until: Some(1_789_416_000),
            by_day: vec![(0, 1), (-1, 5)],
            wkst: 1,
            ..LocalRule::default()
        };
        assert_eq!(
            serialize_rrule(Some(&rule)),
            (
                true,
                "FREQ=WEEKLY;INTERVAL=2;UNTIL=20260914T200000Z;BYDAY=MO,-1FR;WKST=MO".into()
            )
        );
        let sub = LocalRule {
            freq: "SUBDAILY".into(),
            ..LocalRule::default()
        };
        assert_eq!(serialize_rrule(Some(&sub)), (true, String::new()));
        assert_eq!(serialize_rrule(None), (false, String::new()));
        let parsed = parse_rrule(
            "freq=monthly;bymonthday=0,31,-1,99;byday=1FR,XX;count=3;until=20260101",
            "UTC",
        )
        .unwrap();
        assert_eq!(parsed.freq, "MONTHLY");
        assert_eq!(parsed.by_month_day, vec![31, -1]);
        assert_eq!(parsed.by_day, vec![(1, 5)]);
        assert_eq!(parsed.count, Some(3));
        assert_eq!(parsed.until, None);
    }

    #[test]
    fn test_triggers() {
        assert_eq!(duration_trigger(-900), "-PT15M");
        assert_eq!(duration_trigger(-604_800), "-P1W");
        assert_eq!(duration_trigger(-691_200), "-P8D");
        assert_eq!(duration_trigger(0), "PT0S");
        assert_eq!(duration_trigger(90_061), "P1DT1H1M1S");
    }

    #[test]
    fn test_inventory_creates_dirt_and_tombstones() {
        let mut s = Settings::default();
        let g = s.0.entry(ACC.into()).or_default();
        g.insert(LAST_MODIFIED.into(), json!({"a": 1}).to_string());
        g.insert(ID_MAP.into(), json!({"gone": "E2"}).to_string());
        g.insert(ANCHORS.into(), json!({"E1": 50, "E2": 60}).to_string());
        g.insert(PENDING.into(), json!({"phone": "stable"}).to_string());
        let mut edited = local("a", &nb("c1"));
        edited.event_id = "E1".into();
        edited.last_modified = Some(2);
        edited.alarms = vec![-900];
        let mut created = local("phone", &nb("c1"));
        created.recurs = true;
        created.rule = Some(LocalRule {
            freq: "SUBDAILY".into(),
            ..LocalRule::default()
        });
        let mut tomb = local("gone", &nb("c1"));
        tomb.deleted = true;
        let mut shadow = local("a", &nb("c1"));
        shadow.deleted = true;
        let legacy = local("old", &format!("proton-calendar-{ACC}"));
        let inv = inventory(&s, ACC, &[edited, created, tomb, shadow, legacy]);
        assert_eq!(inv.len(), 3);
        assert!(inv[0].modified);
        assert_eq!(inv[0].last_synced_mtime, Some(50));
        let f = inv[0].fields.as_ref().unwrap();
        assert_eq!(f.notifications.as_ref().unwrap()[0]["Trigger"], "-PT15M");
        assert_eq!(inv[1].pending_uid.as_deref(), Some("stable"));
        assert!(inv[1].fields.as_ref().unwrap().has_recurrence);
        assert!(inv[2].deleted);
        assert_eq!(inv[2].proton_id.as_deref(), Some("E2"));
        assert_eq!(inv[2].calendar_id.as_deref(), Some("c1"));
        assert_eq!(inv[2].uid.as_deref(), Some("gone"));
    }

    #[test]
    fn test_write_plan_series_lifecycle() {
        let rows = json!([
            row("same", "c1", 0, "Same"),
            row("rec", "c1", 0, "Series"),
            row("rec", "c1", 2000, "Moved occurrence"),
            row("new", "c2", 0, ""),
        ]);
        let same_key = identity::stored_uid(ACC, "c1", "same", 0);
        let rec_key = identity::stored_uid(ACC, "c1", "rec", 0);
        let gone_key = identity::stored_uid(ACC, "c1", "gone", 0);
        let mut s = Settings::default();
        let same_hash = reconcile::group_hash(&[reconcile::row_hash(&rows[0], &[])]);
        s.0.entry(ACC.into()).or_default().insert(
            ROW_HASHES.into(),
            json!({ same_key.clone(): same_hash, rec_key.clone(): "old" }).to_string(),
        );
        let mut phone_exception = local(&format!("{rec_key}#2000"), &nb("c1"));
        phone_exception.recurrence_id = Some(2000);
        let local_events = vec![
            local(&same_key, &nb("c1")),
            local(&rec_key, &nb("c1")),
            phone_exception,
            local(&gone_key, &nb("c1")),
            local("phone-made", &nb("c1")),
            local("confirmed-copy", &nb("c2")),
        ];
        let confirmed = BTreeMap::from([("confirmed-copy".to_string(), "new".to_string())]);
        let (plan, ctx, log) = write_plan(
            &s,
            ACC,
            &rows.to_string(),
            &confirmed,
            &BTreeSet::from(["tomb".to_string()]),
            &LocalCalendar {
                notebooks: vec![nb("c1"), format!("proton-calendar-{ACC}")],
                events: local_events,
            },
            0,
        )
        .unwrap();
        assert!(
            log[0].contains("added=1 updated=1 unchanged=1 removed=2 kept_local=1"),
            "{log:?}"
        );
        // Exception before master, then the upstream-deleted series and the
        // superseded phone copy.
        assert_eq!(plan.delete, vec![2, 1, 5, 3]);
        assert_eq!(
            plan.delete_notebooks,
            vec![format!("proton-calendar-{ACC}")]
        );
        let uids: Vec<&str> = plan.add.iter().map(|e| e.uid.as_str()).collect();
        assert_eq!(
            uids,
            vec![
                identity::stored_uid(ACC, "c2", "new", 0).as_str(),
                rec_key.as_str(),
                identity::stored_uid(ACC, "c1", "rec", 2000).as_str(),
            ]
        );
        assert_eq!(plan.add[0].summary, "new");
        assert_eq!(plan.add[1].exdates, vec![CalTime::Utc { utc: 2000 }]);
        assert_eq!(plan.add[2].summary, "Moved occurrence");
        assert_eq!(plan.notebooks.len(), 2);
        assert!(plan.purge[1].uids.contains(&"tomb".to_string()));
        assert!(plan.purge[1].uids.contains(&gone_key));

        let reported: BTreeMap<String, i64> = plan.report.iter().map(|u| (u.clone(), 77)).collect();
        let (patch, _) = commit(&s, ACC, &ctx, &reported);
        s.apply(&patch);
        assert_eq!(s.string_map(ACC, ID_MAP).len(), 4);
        assert_eq!(s.int_map(ACC, ANCHORS).get("id-same-0"), Some(&9));
        assert_eq!(s.string_map(ACC, ROW_HASHES).len(), 3);
    }

    #[test]
    fn test_duplicate_identity_aborts() {
        let rows = json!([row("a", "c1", 0, ""), row("a", "c1", 0, "")]);
        let err = write_plan(
            &Settings::default(),
            ACC,
            &rows.to_string(),
            &BTreeMap::new(),
            &BTreeSet::new(),
            &LocalCalendar::default(),
            0,
        )
        .unwrap_err();
        assert!(err.contains("duplicate_uid"));
    }

    #[test]
    fn test_event_spec_resolves_fields() {
        let row = json!({
            "id": "E", "uid": "u", "summary": "", "full_day": true,
            "dtstart": "20260914", "dtend": "20260915",
            "start_timezone": "Europe/Rome",
            "rrule": "FREQ=DAILY;UNTIL=20261001T100000", "exdates": ["20260916T100000"],
            "attendees_full": [{"email": "MAILTO:a@b.c;x=y", "partstat": "accepted"}, {"email": ""}],
            "organizer": "mailto:o@p.q", "status": "tentative", "transp": "transparent",
            "notifications": [{"offset_secs": -600, "action": "email"}]
        });
        let e = event_spec(&row, "stored".into(), "nb", "u", 0);
        assert_eq!(e.summary, "u");
        assert_eq!(e.start, CalTime::Utc { utc: 1_789_344_000 });
        // Inclusive all-day end: one day.
        assert_eq!(e.end, e.start);
        assert_eq!(
            e.rrule.unwrap().until,
            Some(CalTime::Local {
                local: "2026-10-01T10:00:00".into(),
                tz: Some("Europe/Rome".into())
            })
        );
        assert_eq!(e.exdates.len(), 1);
        assert_eq!(e.attendees.len(), 1);
        assert_eq!(e.attendees[0].email, "a@b.c");
        assert_eq!(e.attendees[0].partstat, "ACCEPTED");
        assert_eq!(e.organizer_email, "o@p.q");
        assert_eq!(e.status, "TENTATIVE");
        assert!(e.transparent);
        assert_eq!(
            e.alarms,
            vec![Alarm {
                offset_secs: -600,
                email: true
            }]
        );
        assert_eq!(e.properties.get("EVENT-ID").map(String::as_str), Some("E"));
    }
}
