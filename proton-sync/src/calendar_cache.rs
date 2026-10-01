//! Encrypted calendar snapshots paired with per-calendar model-event cursors.
//! The shim commits these only after the corresponding mKCal save succeeds.
use proton_api::{CalendarClient, CalendarEvent, ProtonError, Result};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap, HashSet};

#[derive(Clone, Serialize, Deserialize)]
pub struct CalendarSnapshot {
    pub version: u32,
    pub owner: String,
    pub calendars: HashMap<String, CachedCalendar>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct CachedCalendar {
    pub cursor: Option<String>,
    pub full_sync_time: i64,
    pub events: Vec<CalendarEvent>,
}

fn validate(calendar: &str, events: &mut [CalendarEvent]) -> Result<()> {
    let mut ids = HashSet::new();
    for event in events {
        if event.ID.is_empty()
            || !ids.insert(event.ID.clone())
            || (!event.CalendarID.is_empty() && event.CalendarID != calendar)
        {
            return Err(ProtonError::Api {
                code: 0,
                message: "Invalid calendar snapshot identities".into(),
            });
        }
        event.CalendarID = calendar.to_owned();
    }
    Ok(())
}

fn full_snapshot(client: &CalendarClient, calendar: &str, now: i64) -> Result<CachedCalendar> {
    // Capture the cursor BEFORE listing: edits racing the download are
    // replayed next time, never skipped by a cursor captured after the list.
    let cursor = client.latest_model_event_id(calendar)?;
    // Retain the full encrypted listing, not the display window: time moving
    // forward must not hide events which enter the window without an edit.
    let mut events = client.list_all_events_untyped(calendar, i64::MIN, i64::MAX)?;
    validate(calendar, &mut events)?;
    Ok(CachedCalendar {
        cursor,
        full_sync_time: now,
        events,
    })
}

pub fn download(
    client: &CalendarClient,
    calendar: &str,
    cached: Option<&CachedCalendar>,
    now: i64,
) -> Result<CachedCalendar> {
    let Some(mut snapshot) = cached.cloned().filter(|cached| {
        cached.cursor.as_ref().is_some_and(|c| !c.is_empty())
            && cached.full_sync_time <= now
            && now.saturating_sub(cached.full_sync_time) < 7 * 86400
    }) else {
        return full_snapshot(client, calendar, now);
    };
    if validate(calendar, &mut snapshot.events).is_err() {
        return full_snapshot(client, calendar, now);
    }
    let mut cursor = snapshot.cursor.clone().expect("validated cursor");
    let mut cursors = HashSet::from([cursor.clone()]);
    let mut changes = BTreeMap::new();
    for page in 0..1000 {
        let Some(feed) = client.model_changes(calendar, &cursor)? else {
            return full_snapshot(client, calendar, now);
        };
        if feed.refresh {
            return full_snapshot(client, calendar, now);
        }
        for (id, action) in feed.events {
            changes.insert(id, action);
        }
        cursor = feed.cursor;
        if feed.more && !cursors.insert(cursor.clone()) {
            return Err(ProtonError::Api {
                code: 0,
                message: "Calendar change cursor did not advance".into(),
            });
        }
        if feed.more {
            if page == 999 {
                return Err(ProtonError::Api {
                    code: 0,
                    message: "Calendar change pagination limit exceeded".into(),
                });
            }
            continue;
        }
        let mut rows: BTreeMap<String, CalendarEvent> = snapshot
            .events
            .into_iter()
            .map(|event| (event.ID.clone(), event))
            .collect();
        // Fetch each changed ID once after draining the feed. Deletions
        // need no detail request; metadata-only updates need full blobs.
        for (id, action) in changes {
            if action == 0 {
                rows.remove(&id);
            } else {
                let mut event = client.get_event(calendar, &id)?;
                if event.ID != id {
                    return Err(ProtonError::Api {
                        code: 0,
                        message: "Calendar detail ID mismatch".into(),
                    });
                }
                validate(calendar, std::slice::from_mut(&mut event))?;
                rows.insert(id, event);
            }
        }
        snapshot.events = rows.into_values().collect();
        snapshot.cursor = Some(cursor);
        return Ok(snapshot);
    }
    unreachable!("bounded feed loop")
}

pub fn in_display_window(event: &CalendarEvent, now: i64) -> bool {
    event.RRule.as_ref().is_some_and(|r| !r.is_empty())
        || (event.StartTime < now + 365 * 86400 && event.EndTime > now - 365 * 86400)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(id: &str) -> CalendarEvent {
        CalendarEvent {
            ID: id.into(),
            UID: "meeting".into(),
            CalendarID: "cal".into(),
            ..Default::default()
        }
    }

    fn cached(events: Vec<CalendarEvent>) -> CachedCalendar {
        CachedCalendar {
            cursor: Some("old".into()),
            full_sync_time: 10_000,
            events,
        }
    }

    fn client(server: &mockito::Server) -> CalendarClient {
        CalendarClient::new_with_base_url(server.url(), "at".into(), "uid".into())
    }

    #[test]
    fn incremental_pages_fetch_each_changed_id_once_and_apply_deletes() {
        let mut server = mockito::Server::new();
        let first = server.mock("GET", "/calendar/v1/cal/modelevents/old")
            .with_body(r#"{"CalendarModelEventID":"middle","More":1,"CalendarEvents":[{"ID":"a","Action":2},{"ID":"b","Action":0}]}"#).create();
        let second = server.mock("GET", "/calendar/v1/cal/modelevents/middle")
            .with_body(r#"{"CalendarModelEventID":"new","More":false,"CalendarEvents":[{"ID":"a","Action":2},{"ID":"c","Action":1}]}"#).create();
        let a = server
            .mock("GET", "/calendar/v1/cal/events/a")
            .with_body(r#"{"Event":{"ID":"a","UID":"meeting","LastEditTime":20}}"#)
            .create();
        let c = server
            .mock("GET", "/calendar/v1/cal/events/c")
            .with_body(r#"{"Event":{"ID":"c","UID":"new-meeting"}}"#)
            .create();
        let deleted = server
            .mock("GET", "/calendar/v1/cal/events/b")
            .expect(0)
            .create();
        let full = server
            .mock("GET", "/calendar/v1/cal/events")
            .match_query(mockito::Matcher::Any)
            .expect(0)
            .create();
        let previous = cached(vec![row("a"), row("b"), row("unchanged")]);
        let snapshot = download(&client(&server), "cal", Some(&previous), 10_001).unwrap();
        assert_eq!(snapshot.cursor.as_deref(), Some("new"));
        assert_eq!(
            snapshot
                .events
                .iter()
                .map(|e| e.ID.as_str())
                .collect::<Vec<_>>(),
            ["a", "c", "unchanged"]
        );
        assert_eq!(snapshot.events[0].LastEditTime, 20);
        assert_eq!(snapshot.events[0].CalendarID, "cal");
        assert_eq!(previous.events.len(), 3, "input remains uncommitted");
        first.assert();
        second.assert();
        a.assert();
        c.assert();
        deleted.assert();
        full.assert();
    }

    #[test]
    fn unchanged_calendar_requires_only_one_change_request() {
        let mut server = mockito::Server::new();
        let feed = server
            .mock("GET", "/calendar/v1/cal/modelevents/old")
            .with_body(r#"{"CalendarModelEventID":"old","More":0}"#)
            .create();
        let details = server
            .mock(
                "GET",
                mockito::Matcher::Regex("/calendar/v1/cal/events.*".into()),
            )
            .expect(0)
            .create();
        let snapshot = download(
            &client(&server),
            "cal",
            Some(&cached(vec![row("a")])),
            10_001,
        )
        .unwrap();
        assert_eq!(snapshot.events.len(), 1);
        feed.assert();
        details.assert();
    }

    #[test]
    fn refresh_and_expired_cursor_take_one_full_snapshot_with_pre_listing_cursor() {
        for expired in [false, true] {
            let mut server = mockito::Server::new();
            let feed = server
                .mock("GET", "/calendar/v1/cal/modelevents/old")
                .with_status(if expired { 400 } else { 200 })
                .with_body(if expired {
                    r#"{"Code":2061}"#
                } else {
                    r#"{"CalendarModelEventID":"lost","More":0,"Refresh":1}"#
                })
                .create();
            let cursor = server
                .mock("GET", "/calendar/v1/cal/modelevents/latest")
                .with_body(r#"{"CalendarModelEventID":"before-list"}"#)
                .create();
            let full = server.mock("GET", "/calendar/v1/cal/events").match_query(mockito::Matcher::Any)
                .with_body(r#"{"Events":[{"ID":"replacement","UID":"meeting","StartTime":1,"EndTime":2}],"More":0}"#).create();
            let snapshot = download(
                &client(&server),
                "cal",
                Some(&cached(vec![row("a")])),
                10_001,
            )
            .unwrap();
            assert_eq!(snapshot.cursor.as_deref(), Some("before-list"));
            assert_eq!(snapshot.events[0].ID, "replacement");
            assert_eq!(snapshot.full_sync_time, 10_001);
            feed.assert();
            cursor.assert();
            full.assert();
        }
    }

    #[test]
    fn malformed_rate_limited_and_stalled_feeds_preserve_snapshot_without_full_download() {
        for (status, body) in [
            (429, "{}"),
            (503, "{}"),
            (400, r#"{"Code":9001}"#),
            (
                200,
                r#"{"CalendarModelEventID":"next","More":0,"CalendarEvents":[{"ID":"a","Action":99}]}"#,
            ),
            (200, r#"{"CalendarModelEventID":"old","More":1}"#),
            (200, r#"{}"#),
        ] {
            let mut server = mockito::Server::new();
            let feed = server
                .mock("GET", "/calendar/v1/cal/modelevents/old")
                .with_status(status)
                .with_body(body)
                .create();
            let full = server
                .mock("GET", "/calendar/v1/cal/events")
                .match_query(mockito::Matcher::Any)
                .expect(0)
                .create();
            let previous = cached(vec![row("a")]);
            assert!(
                download(&client(&server), "cal", Some(&previous), 10_001).is_err(),
                "{status} {body}"
            );
            assert_eq!(previous.cursor.as_deref(), Some("old"));
            feed.assert();
            full.assert();
        }
    }

    #[test]
    fn failed_changed_event_fetch_does_not_advance_cursor() {
        let mut server = mockito::Server::new();
        let _feed = server.mock("GET", "/calendar/v1/cal/modelevents/old")
            .with_body(r#"{"CalendarModelEventID":"new","More":0,"CalendarEvents":[{"ID":"a","Action":2}]}"#).create();
        let _detail = server
            .mock("GET", "/calendar/v1/cal/events/a")
            .with_status(503)
            .create();
        let previous = cached(vec![row("a")]);
        assert!(download(&client(&server), "cal", Some(&previous), 10_001).is_err());
        assert_eq!(previous.cursor.as_deref(), Some("old"));
    }

    #[test]
    fn unsupported_cursor_route_still_downloads_complete_snapshot() {
        let mut server = mockito::Server::new();
        let _latest = server
            .mock("GET", "/calendar/v1/cal/modelevents/latest")
            .with_status(404)
            .create();
        let full = server
            .mock("GET", "/calendar/v1/cal/events")
            .match_query(mockito::Matcher::Any)
            .with_body(r#"{"Events":[{"ID":"old-history","StartTime":1,"EndTime":2}],"More":0}"#)
            .create();
        let snapshot = download(&client(&server), "cal", None, 2_000_000_000).unwrap();
        assert_eq!(snapshot.cursor, None);
        assert_eq!(
            snapshot.events.len(),
            1,
            "cache retains out-of-window history"
        );
        assert!(!in_display_window(&snapshot.events[0], 2_000_000_000));
        full.assert();
    }

    #[test]
    fn incomplete_full_listing_cannot_be_committed_as_empty() {
        for body in [
            r#"{}"#,
            r#"{"Events":null,"More":0}"#,
            r#"{"Events":[],"More":1}"#,
        ] {
            let mut server = mockito::Server::new();
            let _latest = server
                .mock("GET", "/calendar/v1/cal/modelevents/latest")
                .with_body(r#"{"CalendarModelEventID":"before"}"#)
                .create();
            let _full = server
                .mock("GET", "/calendar/v1/cal/events")
                .match_query(mockito::Matcher::Any)
                .with_body(body)
                .create();
            assert!(
                download(&client(&server), "cal", None, 10_001).is_err(),
                "{body}"
            );
        }
    }

    #[test]
    fn corrupted_cache_forces_full_refresh_instead_of_using_foreign_rows() {
        let mut server = mockito::Server::new();
        let _latest = server
            .mock("GET", "/calendar/v1/cal/modelevents/latest")
            .with_body(r#"{"CalendarModelEventID":"before"}"#)
            .create();
        let full = server
            .mock("GET", "/calendar/v1/cal/events")
            .match_query(mockito::Matcher::Any)
            .with_body(r#"{"Events":[],"More":0}"#)
            .create();
        let feed = server
            .mock("GET", "/calendar/v1/cal/modelevents/old")
            .expect(0)
            .create();
        let mut foreign = row("foreign");
        foreign.CalendarID = "other".into();
        let result = download(
            &client(&server),
            "cal",
            Some(&cached(vec![foreign])),
            10_001,
        )
        .unwrap();
        assert!(result.events.is_empty());
        full.assert();
        feed.assert();
    }

    #[test]
    fn cached_events_enter_display_window_as_time_moves_forward() {
        let mut event = row("future");
        let now = 2_000_000_000;
        event.StartTime = now + 365 * 86400 + 100;
        event.EndTime = event.StartTime + 3600;
        assert!(!in_display_window(&event, now));
        assert!(in_display_window(&event, now + 200));
        event.RRule = Some("FREQ=YEARLY".into());
        assert!(in_display_window(&event, 10_000));
    }
}
