//! mKCal storage identities for Proton events.
//!
//! mKCal enforces UNIQUE incidence UIDs across the whole storage, but the
//! Proton/iCal UID is account-independent: re-creating the account re-inserts
//! the same UIDs next to orphaned notebooks and the batch INSERT fails,
//! rolling back the entire save. Every stored UID is therefore namespaced by
//! account AND calendar (invitations can also exist in a shared calendar),
//! with both components encoded so wire separators cannot collide with the
//! namespace or the standalone-exception `#<rid>` suffix.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;

/// Notebook UID prefix of the per-calendar notebooks (`<prefix><calId>`).
pub fn notebook_prefix(account: &str) -> String {
    format!("proton-calendar-{account}-")
}

/// Retired single notebook of the first version.
pub fn legacy_notebook(account: &str) -> String {
    format!("proton-calendar-{account}")
}

/// Prefix shared by every stored event UID of this account.
pub fn stored_prefix(account: &str) -> String {
    format!("proton-cal-{account}-")
}

pub fn calendar_id(id: &str) -> &str {
    if id.is_empty() {
        "default"
    } else {
        id
    }
}

fn encoded(value: &str) -> String {
    URL_SAFE_NO_PAD.encode(value.as_bytes())
}

pub fn stored_uid(account: &str, calendar: &str, uid: &str, recurrence_id: i64) -> String {
    let mut stored = format!(
        "{}{}:{}",
        stored_prefix(account),
        encoded(calendar_id(calendar)),
        encoded(uid)
    );
    if recurrence_id > 0 {
        stored.push_str(&format!("#{recurrence_id}"));
    }
    stored
}

/// Series key of a stored UID (exception standalones share their master's).
pub fn series_key(stored: &str) -> &str {
    stored.split('#').next().unwrap_or(stored)
}

/// Wire UID back from a stored one. Old account-only identities remain
/// upload inputs until replacement succeeds.
pub fn raw_uid(stored: &str, account: &str, calendar: &str) -> String {
    let prefix = stored_prefix(account);
    let scoped = format!("{prefix}{}:", encoded(calendar_id(calendar)));
    if let Some(rest) = stored.strip_prefix(&scoped) {
        let encoded_uid = series_key(rest).trim_end_matches('=');
        return URL_SAFE_NO_PAD
            .decode(encoded_uid)
            .map(|bytes| String::from_utf8_lossy(&bytes).into_owned())
            .unwrap_or_default();
    }
    let mut raw = stored.strip_prefix(&prefix).unwrap_or(stored);
    if let Some(hash) = raw.rfind('#') {
        if raw[hash + 1..].parse::<i64>().is_ok_and(|n| n > 0) {
            raw = &raw[..hash];
        }
    }
    raw.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    const MEETING: &str = "6r904ZblLJdlpyRzSkQbUfxxtKtU@proton.me";

    #[test]
    fn test_calendar_and_recurrence_copies_coexist_and_round_trip() {
        let mut identities = HashSet::new();
        for calendar in ["personal", "shared"] {
            for recurrence in [0, 1_789_502_400] {
                let stored = stored_uid("143", calendar, MEETING, recurrence);
                assert!(identities.insert(stored.clone()));
                assert_eq!(raw_uid(&stored, "143", calendar), MEETING);
            }
        }
    }

    #[test]
    fn test_accounts_and_default_calendar() {
        assert_ne!(
            stored_uid("144", "personal", MEETING, 0),
            stored_uid("143", "personal", MEETING, 0)
        );
        assert_eq!(
            stored_uid("143", "", MEETING, 0),
            stored_uid("143", "default", MEETING, 0)
        );
    }

    #[test]
    fn test_legacy_migration() {
        assert_eq!(
            raw_uid(&format!("proton-cal-143-{MEETING}"), "143", "personal"),
            MEETING
        );
        assert_eq!(
            raw_uid(
                &format!("proton-cal-143-{MEETING}#1789502400"),
                "143",
                "personal"
            ),
            MEETING
        );
    }

    #[test]
    fn test_separators_and_unicode_stay_inside_components() {
        let unusual = "meeting:#123/è@example.org";
        assert_eq!(
            raw_uid(&stored_uid("143", "cal:/#", unusual, 200), "143", "cal:/#"),
            unusual
        );
        assert_ne!(
            stored_uid("143", "personal", "meeting#200", 0),
            stored_uid("143", "personal", "meeting", 200)
        );
    }

    #[test]
    fn test_matches_qt_encoding() {
        // QByteArray::toBase64(Base64UrlEncoding | OmitTrailingEquals),
        // the form already persisted on phones by the C++ shim.
        assert_eq!(stored_uid("143", "a", "b?", 5), "proton-cal-143-YQ:Yj8#5");
    }
}
