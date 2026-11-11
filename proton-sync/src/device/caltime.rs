//! iCal time values → instructions the shim can turn into a `QDateTime`
//! without any parsing of its own.

use chrono::{Duration, NaiveDate, NaiveDateTime, TimeZone, Utc};
use serde::Serialize;

/// One point in time as the phone stores it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(untagged)]
pub enum CalTime {
    /// UTC instant (unix seconds).
    Utc { utc: i64 },
    /// Wall-clock time. `tz` (IANA name) attaches a zone so occurrence
    /// instants match the server's recurrence-id instants; absent (or a zone
    /// the phone does not know) means device-local floating time.
    Local {
        local: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        tz: Option<String>,
    },
}

const LOCAL_FMT: &str = "%Y-%m-%dT%H:%M:%S";

impl CalTime {
    fn naive(&self) -> Option<NaiveDateTime> {
        match self {
            CalTime::Local { local, .. } => NaiveDateTime::parse_from_str(local, LOCAL_FMT).ok(),
            CalTime::Utc { .. } => None,
        }
    }

    fn local(naive: NaiveDateTime, tz: Option<String>) -> Self {
        CalTime::Local {
            local: naive.format(LOCAL_FMT).to_string(),
            tz,
        }
    }

    pub fn add_secs(&self, secs: i64) -> Self {
        match self {
            CalTime::Utc { utc } => CalTime::Utc { utc: utc + secs },
            CalTime::Local { tz, .. } => match self.naive() {
                Some(n) => Self::local(n + Duration::seconds(secs), tz.clone()),
                None => self.clone(),
            },
        }
    }

    /// Ordering when both sides are comparable without a zone database
    /// (both UTC, or both wall-clock in the same zone). `None` otherwise.
    pub fn before(&self, other: &CalTime) -> Option<bool> {
        match (self, other) {
            (CalTime::Utc { utc: a }, CalTime::Utc { utc: b }) => Some(a < b),
            (CalTime::Local { tz: ta, .. }, CalTime::Local { tz: tb, .. }) if ta == tb => {
                Some(self.naive()? < other.naive()?)
            }
            _ => None,
        }
    }
}

/// Parse an iCal date/date-time (TZID parameters already stripped): UTC
/// (`…Z`), floating, or DATE-only. Floating values get the event timezone
/// attached unless it is empty or `UTC` (those stay device-local, as the
/// phone always stored them). Unparseable → the row's unix time, if any.
pub fn parse(ical: &str, unix_fallback: i64, tz: &str) -> Option<CalTime> {
    let s = ical.trim();
    if s.len() == 8 && !s.contains('T') {
        if let Ok(d) = NaiveDate::parse_from_str(s, "%Y%m%d") {
            let midnight = d.and_hms_opt(0, 0, 0)?;
            return Some(CalTime::Utc {
                utc: Utc.from_utc_datetime(&midnight).timestamp(),
            });
        }
    }
    if !s.is_empty() {
        let utc = s.ends_with('Z');
        let body = s.trim_end_matches('Z');
        let parsed = NaiveDateTime::parse_from_str(body, "%Y%m%dT%H%M%S")
            .or_else(|_| NaiveDateTime::parse_from_str(body, LOCAL_FMT));
        if let Ok(naive) = parsed {
            if utc {
                return Some(CalTime::Utc {
                    utc: Utc.from_utc_datetime(&naive).timestamp(),
                });
            }
            let zone = (!tz.is_empty() && tz != "UTC").then(|| tz.to_string());
            return Some(CalTime::local(naive, zone));
        }
    }
    (unix_fallback > 0).then_some(CalTime::Utc { utc: unix_fallback })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_forms() {
        assert_eq!(
            parse("20260914T200000Z", 0, "Europe/Rome"),
            Some(CalTime::Utc { utc: 1_789_416_000 })
        );
        assert_eq!(
            parse("20260914T200000", 0, "Europe/Rome"),
            Some(CalTime::Local {
                local: "2026-09-14T20:00:00".into(),
                tz: Some("Europe/Rome".into())
            })
        );
        assert_eq!(
            parse("2026-09-14T20:00:00", 0, "UTC"),
            Some(CalTime::Local {
                local: "2026-09-14T20:00:00".into(),
                tz: None
            })
        );
        assert_eq!(
            parse("20260914", 0, "Europe/Rome"),
            Some(CalTime::Utc { utc: 1_789_344_000 })
        );
        assert_eq!(parse("garbage", 77, ""), Some(CalTime::Utc { utc: 77 }));
        assert_eq!(parse("", 0, ""), None);
    }

    #[test]
    fn test_arithmetic_and_order() {
        let a = parse("20260914T235000", 0, "Europe/Rome").unwrap();
        let b = a.add_secs(3600);
        assert_eq!(
            b,
            CalTime::Local {
                local: "2026-09-15T00:50:00".into(),
                tz: Some("Europe/Rome".into())
            }
        );
        assert_eq!(a.before(&b), Some(true));
        assert_eq!(a.before(&CalTime::Utc { utc: 0 }), None);
        assert_eq!(
            serde_json::to_string(&CalTime::Utc { utc: 5 }).unwrap(),
            r#"{"utc":5}"#
        );
    }
}
