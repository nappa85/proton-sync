//! Download-side reconciliation shared by the contacts and calendar writes.
//!
//! Replaces the old "delete every local row, re-insert the server snapshot"
//! write. That approach avoided duplicates and dropped upstream deletes, but
//! it also silently destroyed anything the upload phase had not delivered
//! yet (deferred creates/edits) and re-created every row on every sync.
//!
//! Rows are matched by a stable key (Proton contact UID / namespaced event
//! series UID). A content fingerprint of each incoming row, persisted after
//! every successful write, tells which server rows actually changed:
//!
//! | case                                      | action                     |
//! |-------------------------------------------|----------------------------|
//! | incoming, no local copy                   | add                        |
//! | incoming, local copy, fingerprint same    | leave untouched (a pending |
//! |                                           | local edit stays intact)   |
//! | incoming, local copy, fingerprint new     | rewrite (server wins)      |
//! | local only, previously synced             | remove (deleted upstream)  |
//! | local only, never synced                  | keep (not uploaded yet)    |

use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

/// Canonical compact JSON: object keys sorted at every level, so the
/// fingerprint never depends on serializer key order.
fn canonical(value: &Value, out: &mut String) {
    match value {
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            out.push('{');
            for (i, key) in keys.into_iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                out.push_str(&Value::String(key.clone()).to_string());
                out.push(':');
                canonical(&map[key], out);
            }
            out.push('}');
        }
        Value::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                canonical(item, out);
            }
            out.push(']');
        }
        other => out.push_str(&other.to_string()),
    }
}

fn hex_sha256(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// Content fingerprint of one incoming row, ignoring diagnostic-only keys.
pub fn row_hash(row: &Value, ignored: &[&str]) -> String {
    let mut text = String::new();
    match row {
        Value::Object(map) if !ignored.is_empty() => {
            let mut trimmed = map.clone();
            for key in ignored {
                trimmed.remove(*key);
            }
            canonical(&Value::Object(trimmed), &mut text);
        }
        other => canonical(other, &mut text),
    }
    hex_sha256(text.as_bytes())
}

/// Fingerprint of a group of row fingerprints (a recurring series and its
/// exceptions), independent of input order.
pub fn group_hash(parts: &[String]) -> String {
    let mut sorted = parts.to_vec();
    sorted.sort();
    hex_sha256(sorted.join("\n").as_bytes())
}

/// State of one local copy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Local {
    /// Written by an earlier download (or confirmed uploaded this cycle):
    /// absence from the server snapshot means it was deleted upstream.
    pub synced: bool,
    /// The local copy is structurally what the last write produced (right
    /// notebook, right number of parts). `false` forces a rewrite even when
    /// the server content is unchanged.
    pub intact: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Plan {
    /// Incoming keys with no local copy.
    pub add: Vec<String>,
    /// Incoming keys whose local copy is replaced.
    pub rewrite: Vec<String>,
    /// Incoming keys left untouched.
    pub unchanged: Vec<String>,
    /// Synced local keys the server no longer has.
    pub remove: Vec<String>,
    /// Never-synced local keys (upload pending).
    pub keep_local: Vec<String>,
    /// Fingerprints to persist for the next cycle (incoming keys only).
    pub hashes: BTreeMap<String, String>,
}

impl Plan {
    pub fn summary(&self) -> String {
        format!(
            "added={} updated={} unchanged={} removed={} kept_local={}",
            self.add.len(),
            self.rewrite.len(),
            self.unchanged.len(),
            self.remove.len(),
            self.keep_local.len()
        )
    }
}

/// `partial`: incoming keys whose rows are incomplete (undecryptable): they
/// never overwrite an existing local copy and are not recorded as written,
/// so the full row rewrites them once it decrypts again.
pub fn plan(
    incoming: &BTreeMap<String, String>,
    previous: &BTreeMap<String, String>,
    local: &BTreeMap<String, Local>,
    partial: &BTreeSet<String>,
) -> Plan {
    let mut p = Plan::default();
    for (key, hash) in incoming {
        match local.get(key) {
            None => {
                p.add.push(key.clone());
                if !partial.contains(key) {
                    p.hashes.insert(key.clone(), hash.clone());
                }
            }
            Some(_) if partial.contains(key) => {
                p.unchanged.push(key.clone());
                if let Some(prev) = previous.get(key) {
                    p.hashes.insert(key.clone(), prev.clone());
                }
            }
            Some(state) if state.intact && previous.get(key) == Some(hash) => {
                p.unchanged.push(key.clone());
                p.hashes.insert(key.clone(), hash.clone());
            }
            Some(_) => {
                p.rewrite.push(key.clone());
                p.hashes.insert(key.clone(), hash.clone());
            }
        }
    }
    for (key, state) in local {
        if incoming.contains_key(key) {
            continue;
        }
        if state.synced {
            p.remove.push(key.clone());
        } else {
            p.keep_local.push(key.clone());
        }
    }
    p
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn map(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
            .collect()
    }

    const SYNCED: Local = Local {
        synced: true,
        intact: true,
    };

    #[test]
    fn test_fingerprints_are_canonical() {
        let a = json!({"uid": "u1", "summary": "Lunch", "nested": {"b": 1, "a": [1, {"y": 2, "x": 1}]}});
        let b: Value = serde_json::from_str(
            r#"{"summary":"Lunch","nested":{"a":[1,{"x":1,"y":2}],"b":1},"uid":"u1"}"#,
        )
        .unwrap();
        assert_eq!(row_hash(&a, &[]), row_hash(&b, &[]));
        let mut noisy = a.clone();
        noisy["keys_debug"] = json!("noise");
        assert_eq!(row_hash(&noisy, &["keys_debug"]), row_hash(&a, &[]));
        assert_ne!(row_hash(&json!({"uid": "u1"}), &[]), row_hash(&a, &[]));
        assert_eq!(
            group_hash(&["x".into(), "y".into()]),
            group_hash(&["y".into(), "x".into()])
        );
    }

    #[test]
    fn test_plan_cases() {
        let incoming = map(&[
            ("same", "h1"),
            ("changed", "h2"),
            ("new", "h1"),
            ("moved", "h1"),
            ("first-run", "h1"),
        ]);
        let previous = map(&[
            ("same", "h1"),
            ("changed", "h1"),
            ("moved", "h1"),
            ("gone", "h1"),
        ]);
        let mut local = BTreeMap::new();
        for key in ["same", "changed", "first-run", "gone"] {
            local.insert(key.to_string(), SYNCED);
        }
        local.insert(
            "moved".into(),
            Local {
                synced: true,
                intact: false,
            },
        );
        local.insert(
            "phone-only".into(),
            Local {
                synced: false,
                intact: true,
            },
        );
        let p = plan(&incoming, &previous, &local, &BTreeSet::new());
        assert_eq!(p.add, vec!["new"]);
        assert_eq!(p.unchanged, vec!["same"]);
        assert_eq!(p.rewrite, vec!["changed", "first-run", "moved"]);
        assert_eq!(p.remove, vec!["gone"]);
        assert_eq!(p.keep_local, vec!["phone-only"]);
        assert_eq!(p.hashes.len(), incoming.len());
        assert!(!p.hashes.contains_key("gone"));

        // Empty server snapshot: synced rows go, phone-only rows stay.
        let r = plan(&BTreeMap::new(), &previous, &local, &BTreeSet::new());
        assert_eq!(r.remove.len(), 5);
        assert_eq!(r.keep_local, vec!["phone-only"]);
    }

    #[test]
    fn test_partial_rows_never_overwrite() {
        let incoming = map(&[("partial-local", "h2"), ("partial-new", "h2")]);
        let previous = map(&[("partial-local", "h1")]);
        let mut local = BTreeMap::new();
        local.insert("partial-local".to_string(), SYNCED);
        let partial: BTreeSet<String> = ["partial-local".to_string(), "partial-new".to_string()]
            .into_iter()
            .collect();
        let q = plan(&incoming, &previous, &local, &partial);
        assert_eq!(q.unchanged, vec!["partial-local"]);
        assert_eq!(
            q.hashes.get("partial-local").map(String::as_str),
            Some("h1")
        );
        assert_eq!(q.add, vec!["partial-new"]);
        assert!(!q.hashes.contains_key("partial-new"));
    }
}
