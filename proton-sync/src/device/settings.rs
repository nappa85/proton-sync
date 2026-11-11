//! The plugin's persisted state (`QSettings proton/sync-tokens`) as seen
//! from Rust. The shim hands over every group as plain strings and writes
//! back whatever [`SettingsPatch`] says; it never interprets a value.
//!
//! Contacts and calendar share the per-account group (tokens, derived
//! passwords) and may run concurrently, so a patch only ever names the keys
//! its run owns: it is applied key by key, never as a whole-group rewrite.

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;

/// Every settings group: group name → key → string value.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Settings(pub BTreeMap<String, BTreeMap<String, String>>);

impl Settings {
    /// Raw value, `""` when absent.
    pub fn get(&self, group: &str, key: &str) -> &str {
        self.0
            .get(group)
            .and_then(|g| g.get(key))
            .map_or("", String::as_str)
    }

    /// JSON-encoded value; absent or malformed → `T::default()`.
    pub fn json<T: DeserializeOwned + Default>(&self, group: &str, key: &str) -> T {
        let raw = self.get(group, key);
        if raw.is_empty() {
            return T::default();
        }
        serde_json::from_str(raw).unwrap_or_default()
    }

    /// JSON object of strings (ID maps, pending maps).
    pub fn string_map(&self, group: &str, key: &str) -> BTreeMap<String, String> {
        let raw: BTreeMap<String, Value> = self.json(group, key);
        raw.into_iter()
            .filter_map(|(k, v)| match v {
                Value::String(s) => Some((k, s)),
                Value::Number(n) => Some((k, n.to_string())),
                _ => None,
            })
            .collect()
    }

    /// JSON object of integers. Older shims wrote these through
    /// `QJsonDocument` (doubles), so floats and numeric strings are read too.
    pub fn int_map(&self, group: &str, key: &str) -> BTreeMap<String, i64> {
        let raw: BTreeMap<String, Value> = self.json(group, key);
        raw.into_iter()
            .filter_map(|(k, v)| as_i64(&v).map(|n| (k, n)))
            .collect()
    }

    pub fn apply(&mut self, patch: &SettingsPatch) {
        for (group, keys) in &patch.0 {
            let target = self.0.entry(group.clone()).or_default();
            for (key, value) in keys {
                match value {
                    Some(v) => {
                        target.insert(key.clone(), v.clone());
                    }
                    None => {
                        target.remove(key);
                    }
                }
            }
        }
    }
}

/// Lenient integer read for values that went through Qt's JSON (double).
pub fn as_i64(v: &Value) -> Option<i64> {
    match v {
        Value::Number(n) => n.as_i64().or_else(|| n.as_f64().map(|f| f.round() as i64)),
        Value::String(s) => s.trim().parse().ok(),
        _ => None,
    }
}

/// Keys to write (`Some`) or remove (`None`), per group.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct SettingsPatch(pub BTreeMap<String, BTreeMap<String, Option<String>>>);

impl SettingsPatch {
    pub fn is_empty(&self) -> bool {
        self.0.values().all(BTreeMap::is_empty)
    }

    pub fn set(&mut self, group: &str, key: &str, value: impl Into<String>) {
        self.0
            .entry(group.to_string())
            .or_default()
            .insert(key.to_string(), Some(value.into()));
    }

    /// Store a JSON value compactly.
    pub fn set_json<T: Serialize>(&mut self, group: &str, key: &str, value: &T) {
        self.set(
            group,
            key,
            serde_json::to_string(value).unwrap_or_else(|_| "{}".into()),
        );
    }

    pub fn merge(&mut self, other: SettingsPatch) {
        for (group, keys) in other.0 {
            self.0.entry(group).or_default().extend(keys);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn settings(group: &str, key: &str, value: &str) -> Settings {
        let mut s = Settings::default();
        s.0.entry(group.into())
            .or_default()
            .insert(key.into(), value.into());
        s
    }

    #[test]
    fn test_int_map_reads_qt_doubles_and_strings() {
        let s = settings("1", "m", r#"{"a":1.7628e12,"b":"42","c":7,"d":null}"#);
        let m = s.int_map("1", "m");
        assert_eq!(m.get("a"), Some(&1_762_800_000_000));
        assert_eq!(m.get("b"), Some(&42));
        assert_eq!(m.get("c"), Some(&7));
        assert!(!m.contains_key("d"));
    }

    #[test]
    fn test_malformed_values_degrade_to_empty() {
        let s = settings("1", "m", "not json");
        assert!(s.string_map("1", "m").is_empty());
        assert!(s.int_map("1", "missing").is_empty());
    }

    #[test]
    fn test_patch_applies_per_key() {
        let mut s = settings("1", "keep", "x");
        let mut p = SettingsPatch::default();
        p.set("1", "new", "y");
        s.apply(&p);
        assert_eq!(s.get("1", "keep"), "x");
        assert_eq!(s.get("1", "new"), "y");
        assert_eq!(serde_json::to_string(&p).unwrap(), r#"{"1":{"new":"y"}}"#);
    }
}
