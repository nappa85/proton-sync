use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;

#[derive(Clone, Serialize, Deserialize, Default)]
pub struct CalendarDefaults {
    #[serde(default)]
    pub part: Vec<proton_api::CalNotification>,
    #[serde(default)]
    pub full: Vec<proton_api::CalNotification>,
}

impl fmt::Debug for CalendarDefaults {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CalendarDefaults")
            .field("part", &self.part)
            .field("full", &self.full)
            .finish()
    }
}

#[derive(Clone, Serialize, Deserialize, Default)]
pub struct SyncConfig {
    pub account_id: String,
    pub username: String,
    pub password: String,
    pub derived_passwords: Option<HashMap<String, String>>,
    pub access_token: Option<String>,
    pub refresh_token: Option<String>,
    pub uid: Option<String>,
    pub sync_token: Option<String>,
    pub two_way: bool,
    pub last_sync: Option<String>,
    pub collection_remote_uid: Option<String>,
    pub custom_fields: HashMap<String, String>,
    pub totp_code: Option<String>,
    #[serde(default)]
    pub calendar_defaults: Option<HashMap<String, CalendarDefaults>>,
    #[serde(default)]
    pub calendar_snapshot: Option<crate::calendar_cache::CalendarSnapshot>,
    #[serde(default)]
    pub local_inventory: Option<Vec<crate::upsync::LocalItem>>,
    #[serde(default)]
    pub anchor_map: Option<HashMap<String, i64>>,
    #[serde(default)]
    pub api_base_url: Option<String>,
    #[serde(default)]
    pub contact_inventory: Option<Vec<crate::contact_plan::ContactItem>>,
    #[serde(default)]
    pub contact_known_uids: Option<std::collections::HashSet<String>>,
    #[serde(default)]
    pub contact_anchors: Option<std::collections::HashMap<String, i64>>,
}

impl fmt::Debug for SyncConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SyncConfig")
            .field("account_id", &self.account_id)
            .field("username", &self.username)
            .field("password", &"[REDACTED]")
            .field(
                "derived_passwords",
                &self.derived_passwords.as_ref().map(|_| "[REDACTED]"),
            )
            .field(
                "access_token",
                &self.access_token.as_ref().map(|_| "[REDACTED]"),
            )
            .field(
                "refresh_token",
                &self.refresh_token.as_ref().map(|_| "[REDACTED]"),
            )
            .field("uid", &self.uid)
            .field("sync_token", &self.sync_token)
            .field("two_way", &self.two_way)
            .field("last_sync", &self.last_sync)
            .field("collection_remote_uid", &self.collection_remote_uid)
            .field("custom_fields", &self.custom_fields)
            .field("totp_code", &self.totp_code.as_ref().map(|_| "[REDACTED]"))
            .field("calendar_defaults", &self.calendar_defaults)
            .field("local_inventory", &self.local_inventory)
            .field("anchor_map", &self.anchor_map)
            .field("api_base_url", &self.api_base_url)
            .field("contact_inventory", &self.contact_inventory)
            .field("contact_known_uids", &self.contact_known_uids)
            .field("contact_anchors", &self.contact_anchors)
            .finish()
    }
}
