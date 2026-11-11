//! Contacts on the phone: what the shim dumps, the upload inventory built
//! from it, the reconciling write plan for the downloaded rows, and the
//! bookkeeping persisted after the write.
//!
//! Persisted keys (account group):
//! - `contacts_id_map`: `{proton_uid: qcontact_id}` — known set for delete
//!   detection (QtContacts has no tombstones).
//! - `contacts_last_modified`: `{qcontact_id: msecs}` — dirt baseline
//!   (missing entry = clean, so pre-feature rows never mass-upload).
//! - `contacts_photos`: `{qcontact_id: avatar url}` — avatar baseline.
//! - `contacts_anchors`: `{proton_uid: server ModifyTime}` — planner anchors.
//! - `contacts_pending`: `{qcontact_id: stable uid}` — retry UIDs.
//! - `contacts_row_hashes`: `{proton_uid: fingerprint}` — reconcile input.

use super::reconcile::{self, Local};
use super::settings::{Settings, SettingsPatch};
use crate::contact_plan::ContactItem;
use proton_api::vcard::{ParsedAddress, ParsedContact, ParsedEmail, ParsedPhone};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet, HashSet};

pub const ID_MAP: &str = "contacts_id_map";
pub const LAST_MODIFIED: &str = "contacts_last_modified";
pub const PHOTOS: &str = "contacts_photos";
pub const ANCHORS: &str = "contacts_anchors";
pub const PENDING: &str = "contacts_pending";
pub const ROW_HASHES: &str = "contacts_row_hashes";

/// Phone sub-types the shim maps, in vCard export order.
const SUB_TYPES: [(&str, &str); 6] = [
    ("mobile", "cell"),
    ("fax", "fax"),
    ("pager", "pager"),
    ("voice", "voice"),
    ("video", "video"),
    ("car", "car"),
];
const CONTEXTS: [&str; 2] = ["home", "work"];

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Email {
    pub email: String,
    #[serde(default)]
    pub contexts: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Phone {
    pub number: String,
    #[serde(default)]
    pub sub_types: Vec<String>,
    #[serde(default)]
    pub contexts: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Address {
    #[serde(default)]
    pub street: String,
    #[serde(default)]
    pub locality: String,
    #[serde(default)]
    pub region: String,
    #[serde(default)]
    pub postcode: String,
    #[serde(default)]
    pub country: String,
    #[serde(default)]
    pub contexts: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Organization {
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub title: String,
    #[serde(default)]
    pub role: String,
}

/// One contact as stored on the phone. The shim dumps these (with `id`,
/// `guid`, `last_modified`, `avatars`) and builds new ones from
/// [`ContactSpec`] (same detail fields). Strings are empty when unset.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Details {
    #[serde(default)]
    pub first_name: String,
    #[serde(default)]
    pub last_name: String,
    #[serde(default)]
    pub display_label: String,
    #[serde(default)]
    pub emails: Vec<Email>,
    #[serde(default)]
    pub phones: Vec<Phone>,
    #[serde(default)]
    pub addresses: Vec<Address>,
    #[serde(default)]
    pub organization: Option<Organization>,
    /// `YYYY-MM-DD` or empty.
    #[serde(default)]
    pub birthday: String,
    #[serde(default)]
    pub anniversary: String,
    #[serde(default)]
    pub nickname: String,
    #[serde(default)]
    pub url: String,
    /// `male`, `female` or empty.
    #[serde(default)]
    pub gender: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
pub struct LocalContact {
    /// QContactId string (opaque).
    pub id: String,
    /// QContactGuid = Proton UID; empty for phone-only rows.
    #[serde(default)]
    pub guid: String,
    #[serde(default)]
    pub last_modified: Option<i64>,
    #[serde(flatten)]
    pub details: Details,
    #[serde(default)]
    pub notes: Vec<String>,
    /// Every avatar detail's URL; app edits accumulate them, so the LAST
    /// one is the freshest write.
    #[serde(default)]
    pub avatars: Vec<String>,
}

impl LocalContact {
    fn avatar(&self) -> &str {
        self.avatars.last().map_or("", String::as_str)
    }
}

/// A contact to save (new or replacing the referenced local one).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct ContactSpec {
    pub guid: String,
    #[serde(flatten)]
    pub details: Details,
    /// Notes joined into one detail (empty = none).
    pub note: String,
    /// Avatar URL (`data:` URI or encoded URL; empty = none).
    pub avatar: String,
}

/// Inventory build: which local rows upload and with what content.
pub struct Inventory {
    pub items: Vec<ContactItem>,
    pub known_uids: HashSet<String>,
    pub anchors: std::collections::HashMap<String, i64>,
    pub log: Vec<String>,
}

fn ordered(values: &[String], table: &[(&str, &str)]) -> Vec<String> {
    table
        .iter()
        .filter(|(name, _)| values.iter().any(|v| v == name))
        .map(|(_, wire)| (*wire).to_string())
        .collect()
}

fn context_types(contexts: &[String]) -> Vec<String> {
    let table: Vec<(&str, &str)> = CONTEXTS.iter().map(|c| (*c, *c)).collect();
    ordered(contexts, &table)
}

fn gender_out(gender: &str) -> String {
    match gender {
        "male" => "Male".into(),
        "female" => "Female".into(),
        // Unspecified exports as "" = no gender detail.
        _ => String::new(),
    }
}

/// Avatars that must be read from disk and turned into data URIs before
/// the inventory can be built (the shim does the image work).
pub fn avatars_needed(settings: &Settings, account: &str, local: &[LocalContact]) -> Vec<String> {
    let last_mod = settings.int_map(account, LAST_MODIFIED);
    let photos = settings.string_map(account, PHOTOS);
    let mut out = BTreeSet::new();
    for c in local {
        let dirty = is_dirty(c, &last_mod);
        if !c.guid.is_empty() && !dirty {
            continue;
        }
        let avatar = c.avatar();
        if avatar_changed(avatar, photos.get(&c.id)) && !avatar.starts_with("data:") {
            out.insert(avatar.to_string());
        }
    }
    out.into_iter().collect()
}

fn is_dirty(c: &LocalContact, last_mod: &BTreeMap<String, i64>) -> bool {
    match (c.last_modified, last_mod.get(&c.id)) {
        (Some(now), Some(base)) => now != *base,
        _ => false,
    }
}

fn avatar_changed(avatar: &str, baseline: Option<&String>) -> bool {
    !avatar.is_empty() && baseline.is_none_or(|b| b != avatar)
}

/// Local inventory for the contacts planner (`contact_plan::ContactItem`).
/// `fields` carries the full phone snapshot for dirty/never-synced rows only,
/// including `photos` (device avatar as data URI) when the avatar differs
/// from the persisted download baseline — untouched avatars stay omitted so
/// the server copy is carried engine-side.
pub fn inventory(
    settings: &Settings,
    account: &str,
    local: &[LocalContact],
    avatar_data: &BTreeMap<String, String>,
) -> Inventory {
    let anchors = settings.int_map(account, ANCHORS);
    let last_mod = settings.int_map(account, LAST_MODIFIED);
    let pending = settings.string_map(account, PENDING);
    let photos = settings.string_map(account, PHOTOS);
    let mut log = Vec::new();
    let mut items = Vec::with_capacity(local.len());
    for c in local {
        let dirty = is_dirty(c, &last_mod);
        let mut item = ContactItem {
            qcontact_id: c.id.clone(),
            proton_uid: (!c.guid.is_empty()).then(|| c.guid.clone()),
            modified: dirty,
            last_synced_mtime: (!c.guid.is_empty())
                .then(|| anchors.get(&c.guid).copied())
                .flatten(),
            fields: None,
            pending_uid: None,
        };
        if !c.guid.is_empty() && !dirty {
            items.push(item);
            continue;
        }
        if c.guid.is_empty() {
            item.pending_uid = pending.get(&c.id).cloned();
        }
        let d = &c.details;
        let org = d.organization.clone().unwrap_or_default();
        let mut fields = ParsedContact {
            first_name: d.first_name.clone(),
            last_name: d.last_name.clone(),
            display_name: d.display_label.clone(),
            emails: d
                .emails
                .iter()
                .filter(|e| !e.email.is_empty())
                .map(|e| ParsedEmail {
                    email: e.email.clone(),
                    types: context_types(&e.contexts),
                })
                .collect(),
            phones: d
                .phones
                .iter()
                .filter(|p| !p.number.is_empty())
                .map(|p| {
                    let mut types = ordered(&p.sub_types, &SUB_TYPES);
                    types.extend(context_types(&p.contexts));
                    ParsedPhone {
                        number: p.number.clone(),
                        types,
                    }
                })
                .collect(),
            addresses: d
                .addresses
                .iter()
                .map(|a| ParsedAddress {
                    street: a.street.clone(),
                    locality: a.locality.clone(),
                    region: a.region.clone(),
                    postal_code: a.postcode.clone(),
                    country: a.country.clone(),
                    types: context_types(&a.contexts),
                })
                .collect(),
            organization: org.name,
            title: org.title,
            role: org.role,
            notes: c.notes.iter().filter(|n| !n.is_empty()).cloned().collect(),
            url: d.url.clone(),
            birthday: d.birthday.clone(),
            anniversary: d.anniversary.clone(),
            nickname: d.nickname.clone(),
            gender: gender_out(&d.gender),
            photos: Vec::new(),
            photo_removed: false,
        };
        // Device avatar: export only when it differs from the persisted
        // download baseline (conversion failure → omit, server copy wins).
        // A known row whose avatar is gone (baseline present, or no
        // baseline to compare against) flags photo_removed so the rebuild
        // emits a bare PHOTO: line; never-synced rows never flag.
        let avatar = c.avatar();
        let baseline = photos.get(&c.id);
        if !c.guid.is_empty() {
            log.push(format!(
                "Contacts avatar uid={} n={} len={} baseline={} dirty={}",
                c.guid,
                c.avatars.len(),
                avatar.len(),
                u8::from(baseline.is_some()),
                u8::from(dirty)
            ));
        }
        if avatar_changed(avatar, baseline) {
            let data = if avatar.starts_with("data:") {
                Some(avatar.to_string())
            } else {
                avatar_data.get(avatar).filter(|d| !d.is_empty()).cloned()
            };
            if let Some(data) = data {
                fields.photos.push(data);
            }
        } else if avatar.is_empty() && !c.guid.is_empty() && baseline.is_none_or(|b| !b.is_empty())
        {
            fields.photo_removed = true;
        }
        item.fields = Some(fields);
        items.push(item);
    }

    let known_uids: HashSet<String> = settings.string_map(account, ID_MAP).into_keys().collect();
    // Upsync trace: identity flags only, never field contents.
    let flags: Vec<Value> = items
        .iter()
        .map(|i| {
            serde_json::json!({
                "qid": i.qcontact_id,
                "uid": i.proton_uid,
                "modified": i.modified,
                "anchor": i.last_synced_mtime,
                "has_fields": i.fields.is_some(),
            })
        })
        .collect();
    log.insert(0, format!("Contacts inventory: {} rows", items.len()));
    log.push(format!(
        "Contacts upsync in: {}",
        truncate(&Value::Array(flags).to_string(), 3000)
    ));
    let mut known_sorted: Vec<&String> = known_uids.iter().collect();
    known_sorted.sort();
    log.push(format!(
        "Contacts upsync known={} anchors={}",
        truncate(
            &serde_json::to_string(&known_sorted).unwrap_or_default(),
            2000
        ),
        truncate(settings.get(account, ANCHORS), 500)
    ));
    Inventory {
        items,
        known_uids,
        anchors: anchors.into_iter().collect(),
        log,
    }
}

pub fn truncate(s: &str, max_chars: usize) -> String {
    s.chars().take(max_chars).collect()
}

/// A server row (engine `ProcessedContact` JSON), the fields the phone uses.
#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct ServerContact {
    uid: String,
    first_name: String,
    last_name: String,
    display_name: String,
    emails: Vec<ParsedEmail>,
    phones: Vec<ParsedPhone>,
    addresses: Vec<ParsedAddress>,
    organization: String,
    title: String,
    role: String,
    notes: Vec<String>,
    birthday: String,
    anniversary: String,
    nickname: String,
    url: String,
    gender: String,
    photos: Vec<String>,
    decrypt_failed: bool,
}

fn contexts_of(types: &[String]) -> Vec<String> {
    let mut out = Vec::new();
    for t in types {
        let t = t.to_lowercase();
        if CONTEXTS.contains(&t.as_str()) {
            out.push(t);
        }
    }
    out
}

fn date_of(value: &str) -> String {
    chrono::NaiveDate::parse_from_str(value, "%Y-%m-%d")
        .or_else(|_| chrono::NaiveDate::parse_from_str(value, "%Y%m%d"))
        .map(|d| d.format("%Y-%m-%d").to_string())
        .unwrap_or_default()
}

/// One server row → the phone contact to save.
fn spec(row: &ServerContact) -> ContactSpec {
    let mut first = row.first_name.clone();
    let mut last = row.last_name.clone();
    if first.is_empty() && last.is_empty() && !row.display_name.is_empty() {
        let parts: Vec<&str> = row.display_name.split(' ').collect();
        if parts.len() >= 2 {
            first = parts[..parts.len() - 1].join(" ");
            last = parts[parts.len() - 1].to_string();
        } else {
            first = row.display_name.clone();
        }
    }
    let phones = row
        .phones
        .iter()
        .filter(|p| !p.number.is_empty())
        .map(|p| {
            let mut sub_types = Vec::new();
            for t in &p.types {
                let t = t.to_lowercase();
                let sub = match t.as_str() {
                    "cell" | "mobile" => Some("mobile"),
                    "fax" | "pager" | "voice" | "video" | "car" => Some(t.as_str()),
                    _ => None,
                };
                if let Some(sub) = sub {
                    sub_types.push(sub.to_string());
                }
            }
            Phone {
                number: p.number.clone(),
                sub_types,
                contexts: contexts_of(&p.types),
            }
        })
        .collect();
    let has_org = !row.organization.is_empty() || !row.title.is_empty() || !row.role.is_empty();
    let gender = if row.gender.is_empty() {
        String::new()
    } else if row.gender.eq_ignore_ascii_case("female") {
        "female".into()
    } else {
        // Historical mapping: anything but Female is stored as male.
        "male".into()
    };
    ContactSpec {
        guid: row.uid.clone(),
        details: Details {
            first_name: first,
            last_name: last,
            display_label: row.display_name.clone(),
            emails: row
                .emails
                .iter()
                .filter(|e| !e.email.is_empty())
                .map(|e| Email {
                    email: e.email.clone(),
                    contexts: contexts_of(&e.types),
                })
                .collect(),
            phones,
            addresses: row
                .addresses
                .iter()
                .map(|a| Address {
                    street: a.street.clone(),
                    locality: a.locality.clone(),
                    region: a.region.clone(),
                    postcode: a.postal_code.clone(),
                    country: a.country.clone(),
                    contexts: contexts_of(&a.types),
                })
                .collect(),
            organization: has_org.then(|| Organization {
                name: row.organization.clone(),
                title: row.title.clone(),
                role: row.role.clone(),
            }),
            birthday: date_of(&row.birthday),
            anniversary: date_of(&row.anniversary),
            nickname: row.nickname.clone(),
            url: row.url.clone(),
            gender,
        },
        note: row
            .notes
            .iter()
            .filter(|n| !n.is_empty())
            .cloned()
            .collect::<Vec<_>>()
            .join("\n"),
        avatar: row.photos.first().cloned().unwrap_or_default(),
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Save {
    /// Index into the dumped local contacts: rewrite that contact in place
    /// (keeps its QContactId); `None` = new contact.
    #[serde(rename = "ref")]
    pub local: Option<usize>,
    pub contact: ContactSpec,
}

/// What the shim executes: saves first, removals after (a failed save
/// leaves every local row in place).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct WritePlan {
    pub save: Vec<Save>,
    /// Indexes into the dumped local contacts.
    pub remove: Vec<usize>,
}

/// Bookkeeping carried from the plan to the commit.
#[derive(Debug, Clone, Default)]
pub struct WriteContext {
    saved_keys: Vec<String>,
    untouched: Vec<(String, String)>,
    hashes: BTreeMap<String, String>,
}

/// Reconciling write (see `reconcile`): rows are matched by Proton UID
/// (QContactGuid). Guid-less rows (created on the phone, not uploaded yet)
/// are kept; once the engine confirms their upload (`confirmed`:
/// `{qcontact_id: uid}`) the server row is merged into that same contact
/// instead of creating a second copy.
pub fn write_plan(
    settings: &Settings,
    account: &str,
    rows_json: &str,
    confirmed: &BTreeMap<String, String>,
    local: &[LocalContact],
) -> Result<(WritePlan, WriteContext, Vec<String>), String> {
    let rows: Vec<Value> =
        serde_json::from_str(rows_json).map_err(|_| "Expected JSON array of contacts")?;
    let mut log = Vec::new();

    let mut local_by_key: BTreeMap<String, usize> = BTreeMap::new();
    let mut local_state: BTreeMap<String, Local> = BTreeMap::new();
    let mut duplicates = Vec::new();
    let mut merged = 0;
    for (index, c) in local.iter().enumerate() {
        let mut state = Local {
            synced: !c.guid.is_empty(),
            intact: true,
        };
        let key = if !c.guid.is_empty() {
            c.guid.clone()
        } else if let Some(uid) = confirmed.get(&c.id) {
            // Uploaded this cycle: the server row takes over this contact.
            state = Local {
                synced: true,
                intact: false,
            };
            merged += 1;
            uid.clone()
        } else {
            format!("local:{}", c.id)
        };
        if local_by_key.contains_key(&key) {
            // Two local rows for one server contact (left over from older
            // versions): keep the first, drop the extra copy.
            duplicates.push(index);
            continue;
        }
        local_by_key.insert(key.clone(), index);
        local_state.insert(key, state);
    }

    let mut incoming_rows: BTreeMap<String, ServerContact> = BTreeMap::new();
    let mut incoming = BTreeMap::new();
    let mut partial = BTreeSet::new();
    for row in &rows {
        let parsed: ServerContact = serde_json::from_value(row.clone()).unwrap_or_default();
        if parsed.uid.is_empty() || incoming_rows.contains_key(&parsed.uid) {
            log.push(format!(
                "Skipping contact row with {} UID id={}",
                if parsed.uid.is_empty() {
                    "empty"
                } else {
                    "duplicate"
                },
                row.get("id").and_then(Value::as_str).unwrap_or("")
            ));
            continue;
        }
        if crate::device::verbose() {
            log.push(format!(
                "Contact JSON: {}",
                truncate(&row.to_string(), 2000)
            ));
        }
        incoming.insert(
            parsed.uid.clone(),
            reconcile::row_hash(row, &["keys_debug"]),
        );
        if parsed.decrypt_failed {
            partial.insert(parsed.uid.clone());
        }
        incoming_rows.insert(parsed.uid.clone(), parsed);
    }
    let previous = settings.string_map(account, ROW_HASHES);
    let plan = reconcile::plan(&incoming, &previous, &local_state, &partial);
    log.push(format!(
        "Contacts reconcile: {} merged={} duplicates={} partial={}",
        plan.summary(),
        merged,
        duplicates.len(),
        partial.len()
    ));

    let mut write = WritePlan::default();
    let mut ctx = WriteContext {
        hashes: plan.hashes.clone(),
        ..WriteContext::default()
    };
    for key in plan.add.iter().chain(&plan.rewrite) {
        write.save.push(Save {
            local: local_by_key.get(key).copied(),
            contact: spec(&incoming_rows[key]),
        });
        ctx.saved_keys.push(key.clone());
    }
    write.remove = duplicates;
    write
        .remove
        .extend(plan.remove.iter().map(|k| local_by_key[k]));
    ctx.untouched = plan
        .unchanged
        .iter()
        .map(|k| (k.clone(), local[local_by_key[k]].id.clone()))
        .collect();
    Ok((write, ctx, log))
}

/// What the shim reports for each saved contact, in plan order: the stored
/// id, timestamp and LAST avatar URL as re-read from storage (so the
/// baseline compares like-for-like through QUrl).
#[derive(Debug, Clone, Default, Deserialize)]
pub struct Saved {
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub last_modified: Option<i64>,
    #[serde(default)]
    pub avatar: String,
}

/// Settings after a successful write. Untouched rows keep their previous
/// baselines, so a local edit that has not reached the server yet stays
/// dirty and is retried.
pub fn commit(
    settings: &Settings,
    account: &str,
    ctx: &WriteContext,
    saved: &[Saved],
) -> (SettingsPatch, Vec<String>) {
    let previous_mod = settings.int_map(account, LAST_MODIFIED);
    let previous_photos = settings.string_map(account, PHOTOS);
    let mut id_map = BTreeMap::new();
    let mut last_mod = BTreeMap::new();
    let mut photos = BTreeMap::new();
    for (key, row) in ctx.saved_keys.iter().zip(saved) {
        if row.id.is_empty() {
            continue;
        }
        id_map.insert(key.clone(), row.id.clone());
        if let Some(ms) = row.last_modified {
            last_mod.insert(row.id.clone(), ms);
        }
        if !row.avatar.is_empty() {
            photos.insert(row.id.clone(), row.avatar.clone());
        }
    }
    for (key, id) in &ctx.untouched {
        id_map.insert(key.clone(), id.clone());
        if let Some(ms) = previous_mod.get(id) {
            last_mod.insert(id.clone(), *ms);
        }
        if let Some(p) = previous_photos.get(id) {
            photos.insert(id.clone(), p.clone());
        }
    }
    let hashes: BTreeMap<&String, &String> = ctx
        .hashes
        .iter()
        .filter(|(k, _)| id_map.contains_key(*k))
        .collect();
    let mut patch = SettingsPatch::default();
    patch.set_json(account, ID_MAP, &id_map);
    patch.set_json(account, LAST_MODIFIED, &last_mod);
    patch.set_json(account, PHOTOS, &photos);
    patch.set_json(account, ROW_HASHES, &hashes);
    let log = vec![format!(
        "Saved {} contacts ({} unchanged)",
        ctx.saved_keys.len(),
        ctx.untouched.len()
    )];
    (patch, log)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const ACC: &str = "143";

    fn settings(pairs: &[(&str, Value)]) -> Settings {
        let mut s = Settings::default();
        let group = s.0.entry(ACC.into()).or_default();
        for (k, v) in pairs {
            group.insert((*k).into(), v.to_string());
        }
        s
    }

    fn contact(id: &str, guid: &str, modified: i64) -> LocalContact {
        LocalContact {
            id: id.into(),
            guid: guid.into(),
            last_modified: Some(modified),
            details: Details {
                first_name: "Ada".into(),
                ..Details::default()
            },
            ..LocalContact::default()
        }
    }

    fn server(uid: &str, name: &str) -> Value {
        json!({"uid": uid, "first_name": name, "mtime": 1, "keys_debug": "x"})
    }

    #[test]
    fn test_inventory_dirt_pending_and_types() {
        let s = settings(&[
            (LAST_MODIFIED, json!({"q1": 10, "q2": 10})),
            (ANCHORS, json!({"u1": 5})),
            (PENDING, json!({"q3": "stable"})),
        ]);
        let mut phone = contact("q3", "", 1);
        phone.details.phones.push(Phone {
            number: "+39".into(),
            sub_types: vec!["car".into(), "mobile".into()],
            contexts: vec!["work".into(), "home".into()],
        });
        phone.details.gender = "female".into();
        let local = vec![contact("q1", "u1", 10), contact("q2", "u2", 11), phone];
        let inv = inventory(&s, ACC, &local, &BTreeMap::new());
        assert!(!inv.items[0].modified && inv.items[0].fields.is_none());
        assert_eq!(inv.items[0].last_synced_mtime, Some(5));
        assert!(inv.items[1].modified && inv.items[1].fields.is_some());
        let created = &inv.items[2];
        assert_eq!(created.pending_uid.as_deref(), Some("stable"));
        let fields = created.fields.as_ref().unwrap();
        assert_eq!(fields.phones[0].types, vec!["cell", "car", "home", "work"]);
        assert_eq!(fields.gender, "Female");
    }

    #[test]
    fn test_avatar_changes_and_removals() {
        let s = settings(&[
            (LAST_MODIFIED, json!({"q1": 1, "q2": 1})),
            (PHOTOS, json!({"q1": "file:///old.jpg", "q2": "data:x"})),
        ]);
        let mut changed = contact("q1", "u1", 2);
        changed.avatars = vec!["file:///stale.jpg".into(), "file:///new.jpg".into()];
        let removed = contact("q2", "u2", 2);
        let local = vec![changed, removed];
        assert_eq!(avatars_needed(&s, ACC, &local), vec!["file:///new.jpg"]);
        let data = BTreeMap::from([("file:///new.jpg".to_string(), "data:new".to_string())]);
        let inv = inventory(&s, ACC, &local, &data);
        assert_eq!(
            inv.items[0].fields.as_ref().unwrap().photos,
            vec!["data:new"]
        );
        assert!(inv.items[1].fields.as_ref().unwrap().photo_removed);
    }

    #[test]
    fn test_write_plan_merges_keeps_and_removes() {
        let rows = json!([
            server("u1", "Same"),
            server("u2", "Changed"),
            server("u9", "Uploaded")
        ]);
        let mut s = settings(&[]);
        let hash_same = reconcile::row_hash(&server("u1", "Same"), &["keys_debug"]);
        s.0.get_mut(ACC).unwrap().insert(
            ROW_HASHES.into(),
            json!({"u1": hash_same, "u2": "old", "gone": "old"}).to_string(),
        );
        let local = vec![
            contact("q1", "u1", 1),
            contact("q2", "u2", 1),
            contact("q3", "gone", 1),
            contact("q4", "", 1),
            contact("q5", "", 1),
            contact("q6", "u1", 1),
        ];
        let confirmed = BTreeMap::from([("q5".to_string(), "u9".to_string())]);
        let (plan, ctx, log) = write_plan(&s, ACC, &rows.to_string(), &confirmed, &local).unwrap();
        assert!(log.iter().any(|l| l.contains("merged=1 duplicates=1")));
        let saved: Vec<(Option<usize>, &str)> = plan
            .save
            .iter()
            .map(|s| (s.local, s.contact.guid.as_str()))
            .collect();
        assert_eq!(saved, vec![(Some(1), "u2"), (Some(4), "u9")]);
        // Duplicate u1 copy and the upstream-deleted row go; q4 stays.
        assert_eq!(plan.remove, vec![5, 2]);

        let results = vec![
            Saved {
                id: "q2".into(),
                last_modified: Some(20),
                avatar: String::new(),
            },
            Saved {
                id: "q5".into(),
                last_modified: Some(21),
                avatar: "data:a".into(),
            },
        ];
        let mut s2 = s.clone();
        s2.0.get_mut(ACC)
            .unwrap()
            .insert(LAST_MODIFIED.into(), json!({"q1": 7}).to_string());
        let (patch, _) = commit(&s2, ACC, &ctx, &results);
        s2.apply(&patch);
        assert_eq!(
            s2.string_map(ACC, ID_MAP),
            BTreeMap::from([
                ("u1".into(), "q1".into()),
                ("u2".into(), "q2".into()),
                ("u9".into(), "q5".into())
            ])
        );
        assert_eq!(s2.int_map(ACC, LAST_MODIFIED).get("q1"), Some(&7));
        assert_eq!(s2.int_map(ACC, LAST_MODIFIED).get("q5"), Some(&21));
        assert_eq!(s2.string_map(ACC, ROW_HASHES).len(), 3);
    }

    #[test]
    fn test_spec_maps_server_fields() {
        let row: ServerContact = serde_json::from_value(json!({
            "uid": "u", "display_name": "Ada King Lovelace",
            "phones": [{"number": "1", "types": ["CELL", "work"]}, {"number": "", "types": []}],
            "notes": ["a", "", "b"], "birthday": "18151210", "gender": "F",
            "photos": ["data:p"]
        }))
        .unwrap();
        let s = spec(&row);
        assert_eq!(s.details.first_name, "Ada King");
        assert_eq!(s.details.last_name, "Lovelace");
        assert_eq!(s.details.phones.len(), 1);
        assert_eq!(s.details.phones[0].sub_types, vec!["mobile"]);
        assert_eq!(s.details.phones[0].contexts, vec!["work"]);
        assert_eq!(s.note, "a\nb");
        assert_eq!(s.details.birthday, "1815-12-10");
        assert_eq!(s.details.gender, "male");
        assert_eq!(s.avatar, "data:p");
        assert!(s.details.organization.is_none());
    }
}
