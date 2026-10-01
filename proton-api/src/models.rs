// proton-api/src/models.rs
// Proton API uses PascalCase JSON keys; allow non-snake-case field names to match wire format.
#![allow(non_snake_case)]
use serde::{Deserialize, Deserializer, Serialize};

/// Lenient helpers: the live API mixes JSON shapes (Go int-bools 0/1, explicit
/// nulls, number-or-string IDs). Strict types turned one odd row into a
/// whole-list parse failure (verified live 2026-09-06: 19 rows dropped).
fn deserialize_opt_bool<'de, D: Deserializer<'de>>(
    d: D,
) -> std::result::Result<Option<bool>, D::Error> {
    let v = Option::<serde_json::Value>::deserialize(d)?;
    Ok(match v {
        None | Some(serde_json::Value::Null) => None,
        Some(serde_json::Value::Bool(b)) => Some(b),
        Some(serde_json::Value::Number(n)) => Some(n.as_i64().unwrap_or(0) != 0),
        Some(serde_json::Value::String(s)) => {
            Some(matches!(s.to_lowercase().as_str(), "1" | "true" | "yes"))
        }
        Some(_) => None,
    })
}

fn deserialize_vec_i64<'de, D: Deserializer<'de>>(d: D) -> std::result::Result<Vec<i64>, D::Error> {
    let v = Option::<serde_json::Value>::deserialize(d)?;
    Ok(match v {
        None | Some(serde_json::Value::Null) => Vec::new(),
        Some(serde_json::Value::Array(a)) => a.iter().filter_map(|x| x.as_i64()).collect(),
        Some(serde_json::Value::Number(n)) => n.as_i64().map_or_else(Vec::new, |x| vec![x]),
        Some(_) => Vec::new(),
    })
}

fn deserialize_opt_string<'de, D: Deserializer<'de>>(
    d: D,
) -> std::result::Result<Option<String>, D::Error> {
    let v = Option::<serde_json::Value>::deserialize(d)?;
    Ok(match v {
        None | Some(serde_json::Value::Null) => None,
        Some(serde_json::Value::String(s)) => Some(s),
        Some(other) => Some(other.to_string()),
    })
}

fn deserialize_opt_value_vec<'de, D: Deserializer<'de>>(
    d: D,
) -> std::result::Result<Option<Vec<serde_json::Value>>, D::Error> {
    let v = Option::<serde_json::Value>::deserialize(d)?;
    Ok(match v {
        None | Some(serde_json::Value::Null) => None,
        Some(serde_json::Value::Array(a)) => Some(a),
        Some(_) => None,
    })
}

/// Null- and type-tolerant scalars: explicit nulls must behave like missing
/// keys (plain #[serde(default)] does NOT accept null), and numeric IDs may
/// arrive as strings.
fn deserialize_string_default<'de, D: Deserializer<'de>>(
    d: D,
) -> std::result::Result<String, D::Error> {
    let v = Option::<serde_json::Value>::deserialize(d)?;
    Ok(match v {
        None | Some(serde_json::Value::Null) => String::new(),
        Some(serde_json::Value::String(s)) => s,
        Some(other) => other.to_string(),
    })
}

fn deserialize_i64_default<'de, D: Deserializer<'de>>(d: D) -> std::result::Result<i64, D::Error> {
    let v = Option::<serde_json::Value>::deserialize(d)?;
    Ok(match v {
        None | Some(serde_json::Value::Null) | Some(serde_json::Value::Bool(false)) => 0,
        Some(serde_json::Value::Bool(true)) => 1,
        Some(serde_json::Value::Number(n)) => n.as_i64().unwrap_or(0),
        Some(serde_json::Value::String(s)) => s.parse::<i64>().unwrap_or(0),
        Some(_) => 0,
    })
}

fn deserialize_opt_i64<'de, D: Deserializer<'de>>(
    d: D,
) -> std::result::Result<Option<i64>, D::Error> {
    let v = Option::<serde_json::Value>::deserialize(d)?;
    Ok(match v {
        None | Some(serde_json::Value::Null) => None,
        Some(serde_json::Value::Bool(b)) => Some(i64::from(b)),
        Some(serde_json::Value::Number(n)) => n.as_i64().or(Some(0)),
        Some(serde_json::Value::String(s)) => s.parse::<i64>().ok(),
        Some(_) => None,
    })
}

/// Null-tolerant vec where one bad element must not kill the whole list.
fn deserialize_vec_default<'de, D: Deserializer<'de>, T: serde::de::DeserializeOwned>(
    d: D,
) -> std::result::Result<Vec<T>, D::Error> {
    let v = Option::<serde_json::Value>::deserialize(d)?;
    Ok(match v {
        None | Some(serde_json::Value::Null) => Vec::new(),
        Some(serde_json::Value::Array(a)) => a
            .into_iter()
            .filter_map(|x| serde_json::from_value(x).ok())
            .collect(),
        Some(_) => Vec::new(),
    })
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthRequest {
    pub Username: String,
    pub Password: String,
    pub Remember: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthResponse {
    pub AccessToken: String,
    pub RefreshToken: String,
    pub UID: String,
    pub ExpiresIn: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthTokens {
    pub access_token: String,
    pub refresh_token: String,
    pub uid: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Contact {
    pub ID: String,
    #[serde(default)]
    pub Name: String,
    #[serde(default)]
    pub UID: String,
    #[serde(default)]
    pub Size: i64,
    #[serde(default)]
    pub CreateTime: i64,
    #[serde(default)]
    pub ModifyTime: i64,
    #[serde(default)]
    pub ContactEmails: Vec<ContactEmail>,
    #[serde(default)]
    pub LabelIDs: Vec<String>,
    #[serde(default)]
    pub Cards: Option<Vec<ContactCard>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContactEmail {
    #[serde(default)]
    pub ID: String,
    #[serde(default)]
    pub Name: String,
    #[serde(default)]
    pub Email: String,
    #[serde(rename = "Type", default)]
    pub Type: Vec<String>,
    #[serde(default)]
    pub ContactID: String,
    #[serde(default)]
    pub LabelIDs: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContactCard {
    #[serde(deserialize_with = "deserialize_card_type")]
    pub Type: i32,
    pub Data: String,
    /// Armored detached signature (Types 2/3). Cleartext cards (Type 0)
    /// carry JSON `null` on the wire: tolerated on read, omitted on write
    /// (WebClients sends explicit null; Go treats absent identically).
    #[serde(
        default,
        deserialize_with = "deserialize_string_default",
        skip_serializing_if = "String::is_empty"
    )]
    pub Signature: String,
}

fn deserialize_card_type<'de, D: serde::Deserializer<'de>>(
    d: D,
) -> std::result::Result<i32, D::Error> {
    use serde::de;
    let val = serde_json::Value::deserialize(d)?;
    match val {
        serde_json::Value::Number(n) => n
            .as_i64()
            .map(|v| v as i32)
            .ok_or_else(|| de::Error::custom("invalid number")),
        serde_json::Value::String(s) => s
            .parse::<i32>()
            .map_err(|_| de::Error::custom("invalid string number")),
        _ => Err(de::Error::custom("expected number or string")),
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContactSettings {
    pub Scheme: Option<String>,   // "pgp-inline" or "pgp-mime"
    pub MIMEType: Option<String>, // "text/plain" or "multipart/encrypted"
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContactsListResponse {
    pub Contacts: Vec<Contact>,
    pub Total: i32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateContactsRequest {
    /// One entry per contact (WebClients `addContacts` + go-proton-api
    /// `CreateContactsReq`: array of `{Cards: [...]}` OBJECTS — never a
    /// bare array of arrays; the server rejects the latter).
    pub Contacts: Vec<CreateContactCards>,
    pub Overwrite: i32,
    pub Labels: i32,
}

/// Single batch-create entry: the sealed cards for one new contact.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateContactCards {
    pub Cards: Vec<ContactCard>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateContactsResponse {
    pub Responses: Vec<CreateContactResponse>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateContactResponse {
    pub Index: i32,
    pub Response: CreateContactResult,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateContactResult {
    pub Code: i32,
    pub Error: Option<String>,
    /// Echoed contact, nested under its own key (WebClients reference shape;
    /// absent on per-op failure). NOTE: NOT flattened — an earlier flatten
    /// layout never matched the wire and was caught by mock tests.
    #[serde(default)]
    pub Contact: Option<Contact>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateContactRequest {
    pub Cards: Vec<ContactCard>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserKey {
    #[serde(default)]
    pub ID: String,
    #[serde(default)]
    pub Version: i64,
    #[serde(default)]
    pub PrivateKey: String,
    #[serde(default)]
    pub Token: String,
    #[serde(default)]
    pub Signature: String,
    #[serde(default)]
    pub Primary: i64,
    #[serde(default)]
    pub Active: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserResponse {
    pub User: User,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    #[serde(default)]
    pub ID: String,
    #[serde(default)]
    pub Name: String,
    #[serde(default)]
    pub Keys: Vec<UserKey>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AddressKey {
    #[serde(default)]
    pub ID: String,
    #[serde(default)]
    pub Version: i64,
    #[serde(default)]
    pub PrivateKey: String,
    #[serde(default)]
    pub Token: String,
    #[serde(default)]
    pub Signature: String,
    #[serde(default)]
    pub Primary: i64,
    #[serde(default)]
    pub Active: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Address {
    #[serde(default)]
    pub ID: String,
    #[serde(default)]
    pub Email: String,
    #[serde(default)]
    pub Keys: Vec<AddressKey>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AddressesResponse {
    pub Addresses: Vec<Address>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeySalt {
    #[serde(default)]
    pub ID: String,
    #[serde(default)]
    pub KeySalt: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeySaltsResponse {
    pub KeySalts: Vec<KeySalt>,
}

// ---- Calendar ----
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Calendar {
    #[serde(default)]
    pub ID: String,
    #[serde(default)]
    pub Name: String,
    #[serde(default)]
    pub Description: String,
    #[serde(default)]
    pub Color: String,
    #[serde(default, deserialize_with = "deserialize_opt_bool")]
    pub Display: Option<bool>,
    #[serde(default)]
    pub Type: i64,
    #[serde(default)]
    pub Flags: i64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CalendarKey {
    #[serde(default)]
    pub ID: String,
    #[serde(default)]
    pub CalendarID: String,
    #[serde(default)]
    pub PassphraseID: String,
    #[serde(default)]
    pub PrivateKey: String,
    #[serde(default)]
    pub Flags: i64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CalendarPassphrase {
    #[serde(default)]
    pub ID: String,
    #[serde(default)]
    pub Flags: i64,
    #[serde(default)]
    pub MemberPassphrases: Vec<MemberPassphrase>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MemberPassphrase {
    #[serde(default)]
    pub MemberID: String,
    #[serde(default)]
    pub Passphrase: String,
    #[serde(default)]
    pub Signature: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CalendarMember {
    #[serde(default)]
    pub ID: String,
    #[serde(default)]
    pub CalendarID: String,
    #[serde(default)]
    pub AddressID: String,
    #[serde(default)]
    pub Email: String,
    #[serde(default)]
    pub Name: String,
    #[serde(default)]
    pub Description: String,
    #[serde(default)]
    pub Color: String,
    #[serde(default)]
    pub Permissions: i64,
    #[serde(default)]
    pub Flags: i64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CalendarBootstrap {
    #[serde(default)]
    pub Members: Vec<CalendarMember>,
    #[serde(default)]
    pub Keys: Vec<CalendarKey>,
    #[serde(default)]
    pub Passphrase: Option<CalendarPassphrase>,
    #[serde(default)]
    pub Settings: Option<CalendarSettings>,
}

/// Per-calendar defaults from bootstrap (api.md): default reminder sets for
/// timed (`DefaultPartDayNotifications`) and all-day
/// (`DefaultFullDayNotifications`) events, as `{Type, Trigger}` entries just
/// like event-level `Notifications`. `null`/absent on the event means
/// "inherit these"; `[]` means explicitly none.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CalendarSettings {
    #[serde(default)]
    pub DefaultEventDuration: Option<i64>,
    #[serde(default)]
    pub DefaultPartDayNotifications: Option<Vec<serde_json::Value>>,
    #[serde(default)]
    pub DefaultFullDayNotifications: Option<Vec<serde_json::Value>>,
    #[serde(default, deserialize_with = "deserialize_opt_bool")]
    pub MakesUserBusy: Option<bool>,
}

impl CalendarSettings {
    /// An absent defaults object needs a v1 fill-in; explicit empty arrays
    /// are authoritative "no reminders", not missing settings.
    pub fn is_empty(&self) -> bool {
        self.DefaultPartDayNotifications.is_none() && self.DefaultFullDayNotifications.is_none()
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CalendarEventsListResponse {
    #[serde(default)]
    pub Events: Vec<CalendarEvent>,
    #[serde(default)]
    pub More: i64,
    #[serde(default)]
    pub Total: Option<i64>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CalendarEvent {
    #[serde(default, deserialize_with = "deserialize_string_default")]
    pub ID: String,
    #[serde(default, deserialize_with = "deserialize_string_default")]
    pub UID: String,
    #[serde(default, deserialize_with = "deserialize_string_default")]
    pub CalendarID: String,
    #[serde(default, deserialize_with = "deserialize_string_default")]
    pub SharedEventID: String,
    #[serde(default, deserialize_with = "deserialize_i64_default")]
    pub CreateTime: i64,
    #[serde(default, deserialize_with = "deserialize_i64_default")]
    pub LastEditTime: i64,
    #[serde(default, deserialize_with = "deserialize_i64_default")]
    pub StartTime: i64,
    #[serde(default, deserialize_with = "deserialize_i64_default")]
    pub EndTime: i64,
    #[serde(default, deserialize_with = "deserialize_string_default")]
    pub StartTimezone: String,
    #[serde(default, deserialize_with = "deserialize_string_default")]
    pub EndTimezone: String,
    #[serde(default, deserialize_with = "deserialize_opt_bool")]
    pub FullDay: Option<bool>,
    #[serde(default, deserialize_with = "deserialize_string_default")]
    pub Author: String,
    #[serde(default, deserialize_with = "deserialize_string_default")]
    pub SharedKeyPacket: String,
    #[serde(default, deserialize_with = "deserialize_string_default")]
    pub CalendarKeyPacket: String,
    #[serde(default, deserialize_with = "deserialize_vec_default")]
    pub SharedEvents: Vec<CalendarEventPart>,
    #[serde(default, deserialize_with = "deserialize_vec_default")]
    pub CalendarEvents: Vec<CalendarEventPart>,
    #[serde(default, deserialize_with = "deserialize_vec_default")]
    pub AttendeesEvents: Vec<CalendarEventPart>,
    #[serde(default, deserialize_with = "deserialize_vec_default")]
    pub PersonalEvents: Vec<CalendarEventPart>,
    // Plaintext row columns (api.md – no decryption needed)
    #[serde(default, deserialize_with = "deserialize_opt_string")]
    pub RRule: Option<String>,
    #[serde(default, deserialize_with = "deserialize_vec_i64")]
    pub Exdates: Vec<i64>,
    #[serde(default, deserialize_with = "deserialize_opt_i64")]
    pub RecurrenceID: Option<i64>,
    #[serde(default, deserialize_with = "deserialize_opt_string")]
    pub Color: Option<String>,
    #[serde(default, deserialize_with = "deserialize_opt_value_vec")]
    pub Notifications: Option<Vec<serde_json::Value>>,
    #[serde(default, deserialize_with = "deserialize_opt_i64")]
    pub IsOrganizer: Option<i64>,
    #[serde(default, deserialize_with = "deserialize_opt_i64")]
    pub Permissions: Option<i64>,
    /// Clear attendee rows: opaque token + live RSVP status (0 needs-action,
    /// 1 tentative, 2 declined, 3 accepted). Identities live encrypted in
    /// the AttendeesEvents card and join by Token (api.md). Re-sent verbatim
    /// on update — omitting them wipes RSVP state server-side.
    #[serde(default, deserialize_with = "deserialize_vec_default")]
    pub Attendees: Vec<AttendeeToken>,
}

/// One clear attendee row (see `CalendarEvent::Attendees`).
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct AttendeeToken {
    #[serde(default, deserialize_with = "deserialize_string_default")]
    pub Token: String,
    #[serde(default, deserialize_with = "deserialize_i64_default")]
    pub Status: i64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CalendarEventPart {
    #[serde(default, deserialize_with = "deserialize_string_default")]
    pub MemberID: String,
    #[serde(default, deserialize_with = "deserialize_i64_default")]
    pub Type: i64,
    #[serde(default, deserialize_with = "deserialize_string_default")]
    pub Data: String,
    #[serde(default, deserialize_with = "deserialize_string_default")]
    pub Signature: String,
    #[serde(default, deserialize_with = "deserialize_string_default")]
    pub Author: String,
}
