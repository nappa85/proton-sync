use crate::{config::SyncConfig, status::SyncStatus};

use base64::Engine;
use proton_api::{
    decrypt_contact_card, derive_mailbox_password, download_url_photos, parse_vcard, AuthTokens,
    ContactsClient, KeysClient, LoginState, TokenManager, UnlockedKey,
};
use serde::Serialize;
use std::sync::{Arc, Mutex};

fn lock_or_recover<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|e| e.into_inner())
}

#[derive(Serialize)]
struct ProcessedContact {
    id: String,
    uid: String,
    name: String,
    first_name: String,
    last_name: String,
    display_name: String,
    emails: Vec<ProcessedEmail>,
    phones: Vec<ProcessedPhone>,
    addresses: Vec<ProcessedAddress>,
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
    keys_debug: String,
    #[serde(skip_serializing)]
    decrypt_failed: bool,
}

#[derive(Serialize)]
struct ProcessedEmail {
    email: String,
    types: Vec<String>,
}

#[derive(Serialize)]
struct ProcessedPhone {
    number: String,
    types: Vec<String>,
}

#[derive(Serialize)]
struct ProcessedAddress {
    street: String,
    locality: String,
    region: String,
    postal_code: String,
    country: String,
    types: Vec<String>,
}

pub struct SyncEngine {
    config: Arc<Mutex<SyncConfig>>,
    status: Arc<Mutex<SyncStatus>>,
    token_manager: Arc<Mutex<TokenManager>>,
    contacts_client: Option<ContactsClient>,
    access_token: Option<String>,
    uid: Option<String>,
    abort_flag: Arc<Mutex<bool>>,
    contacts_json: Arc<Mutex<Option<String>>>,
    keys_debug: Option<String>,
    derived_passwords: Arc<Mutex<Option<std::collections::HashMap<String, String>>>>,
    decrypt_errors: Arc<Mutex<u32>>,
    contact_conflicts: Arc<Mutex<Vec<crate::contact_plan::ContactConflict>>>,
    contact_anchors: Arc<Mutex<std::collections::HashMap<String, i64>>>,
    contact_pending: Arc<Mutex<std::collections::HashMap<String, String>>>,
    contact_deferred: Arc<Mutex<Vec<ContactDeferred>>>,
}

impl SyncEngine {
    pub fn new(config: SyncConfig) -> Self {
        let mut token_manager = TokenManager::new();
        if let (Some(rt), Some(uid)) = (&config.refresh_token, &config.uid) {
            if !rt.is_empty() && !uid.is_empty() {
                let at = config.access_token.as_deref().unwrap_or("");
                token_manager.restore_tokens(AuthTokens {
                    access_token: at.to_string(),
                    refresh_token: rt.clone(),
                    uid: uid.clone(),
                });
                if !at.is_empty() {
                    token_manager.set_expiry(3600);
                }
            }
        }

        Self {
            config: Arc::new(Mutex::new(config)),
            status: Arc::new(Mutex::new(SyncStatus::default())),
            token_manager: Arc::new(Mutex::new(token_manager)),
            contacts_client: None,
            access_token: None,
            uid: None,
            abort_flag: Arc::new(Mutex::new(false)),
            contacts_json: Arc::new(Mutex::new(None)),
            keys_debug: None,
            derived_passwords: Arc::new(Mutex::new(None)),
            decrypt_errors: Arc::new(Mutex::new(0)),
            contact_conflicts: Arc::new(Mutex::new(Vec::new())),
            contact_anchors: Arc::new(Mutex::new(std::collections::HashMap::new())),
            contact_pending: Arc::new(Mutex::new(std::collections::HashMap::new())),
            contact_deferred: Arc::new(Mutex::new(Vec::new())),
        }
    }

    pub fn config(&self) -> SyncConfig {
        lock_or_recover(&self.config).clone()
    }

    pub fn start_sync(&mut self, config: SyncConfig) {
        *lock_or_recover(&self.config) = config;
        *lock_or_recover(&self.abort_flag) = false;

        self.run_sync();
    }

    fn run_sync(&mut self) {
        self.set_status(SyncStatus {
            state: "syncing".into(),
            progress: 0.0,
            total_contacts: 0,
            synced_contacts: 0,
            error: None,
            last_sync: None,
        });

        let config = lock_or_recover(&self.config).clone();

        if config.username.is_empty() {
            self.set_status(SyncStatus {
                state: "error".into(),
                error: Some("Username is required".into()),
                ..Default::default()
            });
            return;
        }

        if let Err(e) = self.authenticate(&config) {
            // Preserve the distinct needs_2fa state (OTP code required):
            // authenticate() already set it with the right message, and the
            // sync plugin turns it into an "OTP required" notification
            // instead of a generic auth failure.
            self.set_status(Self::auth_error_status(&self.status(), &e));
            return;
        }

        if self.should_abort() {
            self.set_status(SyncStatus {
                state: "idle".into(),
                ..Default::default()
            });
            return;
        }

        let (mut unlocked_keys, user_end) = match self.unlock_keys(&config) {
            Ok(keys) => keys,
            Err(e) => {
                eprintln!("Key unlock failed (will sync without decryption): {e}");
                self.set_status(SyncStatus {
                    state: "error".into(),
                    error: Some(format!(
                        "Key unlock failed: {e} – re-enter credentials in Settings → Proton"
                    )),
                    ..Default::default()
                });
                *lock_or_recover(&self.decrypt_errors) = 1;
                return;
            }
        };
        let user_end = user_end.min(unlocked_keys.len());

        // Notify if no keys could be unlocked but keys were expected – likely password changed or derived map stale
        if unlocked_keys.is_empty() {
            let debug = self.keys_debug.clone().unwrap_or_default();
            // user_keys>0 but total_unlocked==0 indicates failure
            if debug.contains("user_keys=") && !debug.contains("user_keys=0") {
                self.set_status(SyncStatus {
                    state: "error".into(),
                    error: Some("Failed to unlock any Proton keys – password changed or new key requires re-authentication. Update credentials in Settings → Proton.".into()),
                    ..Default::default()
                });
                *lock_or_recover(&self.decrypt_errors) = 1;
                return;
            }
        }

        match self.fetch_contacts() {
            Ok(contacts) => {
                // Upsync phase 1 (uploads) before download processing.
                // Fail-closed: Err aborts before any local apply (status
                // error; uploads retry next cycle). Posted-but-unconfirmed
                // creates still land in the pending map either way so the
                // shim can persist retry UIDs even on error.
                let mut pending = std::collections::HashMap::new();
                let outcome = match Self::run_contact_upload_phase(
                    self.contacts_client.as_ref(),
                    &config,
                    &mut unlocked_keys,
                    user_end,
                    contacts,
                    &mut pending,
                ) {
                    Ok(outcome) => {
                        *lock_or_recover(&self.contact_pending) = outcome.pending_creates.clone();
                        *lock_or_recover(&self.contact_deferred) = outcome.deferred_list.clone();
                        outcome
                    }
                    Err(e) => {
                        *lock_or_recover(&self.contact_pending) = pending;
                        self.set_status(SyncStatus {
                            state: "error".into(),
                            error: Some(format!("Contacts upsync upload failed: {e}")),
                            ..Default::default()
                        });
                        return;
                    }
                };
                *lock_or_recover(&self.contact_conflicts) = outcome.conflicts;
                *lock_or_recover(&self.contact_anchors) = outcome.anchors;
                // File-log visibility: the shim logs `keys_debug` on every
                // run, so the upload trace survives without the journal.
                if !outcome.trace.is_empty() {
                    let prev = self.keys_debug.clone().unwrap_or_default();
                    self.keys_debug = Some(if prev.is_empty() {
                        outcome.trace
                    } else {
                        format!("{prev}|{}", outcome.trace)
                    });
                }
                let contacts = outcome.contacts;
                let total = contacts.len() as u32;

                let mut unlocked_keys_mut = unlocked_keys;
                let keys_debug = self.keys_debug.clone().unwrap_or_default();
                let mut decrypt_err_count: u32 = 0;

                let mut processed: Vec<ProcessedContact> = contacts
                    .iter()
                    .map(|c| {
                        let mut pc = ProcessedContact {
                            id: c.ID.clone(),
                            uid: c.UID.clone(),
                            name: c.Name.clone(),
                            first_name: String::new(),
                            last_name: String::new(),
                            display_name: c.Name.clone(),
                            emails: c
                                .ContactEmails
                                .iter()
                                .map(|e| ProcessedEmail {
                                    email: e.Email.clone(),
                                    types: e.Type.clone(),
                                })
                                .collect(),
                            phones: Vec::new(),
                            addresses: Vec::new(),
                            organization: String::new(),
                            title: String::new(),
                            role: String::new(),
                            notes: Vec::new(),
                            birthday: String::new(),
                            anniversary: String::new(),
                            nickname: String::new(),
                            url: String::new(),
                            gender: String::new(),
                            photos: Vec::new(),
                            keys_debug: keys_debug.clone(),
                            decrypt_failed: false,
                        };

                        let mut encrypted_count: u32 = 0;
                        let mut encrypted_fail_count: u32 = 0;
                        let mut had_vcard_data = false;

                        if let Some(cards) = &c.Cards {
                            for card in cards {
                                let vcard_data = if card.Type == 1 || card.Type == 3 {
                                    encrypted_count += 1;
                                    match decrypt_contact_card(&card.Data, &mut unlocked_keys_mut) {
                                        Ok(plain) => {
                                            pc.keys_debug = format!(
                                                "{};decrypted_type_{}=ok",
                                                pc.keys_debug, card.Type
                                            );
                                            plain
                                        }
                                        Err(e) => {
                                            encrypted_fail_count += 1;
                                            decrypt_err_count += 1;
                                            pc.keys_debug = format!(
                                                "{};decrypted_type_{}=ERR:{}",
                                                pc.keys_debug, card.Type, e
                                            );
                                            continue;
                                        }
                                    }
                                } else if card.Type == 0 || card.Type == 2 {
                                    if card.Data.starts_with("BEGIN:VCARD") {
                                        card.Data.clone()
                                    } else if let Ok(decoded) =
                                        base64::engine::general_purpose::STANDARD.decode(&card.Data)
                                    {
                                        String::from_utf8_lossy(&decoded).to_string()
                                    } else {
                                        card.Data.clone()
                                    }
                                } else {
                                    continue;
                                };

                                match parse_vcard(&vcard_data) {
                                    Ok(vc) => {
                                        had_vcard_data = true;
                                        if !vc.first_name.is_empty() || !vc.last_name.is_empty() {
                                            pc.first_name = vc.first_name;
                                            pc.last_name = vc.last_name;
                                        }
                                        if !vc.display_name.is_empty() {
                                            pc.display_name = vc.display_name;
                                        }
                                        if !vc.emails.is_empty() && pc.emails.is_empty() {
                                            pc.emails = vc
                                                .emails
                                                .into_iter()
                                                .map(|e| ProcessedEmail {
                                                    email: e.email,
                                                    types: e.types,
                                                })
                                                .collect();
                                        }
                                        if !vc.phones.is_empty() {
                                            pc.phones = vc
                                                .phones
                                                .into_iter()
                                                .map(|p| ProcessedPhone {
                                                    number: p.number,
                                                    types: p.types,
                                                })
                                                .collect();
                                        }
                                        if !vc.addresses.is_empty() {
                                            pc.addresses = vc
                                                .addresses
                                                .into_iter()
                                                .map(|a| ProcessedAddress {
                                                    street: a.street,
                                                    locality: a.locality,
                                                    region: a.region,
                                                    postal_code: a.postal_code,
                                                    country: a.country,
                                                    types: a.types,
                                                })
                                                .collect();
                                        }
                                        if !vc.organization.is_empty() {
                                            pc.organization = vc.organization;
                                        }
                                        if !vc.title.is_empty() {
                                            pc.title = vc.title;
                                        }
                                        if !vc.role.is_empty() {
                                            pc.role = vc.role;
                                        }
                                        if !vc.notes.is_empty() {
                                            pc.notes = vc.notes;
                                        }
                                        if !vc.birthday.is_empty() {
                                            pc.birthday = vc.birthday;
                                        }
                                        if !vc.anniversary.is_empty() {
                                            pc.anniversary = vc.anniversary;
                                        }
                                        if !vc.nickname.is_empty() {
                                            pc.nickname = vc.nickname;
                                        }
                                        if !vc.url.is_empty() {
                                            pc.url = vc.url;
                                        }
                                        if !vc.gender.is_empty() {
                                            pc.gender = vc.gender;
                                        }
                                        if !vc.photos.is_empty() {
                                            pc.photos = vc.photos;
                                        }
                                    }
                                    Err(e) => {
                                        pc.keys_debug =
                                            format!("{};parse_vcard_err={}", pc.keys_debug, e);
                                    }
                                }
                            }
                        }

                        pc.decrypt_failed = encrypted_count > 0
                            && encrypted_fail_count == encrypted_count
                            && !had_vcard_data;

                        pc
                    })
                    .collect();

                for pc in &mut processed {
                    download_url_photos(&mut pc.photos);
                }

                let json = serde_json::to_string(&processed).unwrap_or_else(|_| "[]".into());
                *lock_or_recover(&self.contacts_json) = Some(json);
                *lock_or_recover(&self.decrypt_errors) = decrypt_err_count;

                let skipped = processed.iter().filter(|pc| pc.decrypt_failed).count() as u32;
                if skipped > 0 {
                    let _debug = self.keys_debug.clone().unwrap_or_default();
                    self.set_status(SyncStatus {
                        state: "complete".into(),
                        progress: 1.0,
                        total_contacts: total,
                        synced_contacts: total - skipped,
                        error: Some(format!(
                            "{skipped} contact(s) skipped (decryption failed, key may have rotated)"
                        )),
                        last_sync: Some(chrono::Utc::now().to_rfc3339()),
                    });
                } else {
                    self.set_status(SyncStatus {
                        state: "complete".into(),
                        progress: 1.0,
                        total_contacts: total,
                        synced_contacts: total,
                        error: None,
                        last_sync: Some(chrono::Utc::now().to_rfc3339()),
                    });
                }
            }
            Err(e) => {
                self.set_status(SyncStatus {
                    state: "error".into(),
                    error: Some(format!("Fetch failed: {e}")),
                    ..Default::default()
                });
            }
        }
    }

    /// Unlock user + address keys. Returns the keys with the USER-key
    /// prefix length: contact sealing encrypts/signs with user keys
    /// (`keys[..user_end]`, WebClients import flow), while decryption tries
    /// everything.
    fn unlock_keys(
        &mut self,
        config: &SyncConfig,
    ) -> Result<(Vec<UnlockedKey>, usize), proton_api::ProtonError> {
        let access_token = match &self.access_token {
            Some(t) => t.clone(),
            None => {
                self.keys_debug = Some("no_access_token".into());
                return Ok((Vec::new(), 0));
            }
        };
        let uid = match &self.uid {
            Some(u) => u.clone(),
            None => {
                self.keys_debug = Some("no_uid".into());
                return Ok((Vec::new(), 0));
            }
        };

        let keys_client = match &config.api_base_url {
            Some(base) if !base.is_empty() => {
                KeysClient::new_with_base_url(base.clone(), access_token, uid)
            }
            _ => KeysClient::new(access_token, uid),
        };

        let user = match keys_client.get_user() {
            Ok(u) => u,
            Err(e) => {
                self.keys_debug = Some(format!("get_user_err={e}"));
                return Err(e);
            }
        };
        let salts = match keys_client.get_key_salts() {
            Ok(s) => (s, None),
            Err(e) => {
                // Best-effort (see calendar.rs): restored sessions lack the
                // elevated ("locked") scope for salts (403/9101). Derived +
                // Token paths proceed without them.
                let msg = format!("{e}");
                let short: String = msg.chars().take(80).collect();
                (Vec::new(), Some(format!("salts_unavailable:{short}")))
            }
        };
        let (salts, salts_note) = salts;
        let addresses = match keys_client.get_addresses() {
            Ok(a) => a,
            Err(e) => {
                self.keys_debug = Some(format!("get_addresses_err={e}"));
                return Err(e);
            }
        };

        let mut unlocked_keys: Vec<UnlockedKey> = Vec::new();
        let mut derived_map: std::collections::HashMap<String, String> =
            std::collections::HashMap::new();
        let mut debug_parts: Vec<String> = Vec::new();
        if let Some(note) = salts_note {
            debug_parts.push(note);
        }
        debug_parts.push(format!("user_keys={}", user.Keys.len()));
        debug_parts.push(format!("salts={}", salts.len()));
        debug_parts.push(format!("addrs={}", addresses.len()));
        debug_parts.push(format!("pw_len={}", config.password.len()));
        debug_parts.push(format!(
            "derived_keys={}",
            config
                .derived_passwords
                .as_ref()
                .map(|m| m.len())
                .unwrap_or(0)
        ));

        for key in &user.Keys {
            if key.PrivateKey.is_empty() {
                debug_parts.push(format!("userkey_{}_skip_empty", &key.ID[..8]));
                continue;
            }

            let salt = salts.iter().find(|s| s.ID == key.ID);
            let has_salt = salt.is_some();
            let salt_val = salt
                .and_then(|s| s.KeySalt.as_ref())
                .cloned()
                .unwrap_or_default();
            let salt_len = salt_val.len();

            let passphrase = Self::get_passphrase_for_key(
                &key.ID,
                &config.password,
                config.derived_passwords.as_ref(),
                salt,
                &key.Token,
            );

            match passphrase {
                Some(pp) => {
                    // Remember derived passphrase for storage (only if derived from raw password, not from stored derived)
                    let pp_for_store = if config.password.is_empty() {
                        None
                    } else {
                        Some(pp.clone())
                    };
                    match UnlockedKey::from_armored(&key.PrivateKey, &pp) {
                        Ok(unlocked) => {
                            debug_parts.push(format!("userkey_{}_ok", &key.ID[..8]));
                            if let Some(store_pp) = pp_for_store {
                                derived_map.insert(
                                    key.ID.clone(),
                                    base64::engine::general_purpose::STANDARD.encode(&store_pp),
                                );
                            }
                            unlocked_keys.push(unlocked);
                        }
                        Err(e) => {
                            debug_parts.push(format!(
                                "userkey_{}_unlock_err={}_pp_len={}",
                                &key.ID[..8],
                                e,
                                pp.len()
                            ));
                        }
                    }
                }
                None => {
                    debug_parts.push(format!(
                        "userkey_{}_no_passphase_has_salt={}_salt_len={}",
                        &key.ID[..8],
                        has_salt,
                        salt_len
                    ));
                }
            }
        }

        let user_end = unlocked_keys.len();
        for addr in &addresses {
            for key in &addr.Keys {
                if key.PrivateKey.is_empty() {
                    continue;
                }

                let salt = salts.iter().find(|s| s.ID == key.ID);
                let has_token = !key.Token.is_empty();

                // Token path first (go-proton-api Key::Unlock): Token is an
                // armored PGP message encrypted to a user key whose binary
                // content IS this address key's passphrase. Signature verify
                // is lenient-skipped (proton-cal behavior).
                if has_token && !unlocked_keys.is_empty() {
                    if let Some(secret) = Self::decrypt_token_secret(&key.Token, &mut unlocked_keys)
                    {
                        match UnlockedKey::from_armored(&key.PrivateKey, &secret) {
                            Ok(unlocked) => {
                                debug_parts.push(format!(
                                    "addrkey_{}_ok_via_token",
                                    &key.ID[..8.min(key.ID.len())]
                                ));
                                if !config.password.is_empty() {
                                    derived_map.insert(
                                        key.ID.clone(),
                                        base64::engine::general_purpose::STANDARD.encode(&secret),
                                    );
                                } else if config
                                    .derived_passwords
                                    .as_ref()
                                    .and_then(|m| m.get(&key.ID))
                                    .is_none()
                                {
                                    // Cache Token-derived secret even in derived-only
                                    // mode so future runs can use the fast path.
                                    derived_map.insert(
                                        key.ID.clone(),
                                        base64::engine::general_purpose::STANDARD.encode(&secret),
                                    );
                                }
                                unlocked_keys.push(unlocked);
                                continue;
                            }
                            Err(e) => {
                                debug_parts.push(format!(
                                    "addrkey_{}_token_unlock_err={}",
                                    &key.ID[..8.min(key.ID.len())],
                                    e
                                ));
                                // Fall through to salt path.
                            }
                        }
                    } else {
                        debug_parts.push(format!(
                            "addrkey_{}_token_decrypt_fail",
                            &key.ID[..8.min(key.ID.len())]
                        ));
                    }
                }

                let passphrase = Self::get_passphrase_for_key(
                    &key.ID,
                    &config.password,
                    config.derived_passwords.as_ref(),
                    salt,
                    &key.Token,
                );

                match passphrase {
                    Some(pp) => {
                        let pp_for_store = if config.password.is_empty() {
                            None
                        } else {
                            Some(pp.clone())
                        };
                        match UnlockedKey::from_armored(&key.PrivateKey, &pp) {
                            Ok(unlocked) => {
                                debug_parts.push(format!(
                                    "addrkey_{}_ok_token={}",
                                    &key.ID[..8],
                                    has_token
                                ));
                                if let Some(store_pp) = pp_for_store {
                                    derived_map.insert(
                                        key.ID.clone(),
                                        base64::engine::general_purpose::STANDARD.encode(&store_pp),
                                    );
                                }
                                unlocked_keys.push(unlocked);
                            }
                            Err(e) => {
                                debug_parts.push(format!(
                                    "addrkey_{}_unlock_err={}_token={}",
                                    &key.ID[..8],
                                    e,
                                    has_token
                                ));
                            }
                        }
                    }
                    None => {
                        debug_parts.push(format!(
                            "addrkey_{}_no_pp_token={}",
                            &key.ID[..8],
                            has_token
                        ));
                    }
                }
            }
        }

        debug_parts.push(format!("total_unlocked={}", unlocked_keys.len()));
        self.keys_debug = Some(debug_parts.join(";"));
        if !derived_map.is_empty() {
            *lock_or_recover(&self.derived_passwords) = Some(derived_map);
        }
        Ok((unlocked_keys, user_end))
    }

    /// Decrypt an address-key Token with any unlocked user key.
    /// Per go-proton-api `Key::getPassphraseFromToken`: Token is armored PGP
    /// to userKR; binary plaintext is the address key passphrase. Signature
    /// verification is intentionally lenient-skipped (proton-cal behavior).
    fn decrypt_token_secret(token_armored: &str, user_keys: &mut [UnlockedKey]) -> Option<Vec<u8>> {
        for uk in user_keys.iter_mut() {
            if let Ok(secret) = proton_api::crypto::decrypt_raw_with_key(token_armored, uk) {
                if !secret.is_empty() {
                    return Some(secret);
                }
            }
        }
        None
    }

    fn get_passphrase_for_key(
        key_id: &str,
        password: &str,
        derived: Option<&std::collections::HashMap<String, String>>,
        salt: Option<&proton_api::KeySalt>,
        token: &str,
    ) -> Option<Vec<u8>> {
        if let Some(map) = derived {
            if let Some(b64) = map.get(key_id) {
                if let Ok(bytes) = base64::engine::general_purpose::STANDARD.decode(b64) {
                    return Some(bytes);
                }
            }
        }
        Self::derive_passphrase(password, salt, token)
    }

    fn derive_passphrase(
        password: &str,
        salt: Option<&proton_api::KeySalt>,
        _token: &str,
    ) -> Option<Vec<u8>> {
        if password.is_empty() {
            return None;
        }
        let salt = salt?;
        let key_salt_str = salt.KeySalt.as_ref()?;

        if key_salt_str.is_empty() {
            return Some(password.as_bytes().to_vec());
        }

        match derive_mailbox_password(password.as_bytes(), key_salt_str) {
            Ok(pp) => Some(pp),
            Err(e) => {
                eprintln!("Failed to derive mailbox password: {e}");
                None
            }
        }
    }

    fn authenticate(&mut self, config: &SyncConfig) -> Result<(), proton_api::ProtonError> {
        let mut tm = lock_or_recover(&self.token_manager);

        let has_refresh = tm.refresh_token().is_some() && !tm.refresh_token().unwrap().is_empty();

        if has_refresh {
            match tm.access_token() {
                Ok(token) => {
                    let uid = tm.uid().unwrap_or(&config.username).to_string();
                    drop(tm);
                    self.access_token = Some(token.clone());
                    self.uid = Some(uid.clone());
                    self.contacts_client = Some(Self::contacts_client_for(config, token, uid));
                    return Ok(());
                }
                Err(_) => {
                    drop(tm);
                    tm = lock_or_recover(&self.token_manager);
                }
            }
        }

        if config.password.is_empty() {
            return Err(proton_api::ProtonError::Auth(
                "No refresh token and no password available".into(),
            ));
        }

        match tm.login(&config.username, &config.password, None)? {
            LoginState::Authenticated { .. } => {}
            LoginState::Requires2FA {
                access_token,
                refresh_token,
                uid,
                ..
            } => {
                if let Some(code) = &config.totp_code {
                    tm.submit_2fa(code, &access_token, &refresh_token, &uid, None)?;
                } else {
                    drop(tm);
                    self.set_status(SyncStatus {
                        state: "needs_2fa".into(),
                        error: Some("2FA verification required".into()),
                        ..Default::default()
                    });
                    return Err(proton_api::ProtonError::Auth("2FA_REQUIRED".into()));
                }
            }
        }

        let access_token = tm.access_token()?;
        let uid = tm.uid().unwrap_or(&config.username).to_string();
        drop(tm);

        self.access_token = Some(access_token.clone());
        self.uid = Some(uid.clone());
        self.contacts_client = Some(Self::contacts_client_for(config, access_token, uid));
        Ok(())
    }

    fn contacts_client_for(
        config: &SyncConfig,
        access_token: String,
        uid: String,
    ) -> ContactsClient {
        match &config.api_base_url {
            Some(base) if !base.is_empty() => {
                ContactsClient::new_with_base_url(base.clone(), access_token, uid)
            }
            _ => ContactsClient::new(access_token, uid),
        }
    }
}

/// One skipped upload for the user-visible deferred list: which local
/// change did not reach the server this cycle (the download overwrote
/// it). IDs and reason codes only — never field contents.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ContactDeferred {
    /// `create` (id = phone row) or `update` (id = Proton UID).
    pub kind: String,
    pub id: String,
    pub reason: String,
}

/// Outcome of the contacts upload phase: reconciled server rows plus
/// shim outputs (conflicts to notify, anchors to persist) plus a
/// single-line trace (`contact_upsync …` fragments) that `run_sync` folds
/// into `keys_debug` — the shim logs that to the file log on every run, so
/// upload decisions are diagnosable without the (volatile, root-only)
/// system journal. IDs only, never field contents.
/// `pending_creates` (`shim` persists it on error for stable retry UIDs).
#[derive(Debug)]
pub struct ContactUploadOutcome {
    pub contacts: Vec<proton_api::Contact>,
    pub conflicts: Vec<crate::contact_plan::ContactConflict>,
    pub anchors: std::collections::HashMap<String, i64>,
    pub trace: String,
    /// Posted-but-unconfirmed creates (qcontact_id → stable UID) for the
    /// shim to persist when the phase fails after posting (re-list
    /// failure). Empty on every successful return (re-list confirms).
    pub pending_creates: std::collections::HashMap<String, String>,
    /// Skipped uploads this cycle, for the user-visible deferred list.
    pub deferred_list: Vec<ContactDeferred>,
}

/// Pacing between upload requests (WebClients `API_SAFE_INTERVAL`:
/// 100 requests per 10 seconds). Sleeps only trigger on multi-op cycles;
/// single-edit syncs are unaffected.
const CONTACT_UPLOAD_PACING_MS: u64 = 100;

/// Fail-closed engine error for one upload batch kind.
fn contact_api_err(what: &str, e: impl std::fmt::Display) -> proton_api::ProtonError {
    proton_api::ProtonError::Api {
        code: 0,
        message: format!("contacts upsync {what} upload failed: {e}"),
    }
}

impl SyncEngine {
    /// Upsync upload phase for contacts (phase 1). Plans from the
    /// shim-fed inventory + listed rows + known-UID map, executes creates
    /// (chunked ≤10, the web-client batch limit), updates (rebuilt cards),
    /// deletes (single batch call), then re-lists when anything uploaded
    /// (fresh server truth incl. new IDs; fail-closed on error). Without a
    /// fed inventory the plan is empty and the input returns untouched.
    /// Unsealable rows defer (log + skip, never fail the phase).
    ///
    /// Delete safety (2026-09-09 incident: a phone edit that lost its Guid
    /// looked like create-new + delete-old, wiping the server contact):
    /// deletes are HELD whenever local identity is ambiguous — i.e. the
    /// inventory holds guid-less rows (never-synced/phone-created) or rows
    /// the server doesn't know (`apply_server_deletes`). The hold is always
    /// transient: the next download replacement drops stray rows and the
    /// persisted ID map refreshes, so a held delete either resolves (row
    /// was an edit — nothing lost) or fires next cycle (genuine delete).
    /// A held cycle still uploads creates/updates and still downloads, so
    /// sync keeps converging; the hold is recorded in the trace.
    fn run_contact_upload_phase(
        client: Option<&ContactsClient>,
        config: &SyncConfig,
        unlocked_keys: &mut [UnlockedKey],
        user_end: usize,
        contacts: Vec<proton_api::Contact>,
        pending_out: &mut std::collections::HashMap<String, String>,
    ) -> Result<ContactUploadOutcome, proton_api::ProtonError> {
        use crate::contact_plan as cp;
        // File-log trace fragments (IDs only, never contents) — folded into
        // `keys_debug` after the phase so upload decisions survive without
        // the journal.
        let mut trace: Vec<String> = Vec::new();
        let mut defer_reasons: Vec<String> = Vec::new();
        // Structured twin of the trace reasons above (IDs + reason codes
        // only, never contents) for the user-visible deferred list. The
        // trace strings stay byte-identical; this only adds fields.
        let mut deferred_list: Vec<ContactDeferred> = Vec::new();
        // Half-fed defense (2026-09-09 wipe): the shim always feeds inventory
        // AND known together, so inventory=None + known=Some(non-empty) can
        // only mean the inventory JSON failed to parse (e.g. a contract key
        // drift like `missing field photos`). Planning deletes from that
        // shape wiped a server contact. Drop known (never plan deletes
        // half-fed) and say so in the trace. Genuine "user deleted every
        // local contact" arrives as Some([]) — untouched by this branch —
        // and the pre-inventory constructor sends both as None (early return
        // below, byte-identical download-only).
        let mut known: std::collections::HashSet<String> =
            config.contact_known_uids.clone().unwrap_or_default();
        if config.contact_inventory.is_none() && !known.is_empty() {
            trace.push(format!(
                "contact_upsync half_fed known_dropped={} (inventory absent/unparsable — deletes disabled)",
                known.len()
            ));
            known.clear();
        }
        let inventory = config.contact_inventory.clone().unwrap_or_default();
        trace.push(format!(
            "contact_upsync inputs inv={} known={}",
            inventory.len(),
            known.len()
        ));
        // Avatar removals feed a bare-PHOTO rebuild (IDs only, never
        // contents) — the one upload decision invisible otherwise.
        for uid in cp::photo_delete_uids(&inventory) {
            trace.push(format!("contact_upsync photo_delete {uid}"));
        }
        let local_uids: std::collections::HashSet<String> = inventory
            .iter()
            .filter_map(|item| item.proton_uid.clone())
            .collect();
        let anchors = cp::merge_contact_anchors(
            config
                .contact_anchors
                .as_ref()
                .unwrap_or(&std::collections::HashMap::new()),
            &contacts,
            &local_uids,
        );
        if inventory.is_empty() && known.is_empty() {
            return Ok(ContactUploadOutcome {
                contacts,
                conflicts: Vec::new(),
                anchors,
                trace: trace.join("|"),
                pending_creates: std::collections::HashMap::new(),
                deferred_list: Vec::new(),
            });
        }
        let client = client
            .ok_or_else(|| proton_api::ProtonError::Auth("No contacts client for upload".into()))?;
        let plan = cp::plan_contacts(&contacts, &inventory, &known);
        // File-log trace: planned ops next (IDs only, never contents).
        trace.push(format!(
            "contact_upsync plan c={} u={} d={} server_deletes_locally={}",
            plan.uploads
                .iter()
                .filter(|op| matches!(op, cp::ContactUploadOp::Create { .. }))
                .count(),
            plan.uploads
                .iter()
                .filter(|op| matches!(op, cp::ContactUploadOp::Update { .. }))
                .count(),
            plan.uploads
                .iter()
                .filter(|op| matches!(op, cp::ContactUploadOp::Delete { .. }))
                .count(),
            plan.apply_server_deletes.len(),
        ));
        let items: std::collections::HashMap<&str, &cp::ContactItem> = inventory
            .iter()
            .map(|item| (item.qcontact_id.as_str(), item))
            .collect();
        let rows: std::collections::HashMap<&str, &proton_api::Contact> =
            contacts.iter().map(|c| (c.UID.as_str(), c)).collect();
        let user_len = user_end.min(unlocked_keys.len());
        let user_keys = &mut unlocked_keys[..user_len];
        let mut content_changed = false;
        let mut deferred = 0u32;
        // Creates first (chunked ≤10 per the web batch limit). Each job
        // seals under a STABLE uid: `pending_uid` carried from the previous
        // cycle when the last attempt posted but never confirmed (re-list
        // failure), else a fresh `proton-web-` UID. Stable UIDs make
        // retries idempotent: a retry either succeeds cleanly (the first
        // POST never landed) or hits the UID-conflict per-op error (it
        // did) and is ADOPTED below — never duplicated, never stuck.
        // `pending_out` collects posted-but-unconfirmed (qid → uid) jobs
        // for the shim to persist even when the phase later fails.
        let mut create_jobs: Vec<(String, String, proton_api::vcard::ParsedContact)> = Vec::new();
        for op in plan.uploads.iter().filter_map(|op| match op {
            cp::ContactUploadOp::Create { qcontact_id } => Some(qcontact_id),
            _ => None,
        }) {
            match items.get(op.as_str()).and_then(|item| item.fields.clone()) {
                Some(fields) => {
                    let uid = items
                        .get(op.as_str())
                        .and_then(|item| item.pending_uid.clone())
                        .filter(|u| !u.is_empty())
                        .unwrap_or_else(proton_api::generate_contact_uid);
                    create_jobs.push((op.clone(), uid, fields));
                }
                None => {
                    deferred += 1;
                    defer_reasons.push(format!("create:{op}:no-fields"));
                    deferred_list.push(ContactDeferred {
                        kind: "create".into(),
                        id: op.clone(),
                        reason: "no-fields".into(),
                    });
                    proton_api::vlog!("upsync_deferred contact create {op} no-fields");
                }
            }
        }
        let mut created = 0u32;
        let mut adopted = 0u32;
        // (qid, stable-uid, per-op code, per-op error) for non-1000 posts.
        let mut conflict_uids: Vec<(String, String, i32, String)> = Vec::new();
        let mut first_chunk = true;
        for chunk in create_jobs.chunks(10) {
            // Rate pacing (WebClients API_SAFE_INTERVAL: 100 req/10s).
            if !first_chunk {
                std::thread::sleep(std::time::Duration::from_millis(CONTACT_UPLOAD_PACING_MS));
            }
            first_chunk = false;
            let mut cards_batch = Vec::with_capacity(chunk.len());
            let mut sealed_meta: Vec<(String, String)> = Vec::with_capacity(chunk.len());
            for (qid, uid, fields) in chunk {
                match proton_api::contact_seal::build_contact_create_cards(fields, uid, user_keys) {
                    Ok(Some(cards)) => {
                        sealed_meta.push((qid.clone(), uid.clone()));
                        cards_batch.push(proton_api::CreateContactCards { Cards: cards })
                    }
                    Ok(None) => {
                        deferred += 1;
                        defer_reasons.push("create:unsealable".to_string());
                        deferred_list.push(ContactDeferred {
                            kind: "create".into(),
                            id: qid.clone(),
                            reason: "unsealable".into(),
                        });
                        proton_api::vlog!("upsync_deferred contact create unsealable");
                    }
                    Err(e) => {
                        deferred += 1;
                        defer_reasons.push(format!("create:seal-error:{e}"));
                        deferred_list.push(ContactDeferred {
                            kind: "create".into(),
                            id: qid.clone(),
                            reason: "seal-error".into(),
                        });
                        proton_api::vlog!("upsync_deferred contact create: {e}");
                    }
                }
            }
            if cards_batch.is_empty() {
                continue;
            }
            let resp = client
                .create(proton_api::CreateContactsRequest {
                    Contacts: cards_batch,
                    Overwrite: 0,
                    Labels: 0,
                })
                .map_err(|e| contact_api_err("create", e))?;
            // Partition per-op outcomes by Index (chunk order). Code 1000
            // posts confirm (pending re-list); anything else is a
            // UID-conflict candidate for adoption; a missing Index is a
            // protocol violation and fails closed like before.
            for (i, (qid, uid)) in sealed_meta.iter().enumerate() {
                match resp.Responses.iter().find(|r| r.Index == i as i32) {
                    Some(entry) if entry.Response.Code == 1000 => {
                        created += 1;
                        pending_out.insert(qid.clone(), uid.clone());
                    }
                    Some(entry) => {
                        conflict_uids.push((
                            qid.clone(),
                            uid.clone(),
                            entry.Response.Code,
                            entry.Response.Error.clone().unwrap_or_default(),
                        ));
                    }
                    None => {
                        return Err(proton_api::ProtonError::Api {
                            code: 0,
                            message: format!(
                                "contacts upsync create upload failed: \
                                 response missing Index {i}"
                            ),
                        });
                    }
                }
            }
            proton_api::vlog!("upsync_created contacts chunk n={}", sealed_meta.len());
        }
        // Conflict-adopt: a UID-conflict per-op error proves an earlier
        // POST landed (Overwrite=0 throws instead of overwriting). List and
        // adopt rows carrying those UIDs; anything still missing fails
        // closed (the old whole-batch error behavior).
        if !conflict_uids.is_empty() {
            let reconciled = client
                .list_all()
                .map_err(|e| contact_api_err("conflict-adopt-list", e))?;
            for (qid, uid, code, err) in &conflict_uids {
                if reconciled.iter().any(|c| &c.UID == uid) {
                    adopted += 1;
                    pending_out.remove(qid);
                    proton_api::vlog!("upsync_adopted contact {qid} uid-conflict");
                } else {
                    return Err(proton_api::ProtonError::Api {
                        code: 0,
                        message: format!(
                            "contacts upsync create upload failed: \
                             code {code} {err} (uid unresolvable, failing closed)"
                        ),
                    });
                }
            }
            content_changed = true;
        }
        if created > 0 {
            content_changed = true;
        }
        // Updates: rebuild from listed rows + phone snapshots.
        let mut updated = 0u32;
        for op in plan.uploads.iter().filter_map(|op| match op {
            cp::ContactUploadOp::Update { proton_uid } => Some(proton_uid),
            _ => None,
        }) {
            let (Some(row), Some(fields)) = (
                rows.get(op.as_str()),
                items
                    .values()
                    .find_map(|item| {
                        (item.proton_uid.as_deref() == Some(op.as_str()))
                            .then_some(item.fields.as_ref())
                    })
                    .flatten(),
            ) else {
                deferred += 1;
                defer_reasons.push(format!("update:{op}:no-row-or-fields"));
                deferred_list.push(ContactDeferred {
                    kind: "update".into(),
                    id: op.clone(),
                    reason: "no-row-or-fields".into(),
                });
                proton_api::vlog!("upsync_deferred contact update {op} no-row-or-fields");
                continue;
            };
            let cards = row.Cards.clone().unwrap_or_default();
            match proton_api::contact_seal::build_contact_update_cards(
                &cards, fields, &row.UID, user_keys,
            ) {
                Ok(Some(sealed)) => {
                    // Rate pacing (WebClients API_SAFE_INTERVAL: bulk edits
                    // must not trip the 100 req/10s limit).
                    if updated > 0 {
                        std::thread::sleep(std::time::Duration::from_millis(
                            CONTACT_UPLOAD_PACING_MS,
                        ));
                    }
                    client
                        .update(&row.ID, proton_api::UpdateContactRequest { Cards: sealed })
                        .map_err(|e| contact_api_err("update", e))?;
                    updated += 1;
                }
                Ok(None) => {
                    deferred += 1;
                    let why = proton_api::contact_seal::diagnose_update_block(&cards, user_keys);
                    defer_reasons.push(format!("update:{op}:{why}"));
                    deferred_list.push(ContactDeferred {
                        kind: "update".into(),
                        id: op.clone(),
                        reason: why.clone(),
                    });
                    proton_api::vlog!("upsync_deferred contact update {op} {why}");
                }
                Err(e) => {
                    deferred += 1;
                    defer_reasons.push(format!("update:{op}:seal-error:{e}"));
                    deferred_list.push(ContactDeferred {
                        kind: "update".into(),
                        id: op.clone(),
                        reason: "seal-error".into(),
                    });
                    proton_api::vlog!("upsync_deferred contact update {op}: {e}");
                }
            }
        }
        if updated > 0 {
            content_changed = true;
            proton_api::vlog!("upsync_updated contacts n={updated}");
        }
        // Deletes: single batch call (IDs resolved from the listing),
        // filtered locally afterwards (exact IDs known — no re-list).
        // HELD (not executed) while local identity is ambiguous: any
        // guid-less inventory row (phone-created, possibly an edit that lost
        // its Guid) or any row the server doesn't know (apply_server_deletes)
        // means a "missing known UID" may be an edit, not a delete — firing
        // would wipe the server contact (2026-09-09 incident). The hold is
        // transient (next download + map refresh resolves it either way).
        let delete_ids: Vec<String> = plan
            .uploads
            .iter()
            .filter_map(|op| match op {
                cp::ContactUploadOp::Delete { proton_uid } => {
                    rows.get(proton_uid.as_str()).map(|row| row.ID.clone())
                }
                _ => None,
            })
            .collect();
        let ambiguous_local_rows = !plan.apply_server_deletes.is_empty()
            || inventory.iter().any(|item| item.proton_uid.is_none());
        let mut contacts = contacts;
        let mut deleted = 0u32;
        if !delete_ids.is_empty() {
            if ambiguous_local_rows {
                trace.push("contact_upsync deletes_held ambiguous_local_rows".to_string());
                proton_api::vlog!("upsync_held contact deletes (ambiguous local rows)");
            } else {
                client
                    .delete(&delete_ids)
                    .map_err(|e| contact_api_err("delete", e))?;
                deleted = delete_ids.len() as u32;
                proton_api::vlog!("upsync_deleted contacts n={deleted}");
                let gone: std::collections::HashSet<String> = delete_ids.into_iter().collect();
                contacts.retain(|c| !gone.contains(&c.ID));
            }
        }
        if deferred > 0 {
            proton_api::vlog!("upsync_deferred contacts total={deferred}");
        }
        trace.push(format!(
            "contact_upsync ran created={created} updated={updated} deleted={deleted} deferred={deferred} adopted={adopted}"
        ));
        if !defer_reasons.is_empty() {
            trace.push(format!(
                "contact_upsync deferred_reasons {}",
                defer_reasons.join(",")
            ));
        }
        // Reconcile: re-list only when creates/updates landed (fresh truth
        // incl. new IDs; fail-closed on error). Deletes already filtered.
        // A successful re-list confirms every posted create, so the pending
        // map (retry UIDs for the shim) drains here; any re-list failure
        // keeps it for the next cycle via the Err path below.
        let contacts = if content_changed {
            let fresh = client
                .list_all()
                .map_err(|e| contact_api_err("re-list", e))?;
            pending_out.clear();
            fresh
        } else {
            contacts
        };
        let anchors = cp::merge_contact_anchors(
            config
                .contact_anchors
                .as_ref()
                .unwrap_or(&std::collections::HashMap::new()),
            &contacts,
            &local_uids,
        );
        Ok(ContactUploadOutcome {
            contacts,
            conflicts: plan.conflicts,
            anchors,
            trace: trace.join("|"),
            pending_creates: pending_out.clone(),
            deferred_list,
        })
    }

    fn fetch_contacts(&mut self) -> Result<Vec<proton_api::Contact>, proton_api::ProtonError> {
        let client = self
            .contacts_client
            .as_ref()
            .ok_or(proton_api::ProtonError::Auth("No client".into()))?;

        let contacts = client.list_all()?;

        let total = contacts.len() as u32;
        self.set_status(SyncStatus {
            state: "syncing".into(),
            progress: 0.5,
            total_contacts: total,
            synced_contacts: 0,
            error: None,
            last_sync: None,
        });

        Ok(contacts)
    }

    pub fn abort(&mut self) {
        *lock_or_recover(&self.abort_flag) = true;
        self.set_status(SyncStatus {
            state: "idle".into(),
            progress: 0.0,
            ..Default::default()
        });
    }

    pub fn status(&self) -> SyncStatus {
        lock_or_recover(&self.status).clone()
    }

    pub fn get_contacts_json(&self) -> String {
        lock_or_recover(&self.contacts_json)
            .clone()
            .unwrap_or_else(|| "[]".into())
    }

    pub fn get_refresh_token(&self) -> Option<String> {
        lock_or_recover(&self.token_manager)
            .refresh_token()
            .map(|s| s.to_string())
    }

    pub fn get_uid(&self) -> Option<String> {
        lock_or_recover(&self.token_manager)
            .uid()
            .map(|s| s.to_string())
    }

    pub fn get_derived_passwords_json(&self) -> Option<String> {
        let map = lock_or_recover(&self.derived_passwords).clone()?;
        serde_json::to_string(&map).ok()
    }

    pub fn get_decrypt_error_count(&self) -> u32 {
        *lock_or_recover(&self.decrypt_errors)
    }

    /// Server-wins contact conflicts this run (`[]` when none).
    pub fn get_contact_conflicts_json(&self) -> String {
        serde_json::to_string(&*lock_or_recover(&self.contact_conflicts)).unwrap_or_default()
    }

    /// Skipped uploads this run (`[]` when none — IDs and reason codes
    /// only, never field contents).
    pub fn get_contact_deferred_json(&self) -> String {
        serde_json::to_string(&*lock_or_recover(&self.contact_deferred)).unwrap_or_default()
    }

    /// Merged contact anchors (`{}` when nothing known — caller must not
    /// overwrite a good cache with it).
    pub fn get_contact_anchors_json(&self) -> String {
        let map = lock_or_recover(&self.contact_anchors);
        if map.is_empty() {
            return String::new();
        }
        serde_json::to_string(&*map).unwrap_or_default()
    }

    /// Posted-but-unconfirmed creates (`{qcontact_id: stable_uid}`) for
    /// the shim to persist (`contacts_pending`) and feed back as
    /// `pending_uid` next cycle. Empty (this getter returns `""`) when
    /// nothing is unconfirmed — the shim must overwrite its cache
    /// wholesale, never merge, so stale entries vanish.
    pub fn get_contact_pending_json(&self) -> String {
        let map = lock_or_recover(&self.contact_pending);
        if map.is_empty() {
            return String::new();
        }
        serde_json::to_string(&*map).unwrap_or_default()
    }

    pub fn get_keys_debug(&self) -> Option<String> {
        self.keys_debug.clone()
    }

    fn set_status(&self, status: SyncStatus) {
        *lock_or_recover(&self.status) = status;
    }

    /// Maps an `authenticate` failure to the status `run_sync` reports.
    /// A `needs_2fa` state set by `authenticate` (OTP code required) is
    /// preserved as-is so the sync plugin can notify distinctly; anything
    /// else collapses to a generic auth error.
    fn auth_error_status(current: &SyncStatus, err: &proton_api::ProtonError) -> SyncStatus {
        if current.state == "needs_2fa" {
            current.clone()
        } else {
            SyncStatus {
                state: "error".into(),
                error: Some(format!("Auth failed: {err}")),
                ..Default::default()
            }
        }
    }

    fn should_abort(&self) -> bool {
        *lock_or_recover(&self.abort_flag)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_auth_error_preserves_needs_2fa() {
        let current = SyncStatus {
            state: "needs_2fa".into(),
            error: Some("2FA verification required".into()),
            ..Default::default()
        };
        let err = proton_api::ProtonError::Auth("2FA_REQUIRED".into());
        assert_eq!(SyncEngine::auth_error_status(&current, &err), current);
    }

    #[test]
    fn test_auth_error_collapses_generic_failures() {
        let current = SyncStatus {
            state: "syncing".into(),
            ..Default::default()
        };
        let err = proton_api::ProtonError::Auth("bad password".into());
        let out = SyncEngine::auth_error_status(&current, &err);
        assert_eq!(out.state, "error");
        assert!(out.error.unwrap_or_default().contains("bad password"));
    }

    fn cycle_cfg(server_url: String) -> SyncConfig {
        SyncConfig {
            username: "u".into(),
            refresh_token: Some("rt".into()),
            uid: Some("uid".into()),
            access_token: Some("at".into()),
            api_base_url: Some(server_url),
            ..Default::default()
        }
    }

    fn mock_key_mocks(server: &mut mockito::Server, guards: &mut Vec<mockito::Mock>) {
        macro_rules! mock_get {
            ($re:expr, $code:expr, $body:expr) => {
                guards.push(
                    server
                        .mock("GET", mockito::Matcher::Regex($re.into()))
                        .with_status($code)
                        .with_header("content-type", "application/json")
                        .with_body($body)
                        .create(),
                );
            };
        }
        mock_get!(
            r"/core/v4/users.*",
            200,
            r#"{"User":{"ID":"u","Name":"t","Keys":[]}}"#
        );
        mock_get!(r"/core/v4/keys/salts.*", 200, r#"{"KeySalts":[]}"#);
        mock_get!(r"/core/v4/addresses.*", 200, r#"{"Addresses":[]}"#);
    }

    #[test]
    fn test_contact_delete_cycle_end_to_end_mock() {
        // Offline cycle (mockito): known UID missing locally but on server
        // → batch DELETE → re-list drops it → anchors pruned. No crypto
        // needed on this path (ID-only ops).
        let mut server = mockito::Server::new();
        let mut guards = Vec::new();
        mock_key_mocks(&mut server, &mut guards);
        // NOTE: no `$` anchor — mockito matches the regex against
        // path+query, and the list call carries ?Page=&PageSize=.
        // Created BEFORE the /c1 mock so the single-contact route (also
        // matching this pattern) wins by reverse-creation precedence.
        guards.push(
            server
                .mock("GET", mockito::Matcher::Regex(r"/contacts/v4".into()))
                .with_status(200)
                .with_header("content-type", "application/json")
                .with_body(
                    r#"{"Contacts":[{"ID":"c1","Name":"Gone","UID":"u1","ModifyTime":100}],"Total":1}"#,
                )
                .create(),
        );
        guards.push(
            server
                .mock("GET", mockito::Matcher::Regex(r"/contacts/v4/c1".into()))
                .with_status(200)
                .with_header("content-type", "application/json")
                .with_body(r#"{"Contact":{"ID":"c1","Name":"Gone","UID":"u1","ModifyTime":100}}"#)
                .create(),
        );
        let delete = server
            .mock(
                "PUT",
                mockito::Matcher::Regex(r"/contacts/v4/delete".into()),
            )
            .match_body(mockito::Matcher::JsonString(r#"{"IDs":["c1"]}"#.into()))
            .with_status(200)
            .with_body("{}")
            .create();

        let mut c = cycle_cfg(server.url());
        c.contact_known_uids = Some(["u1".to_string()].into_iter().collect());
        c.contact_inventory = Some(Vec::new());

        let mut engine = SyncEngine::new(c.clone());
        engine.start_sync(c);
        assert_eq!(engine.status().state, "complete");
        delete.assert();
        // Re-listed download lacks c1; anchors pruned (gone everywhere).
        assert_eq!(engine.get_contacts_json(), "[]");
        assert_eq!(engine.get_contact_anchors_json(), String::new());
        let _held = guards;
    }

    /// Fresh unlocked test user key, armored TSK (passwordless).
    fn armored_test_key() -> (String, String) {
        use sequoia_openpgp::{cert::CertBuilder, serialize::Serialize};
        let (cert, _) = CertBuilder::new()
            .add_signing_subkey()
            .add_transport_encryption_subkey()
            .generate()
            .expect("test key generation");
        let mut raw = Vec::new();
        cert.as_tsk()
            .armored()
            .export(&mut raw)
            .expect("test cert armor");
        let text = String::from_utf8(raw).unwrap();
        (text.replace('\n', "\\n"), text)
    }

    #[test]
    fn test_contact_create_update_cycle_mock() {
        // Creates seal fresh cards + updates rebuild server cards, all with
        // REAL generated keys through the password unlock path. PUT/POST
        // bodies carry randomized ciphertext — asserted by route + the
        // proton-api decrypt-back tests, not byte-exact here.
        let (user_esc, user_raw) = armored_test_key();
        let (addr_esc, _) = armored_test_key();
        let mut server = mockito::Server::new();
        let mut guards = Vec::new();
        macro_rules! mock_get {
            ($re:expr, $code:expr, $body:expr) => {
                guards.push(
                    server
                        .mock("GET", mockito::Matcher::Regex($re.into()))
                        .with_status($code)
                        .with_header("content-type", "application/json")
                        .with_body($body)
                        .create(),
                );
            };
        }
        mock_get!(
            r"/core/v4/users.*",
            200,
            format!(
                r#"{{"User":{{"ID":"u","Name":"t","Keys":[{{"ID":"k1abcdef01","PrivateKey":"{user_esc}","Token":"","Signature":""}}]}}}}"#
            )
        );
        mock_get!(
            r"/core/v4/keys/salts.*",
            200,
            r#"{"KeySalts":[{"ID":"k1abcdef01","KeySalt":""},{"ID":"ak1abcdef01","KeySalt":""}]}"#
        );
        mock_get!(
            r"/core/v4/addresses.*",
            200,
            format!(
                r#"{{"Addresses":[{{"ID":"a1","Email":"t@x","Keys":[{{"ID":"ak1abcdef01","PrivateKey":"{addr_esc}","Token":"","Signature":""}}]}}]}}"#
            )
        );
        mock_get!(r"/calendar/v1$", 200, r#"{"Code":1000,"Calendars":[]}"#);
        // Server row to update: signed uid/fn + sealed name card. Sealed
        // here with the same generated user key the engine will unlock.
        // Blobs are JSON-escaped (armored PGP contains raw newlines).
        let mut user_key = proton_api::UnlockedKey::from_armored(&user_raw, b"").unwrap();
        let (enc_data_raw, enc_sig_raw) = proton_api::contact_seal::seal_contact_card(
            "BEGIN:VCARD\r\nVERSION:4.0\r\nUID:u1\r\nN:Old;Name;;;\r\nEND:VCARD",
            std::slice::from_mut(&mut user_key),
        )
        .unwrap();
        let enc_data = enc_data_raw.replace('\n', "\\n");
        let enc_sig = enc_sig_raw.replace('\n', "\\n");
        let row_e1 = format!(
            r#"{{"ID":"c1","Name":"Old","UID":"u1","ModifyTime":100,
            "Cards":[{{"Type":2,"Data":"BEGIN:VCARD\r\nVERSION:4.0\r\nUID:u1\r\nFN:Old Name\r\nEND:VCARD","Signature":"s"}},
            {{"Type":3,"Data":"{enc_data}","Signature":"{enc_sig}"}}]}}"#,
        );
        guards.push(
            server
                .mock("GET", mockito::Matcher::Regex(r"/contacts/v4".into()))
                .with_status(200)
                .with_header("content-type", "application/json")
                .with_body(format!("{{\"Contacts\":[{row_e1}],\"Total\":1}}"))
                .create(),
        );
        guards.push(
            server
                .mock("GET", mockito::Matcher::Regex(r"/contacts/v4/c1".into()))
                .with_status(200)
                .with_header("content-type", "application/json")
                .with_body(format!("{{\"Contact\":{row_e1}}}"))
                .create(),
        );
        let post = server
            .mock(
                "POST",
                mockito::Matcher::Regex(r"/contacts/v4".into()),
            )
            // Wire shape guard: `Contacts` is objects-with-`Cards`
            // (`[{"Cards":…}]`), never bare arrays (`[[…]]`).
            .match_body(mockito::Matcher::Regex(
                r#""Contacts":\[\{"Cards":\["#.into(),
            ))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                r#"{"Responses": [{"Index": 0, "Response": {"Code": 1000, "Error": null, "Contact": {"ID": "new1", "Name": "Fresh", "UID": "newu"}}}]}"#,
            )
            .create();
        let put = server
            .mock("PUT", mockito::Matcher::Regex(r"/contacts/v4/c1".into()))
            .match_body(mockito::Matcher::Regex(r#""Cards":\["#.into()))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"Contact":{"ID":"c1","Name":"Edited","UID":"u1","ModifyTime":101}}"#)
            .create();

        let fields_upd = proton_api::vcard::ParsedContact {
            first_name: "Edited".into(),
            ..Default::default()
        };
        let fields_new = proton_api::vcard::ParsedContact {
            display_name: "Fresh".into(),
            ..Default::default()
        };
        let mut c = cycle_cfg(server.url());
        // Password + empty salts unlock the generated (unencrypted) keys
        // via the plain-password fallback, like production derived keys.
        c.password = "testpw".into();
        c.contact_inventory = Some(vec![
            crate::contact_plan::ContactItem {
                qcontact_id: "q1".into(),
                proton_uid: Some("u1".into()),
                modified: true,
                last_synced_mtime: Some(100),
                fields: Some(fields_upd),
                pending_uid: None,
            },
            crate::contact_plan::ContactItem {
                qcontact_id: "q2".into(),
                proton_uid: None,
                modified: true,
                last_synced_mtime: None,
                fields: Some(fields_new),
                pending_uid: None,
            },
        ]);
        let mut anchors = std::collections::HashMap::new();
        anchors.insert("u1".to_string(), 100);
        c.contact_anchors = Some(anchors);

        let mut engine = SyncEngine::new(c.clone());
        engine.start_sync(c);
        assert_eq!(engine.status().state, "complete");
        post.assert();
        put.assert();
        let _held = guards;
    }

    #[test]
    fn test_contact_delete_held_while_create_pending_mock() {
        // 2026-09-09 incident: a phone edit that lost its Guid plans a
        // guid-less CREATE plus a known-diff DELETE in one cycle. The delete
        // must NOT fire while the create is pending — even though the create
        // lands fine here, the pairing is ambiguous (edit vs delete+create).
        let (user_esc, _user_raw) = armored_test_key();
        let (addr_esc, _) = armored_test_key();
        let mut server = mockito::Server::new();
        let mut guards = Vec::new();
        macro_rules! mock_get {
            ($re:expr, $code:expr, $body:expr) => {
                guards.push(
                    server
                        .mock("GET", mockito::Matcher::Regex($re.into()))
                        .with_status($code)
                        .with_header("content-type", "application/json")
                        .with_body($body)
                        .create(),
                );
            };
        }
        mock_get!(
            r"/core/v4/users.*",
            200,
            format!(
                r#"{{"User":{{"ID":"u","Name":"t","Keys":[{{"ID":"k1abcdef01","PrivateKey":"{user_esc}","Token":"","Signature":""}}]}}}}"#
            )
        );
        mock_get!(
            r"/core/v4/keys/salts.*",
            200,
            r#"{"KeySalts":[{"ID":"k1abcdef01","KeySalt":""},{"ID":"ak1abcdef01","KeySalt":""}]}"#
        );
        mock_get!(
            r"/core/v4/addresses.*",
            200,
            format!(
                r#"{{"Addresses":[{{"ID":"a1","Email":"t@x","Keys":[{{"ID":"ak1abcdef01","PrivateKey":"{addr_esc}","Token":"","Signature":""}}]}}]}}"#
            )
        );
        // Pre-upload listing AND post-create re-list serve the same row:
        // the old server contact survives because its delete is held.
        guards.push(
            server
                .mock("GET", mockito::Matcher::Regex(r"/contacts/v4".into()))
                .with_status(200)
                .with_header("content-type", "application/json")
                .with_body(
                    r#"{"Contacts":[{"ID":"c1","Name":"Keep","UID":"u1","ModifyTime":100}],"Total":1}"#,
                )
                .create(),
        );
        let post = server
            .mock(
                "POST",
                mockito::Matcher::Regex(r"/contacts/v4".into()),
            )
            .match_body(mockito::Matcher::Regex(
                r#""Contacts":\[\{"Cards":\["#.into(),
            ))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                r#"{"Responses": [{"Index": 0, "Response": {"Code": 1000, "Error": null, "Contact": {"ID": "new1", "Name": "Fresh", "UID": "newu"}}}]}"#,
            )
            .create();
        // Any PUT to …/delete fails the test (expect-zero + assert).
        let delete = server
            .mock(
                "PUT",
                mockito::Matcher::Regex(r"/contacts/v4/delete".into()),
            )
            .expect(0)
            .with_status(200)
            .with_body("{}")
            .create();

        let mut c = cycle_cfg(server.url());
        c.password = "testpw".into();
        c.contact_inventory = Some(vec![crate::contact_plan::ContactItem {
            qcontact_id: "q2".into(),
            proton_uid: None,
            modified: true,
            last_synced_mtime: None,
            fields: Some(proton_api::vcard::ParsedContact {
                display_name: "Fresh".into(),
                ..Default::default()
            }),
            pending_uid: None,
        }]);
        c.contact_known_uids = Some(["u1".to_string()].into_iter().collect());

        let _detail = server
            .mock("GET", "/contacts/v4/c1")
            .with_body(r#"{"Contact":{"ID":"c1","Name":"Keep","UID":"u1","ModifyTime":100}}"#)
            .create();
        let mut engine = SyncEngine::new(c.clone());
        engine.start_sync(c);
        assert_eq!(engine.status().state, "complete");
        post.assert();
        delete.assert();
        // Old row retained in the reconciled download (delete held).
        assert!(engine.get_contacts_json().contains("\"uid\":\"u1\""));
        // File-log trace carries the plan and the hold (journal-independent).
        let dbg = engine.get_keys_debug().unwrap_or_default();
        assert!(dbg.contains("contact_upsync plan c=1 u=0 d=1"), "{dbg}");
        assert!(dbg.contains("deletes_held"), "{dbg}");
        let _held = guards;
    }

    #[test]
    fn test_contact_delete_held_for_unknown_guid_row_mock() {
        // Same hold, other shape: a clean row with a server-unknown guid
        // (identity replaced, not deleted) holds the known-diff delete.
        // No crypto needed on this path (ID-only ops + holds).
        let mut server = mockito::Server::new();
        let mut guards = Vec::new();
        mock_key_mocks(&mut server, &mut guards);
        guards.push(
            server
                .mock("GET", mockito::Matcher::Regex(r"/contacts/v4".into()))
                .with_status(200)
                .with_header("content-type", "application/json")
                .with_body(
                    r#"{"Contacts":[{"ID":"c1","Name":"Keep","UID":"u1","ModifyTime":100}],"Total":1}"#,
                )
                .create(),
        );
        let delete = server
            .mock(
                "PUT",
                mockito::Matcher::Regex(r"/contacts/v4/delete".into()),
            )
            .expect(0)
            .with_status(200)
            .with_body("{}")
            .create();

        let mut c = cycle_cfg(server.url());
        c.contact_known_uids = Some(["u1".to_string()].into_iter().collect());
        c.contact_inventory = Some(vec![crate::contact_plan::ContactItem {
            qcontact_id: "q9".into(),
            proton_uid: Some("g2-unknown".into()),
            modified: false,
            last_synced_mtime: None,
            fields: None,
            pending_uid: None,
        }]);

        let _detail = server
            .mock("GET", "/contacts/v4/c1")
            .with_body(r#"{"Contact":{"ID":"c1","Name":"Keep","UID":"u1","ModifyTime":100}}"#)
            .create();
        let mut engine = SyncEngine::new(c.clone());
        engine.start_sync(c);
        assert_eq!(engine.status().state, "complete");
        delete.assert();
        // Server row survives locally (download restores it; stray row drops).
        assert!(engine.get_contacts_json().contains("\"uid\":\"u1\""));
        let dbg = engine.get_keys_debug().unwrap_or_default();
        assert!(dbg.contains("server_deletes_locally=1"), "{dbg}");
        assert!(dbg.contains("deletes_held"), "{dbg}");
        let _held = guards;
    }

    #[test]
    fn test_contact_half_fed_inventory_drops_known_mock() {
        // 2026-09-09 wipe, second half of the fix: inventory=None (absent
        // or unparsable — e.g. the old `missing field photos` contract
        // drift) + known=Some must NEVER plan deletes. Genuine "user
        // deleted every local contact" arrives as Some([]) and still fires
        // (covered by the pure-delete cycle test).
        let mut server = mockito::Server::new();
        let mut guards = Vec::new();
        mock_key_mocks(&mut server, &mut guards);
        guards.push(
            server
                .mock("GET", mockito::Matcher::Regex(r"/contacts/v4".into()))
                .with_status(200)
                .with_header("content-type", "application/json")
                .with_body(
                    r#"{"Contacts":[{"ID":"c1","Name":"Keep","UID":"u1","ModifyTime":100}],"Total":1}"#,
                )
                .create(),
        );
        let delete = server
            .mock(
                "PUT",
                mockito::Matcher::Regex(r"/contacts/v4/delete".into()),
            )
            .expect(0)
            .with_status(200)
            .with_body("{}")
            .create();

        let mut c = cycle_cfg(server.url());
        c.contact_known_uids = Some(["u1".to_string()].into_iter().collect());
        c.contact_inventory = None;

        let _detail = server
            .mock("GET", "/contacts/v4/c1")
            .with_body(r#"{"Contact":{"ID":"c1","Name":"Keep","UID":"u1","ModifyTime":100}}"#)
            .create();
        let mut engine = SyncEngine::new(c.clone());
        engine.start_sync(c);
        assert_eq!(engine.status().state, "complete");
        delete.assert();
        assert!(engine.get_contacts_json().contains("\"uid\":\"u1\""));
        let dbg = engine.get_keys_debug().unwrap_or_default();
        assert!(dbg.contains("half_fed"), "{dbg}");
        assert!(dbg.contains("inputs inv=0 known=0"), "{dbg}");
        let _held = guards;
    }

    #[test]
    fn test_contact_grouped_email_update_uploads_mock() {
        // Live 2026-09-09: the re-created web contact carries grouped
        // `item1.EMAIL`, and the plain phone edit deferred (`unsealable`)
        // instead of uploading. With the group-aware guard the same shape
        // must PUT rebuilt cards (REAL generated keys, password unlock).
        let (user_esc, user_raw) = armored_test_key();
        let (addr_esc, _) = armored_test_key();
        let mut server = mockito::Server::new();
        let mut guards = Vec::new();
        macro_rules! mock_get {
            ($re:expr, $code:expr, $body:expr) => {
                guards.push(
                    server
                        .mock("GET", mockito::Matcher::Regex($re.into()))
                        .with_status($code)
                        .with_header("content-type", "application/json")
                        .with_body($body)
                        .create(),
                );
            };
        }
        mock_get!(
            r"/core/v4/users.*",
            200,
            format!(
                r#"{{"User":{{"ID":"u","Name":"t","Keys":[{{"ID":"k1abcdef01","PrivateKey":"{user_esc}","Token":"","Signature":""}}]}}}}"#
            )
        );
        mock_get!(
            r"/core/v4/keys/salts.*",
            200,
            r#"{"KeySalts":[{"ID":"k1abcdef01","KeySalt":""},{"ID":"ak1abcdef01","KeySalt":""}]}"#
        );
        mock_get!(
            r"/core/v4/addresses.*",
            200,
            format!(
                r#"{{"Addresses":[{{"ID":"a1","Email":"t@x","Keys":[{{"ID":"ak1abcdef01","PrivateKey":"{addr_esc}","Token":"","Signature":""}}]}}]}}"#
            )
        );
        let mut user_key = proton_api::UnlockedKey::from_armored(&user_raw, b"").unwrap();
        let (enc_data_raw, enc_sig_raw) = proton_api::contact_seal::seal_contact_card(
            "BEGIN:VCARD\r\nVERSION:4.0\r\nUID:u1\r\nN:Old;Name;;;\r\nEND:VCARD",
            std::slice::from_mut(&mut user_key),
        )
        .unwrap();
        let enc_data = enc_data_raw.replace('\n', "\\n");
        let enc_sig = enc_sig_raw.replace('\n', "\\n");
        // WebClients shape: grouped email in the signed card.
        let row_e1 = format!(
            r#"{{"ID":"c1","Name":"Old","UID":"u1","ModifyTime":100,
            "Cards":[{{"Type":2,"Data":"BEGIN:VCARD\r\nVERSION:4.0\r\nUID:u1\r\nFN:Old Name\r\nitem1.EMAIL:old@example.com\r\nEND:VCARD","Signature":"s"}},
            {{"Type":3,"Data":"{enc_data}","Signature":"{enc_sig}"}}]}}"#,
        );
        guards.push(
            server
                .mock("GET", mockito::Matcher::Regex(r"/contacts/v4".into()))
                .with_status(200)
                .with_header("content-type", "application/json")
                .with_body(format!("{{\"Contacts\":[{row_e1}],\"Total\":1}}"))
                .create(),
        );
        guards.push(
            server
                .mock("GET", mockito::Matcher::Regex(r"/contacts/v4/c1".into()))
                .with_status(200)
                .with_header("content-type", "application/json")
                .with_body(format!("{{\"Contact\":{row_e1}}}"))
                .create(),
        );
        let put = server
            .mock("PUT", mockito::Matcher::Regex(r"/contacts/v4/c1".into()))
            .match_body(mockito::Matcher::Regex(r#""Cards":\["#.into()))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"Contact":{"ID":"c1","Name":"Edited","UID":"u1","ModifyTime":101}}"#)
            .create();

        let mut c = cycle_cfg(server.url());
        c.password = "testpw".into();
        c.contact_inventory = Some(vec![crate::contact_plan::ContactItem {
            qcontact_id: "q1".into(),
            proton_uid: Some("u1".into()),
            modified: true,
            last_synced_mtime: Some(100),
            fields: Some(proton_api::vcard::ParsedContact {
                first_name: "Edited".into(),
                ..Default::default()
            }),
            pending_uid: None,
        }]);
        let mut anchors = std::collections::HashMap::new();
        anchors.insert("u1".to_string(), 100);
        c.contact_anchors = Some(anchors);

        let mut engine = SyncEngine::new(c.clone());
        engine.start_sync(c);
        assert_eq!(engine.status().state, "complete");
        put.assert();
        let dbg = engine.get_keys_debug().unwrap_or_default();
        assert!(
            dbg.contains("ran created=0 updated=1 deleted=0 deferred=0"),
            "{dbg}"
        );
        let _held = guards;
    }

    #[test]
    fn test_contact_labeled_update_uploads_mock() {
        // Labeled (Type-0) server cards no longer defer: the phone edit
        // seals with the carried cleartext part and the PUT fires with
        // REAL generated keys through the password unlock path.
        let (user_esc, user_raw) = armored_test_key();
        let (addr_esc, _) = armored_test_key();
        let mut server = mockito::Server::new();
        let mut guards = Vec::new();
        macro_rules! mock_get {
            ($re:expr, $code:expr, $body:expr) => {
                guards.push(
                    server
                        .mock("GET", mockito::Matcher::Regex($re.into()))
                        .with_status($code)
                        .with_header("content-type", "application/json")
                        .with_body($body)
                        .create(),
                );
            };
        }
        mock_get!(
            r"/core/v4/users.*",
            200,
            format!(
                r#"{{"User":{{"ID":"u","Name":"t","Keys":[{{"ID":"k1abcdef01","PrivateKey":"{user_esc}","Token":"","Signature":""}}]}}}}"#
            )
        );
        mock_get!(
            r"/core/v4/keys/salts.*",
            200,
            r#"{"KeySalts":[{"ID":"k1abcdef01","KeySalt":""},{"ID":"ak1abcdef01","KeySalt":""}]}"#
        );
        mock_get!(
            r"/core/v4/addresses.*",
            200,
            format!(
                r#"{{"Addresses":[{{"ID":"a1","Email":"t@x","Keys":[{{"ID":"ak1abcdef01","PrivateKey":"{addr_esc}","Token":"","Signature":""}}]}}]}}"#
            )
        );
        let mut user_key = proton_api::UnlockedKey::from_armored(&user_raw, b"").unwrap();
        let (enc_data_raw, enc_sig_raw) = proton_api::contact_seal::seal_contact_card(
            "BEGIN:VCARD\r\nVERSION:4.0\r\nUID:u1\r\nN:Old;Name;;;\r\nEND:VCARD",
            std::slice::from_mut(&mut user_key),
        )
        .unwrap();
        let enc_data = enc_data_raw.replace('\n', "\\n");
        let enc_sig = enc_sig_raw.replace('\n', "\\n");
        // Import shape: signed + sealed + cleartext labels.
        let row_e1 = format!(
            r#"{{"ID":"c1","Name":"Old","UID":"u1","ModifyTime":100,
            "Cards":[{{"Type":2,"Data":"BEGIN:VCARD\r\nVERSION:4.0\r\nUID:u1\r\nFN:Old Name\r\nEND:VCARD","Signature":"s"}},
            {{"Type":3,"Data":"{enc_data}","Signature":"{enc_sig}"}},
            {{"Type":0,"Data":"BEGIN:VCARD\r\nVERSION:4.0\r\nUID:u1\r\nFN:Old Name\r\nCATEGORIES:Friends\r\nEND:VCARD","Signature":null}}]}}"#,
        );
        guards.push(
            server
                .mock("GET", mockito::Matcher::Regex(r"/contacts/v4".into()))
                .with_status(200)
                .with_header("content-type", "application/json")
                .with_body(format!("{{\"Contacts\":[{row_e1}],\"Total\":1}}"))
                .create(),
        );
        guards.push(
            server
                .mock("GET", mockito::Matcher::Regex(r"/contacts/v4/c1".into()))
                .with_status(200)
                .with_header("content-type", "application/json")
                .with_body(format!("{{\"Contact\":{row_e1}}}"))
                .create(),
        );
        let put = server
            .mock("PUT", mockito::Matcher::Regex(r"/contacts/v4/c1".into()))
            .match_body(mockito::Matcher::Regex(r#""Cards":\["#.into()))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"Contact":{"ID":"c1","Name":"Edited","UID":"u1","ModifyTime":101}}"#)
            .create();

        let mut c = cycle_cfg(server.url());
        c.password = "testpw".into();
        c.contact_inventory = Some(vec![crate::contact_plan::ContactItem {
            qcontact_id: "q1".into(),
            proton_uid: Some("u1".into()),
            modified: true,
            last_synced_mtime: Some(100),
            fields: Some(proton_api::vcard::ParsedContact {
                first_name: "Edited".into(),
                ..Default::default()
            }),
            pending_uid: None,
        }]);
        let mut anchors = std::collections::HashMap::new();
        anchors.insert("u1".to_string(), 100);
        c.contact_anchors = Some(anchors);

        let mut engine = SyncEngine::new(c.clone());
        engine.start_sync(c);
        assert_eq!(engine.status().state, "complete");
        put.assert();
        let dbg = engine.get_keys_debug().unwrap_or_default();
        assert!(
            dbg.contains("ran created=0 updated=1 deleted=0 deferred=0"),
            "{dbg}"
        );
        let _held = guards;
    }

    #[test]
    fn test_contact_deferred_update_surfaces_structured_mock() {
        // Exotic server props still defer — but now visibly: the file-log
        // trace names the reason AND the structured getter carries it
        // (kind/id/reason, no contents) for the notification.
        let (user_esc, _user_raw) = armored_test_key();
        let (addr_esc, _) = armored_test_key();
        let mut server = mockito::Server::new();
        let mut guards = Vec::new();
        macro_rules! mock_get {
            ($re:expr, $code:expr, $body:expr) => {
                guards.push(
                    server
                        .mock("GET", mockito::Matcher::Regex($re.into()))
                        .with_status($code)
                        .with_header("content-type", "application/json")
                        .with_body($body)
                        .create(),
                );
            };
        }
        mock_get!(
            r"/core/v4/users.*",
            200,
            format!(
                r#"{{"User":{{"ID":"u","Name":"t","Keys":[{{"ID":"k1abcdef01","PrivateKey":"{user_esc}","Token":"","Signature":""}}]}}}}"#
            )
        );
        mock_get!(
            r"/core/v4/keys/salts.*",
            200,
            r#"{"KeySalts":[{"ID":"k1abcdef01","KeySalt":""},{"ID":"ak1abcdef01","KeySalt":""}]}"#
        );
        mock_get!(
            r"/core/v4/addresses.*",
            200,
            format!(
                r#"{{"Addresses":[{{"ID":"a1","Email":"t@x","Keys":[{{"ID":"ak1abcdef01","PrivateKey":"{addr_esc}","Token":"","Signature":""}}]}}]}}"#
            )
        );
        // Signed card with a genuinely exotic prop: no PUT shape exists.
        let row_e1 = r#"{"ID":"c1","Name":"Old","UID":"u1","ModifyTime":100,
            "Cards":[{"Type":2,"Data":"BEGIN:VCARD\r\nVERSION:4.0\r\nUID:u1\r\nFN:Old Name\r\nX-CUSTOM:1\r\nEND:VCARD","Signature":"s"}]}"#;
        guards.push(
            server
                .mock("GET", mockito::Matcher::Regex(r"/contacts/v4".into()))
                .with_status(200)
                .with_header("content-type", "application/json")
                .with_body(format!("{{\"Contacts\":[{row_e1}],\"Total\":1}}"))
                .create(),
        );
        guards.push(
            server
                .mock("GET", mockito::Matcher::Regex(r"/contacts/v4/c1".into()))
                .with_status(200)
                .with_header("content-type", "application/json")
                .with_body(format!("{{\"Contact\":{row_e1}}}"))
                .create(),
        );
        // Any PUT would be wrong (no sealable shape) — expect zero.
        let no_put = server
            .mock("PUT", mockito::Matcher::Regex(r"/contacts/v4".into()))
            .expect(0)
            .create();
        guards.push(no_put);

        let mut c = cycle_cfg(server.url());
        c.password = "testpw".into();
        c.contact_inventory = Some(vec![crate::contact_plan::ContactItem {
            qcontact_id: "q1".into(),
            proton_uid: Some("u1".into()),
            modified: true,
            last_synced_mtime: Some(100),
            fields: Some(proton_api::vcard::ParsedContact {
                first_name: "Edited".into(),
                ..Default::default()
            }),
            pending_uid: None,
        }]);
        let mut anchors = std::collections::HashMap::new();
        anchors.insert("u1".to_string(), 100);
        c.contact_anchors = Some(anchors);

        let mut engine = SyncEngine::new(c.clone());
        engine.start_sync(c);
        assert_eq!(engine.status().state, "complete");
        let dbg = engine.get_keys_debug().unwrap_or_default();
        assert!(
            dbg.contains("ran created=0 updated=0 deleted=0 deferred=1"),
            "{dbg}"
        );
        assert!(dbg.contains("unknown-props:X-CUSTOM"), "{dbg}");
        let deferred: Vec<ContactDeferred> =
            serde_json::from_str(&engine.get_contact_deferred_json()).expect("deferred parses");
        assert_eq!(deferred.len(), 1);
        assert_eq!(deferred[0].kind, "update");
        assert_eq!(deferred[0].id, "u1");
        assert!(deferred[0].reason.contains("X-CUSTOM"), "{deferred:?}");
        let _held = guards;
    }

    #[test]
    fn test_contact_keyed_update_uploads_mock() {
        // Per-email crypto settings no longer defer: the keyed server cards
        // seal (groups carried, regrouped) and the PUT fires with REAL
        // generated keys through the password unlock path.
        let (user_esc, user_raw) = armored_test_key();
        let (addr_esc, _) = armored_test_key();
        let mut server = mockito::Server::new();
        let mut guards = Vec::new();
        macro_rules! mock_get {
            ($re:expr, $code:expr, $body:expr) => {
                guards.push(
                    server
                        .mock("GET", mockito::Matcher::Regex($re.into()))
                        .with_status($code)
                        .with_header("content-type", "application/json")
                        .with_body($body)
                        .create(),
                );
            };
        }
        mock_get!(
            r"/core/v4/users.*",
            200,
            format!(
                r#"{{"User":{{"ID":"u","Name":"t","Keys":[{{"ID":"k1abcdef01","PrivateKey":"{user_esc}","Token":"","Signature":""}}]}}}}"#
            )
        );
        mock_get!(
            r"/core/v4/keys/salts.*",
            200,
            r#"{"KeySalts":[{"ID":"k1abcdef01","KeySalt":""},{"ID":"ak1abcdef01","KeySalt":""}]}"#
        );
        mock_get!(
            r"/core/v4/addresses.*",
            200,
            format!(
                r#"{{"Addresses":[{{"ID":"a1","Email":"t@x","Keys":[{{"ID":"ak1abcdef01","PrivateKey":"{addr_esc}","Token":"","Signature":""}}]}}]}}"#
            )
        );
        let mut user_key = proton_api::UnlockedKey::from_armored(&user_raw, b"").unwrap();
        let (enc_data_raw, enc_sig_raw) = proton_api::contact_seal::seal_contact_card(
            "BEGIN:VCARD\r\nVERSION:4.0\r\nUID:u1\r\nN:Old;Name;;;\r\nEND:VCARD",
            std::slice::from_mut(&mut user_key),
        )
        .unwrap();
        let enc_data = enc_data_raw.replace('\n', "\\n");
        let enc_sig = enc_sig_raw.replace('\n', "\\n");
        // WebClients per-address key groups on the signed card.
        let row_e1 = format!(
            r#"{{"ID":"c1","Name":"Old","UID":"u1","ModifyTime":100,
            "Cards":[{{"Type":2,"Data":"BEGIN:VCARD\r\nVERSION:4.0\r\nUID:u1\r\nFN:Old Name\r\nitem1.EMAIL:old@example.com\r\nitem1.KEY:data:;base64,QUJD\r\nitem1.X-PM-SCHEME:pgp-mime\r\nEND:VCARD","Signature":"s"}},
            {{"Type":3,"Data":"{enc_data}","Signature":"{enc_sig}"}}]}}"#,
        );
        guards.push(
            server
                .mock("GET", mockito::Matcher::Regex(r"/contacts/v4".into()))
                .with_status(200)
                .with_header("content-type", "application/json")
                .with_body(format!("{{\"Contacts\":[{row_e1}],\"Total\":1}}"))
                .create(),
        );
        guards.push(
            server
                .mock("GET", mockito::Matcher::Regex(r"/contacts/v4/c1".into()))
                .with_status(200)
                .with_header("content-type", "application/json")
                .with_body(format!("{{\"Contact\":{row_e1}}}"))
                .create(),
        );
        let put = server
            .mock("PUT", mockito::Matcher::Regex(r"/contacts/v4/c1".into()))
            .match_body(mockito::Matcher::Regex(r#""Cards":\["#.into()))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"Contact":{"ID":"c1","Name":"Edited","UID":"u1","ModifyTime":101}}"#)
            .create();

        let mut c = cycle_cfg(server.url());
        c.password = "testpw".into();
        c.contact_inventory = Some(vec![crate::contact_plan::ContactItem {
            qcontact_id: "q1".into(),
            proton_uid: Some("u1".into()),
            modified: true,
            last_synced_mtime: Some(100),
            fields: Some(proton_api::vcard::ParsedContact {
                first_name: "Edited".into(),
                emails: vec![proton_api::vcard::ParsedEmail {
                    email: "old@example.com".into(),
                    types: Vec::new(),
                }],
                ..Default::default()
            }),
            pending_uid: None,
        }]);
        let mut anchors = std::collections::HashMap::new();
        anchors.insert("u1".to_string(), 100);
        c.contact_anchors = Some(anchors);

        let mut engine = SyncEngine::new(c.clone());
        engine.start_sync(c);
        assert_eq!(engine.status().state, "complete");
        put.assert();
        let dbg = engine.get_keys_debug().unwrap_or_default();
        assert!(
            dbg.contains("ran created=0 updated=1 deleted=0 deferred=0"),
            "{dbg}"
        );
        let _held = guards;
    }

    #[test]
    fn test_contact_email_only_create_uploads_single_card_mock() {
        // `encrypt.ts` gate end-to-end: an email-only phone row seals to one
        // Type-2 card — the POST must carry `"Type":2` and never `"Type":3`
        // (an empty encrypted wrapper was never live-tested). REAL generated
        // keys through the password unlock path.
        let (user_esc, _user_raw) = armored_test_key();
        let (addr_esc, _) = armored_test_key();
        let mut server = mockito::Server::new();
        let mut guards = Vec::new();
        macro_rules! mock_get {
            ($re:expr, $code:expr, $body:expr) => {
                guards.push(
                    server
                        .mock("GET", mockito::Matcher::Regex($re.into()))
                        .with_status($code)
                        .with_header("content-type", "application/json")
                        .with_body($body)
                        .create(),
                );
            };
        }
        mock_get!(
            r"/core/v4/users.*",
            200,
            format!(
                r#"{{"User":{{"ID":"u","Name":"t","Keys":[{{"ID":"k1abcdef01","PrivateKey":"{user_esc}","Token":"","Signature":""}}]}}}}"#
            )
        );
        mock_get!(
            r"/core/v4/keys/salts.*",
            200,
            r#"{"KeySalts":[{"ID":"k1abcdef01","KeySalt":""},{"ID":"ak1abcdef01","KeySalt":""}]}"#
        );
        mock_get!(
            r"/core/v4/addresses.*",
            200,
            format!(
                r#"{{"Addresses":[{{"ID":"a1","Email":"t@x","Keys":[{{"ID":"ak1abcdef01","PrivateKey":"{addr_esc}","Token":"","Signature":""}}]}}]}}"#
            )
        );
        mock_get!(r"/contacts/v4", 200, r#"{"Contacts":[],"Total":0}"#);
        // Catch-all POST first…
        let post = server
            .mock(
                "POST",
                mockito::Matcher::Regex(r"/contacts/v4".into()),
            )
            .match_body(mockito::Matcher::Regex(
                r#""Contacts":\[\{"Cards":\["#.into(),
            ))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                r#"{"Responses": [{"Index": 0, "Response": {"Code": 1000, "Error": null, "Contact": {"ID": "new1", "Name": "Solo", "UID": "newu"}}}]}"#,
            )
            .create();
        // …then the Type-3 detector (reverse precedence: a Type-3 body
        // would land here and fail the expect-zero assert).
        let no_type3 = server
            .mock("POST", mockito::Matcher::Regex(r"/contacts/v4".into()))
            .match_body(mockito::Matcher::Regex(r#""Type":3"#.into()))
            .expect(0)
            .with_status(200)
            .with_body("{}")
            .create();

        let mut c = cycle_cfg(server.url());
        c.password = "testpw".into();
        c.contact_inventory = Some(vec![crate::contact_plan::ContactItem {
            qcontact_id: "q9".into(),
            proton_uid: None,
            modified: true,
            last_synced_mtime: None,
            fields: Some(proton_api::vcard::ParsedContact {
                display_name: "Solo".into(),
                emails: vec![proton_api::vcard::ParsedEmail {
                    email: "solo@example.com".into(),
                    types: Vec::new(),
                }],
                ..Default::default()
            }),
            pending_uid: None,
        }]);
        c.contact_known_uids = Some(std::collections::HashSet::new());

        let mut engine = SyncEngine::new(c.clone());
        engine.start_sync(c);
        assert_eq!(engine.status().state, "complete");
        post.assert();
        no_type3.assert();
        let dbg = engine.get_keys_debug().unwrap_or_default();
        assert!(
            dbg.contains("ran created=1 updated=0 deleted=0 deferred=0"),
            "{dbg}"
        );
        let _held = guards;
    }

    #[test]
    fn test_contact_create_chunks_at_ten_mock() {
        // WebClients `ADD_CONTACTS_MAX_SIZE = 10`: 11 phone-only rows must
        // go out as 2 POSTs (10 + 1), never one oversized batch. No crypto
        // content asserted here (randomized ciphertext) — route + count.
        let (user_esc, _user_raw) = armored_test_key();
        let (addr_esc, _) = armored_test_key();
        let mut server = mockito::Server::new();
        let mut guards = Vec::new();
        macro_rules! mock_get {
            ($re:expr, $code:expr, $body:expr) => {
                guards.push(
                    server
                        .mock("GET", mockito::Matcher::Regex($re.into()))
                        .with_status($code)
                        .with_header("content-type", "application/json")
                        .with_body($body)
                        .create(),
                );
            };
        }
        mock_get!(
            r"/core/v4/users.*",
            200,
            format!(
                r#"{{"User":{{"ID":"u","Name":"t","Keys":[{{"ID":"k1abcdef01","PrivateKey":"{user_esc}","Token":"","Signature":""}}]}}}}"#
            )
        );
        mock_get!(
            r"/core/v4/keys/salts.*",
            200,
            r#"{"KeySalts":[{"ID":"k1abcdef01","KeySalt":""},{"ID":"ak1abcdef01","KeySalt":""}]}"#
        );
        mock_get!(
            r"/core/v4/addresses.*",
            200,
            format!(
                r#"{{"Addresses":[{{"ID":"a1","Email":"t@x","Keys":[{{"ID":"ak1abcdef01","PrivateKey":"{addr_esc}","Token":"","Signature":""}}]}}]}}"#
            )
        );
        mock_get!(r"/contacts/v4", 200, r#"{"Contacts":[],"Total":0}"#);
        let posts = server
            .mock(
                "POST",
                mockito::Matcher::Regex(r"/contacts/v4".into()),
            )
            .match_body(mockito::Matcher::Regex(
                r#""Contacts":\[\{"Cards":\["#.into(),
            ))
            .expect(2)
            .with_status(200)
            .with_header("content-type", "application/json")
            // One response entry per submitted contact (the real wire
            // shape): 10 entries serve the 10-job chunk by Index, and the
            // 1-job chunk reads Index 0 (extras ignored).
            .with_body(
                r#"{"Responses": [{"Index": 0, "Response": {"Code": 1000, "Error": null, "Contact": {"ID": "new1", "Name": "Bulk", "UID": "newu"}}},{"Index": 1, "Response": {"Code": 1000, "Error": null}},{"Index": 2, "Response": {"Code": 1000, "Error": null}},{"Index": 3, "Response": {"Code": 1000, "Error": null}},{"Index": 4, "Response": {"Code": 1000, "Error": null}},{"Index": 5, "Response": {"Code": 1000, "Error": null}},{"Index": 6, "Response": {"Code": 1000, "Error": null}},{"Index": 7, "Response": {"Code": 1000, "Error": null}},{"Index": 8, "Response": {"Code": 1000, "Error": null}},{"Index": 9, "Response": {"Code": 1000, "Error": null}}]}"#,
            )
            .create();

        let rows: Vec<crate::contact_plan::ContactItem> = (0..11)
            .map(|i| crate::contact_plan::ContactItem {
                qcontact_id: format!("qb{i}"),
                proton_uid: None,
                modified: true,
                last_synced_mtime: None,
                fields: Some(proton_api::vcard::ParsedContact {
                    display_name: format!("Bulk {i}"),
                    phones: vec![proton_api::vcard::ParsedPhone {
                        number: "+3902000000".into(),
                        types: Vec::new(),
                    }],
                    ..Default::default()
                }),
                pending_uid: None,
            })
            .collect();
        let mut c = cycle_cfg(server.url());
        c.password = "testpw".into();
        c.contact_inventory = Some(rows);
        c.contact_known_uids = Some(std::collections::HashSet::new());

        let mut engine = SyncEngine::new(c.clone());
        engine.start_sync(c);
        assert_eq!(engine.status().state, "complete");
        posts.assert();
        let _held = guards;
    }

    // Direct phase driver (no auth): the upload phase takes unlocked keys
    // + listed rows, so failure-path tests (POST-ok + re-list-fail) don't
    // need mock sequencing — each phase gets a fresh mock server.
    fn run_phase(
        server_url: String,
        key_raw: &str,
        inventory: Vec<crate::contact_plan::ContactItem>,
        listed: Vec<proton_api::Contact>,
        pending: &mut std::collections::HashMap<String, String>,
    ) -> Result<ContactUploadOutcome, proton_api::ProtonError> {
        let client =
            proton_api::ContactsClient::new_with_base_url(server_url, "at".into(), "uid".into());
        let key = proton_api::UnlockedKey::from_armored(key_raw, b"").expect("test key unlocks");
        let mut keys = vec![key];
        let config = SyncConfig {
            username: "u".into(),
            contact_inventory: Some(inventory),
            contact_known_uids: Some(std::collections::HashSet::new()),
            contact_anchors: Some(std::collections::HashMap::new()),
            ..Default::default()
        };
        SyncEngine::run_contact_upload_phase(Some(&client), &config, &mut keys, 1, listed, pending)
    }

    fn retry_fields() -> proton_api::vcard::ParsedContact {
        proton_api::vcard::ParsedContact {
            display_name: "Retry".into(),
            phones: vec![proton_api::vcard::ParsedPhone {
                number: "+3902000000".into(),
                types: Vec::new(),
            }],
            ..Default::default()
        }
    }

    fn retry_item(pending_uid: Option<&str>) -> crate::contact_plan::ContactItem {
        crate::contact_plan::ContactItem {
            qcontact_id: "q1".into(),
            proton_uid: None,
            modified: true,
            last_synced_mtime: None,
            fields: Some(retry_fields()),
            pending_uid: pending_uid.map(str::to_string),
        }
    }

    #[test]
    fn test_contact_create_retry_reuses_stable_uid_mock() {
        // POST lands but re-list fails → Err + pending {q1: U}. Next cycle
        // feeds pending_uid=U → the re-POST seals the SAME uid (asserted on
        // the plaintext signed card) instead of minting a fresh one, so a
        // retry can never duplicate.
        let (_, key_raw) = armored_test_key();
        let mut server1 = mockito::Server::new();
        server1
            .mock("POST", mockito::Matcher::Regex(r"/contacts/v4".into()))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                r#"{"Responses": [{"Index": 0, "Response": {"Code": 1000, "Error": null, "Contact": {"ID": "c1", "Name": "Retry", "UID": "echo-ignored"}}}]}"#,
            )
            .create();
        server1
            .mock("GET", mockito::Matcher::Regex(r"/contacts/v4".into()))
            .with_status(500)
            .with_body("{}")
            .create();

        let mut pending = std::collections::HashMap::new();
        let err = run_phase(
            server1.url(),
            &key_raw,
            vec![retry_item(None)],
            vec![],
            &mut pending,
        )
        .expect_err("re-list must fail");
        assert!(format!("{err}").contains("re-list"), "{err}");
        assert_eq!(pending.len(), 1);
        let uid = pending["q1"].clone();
        assert!(uid.starts_with("proton-web-"), "{uid}");

        // Cycle 2 (fresh server = fresh mocks): the POST must carry U.
        // (`UID:…` is plaintext in the signed Type-2 card.)
        let mut server2 = mockito::Server::new();
        let post2 = server2
            .mock("POST", mockito::Matcher::Regex(r"/contacts/v4".into()))
            .match_body(mockito::Matcher::Regex(format!("UID:{uid}")))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(format!(
                "{{\"Responses\": [{{\"Index\": 0, \"Response\": {{\"Code\": 1000, \"Error\": null, \"Contact\": {{\"ID\": \"c1\", \"Name\": \"Retry\", \"UID\": \"{uid}\"}}}}}}]}}"
            ))
            .create();
        server2
            .mock("GET", mockito::Matcher::Regex(r"/contacts/v4".into()))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(format!(
                "{{\"Contacts\":[{{\"ID\":\"c1\",\"Name\":\"Retry\",\"UID\":\"{uid}\",\"ModifyTime\":101}}],\"Total\":1}}"
            ))
            .create();
        server2
            .mock("GET", mockito::Matcher::Regex(r"/contacts/v4/c1".into()))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(format!(
                "{{\"Contact\":{{\"ID\":\"c1\",\"Name\":\"Retry\",\"UID\":\"{uid}\",\"ModifyTime\":101}}}}"
            ))
            .create();
        let mut pending2 = std::collections::HashMap::new();
        let outcome = run_phase(
            server2.url(),
            &key_raw,
            vec![retry_item(Some(&uid))],
            vec![],
            &mut pending2,
        )
        .expect("retry completes");
        post2.assert(); // same UID re-POSTed, not a fresh one
        assert!(pending2.is_empty(), "re-list confirms: nothing pending");
        assert_eq!(outcome.anchors.get(&uid), Some(&101));
    }

    #[test]
    fn test_contact_create_conflict_adopts_server_row_mock() {
        // Overwrite=0 throws on UID conflict instead of overwriting: the
        // per-op error proves an earlier POST landed, so adopting the
        // listed row converges (no duplicate, no stuck error).
        let mut server = mockito::Server::new();
        server
            .mock("POST", mockito::Matcher::Regex(r"/contacts/v4".into()))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                r#"{"Responses": [{"Index": 0, "Response": {"Code": 2200, "Error": "UID conflict"}}]}"#,
            )
            .create();
        server
            .mock("GET", mockito::Matcher::Regex(r"/contacts/v4".into()))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                r#"{"Contacts":[{"ID":"c9","Name":"Retry","UID":"u-adopt-1","ModifyTime":77}],"Total":1}"#,
            )
            .create();
        server
            .mock("GET", mockito::Matcher::Regex(r"/contacts/v4/c9".into()))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                r#"{"Contact":{"ID":"c9","Name":"Retry","UID":"u-adopt-1","ModifyTime":77}}"#,
            )
            .create();
        let (_, key_raw) = armored_test_key();
        let mut pending = std::collections::HashMap::new();
        let outcome = run_phase(
            server.url(),
            &key_raw,
            vec![retry_item(Some("u-adopt-1"))],
            vec![],
            &mut pending,
        )
        .expect("conflict adopts");
        assert!(outcome.trace.contains("adopted=1"), "{}", outcome.trace);
        assert!(pending.is_empty());
        assert_eq!(outcome.anchors.get("u-adopt-1"), Some(&77));
    }

    #[test]
    fn test_contact_create_conflict_unresolvable_fails_closed_mock() {
        // Conflict error but the UID is nowhere server-side: fail closed
        // (the old whole-batch error), never silently swallow.
        let mut server = mockito::Server::new();
        server
            .mock("POST", mockito::Matcher::Regex(r"/contacts/v4".into()))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                r#"{"Responses": [{"Index": 0, "Response": {"Code": 2200, "Error": "UID conflict"}}]}"#,
            )
            .create();
        server
            .mock("GET", mockito::Matcher::Regex(r"/contacts/v4".into()))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"Contacts":[],"Total":0}"#)
            .create();
        let (_, key_raw) = armored_test_key();
        let mut pending = std::collections::HashMap::new();
        let err = run_phase(
            server.url(),
            &key_raw,
            vec![retry_item(Some("u-ghost-1"))],
            vec![],
            &mut pending,
        )
        .expect_err("unresolvable conflict must fail");
        assert!(format!("{err}").contains("unresolvable"), "{err}");
    }

    #[test]
    fn test_contact_pending_getter_defaults_empty() {
        let engine = SyncEngine::new(SyncConfig {
            username: "u".into(),
            ..Default::default()
        });
        assert_eq!(engine.get_contact_pending_json(), String::new());
    }
}
