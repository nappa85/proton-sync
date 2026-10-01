use crate::client::{build_client, API_BASE, APP_VERSION};
use crate::{models::*, ProtonError, Result};
use serde::Serialize;
use std::time::Duration;

pub struct ContactsClient {
    client: reqwest::blocking::Client,
    base_url: String,
    access_token: String,
    uid: String,
    pacer: crate::client::RequestPacer,
}

impl ContactsClient {
    pub fn new(access_token: String, uid: String) -> Self {
        Self {
            client: build_client(Duration::from_secs(60)),
            base_url: API_BASE.to_string(),
            access_token,
            uid,
            pacer: Default::default(),
        }
    }

    pub fn new_with_base_url(base_url: String, access_token: String, uid: String) -> Self {
        Self {
            client: build_client(Duration::from_secs(60)),
            base_url,
            access_token,
            uid,
            pacer: Default::default(),
        }
    }

    fn auth_header(&self) -> String {
        format!("Bearer {}", self.access_token)
    }

    /// Like `error_for_status`, but keeps the (truncated) response body in
    /// the error: Proton rejects bad card content with HTTP 4xx + a
    /// `{Code, Error}` JSON body (calendar 2001/2011 lesson), and dropping
    /// it leaves live rejections undiagnosable. Bodies are server-generated
    /// codes/messages, never card plaintext.
    fn check_response(
        resp: reqwest::blocking::Response,
        what: &str,
    ) -> Result<reqwest::blocking::Response> {
        let status = resp.status();
        if status.is_success() {
            return Ok(resp);
        }
        let body = resp.text().unwrap_or_default();
        let short: String = body.chars().take(1000).collect();
        Err(ProtonError::Api {
            code: 0,
            message: format!("contacts {what} failed {status}: {short}"),
        })
    }

    /// List contacts with pagination
    pub fn list(&self, page: u32, page_size: u32) -> Result<ContactsListResponse> {
        self.pacer.wait();
        let resp = self
            .client
            .get(format!("{}/contacts/v4", self.base_url))
            .header("Authorization", self.auth_header())
            .header("x-pm-uid", &self.uid)
            .header("x-pm-appversion", APP_VERSION)
            .query(&[
                ("Page", page.to_string()),
                ("PageSize", page_size.to_string()),
            ])
            .send()?
            .error_for_status()?;
        let text = resp.text()?;
        let parsed: ContactsListResponse = serde_json::from_str(&text)?;
        Ok(parsed)
    }

    /// Complete ID/metadata inventory plus paged encrypted-card export.
    /// Export duplicates (one row per email) are deduped by contact ID.
    pub fn list_all(&self) -> Result<Vec<Contact>> {
        let mut summaries = Vec::new();
        let mut ids = std::collections::HashSet::new();
        let page_size = 100;
        let mut page = 0;
        let mut expected_total = None;

        loop {
            let resp = self.list(page, page_size)?;
            let total = usize::try_from(resp.Total).map_err(|_| ProtonError::Api {
                code: 0,
                message: "Invalid contact total".into(),
            })?;
            if expected_total
                .replace(total)
                .is_some_and(|old| old != total)
            {
                return Err(ProtonError::Api {
                    code: 0,
                    message: "Contact listing changed during download; retry later".into(),
                });
            }
            let contacts_len = resp.Contacts.len();
            for contact in &resp.Contacts {
                if contact.ID.is_empty() || !ids.insert(contact.ID.clone()) {
                    return Err(ProtonError::Api {
                        code: 0,
                        message: "Invalid or repeated contact ID in listing".into(),
                    });
                }
            }
            summaries.extend(resp.Contacts);

            if summaries.len() >= total {
                if summaries.len() != total {
                    return Err(ProtonError::Api {
                        code: 0,
                        message: "Contact listing exceeds reported total".into(),
                    });
                }
                break;
            }
            if contacts_len == 0 {
                return Err(ProtonError::Api {
                    code: 0,
                    message: "Contact listing ended before the reported total".into(),
                });
            }
            page += 1;
        }

        if summaries.is_empty() {
            return Ok(Vec::new());
        }
        let mut exported = std::collections::HashMap::<String, Contact>::new();
        let mut stagnant_pages = 0;
        for page in 0..1000 {
            self.pacer.wait();
            let response = self
                .client
                .get(format!("{}/contacts/v4/contacts/export", self.base_url))
                .header("Authorization", self.auth_header())
                .header("x-pm-uid", &self.uid)
                .header("x-pm-appversion", APP_VERSION)
                .query(&[("Page", page), ("PageSize", 50)])
                .send()?;
            // Only an explicitly unavailable route permits the older,
            // paced single-contact fallback. Never retry 429/5xx failures
            // as hundreds of individual requests.
            if page == 0 && matches!(response.status().as_u16(), 404 | 501) {
                return summaries
                    .iter()
                    .map(|summary| self.get(&summary.ID))
                    .collect();
            }
            let value: serde_json::Value = Self::check_response(response, "export")?.json()?;
            if value
                .get("Code")
                .and_then(|c| c.as_i64())
                .is_some_and(|c| c != 1000)
            {
                return Err(ProtonError::Api {
                    code: 0,
                    message: "Contact export rejected".into(),
                });
            }
            let rows = value
                .get("Contacts")
                .and_then(|c| c.as_array())
                .ok_or_else(|| ProtonError::Api {
                    code: 0,
                    message: "Contact export is missing its Contacts array".into(),
                })?;
            let before = exported.len();
            for row in rows {
                let contact: Contact = serde_json::from_value(row.clone())?;
                if !ids.contains(&contact.ID) {
                    return Err(ProtonError::Api {
                        code: 0,
                        message: "Contact export differs from ID inventory; retry later".into(),
                    });
                }
                if let Some(previous) = exported.get(&contact.ID) {
                    if serde_json::to_value(&previous.Cards)?
                        != serde_json::to_value(&contact.Cards)?
                    {
                        return Err(ProtonError::Api {
                            code: 0,
                            message: "Conflicting duplicate contact export rows".into(),
                        });
                    }
                } else {
                    exported.insert(contact.ID.clone(), contact);
                }
            }
            if exported.len() == ids.len() {
                // Some servers omit cards for a small subset. Targeted detail
                // reads are bounded; a summary-only bulk response cannot
                // quietly degrade back into a full per-contact download.
                let missing_cards = exported.values().filter(|c| c.Cards.is_none()).count();
                if missing_cards > 10 {
                    return Err(ProtonError::Api {
                        code: 0,
                        message: "Bulk contact export omitted encrypted cards".into(),
                    });
                }
                let mut contacts = Vec::with_capacity(summaries.len());
                for mut summary in summaries {
                    let mut full = exported.remove(&summary.ID).expect("complete ID set");
                    if full.Cards.is_none() {
                        full = self.get(&summary.ID)?;
                    }
                    if full.ID != summary.ID {
                        return Err(ProtonError::Api {
                            code: 0,
                            message: "Contact detail ID mismatch".into(),
                        });
                    }
                    // Export need not carry metadata. Keep the listing's
                    // UID and modification anchors for upload planning.
                    summary.Cards = full.Cards;
                    if !full.UID.is_empty() {
                        summary.UID = full.UID;
                    }
                    if full.ModifyTime > 0 {
                        summary.ModifyTime = full.ModifyTime;
                    }
                    contacts.push(summary);
                }
                return Ok(contacts);
            }
            if rows.len() < 50 {
                return Err(ProtonError::Api {
                    code: 0,
                    message: "Contact export ended before all listed IDs were downloaded".into(),
                });
            }
            stagnant_pages = if exported.len() == before {
                stagnant_pages + 1
            } else {
                0
            };
            if stagnant_pages >= 3 {
                return Err(ProtonError::Api {
                    code: 0,
                    message: "Contact export pagination made no progress".into(),
                });
            }
        }
        Err(ProtonError::Api {
            code: 0,
            message: "Contact export pagination limit exceeded".into(),
        })
    }

    /// Get single contact by ID
    pub fn get(&self, contact_id: &str) -> Result<Contact> {
        self.pacer.wait();
        let resp = self
            .client
            .get(format!("{}/contacts/v4/{}", self.base_url, contact_id))
            .header("Authorization", self.auth_header())
            .header("x-pm-uid", &self.uid)
            .header("x-pm-appversion", APP_VERSION)
            .send()?
            .error_for_status()?;
        let text = resp.text()?;
        let parsed: serde_json::Value = serde_json::from_str(&text)?;
        let contact: Contact =
            serde_json::from_value(parsed["Contact"].clone()).map_err(ProtonError::Serde)?;
        if contact.ID != contact_id {
            return Err(ProtonError::Api {
                code: 0,
                message: "Contact detail ID mismatch".into(),
            });
        }
        Ok(contact)
    }

    /// Count contacts
    pub fn count(&self) -> Result<u32> {
        let resp = self
            .client
            .get(format!("{}/contacts/v4", self.base_url))
            .header("Authorization", self.auth_header())
            .header("x-pm-uid", &self.uid)
            .header("x-pm-appversion", APP_VERSION)
            .query(&[("Count", "1")])
            .send()?
            .error_for_status()?
            .json::<serde_json::Value>()?;

        Ok(resp["Total"].as_u64().unwrap_or(0) as u32)
    }

    /// Create contacts (batch)
    pub fn create(&self, req: CreateContactsRequest) -> Result<CreateContactsResponse> {
        self.pacer.wait();
        let resp = Self::check_response(
            self.client
                .post(format!("{}/contacts/v4", self.base_url))
                .header("Authorization", self.auth_header())
                .header("x-pm-uid", &self.uid)
                .header("x-pm-appversion", APP_VERSION)
                .json(&req)
                .send()?,
            "create",
        )?
        .json()?;
        Ok(resp)
    }

    /// Update contact
    pub fn update(&self, contact_id: &str, req: UpdateContactRequest) -> Result<Contact> {
        self.pacer.wait();
        let resp = Self::check_response(
            self.client
                .put(format!("{}/contacts/v4/{}", self.base_url, contact_id))
                .header("Authorization", self.auth_header())
                .header("x-pm-uid", &self.uid)
                .header("x-pm-appversion", APP_VERSION)
                .json(&req)
                .send()?,
            "update",
        )?
        .json::<serde_json::Value>()?;

        serde_json::from_value(resp["Contact"].clone()).map_err(ProtonError::Serde)
    }

    /// Delete contacts (batch). go-proton-api + WebClients `deleteContacts`
    /// both use `PUT …/delete` with `{IDs}` (never HTTP DELETE — the old
    /// `DELETE /contacts/v4` shape matched neither reference and would fail
    /// live). The top-level `Code` is checked leniently (fail only when the
    /// server explicitly reports one outside 1000/1001 — a bare `{}` stays
    /// success, matching go-proton-api's transport-only handling).
    pub fn delete(&self, ids: &[String]) -> Result<()> {
        self.pacer.wait();
        #[allow(non_snake_case)]
        #[derive(Serialize)]
        struct DeleteReq {
            IDs: Vec<String>,
        }

        let body = Self::check_response(
            self.client
                .put(format!("{}/contacts/v4/delete", self.base_url))
                .header("Authorization", self.auth_header())
                .header("x-pm-uid", &self.uid)
                .header("x-pm-appversion", APP_VERSION)
                .json(&DeleteReq { IDs: ids.to_vec() })
                .send()?,
            "delete",
        )?
        .text()?;
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(&body) {
            if let Some(code) = v.get("Code").and_then(serde_json::Value::as_i64) {
                if code != 1000 && code != 1001 {
                    let err_msg = v.get("Error").and_then(|e| e.as_str()).unwrap_or_default();
                    let short: String = body.chars().take(1000).collect();
                    return Err(ProtonError::Api {
                        code: 0,
                        message: format!("contacts delete failed {code}: {err_msg} {short}"),
                    });
                }
            }
        }
        Ok(())
    }
}

/// Generate a fresh contact UID in the WebClients `generateProtonWebUID`
/// shape (`proton-web-<hex…>`). Random via `getrandom` (no new deps);
/// falls back to time+pid mixing only when the RNG is unavailable, so two
/// creates in one batch can never share a UID (the old nanos-only scheme
/// could collide inside a fast loop).
pub fn generate_contact_uid() -> String {
    let mut rand = [0u8; 16];
    if getrandom::getrandom(&mut rand).is_err() {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let pid = std::process::id();
        for (i, b) in rand.iter_mut().enumerate() {
            *b = ((nanos >> (8 * (i % 8))) as u8).wrapping_add((pid >> (8 * (i % 4))) as u8);
        }
    }
    let h = |b: u8| format!("{b:02x}");
    let s4 = |i: usize| format!("{}{}", h(rand[i]), h(rand[i + 1]));
    format!(
        "proton-web-{}{}-{}-{}-{}-{}{}{}",
        s4(0),
        s4(2),
        s4(4),
        s4(6),
        s4(8),
        s4(10),
        s4(12),
        s4(14)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bulk_export_deduplicates_across_pages_and_preserves_metadata() {
        let mut server = mockito::Server::new();
        let list = server.mock("GET", "/contacts/v4")
            .match_query(mockito::Matcher::Any)
            .with_body(r#"{"Total":2,"Contacts":[{"ID":"b","UID":"ub","ModifyTime":20},{"ID":"a","UID":"ua","ModifyTime":10}]}"#).create();
        let card = serde_json::json!({"ID":"a","Cards":[{"Type":2,"Data":"card-a"}]});
        let first = server
            .mock("GET", "/contacts/v4/contacts/export")
            .match_query(mockito::Matcher::AllOf(vec![
                mockito::Matcher::UrlEncoded("Page".into(), "0".into()),
                mockito::Matcher::UrlEncoded("PageSize".into(), "50".into()),
            ]))
            .with_body(serde_json::json!({"Contacts":vec![card;50]}).to_string())
            .create();
        let second = server.mock("GET", "/contacts/v4/contacts/export")
            .match_query(mockito::Matcher::UrlEncoded("Page".into(), "1".into()))
            .with_body(r#"{"Contacts":[{"ID":"a","Cards":[{"Type":2,"Data":"card-a"}]},{"ID":"b","Cards":[{"Type":3,"Data":"card-b"}]}]}"#).create();
        let individual = server
            .mock("GET", mockito::Matcher::Regex("/contacts/v4/[ab]$".into()))
            .expect(0)
            .create();
        let client = ContactsClient::new_with_base_url(server.url(), "at".into(), "uid".into());
        let contacts = client.list_all().unwrap();
        assert_eq!(contacts.len(), 2);
        assert_eq!(contacts[0].UID, "ub");
        assert_eq!(contacts[0].ModifyTime, 20);
        assert_eq!(contacts[0].Cards.as_ref().unwrap()[0].Data, "card-b");
        list.assert();
        first.assert();
        second.assert();
        individual.assert();
    }

    #[test]
    fn incomplete_or_rejected_export_never_falls_back_to_individual_requests() {
        for (status, body) in [
            (200, r#"{"Contacts":[]}"#),
            (200, r#"{"Contacts":[{"ID":"other","Cards":[]}]}"#),
            (200, r#"{}"#),
            (429, r#"{"Code":429,"Error":"Too many requests"}"#),
            (503, r#"{}"#),
        ] {
            let mut server = mockito::Server::new();
            let _list = server
                .mock("GET", "/contacts/v4")
                .match_query(mockito::Matcher::Any)
                .with_body(r#"{"Total":1,"Contacts":[{"ID":"a"}]}"#)
                .create();
            let export = server
                .mock("GET", "/contacts/v4/contacts/export")
                .match_query(mockito::Matcher::Any)
                .with_status(status)
                .with_body(body)
                .create();
            let detail = server.mock("GET", "/contacts/v4/a").expect(0).create();
            let client = ContactsClient::new_with_base_url(server.url(), "at".into(), "uid".into());
            assert!(client.list_all().is_err(), "{status} {body}");
            export.assert();
            detail.assert();
        }
    }

    #[test]
    fn conflicting_export_cards_and_mass_missing_cards_abort_without_request_storm() {
        for large in [false, true] {
            let mut server = mockito::Server::new();
            let inventory: Vec<_> = (0..if large { 11 } else { 1 })
                .map(|i| serde_json::json!({"ID":format!("c{i}")}))
                .collect();
            let _list = server
                .mock("GET", "/contacts/v4")
                .match_query(mockito::Matcher::Any)
                .with_body(
                    serde_json::json!({"Total":inventory.len(),"Contacts":inventory}).to_string(),
                )
                .create();
            let rows = if large {
                inventory
            } else {
                vec![
                    serde_json::json!({"ID":"c0","Cards":[{"Type":2,"Data":"first"}]}),
                    serde_json::json!({"ID":"c0","Cards":[{"Type":2,"Data":"second"}]}),
                ]
            };
            let _export = server
                .mock("GET", "/contacts/v4/contacts/export")
                .match_query(mockito::Matcher::Any)
                .with_body(serde_json::json!({"Contacts":rows}).to_string())
                .create();
            let details = server
                .mock(
                    "GET",
                    mockito::Matcher::Regex("/contacts/v4/c[0-9]+$".into()),
                )
                .expect(0)
                .create();
            let client = ContactsClient::new_with_base_url(server.url(), "at".into(), "uid".into());
            assert!(client.list_all().is_err());
            details.assert();
        }
    }

    #[test]
    fn test_list_all_fetches_full_contacts_in_listing_order() {
        let mut server = mockito::Server::new();
        let list = server.mock("GET", "/contacts/v4")
            .match_query(mockito::Matcher::Any)
            .with_body(r#"{"Total":5,"Contacts":[{"ID":"a"},{"ID":"b"},{"ID":"c"},{"ID":"d"},{"ID":"e"}]}"#)
            .create();
        let details: Vec<_> = ["a", "b", "c", "d", "e"].iter().map(|id| {
            server.mock("GET", format!("/contacts/v4/{id}").as_str())
                .with_body(format!(r#"{{"Contact":{{"ID":"{id}","Cards":[{{"Type":2,"Data":"BEGIN:VCARD","Signature":"s"}}]}}}}"#))
                .create()
        }).collect();
        let client = ContactsClient::new_with_base_url(server.url(), "at".into(), "uid".into());
        let contacts = client.list_all().unwrap();
        assert_eq!(
            contacts.iter().map(|c| c.ID.as_str()).collect::<Vec<_>>(),
            ["a", "b", "c", "d", "e"]
        );
        assert!(contacts
            .iter()
            .all(|c| c.Cards.as_ref().unwrap().len() == 1));
        list.assert();
        for detail in details {
            detail.assert();
        }
    }

    #[test]
    fn test_list_all_detail_failure_aborts_snapshot() {
        let mut server = mockito::Server::new();
        let list = server
            .mock("GET", "/contacts/v4")
            .match_query(mockito::Matcher::Any)
            .with_body(r#"{"Total":2,"Contacts":[{"ID":"a"},{"ID":"b"}]}"#)
            .create();
        let good = server
            .mock("GET", "/contacts/v4/a")
            .with_body(r#"{"Contact":{"ID":"a"}}"#)
            .create();
        let bad = server
            .mock("GET", "/contacts/v4/b")
            .with_status(503)
            .create();
        let client = ContactsClient::new_with_base_url(server.url(), "at".into(), "uid".into());
        assert!(client.list_all().is_err());
        list.assert();
        good.assert();
        bad.assert();
    }

    #[test]
    fn test_generate_contact_uid_shape_and_uniqueness() {
        let a = generate_contact_uid();
        let b = generate_contact_uid();
        for uid in [&a, &b] {
            assert!(uid.starts_with("proton-web-"), "{uid}");
            assert_eq!(uid.len(), "proton-web-".len() + 36, "{uid}");
        }
        assert_ne!(a, b);
    }

    #[test]
    fn test_create_request_wire_shape() {
        // WebClients `addContacts` sends `Contacts` as objects with a
        // `Cards` key — a bare array-of-arrays never matched the wire.
        let req = CreateContactsRequest {
            Contacts: vec![CreateContactCards {
                Cards: vec![ContactCard {
                    Type: 2,
                    Data: "d".into(),
                    Signature: "s".into(),
                }],
            }],
            Overwrite: 0,
            Labels: 0,
        };
        let v = serde_json::to_value(&req).unwrap();
        assert_eq!(v["Contacts"][0]["Cards"][0]["Type"], 2);
        assert_eq!(v["Overwrite"], 0);
        assert!(v["Contacts"][0].get("Cards").unwrap().is_array());
    }

    #[test]
    fn test_update_rejection_keeps_body() {
        // A 400 with a `{Code, Error}` body must surface the body (live
        // 2026-09-09: bare `error_for_status` hid WHY the PUT was rejected).
        let mut server = mockito::Server::new();
        let _m = server
            .mock("PUT", mockito::Matcher::Regex(r"/contacts/v4/c9".into()))
            .with_status(400)
            .with_header("content-type", "application/json")
            .with_body(r#"{"Code":2000,"Error":"Invalid contact data"}"#)
            .create();
        let client = ContactsClient::new_with_base_url(server.url(), "at".into(), "uid".into());
        let err = client
            .update("c9", UpdateContactRequest { Cards: Vec::new() })
            .expect_err("400 must err");
        let msg = format!("{err}");
        assert!(msg.contains("400"), "{msg}");
        assert!(msg.contains("Invalid contact data"), "{msg}");
    }

    #[test]
    fn test_delete_checks_top_level_code_leniently() {
        // Fail-closed on an explicit error Code, success on Code 1000 or a
        // codeless body (go-proton-api treats delete as transport-only).
        for (body, ok) in [
            (r#"{"Code":1000}"#, true),
            (r#"{"Code":1001}"#, true),
            (r#"{}"#, true),
            (r#"{"Code":2000,"Error":"Invalid IDs"}"#, false),
        ] {
            let mut server = mockito::Server::new();
            let _m = server
                .mock(
                    "PUT",
                    mockito::Matcher::Regex(r"/contacts/v4/delete".into()),
                )
                .with_status(200)
                .with_header("content-type", "application/json")
                .with_body(body)
                .create();
            let client = ContactsClient::new_with_base_url(server.url(), "at".into(), "uid".into());
            let res = client.delete(&["c1".to_string()]);
            assert_eq!(res.is_ok(), ok, "{body}");
            if !ok {
                assert!(
                    format!("{}", res.unwrap_err()).contains("Invalid IDs"),
                    "{body}"
                );
            }
        }
    }
}
