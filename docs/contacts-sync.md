# Contacts sync

## Wire shapes (`proton-api/src/contacts.rs`, `models.rs`)

Base `https://mail.proton.me/api`, headers `Bearer + x-pm-uid +
x-pm-appversion`. `check_response` keeps truncated error bodies.

| Method | Route | Request | Response |
|---|---|---|---|
| `GET` | `/contacts/v4?Page=&PageSize=` | — | `{Contacts: Contact[], Total}` (`PageSize=100`, then one `GET` per contact for full cards) |
| `GET` | `/contacts/v4?Count=1` | — | `{Total}` |
| `GET` | `/contacts/v4/{id}` | — | `{Contact}` |
| `POST` | `/contacts/v4` | `{Contacts: [{Cards}], Overwrite: 0, Labels: 0}` | `{Responses: [{Index, Response{Code, Error?, Contact?}}]}` (nested `Contact`) |
| `PUT` | `/contacts/v4/{id}` | `{Cards}` | `{Contact}` |
| `PUT` | `/contacts/v4/delete` | `{IDs: string[]}` | `{Code?, Error?}`: `1000`/`1001`/codeless `{}` = success, other `Code` = failure |

`Contact{ID, Name, UID, Size, CreateTime, ModifyTime,
ContactEmails[{ID, Name, Email, Type, ContactID, LabelIDs}], LabelIDs,
Cards?}`. `ContactCard{Type (number-or-string tolerant), Data, Signature
(null-tolerant)}`.

Card types (`CONTACT_CARD_TYPE`): `3` encrypted+armored, `2` signed
plaintext, `1` encrypted (read like 3), `0` cleartext
(`VERSION`/`PRODID`/`CATEGORIES`, `Signature` null or omitted).

Full-card downloads use up to four concurrent blocking HTTP workers sharing
the connection pool, with listing order preserved. Pagination continues to
the reported total; an early empty page or any failed detail request aborts
the snapshot before uploads/local apply. List summaries never substitute for
missing full cards.

## vCard split and seal (`vcard.rs`, `contact_seal.rs`)

Cards seal to the **user** keypair (encrypt to user-public, detached-sign
with user-private) — the opposite of calendar's address-key rule.

- `build_vcard(contact, uid) -> (signed, Option<encrypted>)`:
  - Signed: `UID`, `FN` (explicit, else `first last`, else first email,
    else `Unknown`), `itemN.EMAIL` (sequentially grouped).
  - Encrypted (`None` when empty, so email-only contacts upload a single
    Type-2 card): `N, TEL, ADR, ORG, TITLE, ROLE, NOTE, URL, BDAY,
    ANNIVERSARY, NICKNAME, GENDER, PHOTO`. Empty-photo + `photo_removed`
    seals a bare `PHOTO:` line; otherwise no photo line.
  - Envelope `VERSION:4.0`, TEXT escaping (`\, \; \\ \n`), 75-octet
    folding, no `PRODID`, no Type-0 emission.
- Preservation on update rebuild: per-email crypto groups (`KEY`,
  `X-PM-*`, signed side only) regrouped onto rebuilt `itemN` numbers
  (deleted addresses drop their groups; encrypted-side keys still defer);
  cleartext `CATEGORIES` (+`PRODID`) lines regrouped into a Type-0 card
  (nothing emitted when unlabeled); server photos carried unless the phone
  has photos or `photo_removed`; server UID kept.
- Seal output order: `[Type2 (plaintext + detached sig), optional Type3
  (whole-message armored encrypt + detached plaintext sig)]` + optional
  carried Type-0. Fresh UIDs: `proton-web-<8hex>-<4hex>-<4hex>-<4hex>-<12hex>`
  (`generate_contact_uid`, `getrandom`).
- Upload limits: creates chunked ≤10 (`ADD_CONTACTS_MAX_SIZE`), 100 ms
  pacing between update PUTs / create chunks (`API_SAFE_INTERVAL`); deletes
  in a single batch.

## Engine cycle (`proton-sync/src/engine.rs`, `contact_plan.rs`)

State machine per sync: download+decrypt → plan → execute uploads →
re-list reconcile → persist maps. Server wins all edit conflicts.

Inputs (`SyncConfig`, all `#[serde(default)]`, `None` = download-only):
`contact_inventory: Vec<ContactItem>`, `contact_known_uids: HashSet<Proton
UID>`, `contact_anchors: {Proton UID: ModifyTime}`. Half-fed guard:
`inventory=None` + non-empty known → drop known, never plan deletes.

`ContactItem{qcontact_id, proton_uid?, modified, last_synced_mtime?,
fields?: ParsedContact, pending_uid?}`.

`plan_contacts` output ordering creates → updates → deletes:

- No `proton_uid` → create.
- Known + present + locally `modified` + `ModifyTime > anchor` (missing
  anchor = 0) → conflict (server-wins, no upload).
- Locally `modified` only → update.
- Known, missing locally, present on server → delete. Known missing on
  both sides → stale map entry (pruned). Present locally, absent on
  server, clean → applied as server delete by the download.
- Deletes held (deferred one cycle) while guid-less or server-unknown rows
  exist. An edit that loses its Guid duplicates instead of deleting.

Execution:

1. Creates seal under a stable UID (`pending_uid`, else fresh) and `POST`
   in ≤10 chunks; per-op `Index` partition: `Code == 1000` confirms, else a
   fresh listing adopts on UID match, else fail closed (missing `Index`
   fails closed).
2. Updates rebuild with `build_contact_update_cards`; unbuildable rows
   defer with `diagnose_update_block` (`unsealable`, `undecryptable-card`,
   `unparsable-card`, `unknown-props:<names>`, `seal-error`).
3. Deletes resolve UID → row ID and fire one `PUT …/delete`.
4. Creates/updates/adopts trigger a re-list (fail-closed); otherwise
   deletes are filtered locally.
5. `merge_contact_anchors` upserts `{UID: ModifyTime}` and retains entries
   seen fresh or still local.

`ContactUploadOutcome{contacts, conflicts, anchors, trace,
pending_creates: {qcontact_id: uid}, deferred: Vec<ContactDeferred{kind:
create|update, id, reason}>}`. `pending_creates` is exposed after every
outcome (error keeps, complete clears) and fed back as `pending_uid`.
Anchors persist wholesale; empty anchors never clobber the cache.

## Sync FFI (`proton-bridge/src/bridge.rs`)

- In: `proton_bridge_create_engine_with_inventory(username, password,
  access_token, refresh_token, uid, totp, derived_json, inventory_json,
  known_uids_json, anchors_json)`. Empty/invalid JSON degrades to `None`
  (download-only), never half-fed. Lifecycle: `create*` →
  `proton_bridge_start_sync` → getters → `proton_bridge_destroy_engine`.
  Status via `proton_bridge_get_status` (16-byte buffer; `needs_2fa` passes
  through and stops the poll with an authentication-failure notification).
- Out (`char*`, free with `proton_bridge_free_string`):
  - `…_get_synced_contacts_json` → `ProcessedContact[]` (full field mirror;
    photos omitted from inventory uploads v1 except avatar handling below).
  - `…_get_contact_conflicts_json` → `ContactConflict[]`.
  - `…_get_contact_deferred_json` → `ContactDeferred[]` (IDs + codes only;
    also appended to the sync notification and the file log).
  - `…_get_contact_anchors_json` → `{uid: mtime}` or null.
  - `…_get_contact_pending_json` → `{qcontact_id: uid}` or null.
  - `…_get_refresh_token`, `…_get_uid`, `…_get_derived_passwords_json`,
    `…_get_keys_debug` (carries the `contact_upsync` trace:
    inputs/plan/ran/defer-reasons/hold markers).

## Shim mapping (`proton_bridge_shim.cpp`, contacts parts)

- One `QContactCollection` per account (`remote_uid=proton-contacts-<id>`),
  full-replacement write, `QContactSyncTarget=proton`, `QContactGuid` =
  Proton UID.
- Field map: name → `QContactName`, display label (+ split fallback),
  emails (Home/Work contexts), phones (cell/mobile/fax/pager/voice/video/car
  subtypes + Home/Work), addresses, organization/title/role, notes
  (newline-joined), birthday/anniversary, nickname, URL, gender
  (Male/Female round-trip), first photo → `QContactAvatar`. Last avatar
  detail wins.
- `exportContactsInventory`: every row exports identity flags
  (`qcontact_id`, `proton_uid|null`, `modified` from `contacts_last_modified`
  vs `lastModified`, `last_synced_mtime` from `contacts_anchors`,
  `pending_uid` for guid-less rows); dirty/never-synced rows additionally
  export `fields`.
- Photos: `data:` URIs pass through; file paths load and downscale to a
  512px JPEG q85 data URI (QtGui built-in). The avatar is exported only when
  it differs from the persisted download baseline (`contacts_photos`, read
  back post-save for like-for-like comparison); conversion failures omit
  (server copy wins). Known row whose avatar is gone while the baseline has
  one exports `photo_removed: true` (never for guid-less rows).
- Notifications name conflict counts (`N contacts changed on both sides;
  server version kept`) and deferred counts (`N local changes could not be
  uploaded; server version kept`).

## References

- https://github.com/ProtonMail/WebClients (`packages/shared/lib/contacts/{encrypt,constants,surgery,vcard,decrypt}.ts`, `packages/shared/lib/api/contacts.ts`, `packages/shared/lib/helpers/uid.ts`)
- https://github.com/ProtonMail/go-proton-api (`contact.go`, `contact_types.go`, `contact_card.go`)
