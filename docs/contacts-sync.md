# Contacts sync

## Wire shapes (`proton-api/src/contacts.rs`, `models.rs`)

Base `https://mail.proton.me/api`, headers `Bearer + x-pm-uid +
x-pm-appversion`. `check_response` keeps truncated error bodies.

| Method | Route | Request | Response |
|---|---|---|---|
| `GET` | `/contacts/v4?Page=&PageSize=` | — | `{Contacts: Contact[], Total}` (`PageSize=100`, metadata/ID inventory) |
| `GET` | `/contacts/v4/contacts/export?Page=&PageSize=50` | — | `{Contacts: Contact[]}` with full encrypted cards; may repeat IDs per email |
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

Full-card downloads use sequential export pages of 50, deduplicated by ID,
with listing order and metadata preserved. The complete ID inventory must
match the export before uploads/local apply. Conflicting duplicate cards,
missing IDs, changing totals and stalled pagination abort the snapshot.
Explicitly unavailable export routes (404/501) use paced single-contact
reads; omitted cards can trigger at most 10 targeted detail reads. HTTP
429/5xx never trigger a per-contact fallback. Requests through each contacts
client are spaced at least 100 ms apart, including writes.

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
- Deletes are also held when the local collection is empty but the ID map
  is not: that is a lost local write, never "delete everything" on Proton.

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
create|update, id, reason}>, confirmed_creates: {qcontact_id: uid}}`.
`pending_creates` is exposed after every outcome (error keeps, complete
keeps only UIDs the re-list did not show) and fed back as `pending_uid`.
`confirmed_creates` (re-listed or adopted creates) is exposed via
`get_contact_confirmed_json`. Download rows carry `mtime`
(server `ModifyTime`) and `decrypt_failed`.
Anchors persist wholesale; empty anchors never clobber the cache.

## Engine outputs and the device session

The engine is driven by `proton-sync/src/device/session.rs` (see
architecture.md, "Shim / Rust split"); no per-field FFI getters remain.
Inputs come from settings + the shim's raw dump: `contact_inventory`,
`contact_known_uids` (`contacts_id_map` keys) and `contact_anchors`
(only when persisted). An unreadable local store degrades to
download-only (`None`), never to a half-fed plan. After the run the
session reads `ProcessedContact[]`, conflicts, deferred uploads (IDs +
reason codes: notification + file log), anchors, pending and confirmed
creates, tokens, derived passwords and the `keys_debug` trace
(`contact_upsync` inputs/plan/ran/defer-reasons/hold markers). `needs_2fa`
ends the run with an authentication failure and a verification notice.

## Phone side (`proton-sync/src/device/contacts.rs`)

The shim dumps every contact of the account collection
(`remote_uid=proton-contacts-<id>`, `QContactSyncTarget=proton`,
`QContactGuid` = Proton UID) as raw details (`id, guid, last_modified,
names, emails/phones/addresses with context and sub-type names,
organization, notes, birthday, anniversary, nickname, url, gender,
avatars[]`) and saves/removes what the write plan says. Everything else is
Rust:

- Inventory: every row exports identity flags (`qcontact_id`,
  `proton_uid|null`, `modified` from `contacts_last_modified` vs
  `last_modified`, `last_synced_mtime` from `contacts_anchors`,
  `pending_uid` for guid-less rows); dirty/never-synced rows additionally
  export `fields` (phone types `cell,fax,pager,voice,video,car` then
  `home,work`; gender `Male`/`Female`).
- Photos: `data:` URIs pass through; other avatars are requested from the
  shim (`avatars` request: file → 512px JPEG q85 data URI). The avatar is
  exported only when it differs from the persisted download baseline
  (`contacts_photos`, read back post-save for like-for-like comparison);
  conversion failures omit (server copy wins). A known row whose avatar is
  gone while the baseline has one exports `photo_removed: true` (never for
  guid-less rows). Last avatar detail wins.
- Reconciling write (`device/reconcile.rs`): rows match by Guid; each
  server row is fingerprinted (SHA-256 of canonical JSON minus
  `keys_debug`, persisted as `contacts_row_hashes`). Unchanged rows are
  left untouched (pending local edits survive; their
  `contacts_last_modified` and `contacts_photos` baselines carry over),
  changed rows are rewritten in place (same `QContactId`), new rows added,
  Guid'd rows the server no longer has removed, local duplicates of one
  Guid dropped. Guid-less rows (phone-created, not uploaded yet) are kept;
  a confirmed create's server row is merged into the same local contact.
  `decrypt_failed` rows never overwrite an existing local copy. The shim
  saves before it removes, so a failed save leaves the collection intact.
  Confirmed creates stay in `contacts_pending` until the write succeeds.
- Field map (server row → phone): name (display-name split fallback),
  display label, emails (home/work), phones (cell/mobile/fax/pager/voice/
  video/car + home/work), addresses, organization/title/role, notes
  (newline-joined), birthday/anniversary (`YYYY-MM-DD` or `YYYYMMDD`),
  nickname, URL, gender (`Female` → female, any other value → male), first
  photo → avatar.
- Notifications name conflict counts (`N contacts changed on both sides;
  server version kept`) and deferred counts (`N local changes could not be
  uploaded yet; kept on the phone, retrying next sync`).

## References

- https://github.com/ProtonMail/WebClients (`packages/shared/lib/contacts/{encrypt,constants,surgery,vcard,decrypt}.ts`, `packages/shared/lib/api/contacts.ts`, `packages/shared/lib/helpers/uid.ts`)
- https://github.com/ProtonMail/go-proton-api (`contact.go`, `contact_types.go`, `contact_card.go`)
