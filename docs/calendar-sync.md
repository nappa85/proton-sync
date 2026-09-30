# Calendar sync

## Wire shapes (`proton-api/src/calendar.rs`, `models.rs`)

Base `https://mail.proton.me/api`, headers `Bearer + x-pm-uid +
x-pm-appversion`.

| Method | Route | Purpose |
|---|---|---|
| `GET` | `/calendar/v1` | List calendars |
| `GET` | `/calendar/v1/{id}/keys`, `/passphrase`, `/members` | Keys / member passphrases / members (v1 fallbacks) |
| `GET` | `/calendar/v2/{id}/bootstrap` | Keys + passphrase + members + settings in one call (list stays v1); empty/`{}` `CalendarSettings` falls back to v1 |
| `GET` | `/calendar/v1/{id}/settings`, `/settings/calendar` | Per-calendar defaults / account view prefs |
| `GET` | `/calendar/v1/{id}/events?Type&Start&End&Timezone&Page&PageSize` | Typed windowed page (`Timezone` mandatory, `"UTC"` neutral; without it: 400 code 2000) |
| `GET` | `…/events?UID&Page&PageSize` | Server-side UID filter (no window) |
| `GET` | `…/events?Page&PageSize` | Untyped listing (no `Type`) |
| `GET` | `…/events/{eventId}` | Single event (`{Event: {}}`) |
| `PUT` | `/calendar/v1/{id}/events/sync` | Batch write (only write route; no standalone POST) |
| `PUT` | `/calendar/v1/{id}/events/{eventId}/personal` | Reminder/color-only update (`{Notifications, Color}`) |

`Calendar{ID, Name, Description, Color, Display, Type (0 normal /
1 subscribed / 2 holidays), Flags}` — display name resolution prefers
`Members[0]` (top-level `Name` may be empty). `CalendarMember{ID,
CalendarID, AddressID, Email, Name, Description, Color, Permissions,
Flags}`. `CalendarPassphrase{ID, Flags, MemberPassphrases[{MemberID,
Passphrase, Signature}]}`. `CalendarKey{ID, CalendarID, PassphraseID,
PrivateKey, Flags}` (all unlockable generations kept).

Event row: `ID, UID, CalendarID, SharedEventID, CreateTime, LastEditTime,
StartTime/EndTime` (unix), `StartTimezone/EndTimezone`, `FullDay`
(int-bool tolerant), `Author`, `SharedKeyPacket/CalendarKeyPacket` (base64,
null → `""`), `SharedEvents/CalendarEvents/AttendeesEvents/PersonalEvents[]`
(parts), `RRule?, Exdates[]` (unix), `RecurrenceID?` (unix), `Color?,
Notifications?[{Trigger, Type}], IsOrganizer?, Permissions?,
Attendees[{Token, Status}]`. Null-tolerant scalars throughout; one bad field
never kills the row (element-wise rows and parts, skip-with-ID logging).

Part: `{MemberID, Type, Data, Signature, Author}`. `Type` bitflags: `&1`
encrypted, `&2` signed (0 plain, 2 signed-clear, 3 encrypted+signed).
Encrypted data with key packets is base64 bare SEIPD; `Type` constants are
identical to proton-cal (`0/1/2/3`).

Listing: `PageSize ≤ 100`, cursor is `More` (int/bool/`Total` fallback).
Typed queries filter server-side only when `Type` is supplied (all 4 Types
`0..3` must be swept); window ≤93 days (chunks ≤91d + ±1d padding so padded
spans stay ≤93d). The engine's primary listing is **untyped** paged
`[now−1y, now+1y]` + client-side overlap filter (`StartTime < end &&
EndTime > start`; recurring masters always kept). The typed windowed listing
is retained mock-tested beside it. Cancelled events are omitted from
listing server-side.

## Decrypt and merge (`calendar.rs`, `crypto.rs`)

Chain: password → salts → user key → address key (`Token`) → per-member
passphrase → calendar keys → per-event session keys.

- `decrypt_calendar_keys`: match `MemberPassphrases[member_id]`, decrypt with
  any address key, unlock every calendar key that opens (old generations
  needed). Member pick is the first member with an any-member fallback.
- `decrypt_calendar_part(part, cal_keys, addr_keys, key_packet)`:
  split-packet path concatenates `base64(key_packet)+base64(Data)` as a
  binary OpenPGP message and decrypts with calendar keys; armored fallback
  tries calendar then address keys. Routing: shared/attendee cards use
  `SharedKeyPacket`, calendar cards use `CalendarKeyPacket`; events without
  an encrypted calendar card have no `CalendarKeyPacket`. Signature
  verification is lenient (never fails decrypt, matching proton-cal).
- `merge_ical_fragments` (shared-signed first): first-wins structural
  (`UID, DTSTART, DTEND, RRULE, RECURRENCE-ID, SEQUENCE, …`), first-seen
  wins otherwise, multi-valued (`EXDATE`, `ATTENDEE`) unioned;
  `X-PM-SESSION-KEY` stripped. Fragments are full `BEGIN:VCALENDAR/VEVENT`
  wrappers (may carry server-sent `VERSION`/`PRODID`, no trailing CRLF).
- `parse_ical`: unfolding (exactly one leading char), param stripping,
  TEXT unescaping, full field set (`UID, SUMMARY, DESCRIPTION, LOCATION,
  DTSTART, DTEND, DTSTAMP, CREATED, RRULE, EXDATE, SEQUENCE, STATUS, TRANSP,
  ORGANIZER, ATTENDEE`), organizer/attendee identities (`CN, RSVP, PARTSTAT,
  ROLE, CUTYPE`; bare emails; quoted-CN and colon-in-CN safe),
  `RECURRENCE-ID` (+`RANGE`).
- `parse_rrule` → `RecurrenceSpec{freq, interval=1, count?, until?,
  byday[{pos, weekday}], bymonthday, bymonth, byyearday, byweekno, bysetpos,
  wkst}` (lenient: bad parts skipped; `BYHOUR/MINUTE/SECOND` ignored by
  design — time comes from `DTSTART`).
- `Notifications` tri-state, mirroring the server model: `null`/absent =
  inherit calendar defaults, `[]` = explicitly none, array = custom list.
  Triggers parse signed seconds (`-PT15M`, `-P1W`; months rejected).
  Resolution: explicit array (Type-0 email entries dropped for mKCal) →
  live per-calendar defaults (`DefaultPartDayNotifications` /
  `DefaultFullDayNotifications` via bootstrap + v1 settings, cached per
  calendar for restored sessions) → none. `Color`: 20 fixed accent hexes
  (code 2011 otherwise); `""` reverts to the member color; update `null` is
  ignored by the server (revert = set the calendar's own color).

## Write path (`calendar_write.rs`, `calendar_seal.rs`)

- `PUT …/events/sync` batch `{MemberID, IsImport?, Events[]}`: create
  `{Overwrite: 0, Event}` with fresh key packets (+ `IsImport: 0`); update
  `{ID, Event}` with **no** key packets (server keeps originals — the caller
  reuses stored session keys); delete `{ID}` only. Response top-level
  `1001` = batch accepted; per-op `{Index, Response{Code: 1000, Error,
  Event?}}`; deletes return top-level only. Whole-object replace: omitted
  `Notifications`/`Color`/`Attendees` reset server-side, so updates re-send
  existing values verbatim unless changing them (content arrays `[]`, never
  `null`). Series delete = master + all same-UID rows in one batch (no
  server cascade).
- Cards are patched in place, never rebuilt: `patch_card` (unfold → delete →
  in-place replace every occurrence, missing sets appended name-sorted,
  appends deduped, `VALARM` blocks + wrapper verbatim, 75-octet folding, no
  trailing CRLF). Update reseal strips server-sent `VERSION`/`PRODID`,
  emits all-day `DATE` values with `;VALUE=DATE`, and re-encrypts with the
  **same** session keys (decrypted from stored packets with the calendar
  key). Sealing signs with the **address** keyring only
  (`UnlockedAddressKeys::address_only()`; author-matched when known).
- `SEQUENCE` (server-enforced, code 2001): bumped only on significant
  (date/time/recurrence) changes; field edits keep it; exceptions need
  `SEQUENCE >= master`; creates use `0`. `RRULE` server limits mirrored
  from the web client: `FREQ ∈ {DAILY, WEEKLY, MONTHLY, YEARLY}`,
  `COUNT ≤ 49`, `UNTIL ≤ 2037-12-31`, `COUNT`/`UNTIL` exclusive.
- `PUT …/events/{id}/personal` (`{Notifications, Color}`) serves
  reminder-only edits: strict whitelist (`content_matches_except_notifications`
  — all compared fields present and exactly equal, non-recurring, no
  attendees/exdates/personal rows); any doubt falls through to the full
  replace. Both routes share one Notifications/Color marshal.
- Creates use stable UIDs (`pending_uid`, else fresh) with per-op `Index`
  partition and UID-conflict adopt via `list_by_uid`; unresolvable conflicts
  fail closed; re-list-confirmed drain (out-of-window creates stay pending).
- RSVP/invites (contract only, no write code): RSVP is `PUT
  …/events/{id}/attendees/{attendeeID} {Status, UpdateTime, Comment?}`
  (`Status` enum identical to the stored comment); invite acceptance is
  `PUT …/events/{uid}/accept {Signature}`; attendee authoring goes through
  the sync update's `Attendees` rows. Requirements not yet met: attendee ID
  (`ID ≠ Token`), `UpdateTime`/`Comment`/self-resolution tracking, a phone
  trigger (attendee events are read-only in the Calendar app), live invite
  data. Download-wins + verbatim attendee re-send is the standing behavior.

## Engine cycle (`proton-sync/src/calendar.rs`, `upsync.rs`)

Order: upload → purge tombstones → download → store anchors. Flow:
list rows → unlock address keys (derived/salt/`Token`; combined set for
decrypt, address-only for seal/sign, author-matched signing index) →
upload phase (fail-closed) → per-calendar bootstrap → unlock calendar keys
→ windowed list → decrypt + merge → `CalEventJson`.

Calendar-list errors, any calendar query error, skipped/unparseable event
rows, and event decryption/merge failures abort the download snapshot. The
shim only applies a complete result, so a failed calendar cannot disappear
from an otherwise successful account-wide replacement.

`CalEventJson`: `id, uid, calendar_id, calendar_name, summary,
description, location, dtstart, dtend, dtstamp, rrule, exdates[], sequence,
status, transp, organizer, organizer_name, attendees[], attendees_full[],
start_time/end_time, start_timezone/end_timezone, full_day, color?,
recurrence_id` (unix, authoritative), `recurrence_id_ical/_range,
notifications[], mtime (= LastEditTime)`.

Upload planning (`plan_sync` over rows + `LocalItem{mkcal_uid
(…/#rid), proton_id?, deleted, modified, last_synced_mtime?, fields?,
calendar_id?, uid?, pending_uid?}`): creates → updates → deletes;
both-sides-edited → conflict (server-wins, no upload); tombstones with IDs
→ delete ops + `purgeable_tombstones`; orphans counted. Out-of-window and
pid-less tombstones are UID-augmented (`list_by_uid`, ID-deduped; master →
series delete via batch expansion, `#rid` standalone → surviving occurrence
only). `AnchorMap::merge_anchors` upserts seen entries and prunes only
gone-everywhere rows (unlisted-by-window ≠ deleted). `SyncConfig`
carries `local_inventory`, `anchor_map`, `calendar_defaults`; getters
expose `defaults/purgeable/conflicts/anchors/pending` (`""` = no clobber).

## Shim mapping (`proton_bridge_shim.cpp`, calendar parts)

- One mKCal notebook per Proton calendar
  (`proton-calendar-<accountId>-<calendarId>`, legacy single notebook
  retired); stored UID `proton-cal-<accountId>-<raw>` (mKCal enforces
  storage-wide uniqueness); exceptions `<uid>#<rid>`; Proton row ID in the
  `X-PROTON-EVENT-ID` custom property (id-map fallback).
- `fillEventFromJson`: summary (empty → UID), description, location, all-day
  (exclusive-end adjusted), start/end (iCal or unix fallback, event timezone
  attached), recurrence (`FREQ/INTERVAL/COUNT/UNTIL/BYDAY/BYMONTHDAY/BYMONTH/
  BYYEARDAY/BYWEEKNO/BYSETPOS/WKST`; raw RRULE also stored), timezone-aware
  `EXDATE`s, attendees (`attendees_full` → `Attendee` + organizer `Person`,
  legacy email lists as fallback), status/transparency, color, alarms
  (display + email start-offsets; `null` inherits calendar defaults, `[]`
  stays reminder-free).
- `exportLocalInventory`: live rows + tombstones with field data only for
  dirty/never-synced rows (common-subset RRULE serializer; unserializable
  phone rules keep the server rule on update / defer creates);
  notification/color/uid exported for the personal-route router.
- `writeEventsToMkCal`: full replacement per notebook (masters first, then
  exceptions as master `EXDATE` + standalone edited event — the framework
  exception machinery does not persist dissociated rows); tombstone purge
   scoped to our notebooks; maps persisted after every save. Empty/duplicate
   UIDs and notebook/load/add failures abort before saving the replacement.
   Replacement deletions use `save(PurgeDeleted)` so they never become
   uploadable user tombstones, including after an interrupted sync. Previously
   persisted tombstones are purged selectively (planner set ∪ replacement
   removals). Legacy notebook retirement happens after the replacement saves.
- Calendar FFI mirrors contacts (`proton_calendar_create_engine_with_inventory`,
  `…_with_derived_and_defaults`, `…_get_events_json`,
  `…_get_{purgeable,conflicts,anchors,pending,defaults}_json`,
  `…_get_refresh_token/uid/keys_debug`).

## References

- https://github.com/cheeseandcereal/proton-cal (`docs/overview.md`, `docs/crypto.md`, `docs/api.md`; `pkg/event/{wire,write}.go`, `pkg/ical/{patch,text}.go`, `pkg/calcolor`)
- https://github.com/Nojuza/proton-calendar-cli/blob/main/RESEARCH.md
- https://proton.me/blog/protoncalendar-security-model
- https://github.com/ProtonMail/go-proton-api (`calendar_types.go`, `calendar.go`, `calendar_event_types.go`, `keyring.go`, `unlock.go`)
- https://github.com/ProtonMail/WebClients (`packages/shared/lib/api/calendars.ts`, `api/auth.ts`, `webauthn/interface.ts`)
- https://github.com/ProtonMail/gopenpgp (split-message packet model)
