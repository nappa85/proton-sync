# Architecture

Native SailfishOS account provider + Buteo sync plugin for Proton
Contacts and Calendar.

```
proton-api/       Pure Rust: Proton REST client (SRP auth, 2FA, contacts,
                  calendar, PGP, key salts)
proton-sync/      Pure Rust: sync engines (contacts SyncEngine, calendar
                  CalendarSyncEngine) + QSettings-derived cache handling
proton-bridge/    Rust FFI + C++: SignOn auth plugin (libprotonplugin.so)
                  + Buteo OOPP plugin (libproton-client.so, QContactManager
                  + mKCal/KCalendarCore notebooks) + settings QML extension
ui/               QML AccountCreationAgent / AccountCredentialsAgent /
                  OnlineSyncAccountSettingsAgent
buteo-profiles/   Buteo client/sync profile templates
packaging/        RPM build staging (assembled by make-pkg-bundle.sh):
                  accounts/ provider+service XML, buteo-plugin/ .so
rpm/              RPM specs (buteo-sync-plugin-proton,
                  sailfish-account-proton)
translations/     Qt Linguist catalogs (proton.ts template +
                  proton_<lang>.ts/.qm)
tools/            build-qm.sh, apply-translations.py
```

## Buteo plugin mechanics

- `libproton-client.so` derives plugin name `proton` (strip `lib` prefix
  + `-client.so` suffix). It is an out-of-process plugin living in
  `/usr/lib64/buteo-plugins-qt5/oopp/` and loaded by
  `/usr/libexec/buteo-oopp-runner` via `QPluginLoader` +
  `qobject_cast<SyncPluginLoader*>` (`Q_PLUGIN_METADATA(IID
  "com.buteo.msyncd.SyncPluginLoader/1.0")`).
- `createClientPlugin` dispatches on the profile name: names containing
  `caldav`, `calendar` or `Calendar` create `ProtonCalendarPlugin`,
  everything else creates `ProtonContactsPlugin`
  (`proton-bridge/cxx/proton_bridge_shim.cpp`).
- Client profile `proton` (`buteo-profiles/client/proton-contacts.xml`);
  sync profiles `proton-carddav` (`buteo-profiles/sync/proton.Contacts.xml`)
  and `proton-caldav` (`buteo-profiles/sync/proton.Calendar.xml`), both
  `enabled=false hidden=true use_accounts=true`. Per-account instances are
  named `<sync-profile>-<accountId>` (observed on device:
  `proton-caldav-105`).
- Accounts&SSO: provider `proton` (`packaging/accounts/proton.provider`,
  auth `method=proton/mechanism=password`); services `proton-carddav`
  (`type=carddav`, `sync_profile_templates=["proton-carddav"]`) and
  `proton-caldav` (`type=proton-calendar`, custom type so the stock
  CalDAV discovery page is not used,
  `sync_profile_templates=["proton-caldav"]`).

## Buteo framework mechanics (reference)

- Discovery: `PluginManager` scans `…/buteo-plugins-qt5/` (in-process)
  and `…/buteo-plugins-qt5/oopp/` (out-of-process) for `.so` files ending
  in `-client.so` / `-server.so` / `-storage.so`, deriving the plugin name
  by stripping the `lib` prefix and the suffix. OOP plugins land in the
  out-of-process client map.
- Manual sync flow: `startSync(profileName)` over D-Bus → profile checks
  (exists, enabled, valid, no same-type sync running, storages reserved) →
  `ClientPluginRunner` → plugin lookup → `startOOPPlugin` launches
  `/usr/libexec/buteo-oopp-runner <pluginName> <profileName>
  <libraryPath>` (up to 30s for D-Bus registration) → `session.start()`
  → runner loads the `.so` via `QPluginLoader` and creates the client
  plugin. The runner registers as
  `com.buteo.msyncd.plugin.<profileName>` and relays plugin signals over
  D-Bus; the in-msyncd `OOPClientPlugin` proxy forwards
  `init`/`startSync`/`abortSync` to it. Manual `startSync` never checks
  connectivity (only scheduled syncs do).
- Account setup: `AccountsHelper` on `accountCreated` clones the service's
  sync profile template into a per-account instance
  (`<template>-<accountId>`, account ID stored under `KEY_ACCOUNT_ID`).
- Naming rule (CardDAV precedent): client profile name, sync protocol,
  and `.so`-derived plugin name all match (`libcarddav-client.so` →
  `carddav`); sync templates carry no `<conditions>` block and ship
  `enabled=false hidden=true` (overridden per account). Auth runs in
  `startSync()`, not `init()`.
- Stock credential flow (CardDAV `auth.cpp` pattern, mirrored by the
  shim): load `Accounts::Account` by ID → pick the service →
  `AccountService` → `credentialsId` → `SignOn::Identity` → session →
  `process(sessionData, mechanism)` → username/token response.

## On-device paths

| Artifact | Path |
|---|---|
| Buteo OOPP plugin | `/usr/lib64/buteo-plugins-qt5/oopp/libproton-client.so` |
| SignOn plugin | `/usr/lib64/signon/libprotonplugin.so` |
| Settings QML extension | `/usr/lib64/qt5/qml/Proton/libprotonsettingsplugin.so` + `qmldir` (`import Proton 1.0`) |
| Account UI agents | `/usr/share/accounts/ui/proton.qml`, `proton-update.qml`, `proton-settings.qml` |
| Provider / services | `/usr/share/accounts/providers/proton.provider`, `/usr/share/accounts/services/proton-carddav.service`, `proton-caldav.service` |
| Buteo profiles | `/etc/buteo/profiles/client/proton.xml`, `/etc/buteo/profiles/sync/proton-carddav.xml`, `proton-caldav.xml` |
| Translations | `/usr/share/proton/translations/proton_<lang>.qm` |
| Debug log | `~/Documents/ProtonSync/YYYY-MM-DD.log` (local date) |
| Token/derived cache | `QSettings("proton", "sync-tokens")` (see below) |

## Settings extension

`proton-bridge/settings/` provides `ProtonDataPurger` (`Q_INVOKABLE bool
purgeData(int accountId)`): removes the `QContactCollection` with
`remote_uid=proton-contacts-<id>` (plus its contacts) and the mKCal
notebooks `proton-calendar-<id>` and `proton-calendar-<id>-*`. Registered
as `ProtonDataPurger` in module `Proton` (`qmldir`). `initializeEngine`
loads `proton_<full-locale>` then `proton_<language>` from
`/usr/share/proton/translations/` and installs the translator (once).

## Persistent state (QSettings "proton"/"sync-tokens")

Groups `[<accountId>]`, `[<Uid>]`, `[<username>]`:

- `derived_passwords`: `DerivedPasswords` JSON (`keyID → base64(mailboxPassword)`).
- `refresh_token`, `uid`.
- Contacts: `contacts_id_map` (`Proton UID → QContactId`), `contacts_anchors`
  (`Proton UID → server ModifyTime`), `contacts_last_modified`
  (`QContactId → msecs`), `contacts_photos` (`QContactId → avatar string`),
  `contacts_pending` (`QContactId → stable UID`).
- Calendar: `proton_id_map`, `proton_anchors`, `proton_last_modified`,
  `calendar_pending`, `calendar_defaults`.

Merge precedence for derived passwords: `accountId < username < Uid <
signond blob`.

## Diagnostics

- `PROTON_VERBOSE` (non-empty, not `"0"`): verbose logging in Rust
  (`proton-api/src/diag.rs` `verbose()` + `vlog!`) and in the shim
  (`proton_verbose()` / `proton_log_verbose()`). The oopp-runner inherits
  msyncd's environment at msyncd start, so toggling requires
  `systemctl --user set-environment PROTON_VERBOSE=1` (or
  `unset-environment`) **plus** `systemctl --user restart msyncd`. No root
  needed.
- Full contact JSON rows are verbose-only; counts, ID-only traces and
  errors always log.
- Persistent daily logs: sync plugins and the Settings purge helper append
  timestamped entries to `~/Documents/ProtonSync/YYYY-MM-DD.log`. The directory
  is created automatically, and the local date is checked on every write so
  a sync crossing midnight switches files. Logs survive reboot; daily files
  are retained without truncation or automatic deletion.

## References

- https://docs.sailfishos.org/Reference/Core_Areas_and_APIs/Apps_and_MW/Accounts_and_SSO/
- https://docs.sailfishos.org/Reference/Core_Areas_and_APIs/Apps_and_MW/Synchronization/
- https://docs.sailfishos.org/Reference/Core_Areas_and_APIs/Apps_and_MW/Calendar
- https://github.com/sailfishos/buteo-sync-plugin-caldav (NotebookSyncAgent pattern)
- https://github.com/sailfishos/buteo-sync-plugins-social/tree/master/src/google/google-contacts (contacts pattern)
