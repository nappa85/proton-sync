# Authentication

All clients send `x-pm-appversion: web-mail@6.3.2` and
`User-Agent: curl/8.0`. Auth endpoint paths are the `v4` variants throughout
(`proton-api/src/auth.rs`).

## SRP login

- `POST /core/v4/auth/info` (`AuthInfoRequest{Username}` →
  `AuthInfoResponse{Modulus, ServerEphemeral, Version, Salt, SRPSession,
  TwoFactor?}`).
- `POST /core/v4/auth` (`AuthRequest{Username, ClientEphemeral,
  ClientProof, SRPSession}` → `AuthResponse{AccessToken, RefreshToken, UID,
  ExpiresIn, ServerProof, TwoFactor?, PasswordMode?, Scopes?, 2FA?}`).
- Result is `LoginState::Authenticated{tokens, scopes}` or
  `LoginState::Requires2FA{access_token, refresh_token, uid, scopes}`. The
  2FA-locked session carries the `twofactor` scope and cannot call
  key-salt routes (403); it is upgraded in place, not replaced.

## 2FA detection and submission

- `is_totp_required` is true when `2FA.Enabled` is 1 or 3, or `2FA.TOTP`
  is 1; same rule for the legacy `TwoFactor` shape. `Enabled == 2` without
  TOTP is FIDO2-only and fails loudly with guidance to enable TOTP
  (TOTP coexists with security keys as `Enabled == 3`).
- `POST /auth/v4/2fa` with headers `Bearer <locked-access-token>` +
  `x-pm-uid`, body `{TwoFactorCode}`. Success (`Code == 1000`) returns the
  **original** tokens unchanged — the server upgrades the locked session's
  scopes in place. Wrong code → `TotpWrong`; reused code → `TotpReuse`.
- `POST /auth/v4/refresh` with `{GrantType: "refresh_token",
  RefreshToken}` (+ `x-pm-uid`) rotates to a new
  `{AccessToken, RefreshToken, UID, ExpiresIn, Scope?, Scopes?}`.
- `TokenManager` restores stored tokens, sets a 1h expiry when an access
  token is present, and refreshes automatically.
- `HEAD https://mail.proton.me/` with the Bearer token returns 200; the
  stock account-creation verification relies on it.

## Human verification (CAPTCHA, code 9001)

- An SRP or 2FA-submit response with `Code == 9001` and
  `Details{HumanVerificationMethods[], HumanVerificationToken, WebUrl?}`
  maps to `ProtonError::Captcha(CaptchaChallenge{methods, token,
  web_url})`. A missing `WebUrl` is constructed Captcha.tsx-style as
  `https://verify.proton.me/?methods=<csv>&token=<token>`. `Display`
  redacts token and URL. Only password logins are gated; the
  refresh-token sync path is unaffected.

## Key unlock chain

`KeysClient` (`proton-api/src/keys.rs`, auth `Bearer + x-pm-uid`):

- `GET /core/v4/users` → `User{Keys: Vec<UserKey>}`.
- `GET /core/v4/addresses` → `Address{Keys: Vec<AddressKey>}`
  (`AddressKey{ID, PrivateKey, Token, ...}`).
- `GET /core/v4/keys/salts` → `[{ID, KeySalt?}]`. Best-effort on restored
  sessions (403 on locked scope is tolerated; the derived-password path
  does not need salts).

`derive_all_passwords(password, access_token, uid)` returns
`{keyID → base64(mailboxPassword)}` (empty `KeySalt` = raw password bytes,
else salted derivation), keeping only keys that verify via
`UnlockedKey::from_armored`. Serialized form is the `DerivedPasswords`
JSON string.

Sync engines unlock in this order:

1. Derived-map hit (base64 entry → `UnlockedKey::from_armored`).
2. Address keys carrying `Token`: decrypt the armored `Token` with the
   unlocked user keys, use the plaintext as the secret (go-proton-api
   `Key::Unlock` semantics; signature verification on the Token path is
   skipped).
3. Salt fallback via the login password (only available at Verify time).

The raw login password is never persisted: it travels only as the
transient `Password` signond parameter used for `derive_all_passwords`
at Verify time. The signond secret column stays the dummy `"x"`.

## SignOn plugin contract (`type="proton"`, `mechanisms=["password"]`)

The C++ plugin (`proton-bridge/signon/proton_signon_plugin.cpp`) only
forwards the session map to `proton_signon_process` and emits what comes
back; the flow lives in `proton-bridge/src/auth.rs` (`process`/`refresh`,
unit-tested against a fake auth client). Inputs: `UserName`, `Secret`
(dummy fallback), transient `Password` (preferred when present),
`RefreshToken`, `Uid`, `AccessToken` (possibly locked),
`TwoFactorPassword` (trimmed), `HumanVerificationToken`. Branch order:

1. TOTP + refresh + UID + locked access token → 2FA submit.
2. No fresh password + refresh + UID → refresh (a failure with the dummy
   secret stops here: no SRP with `"x"`).
3. Otherwise full SRP login.

On success it derives passwords, writes `derived_passwords` to
`QSettings("proton","sync-tokens")` groups `[Uid]`/`[username]`, and emits
`store()` with `{UserName, AccessToken, RefreshToken, Uid,
DerivedPasswords}` plus `result()` with the same map (never `Secret` or
`Password`). Result shapes: success (blob + `UserName`);
`{TwoFARequired: true, AccessToken, RefreshToken, Uid}` (locked, not
stored); `{CaptchaRequired: true, CaptchaUrl, CaptchaMethods}` (nothing
stored); otherwise `NotAuthorized`/`MissingData`.

## QML agents (`ui/proton.qml`, `ui/proton-update.qml`)

- Both call `signInParameters("proton-carddav", username, "x")` (dummy
  secret) + `setParameter("Password", <real password>)`. The 6-digit OTP is
  collected in-page (`otpField`), never via signon-ui.
- Creation: `createSignInCredentials` → on `TwoFARequired`, stash locked
  `AccessToken`/`RefreshToken`/`Uid`, show OTP → `updateSignInCredentials`
  with `{Password, TwoFactorPassword, AccessToken, RefreshToken, Uid}`.
  `CaptchaRequired` shows message + methods + tappable verify link + retry.
  On success the agent enables `proton-carddav`/`proton-caldav`, sets
  `server_address`, writes `CredentialsId` as a **string**
  (`parseInt(identityId)` → `""+int`, keys `""` and `"proton-carddav"`),
  then syncs and calls `goToEndDestination()`.
- Credentials update: same parameter shape; a fresh `Password` forces SRP
  instead of a blind refresh.
- `delayDeletion` is held while async `sync()` / OTP is pending.

## Auth FFI (`proton-bridge/src/auth.rs`)

`char *proton_signon_process(const char *input_json)` with input
`{"mode": "process"|"refresh", "data": {session map}}`; output
`{store?, result?, error?: {code: "not_authorized"|"missing_data",
message}, settings?: {group: {key: value}}, log?: [..]}` (free with
`proton_string_free`). The plugin applies `settings` to
`QSettings("proton","sync-tokens")`, emits `store` then `error` or
`result`.

## References

- https://github.com/ProtonMail/go-proton-api (`manager_auth.go`, `manager_auth_types.go` (`TwoFAStatus` 1/2/3), `auth.go`, `keyring.go`, `unlock.go`)
- https://github.com/sailfishos/sailfish-components-accounts (`account.cpp`: `createSignInCredentials`, `convertValue` type whitelist, `delayDeletion`)
- https://github.com/sailfishos-mirror/signond (`signonsessioncore.cpp`, `pluginproxy.cpp`, `remotepluginprocess.cpp`; blob store except `UserName`/`Secret`)
