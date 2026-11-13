# User mail settings and profile (F19, #306..#309)

All 29 F19 routes are ON; F19 has no workers. `inventory_guard` asserts every F19 route is ON.

`setjoin-user-settings` depends only on foundation crates (`authz`, `contracts`, `db`, `pg`)
and no other family crate. The gateway adapter `bins/gateway/src/user_settings.rs`
translates HTTP (one `Intercept`, a method/pattern `action()` table); business authority
stays in reducers or Go's own single statement. Every F19 route is gated by Go's
`requireAuth` only: the actor comes from the sealed auth context, path ids, query strings
and bodies name targets and never grant authority, and the verified user sits in the same
WHERE as every write (R1-R3). A missing or failed token check forwards the untouched request
to Go. Frozen Go is authoritative (ARCH-029/030). Later slices add modules here and arms to
the adapter's table; they reuse `scope`, `envelope`, `command`, `done`, `s`, `nano`,
`go_marshal` and `go_f64` in `lib.rs`.

## Slice map (all 29 F19 inventory entries, exactly one slice each)

Guard: `inventory_guard::user_settings_slice_ownership_is_exhaustive_and_disjoint`.

| Slice | Routes | State |
| --- | --- | --- |
| `settings-a` (#306, `src/settings.rs`) | 11: `/settings/imap`, `/settings/view`, `/settings/undo-send`, `/settings/newsletter-bundles` (GET+PUT each), `GET /settings/signatures-list`, `PUT /settings/signatures`, `DELETE /settings/signatures/{id}` | ON |
| `settings-b` (#307, `src/prefs.rs`, `src/sync.rs`) | 9: `/user/notification-preferences`, `/user/vip-senders`, `/user/automatic-replies`, `/user/approval-delegation` (GET+PUT each), `PUT /user/offline/sync-preferences` | ON |
| `settings-c` (#308, `src/security.rs`) | 7: `/user/sessions`, `DELETE /user/sessions/{id}`, `POST /user/sessions/revoke-all`, `GET /user/devices`, `GET /user/login-history`, `POST /user/sign-ins/secure-account`, `GET /user/security-score` | ON |
| `profile` (#309, `src/profile.rs`) | 2: `POST /user/profile`, `GET /user/quota` | ON |

Every route mounts at `/api` (`inventory.rs` lists family 19). The oracle is shared:
`tests/settings_oracle/mod.rs` owns masking, observation, goldens, planted mutants and cleanup;
each slice adds a module (`a.rs`) with `route`, `seed`, `request`, `wanted`, `snapshot`,
`plant_foreign` and a `match slice` arm in `run_inner`/`a_route`, a test target
`settings_<slice>.rs` and goldens under `tests/conformance/user-settings/goldens/`
(`<slice>-<action>-<label>.json`, `divergences.json`). The catalog/ON flip script is kept
outside the tree (`tmp/gofree/settings1/catalog.py`, one `SLICES` entry per slice).

## Slice `settings-a`

- `users.view_prefs` is one JSONB document shared by `/settings/view`, `/settings/undo-send`
  and `/settings/newsletter-bundles`. Go reads it as text and decodes into a Go map, so
  every number is a `float64` (`go_f64`: `f` format inside 1e-6..1e21, else `e` with Go's
  exponent shape), objects render in sorted key order (`go_marshal`), and a NULL column, JSON
  `null`, a non-object document or any read error answers the defaults.
- `PUT /settings/view` stores the re-marshalled body (`null` stores JSON null, an array or
  scalar body is Go's 400 `invalid json`); `offlineWindow` must be a string in
  `7d|30d|90d|180d|365d|all` (400 `invalid offlineWindow`). One `UPDATE`, so one receipted
  Rust statement. `PUT /settings/newsletter-bundles` is Go's one `view_prefs || patch`
  statement likewise (patch holds only the given keys). `PUT /settings/imap` is Go's one upsert:
  an omitted field binds NULL, so the INSERT half violates a NOT NULL column and the request
  answers Go's 500 `database error` unless all four fields were present (mirrored).
- `PUT /settings/undo-send` is Go's SELECT then UPDATE, so it calls
  `rust_settings_undo_delay_put` (one transaction; a NULL/null/non-object document is replaced).
  The delay is clamped to 5..30 and decoded as an `int` (`7.5` or a string is 400).
  `GET` reads `undoSendDelay` as `int(float64)` (amd64: an out-of-range value is the minimum
  int64) and answers 5 for any other type.
- `PUT /settings/signatures` calls `rust_settings_signature_put` (the 100-row admission,
  `is_default` clear, upsert and `set_signature_default` role flip in one transaction; Go counts
  outside the transaction). Rust still performs Go's count read first so the validation order
  (alias, lengths, count, `default_for`) matches. `is_default` is a JSON **string** (`"true"`);
  a JSON bool is 400. Body cap 128 KiB (400, not 413). `DELETE` is Go's single
  `DELETE ... WHERE id AND user_id` (204, or 404 `signature not found`).
- Raw `{"status":"ok"}` replies are written without a Content-Type, so Go sniffs
  `text/plain; charset=utf-8`; `WriteJSON` replies are `application/json`.
- Timestamps render in UTC (`nano`), as the other families do.
- Planted family mutants: `no-tenant-filter` (an extra foreign signature row an unfiltered list
  would surface) and `double-bump` (a trigger rewriting `view_prefs` a second time). No-audit
  and no-notify are not applicable: these routes write neither.

## Slice `settings-b`

- Every write is Go's whole transaction as one receipted statement: the notification-preferences
  upsert, or one call of an existing reducer (`vip_sender_set`, `set_vacation`,
  `set_approval_delegation`). The primary mailbox for automatic replies is taken from the verified
  user inside the same statement; Go's earlier 404 `mailbox not found` read stays a separate read.
  Reducer errors keep Go's mapping: `BZ046`/`BZ047` (400 `invalid automatic-reply settings`),
  `BZ119` (400 `invalid approval-delegation settings`), everything else the 500 `database error`.
- Notification GET skips a row whose scan fails in Go (a NULL in a plain column) and renders `TIME`
  as `HH:MM:SS.ffffff`. `device_fingerprint` follows `google/uuid.Parse` (36, `urn:uuid:`, braced
  with an unchecked closing byte, or 32 hex digits) and is stored canonical lower case.
- Frozen-Go bugs mirrored (ARCH-029): `vip_senders` is FORCE-RLS on the user GUC that Go never
  sets, so GET lists nothing and every add is a 500 (delete is a silent no-op); the wrappers
  `rust_vip_sender_set`/`rust_vip_senders_list` clear the GUC function-locally. `GET
  /user/automatic-replies` without a stored row scans NULLs into plain fields and answers 500.
  `PUT /user/offline/sync-preferences` can never succeed under `setjoin_app`: `CallScoped` sets only
  the mailbox GUC, so the reducer's UPDATE finds no row and raises `BZ100` (409 problem);
  `rust_offline_device_set_preferences` mirrors it. Rust's 200 body is therefore not covered by a
  golden (the happy path needs the owner role); every gate (toggles, device claim, `syncQoS.mode`)
  and every validation is.
- `sync-preferences` needs the token's signed `device.id` (`Authorized::device_id()`), both offline
  toggles (DB rows only; Go's env overrides are not read) and a registered device
  (`sha256(fingerprint)` on the user's oldest matching device). Closed gates answer Go's
  `404 page not found` (text/plain, nosniff). Body: 4 KiB, one object, unknown keys rejected.
- No new family mutants: `no-tenant-filter` and `double-bump` stay settings-a's. Oracle labels
  live in `tests/settings_oracle/b.rs`; the `repeat` case of sync-put starts from Go's 409.

## Slice `settings-c`

- Writes are Go's whole transaction as one reducer call keyed by the verified user (R3):
  `rust_session_revoke_one` (web `jti` arm, else the oauth family arm, else the family-less
  single-token fallback; `not_found` is Go's 404 `not found`), `rust_sessions_revoke_all` and
  `rust_secure_account_self`. They compose the existing `revoke_user_sessions` / `secure_account`
  reducers, so denylist rows, audit rows and the `session_revoke` / `admin:alert` notifications are
  Go's. The secure-account address is the gateway's resolved client IP (`Intercept` context).
  `DELETE /user/sessions/revoke-all` is the `{id}` route with id `revoke-all` (404).
- `current` flags the web session whose id equals the token's `jti` (`Authorized::token_id()`).
- Reads: sessions render `{"sessions":[...]}` (oauth refresh/xoauth2/app_password roots plus
  unexpired web sessions, newest first, RFC 3339 seconds UTC). Devices and login events run under the
  user GUC like Go's `RunUserScoped`; a failed devices read answers `{"devices":[]}`. Login history
  uses `ParseLimitOffset(50, 200)` (offset ceiling 1,000,000, unparsable or out-of-range limit is 50)
  and any `outcome` other than `""`/`success` lists failures; `from`/`to` are ignored.
- Accepted divergence (see `divergences.json`): `GET /user/devices` renders `last_seen`/`created_at`
  with Go's `%v` of a `time.Time` in the Go process's local zone; Rust always renders UTC
  (`... +0000 UTC`), identical wherever Go runs in UTC.
- No new family mutants: `no-tenant-filter` and `double-bump` stay settings-a's.

## Slice `profile`

- `POST /user/profile` is Go's one `UPDATE users SET display_name, updated_at = now() WHERE id`
  (no audit, bump or notify), so one receipted Rust statement with the verified user in the WHERE.
  Body decode is `json.Decoder` on `{display_name}` (any type error, an array or scalar body or an
  empty body is 400 `invalid JSON`; `null`, `""` and whitespace-only after Go's `TrimSpace`
  (Unicode White_Space, same set as Rust `trim`) is 400 `display name is required`; more than 255
  runes after trimming is 400 `display name is too long`). The reply is the trimmed name,
  HTML-escaped. A NUL byte reaches Postgres and is Go's 500 `failed to update profile`.
  Problems are Go's `WriteProblemStatus` bodies (`instance` is empty).
- `GET /user/quota` sums `used_bytes`/`quota_bytes` over every mailbox of the verified user
  (disabled included; other users' mailboxes never) and answers `{"quotaBytes","usedBytes"}`.
  Go scans the numeric sums into `int64`, so a sum beyond `int64` is its 500 `database error`;
  Rust reads the sums as text and parses `i64` for the same outcome.
- Oracle: `tests/settings_oracle/p.rs`. Frozen Go's start-up reconciles `used_bytes` from stored
  messages, so the oracle re-applies the storage figures (`p::reapply`) once Go is running.
  The profile cases snapshot only `users`; the quota cases also snapshot `mailboxes`.
- No new family mutants: `no-tenant-filter` and `double-bump` stay settings-a's, `no-audit` and
  `no-notify` settings-c's.

The fault, concurrency and host-timezone divergences in the family oracle were
reviewed by the owner on 2026-11-03 (#468); their recorded baselines stay unchanged.
