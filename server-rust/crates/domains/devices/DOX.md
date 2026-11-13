# Devices (F07, #310–#312)

`setjoin-devices` depends only on foundation crates (`authz`, `contracts`, `db`, `pg`).
The gateway translates HTTP (`bins/gateway/src/devices.rs`); PL/pgSQL reducers keep business
authority. The actor and mailbox come from the sealed auth context; path ids name targets and
never grant authority. MDM state and lifecycle rows (`mdm_device_state`, `devices`, `device_enroll_events`)
stay reducer-owned. MAM evidence uses one scoped INSERT into `device_events` per Go
transaction. Shared authz gates (#405: device trust, revocation, lockdown) read the
authority rows exactly as Go leaves them; those gates are not here.

## Slice map

F07 has 36 routes in three slices; the inventory assigns every route to exactly one:
`mdm` (11, this ticket: `/admin/mdm/*` and `/admin/devices*`), `mam` (10, #311: `/admin/mam/*`)
and `offline` (15, #312: `/admin/offline/*`, `/offline/*`, and the MDM notify worker, which that
ticket owns). MAM and offline extend this crate in their own modules.

## Slice mdm (#310)

- Gates mirror Go's chain from the live governed grants (`authority`): `requireMamRead`
  (`mam.read`) for reads, `requireMamWrite` (`mam.write`) for writes. A refusal writes Go's durable
  `console.denied` audit row and answers the bare 403. The four policy writes also pass
  `requireOrgWideSurface`: a domain-scoped principal gets a 403 and an audit row naming its domain.
- MDM device list/get and the wipe arm carry the domain scope in the same statement (a scoped admin
  sees only devices whose owner is in its domain; out of scope is `device not found`, 404). Reads run
  in a `READ ONLY` transaction with the admin actor GUC, as Go's `RunUserScoped` did.
- Writes: wipe calls the existing `mdm_device_wipe_arm` (state, core audit row, `device_events` row,
  `device_policy` notify) and the lockdown transition invokes `device_enroll_transition` through
  the invoker-rights `rust_device_enroll_transition` scope wrapper
  (state, `device_enroll_events` row, core audit row, `conditional_access` notify on revoke); the
  oracle shows identical effects. Policy create and update are one statement each; delete and reorder
  call the new `rust_mdm_policy_delete` / `rust_mdm_policy_reorder` (Go's multi-statement
  transactions). Follow-up: retire Go's copies once Go is deleted.
- Request bodies decode with `gojson`: Go's `json.Decoder` error text is echoed by the policy routes
  (`invalid JSON: ...`), so the syntax scanner and `UnmarshalTypeError` messages are ported
  (unit-tested against Go output and recorded as goldens). Only the first value is read.
- Go quirks kept: policy update always writes `scope_id` (absent means NULL); the list ignores
  `status|platform|user_id` filters; `?limit=` of the device queue is clamped to 500 and read with
  `Atoi` (garbage means 100); transition ignores a malformed body (empty reason); the queue and
  per-user device list read on the request pool with no actor GUC and the 404 of GET device hides
  every read failure.
- Row security: the oracle cases run on one credential that bypasses RLS (the pre-flip posture) and
  `rls` cases keep the `setjoin_app` role. Go's lockdown transition runs on the request pool with no
  actor GUC, so under the app role every transition is a 500 (`device_enroll_events` insert refused):
  reported as a Go bug. The Rust wrapper uses a function-local empty user GUC to preserve that failure,
  including for the actor's own device (`transition_rls_own`); it restores the caller scope on return.
  No accepted divergences.
- Not here: the CAE, device-trust, revocation and lockdown request gates (#405), offline
  devices and the MDM notify worker (#312).

Security fix 2026-11-05 (#435, owner-approved divergence from Go): the lockdown console used to
ignore the grant's domain scope. The approval queue, the per-user list and the transition are now
confined to devices of users inside the caller's reach (`admin_can_reach_perm` over `mam.read` /
`mam.write`: domain from the stored device owner, OU and scope-set narrowing included, an
organization-wide grant reaches everyone). The transition computes the reach in its own statement and
`rust_device_enroll_transition(.., p_in_scope)` answers a foreign device exactly like a missing one
(BZ095 `device_not_found`, 409). Reviewed record: `tests/conformance/devices/divergences.json`.

Qualification and recorder usage: [HTTP oracle](../../../tests/conformance/devices/README.md).

## Slice mam (#311, default ON)

`src/mam.rs` extends the existing family adapter. Global and group policy map
writes call invoker-rights reducers reproducing Go's data transactions. A separate
receipted notification transaction preserves Go's checked post-commit outcome:
a notification failure reports 500 with policy data already committed. Each
phase has its own operation ID; an unknown commit never reports success.
Organization-wide policy configuration is gated by the live `mam.read`/`mam.write`
grants, including domain-scoped grants, exactly as Go registers these routes.
Global NULL-device keys intentionally insert duplicates on repeated writes.
MAM qualification: [HTTP oracle](../../../tests/conformance/mam/README.md).

The MAM device list projects registry ids and joins MDM state by owner and
fingerprint. Per-device endpoints resolve those ids through the same owner to
`devices.id`; registry-only devices have empty event history and refuse writes.
Event reads/inserts and per-device policy UPSERTs carry domain reach in their own
statements. Lock/unlock commit one evidence INSERT, then notify. Per-device map
writes use `rust_mam_device_policy_set`, then a separately checked evidence INSERT,
then notify, preserving both committed-policy and committed-evidence failure paths.

MAM policy maps use Go field-name folding (including long-s/Kelvin), first-value
JSON decoding, map merge across duplicate fields, and null string values. Group
non-pointer scalars ignore null after an earlier value; MAM retains those values
locally while the existing pointer-field decoder remains unchanged.

Event detail JSON mirrors Go's map[string]any float64 decoding and number
formatting, including large-integer rounding; it never rewrites stored details.

## Slice offline (#312)

`src/offline.rs` and the gateway's `src/offline.rs` implement the offline console
and user HTTP contracts. All JSON paths mount under `/api`, including
`/api/offline/size-estimate` and `/api/offline/wipe-ack`. Policy and toggle routes require live `mail.offline_policy`; the
pending queue requires `mam.read`. Raw JSONB reads preserve PostgreSQL's bytes
without an Encoder newline. All 36 F07 routes now default ON after their complete corpora pass.
Recorder/replay lives in `tests/offline.rs` and `tests/offline_oracle/` in the gateway.

Writes call the invoker `rust_offline_command` adapter to the same offline
reducers Go calls; function-local empty user scope preserves Go's request-pool
RLS behavior. The toggle branch reproduces Go's one toggle/audit/notify
transaction. Notification errors roll the transaction back, as Go's aborted
transaction does despite its best-effort comment. Receipts preserve unknown
COMMIT outcomes. Ack takes the canonical `devices.id`; administrative transitions
take `user_devices.id`. Ack's existing reducer repeats ownership in its UPDATE.
Size reads use the worker credential with the verified user predicate across all
that user's mailboxes; attachment size and other users' messages are excluded.

### MDM notify (#312)

The gateway always starts its cancellable process-local MDM observer task;
`RUST_WORKERS_ON=mdm-notify` remains an accepted handover catalog name.
Frozen Go cannot subscribe: `notify.Dispatcher` rejects `device_policy` before
opening a LISTEN subscription. Its named goroutine therefore waits forever on
an unregistered channel. Rust preserves the two startup messages and dormant
behavior; it does not add a policy-push bridge. There are no shared effects, so
coexistence is safe. The handover oracle additionally proves that
`GO_WORKERS_OFF=mdm-notify` stops Go's named goroutine.

`tests/mdm_notify_recorded.rs` records the actual Go process with the worker
both enabled and disabled, publishes valid and malformed notifications, and
compares unchanged rows/audit, no outbound requests and observable MDM logs.
Rust replay starts the executable without Go and proves clean task cancellation.
The dispatcher vocabulary gap is a mirrored Go functional bug, not a divergence.

Offline qualification compares 144 immutable HTTP/effect observations, 15 route
status mutants, real audit/notify/owner/extra-state mutants and eight before/after
COMMIT cuts. The detailed branch map is
[`COVERAGE.md`](../../../tests/conformance/offline/COVERAGE.md). The gateway
preserves Go's >2KiB chunking and unsized HEAD behavior, plus the distinct toggle
read-error problem detail. SQL boundary and existing offline/QoS suites cover 65
assertions. Scoped admin device access gaps and missing-GUC behavior remain Go
parity facts; they are not accepted divergences.

The toggle bypasses the non-equivalent `feature_toggle_set`: that reducer
requires an audit reason, writes different before/after evidence and emits
`config_changed`, while Go's offline endpoint audits `offline_toggle` and emits
`caps:offline`. A post-parity authority-reconciliation follow-up is supplied in
#312's closeout for the orchestrator to post. Preserve the recorded contract
until that separate behavior decision.

## Security fixes (#511)

Owner-approved security fixes 2026-11-05 (ARCH-029 exception). Tests: gateway `tests/secfix5.rs`
(foreign refused like missing / own allowed / organization-wide allowed), re-baselined goldens
under each family's `security/`, mutants in `scripts/test-secfix5-mutants.py`.

- #435 lockdown: see the mdm slice above.
- #440 offline: `rust_offline_command(.., p_reach)` refuses approve/deny/revoke/wipe of a device
  outside the caller's `mam.write` reach (BZ100 `not_found`, like a missing device); the reach is
  computed in the mutating statement from the owner stored on the `user_devices` row. The pending
  queue calls `rust_offline_devices_pending(actor)` (reach over `mam.read`). Ack is unchanged
  (own device only, by mailbox).
- #513 item 1 lives in `setjoin-authz` (`device.rs`): the lazy re-seal of a legacy plaintext device
  secret runs through `rust_device_secret_reseal` (worker-owned, keyed on id and the exact plaintext
  just proved), so it works under app RLS where Go's no-GUC UPDATE matched nothing.
