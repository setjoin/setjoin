# Shared authentication runtime (#420)

Owns auth-process feed refresh and token retention, process-local security
configuration listeners, GeoIP use and the threat interceptor used by password
protocols. Request reads use DB_DSN, cross-tenant task access DB_WORKER_DSN
(fallback DB_DSN), notification subscriptions DB_DIRECT_DSN (fallback DB_DSN).
No SET ROLE. Authserver shared-effect tasks transfer by the whole-binary process
swap (#331), never two concurrent authorities. Local caches run in both processes.

`RuntimeTasks::cleanup_tick` runs Go's two independent DELETE statements: rotated
OAuth tokens older than 60 seconds; OIDC access older than five minutes with no
live refresh and no recent revocation. One statement per original transaction;
worker context owns cross-user retention. `oracle/seed.sql` + `cleanup-go.json`
record the survivors through frozen Go's two public task functions.

Run `cargo test --locked -p setjoin-threat -- --test-threads=1` with the assigned
strict DB credentials. Go recording uses `gofree_record` and AUTHRT_ORACLE_DIR;
recorders refuse overwrite. Ordinary replay never invokes Go.

The shared `Gate` exports the existing protocol ThreatGate/ConnectionMeta seam;
IMAP re-exports it for compatibility. Pipeline order is feed acquisition, IP rule,
country, lockout, spray, CAPTCHA/tarpit (HTTP only), rate, pre-auth CA, feed reject.
IP allow continues through later steps as Go does. `record` preserves independent
best-effort attempt/sign-in, lockout and scoped device writes; post-auth evaluates
verified user/groups with the shared policy engine. Protocols skip CAPTCHA. Lockout keys
and attempt rows bound long names on every protocol (`bounded_name`: at most 255 bytes,
distinct per name past that; divergences `lockout-key-name-bounded`, `attempt-username-bounded`).
`Gate::refusal` writes a refused request's row under `refusal_budget` (per source and outcome, one
INSERT...SELECT; divergence `http-refusal-rows-bounded`; rows affected come from the command tag via
`protocol_statement_count`). `captcha_needed` also
replenishes one row per window/(2S) seconds whenever the source has no `captcha_needed` row in that
gap. Bound per source and instance, with S = max(tarpit threshold, 29)+1 and P = request-pool size:
at most S + P rows from the budget branch plus at most P rows per replenishment gap, i.e.
<= S + P*(2S+1) `captcha_needed` rows per tarpit window under fully concurrent bursts; sequential
traffic stays <= 3S+1 rows per window.
Clustered expiry cannot empty the tarpit window only after continuous traffic of at least
threshold × gap (threshold = `tarpit_threshold`, gap = window/(2S)). Before that there is a named
dip: after a short burst expires, the window can briefly hold fewer than threshold rows. The dip
closes at request rate: once the window holds fewer than S rows, the budget branch writes one row
per refused request.
Suppressed-row summary (CWE-779): when a budget-bounded INSERT writes 0 rows, `Gate::refusal` and
the HTTP `http_refusal` call `note_suppressed_refusal` (`src/suppressed.rs`). It counts the outcome in
a process-wide `SuppressedRefusals` static (fixed outcome index, no allocation per call) and, at most
once per 60 s per process, writes one stderr line "threat refusal rows suppressed by budget (since last
report): ..." with the non-zero per-outcome counts only, in a fixed outcome order. The line carries no
source IP, username or user agent. Database errors are not counted. The first suppression after start is
reported at once, then at most one line per 60 s; counts left after a flood ends are reported with the
next suppression at least 60 s after the previous report.
`attempt` and `record` keep one row per call.

`Watchers` owns independent direct LISTEN connections for `config_changed` (Go's
feature_toggles listener) and `conditional_access`. Subscribe before reload,
notifications are authoritative-reload hints, reconnect waits 1–30 seconds and
reconciles gaps. Feature subscription/reload is boot-critical; CA setup retries.
Auth CA reload clears stale break-glass on errors; gateway keeps its own posture.
Dropping Watchers aborts its owned tasks and direct connections.

`AuthDenylist` is the auth process's positive-match snapshot, reconciled at boot
and every 30 seconds, with failed reads retaining existing rows. No auth-process
NOTIFY subscription (Go has none); it is independent from gateway sessions.

Boot requires all eight Go SecuritySeededKeys, allowing explicit environment
overrides; missing seeded controls refuse startup before serving. Later reloads
retain Go’s conservative failure posture rather than reapplying the boot tripwire.
The authoritative flag snapshot also requires a registry singleton in observe
or enforce mode, matching Go’s boot and reconnect validation. Only the fixed
registered threat/CA keys are consumed by this crate.

Admission query budgets: threat-feed and `ip_rules` reads each use Go's
three-second `queryTimeout`. A feed timeout or error scores no hits (Go parity:
the feed is optional reputation data and pool exhaustion is caught by ip_rules on
the same pool); an `ip_rules` timeout or error rejects (`ip_rules_unavailable`,
#367). Cancelling a query must leave the pool reusable;
`tasks::ip_rule_lookup_uses_go_three_second_query_budget` exercises that boundary.

Worker pools (#367): `WorkerPools` holds two bounded `ScopedExecutor`s on
DB_WORKER_DSN (fallback DB_DSN): `check` (8) for lockout_check, detect_spray and
the spray side effects, and a reserved `record` (2) for lockout_clear/escalate so
pre-auth floods cannot starve failure accounting. Checkout waits 1 s, creation
2 s, statement 2 s (server-side cancel on timeout). Fail closed on any error:
`lockout_unavailable`, `spray_unavailable`, `rate_limit_unavailable`,
`captcha_unavailable` (HTTP only). Side-effect writes stay best-effort, one
statement per key. `Gate::load` refuses boot when the worker credential lacks
EXECUTE on the lockout accessors (SQLSTATE 42501); an unreachable DB still boots.
Deployments must point DB_WORKER_DSN at setjoin_worker. Tests: `tests/gate_pool.rs`.

`oracle/divergences.json` records the owner-requested immediate gateway session
reconciliation after a LISTEN gap; the auth-process cache keeps Go's independent
30-second schedule and no notification subscription.

HTTP adapters may reuse the exported `fingerprint`/`mask_ip` codecs (#339). Persisted rows use `stored_fingerprint` and `cap_agent` (512-byte user agent cap, divergence `stored-user-agent-capped`); `device_hash` keeps hashing the whole `fingerprint`.
The OP oracle pins the same anonymous `agent|masked-IP` attempt metadata.

`registry` (ProtocolSessionRegistry) and `tracker` (per-user ConnTracker) moved here from
`setjoin-imap` (#501) so IMAP and SMTP submission share one implementation; IMAP re-exports them.

`ip_rule_blocked` returns `Result<bool, ()>` for auth HTTP ingress: no match or allow is `Ok(false)`, block is `Ok(true)`, and timeout/query/decode failure is `Err(())`. HTTP rejects errors with 403 and `ip_rules_unavailable`, matching the protocol gate's approved fail-closed divergence (#367, #342, #346). See `oracle/divergences.json`.

`decide_with(CaptchaStep)` serves HTTP (#349): `Full` without a captcha token, `Skip` for a verified and claimed token (Go), `TarpitOnly` for a token that fails; `decide(_, true)` stays `Skip` for protocol listeners. HTTP lockout checks the `ip:` key even without a username (#349 divergence).

`Gate::engine(&self) -> &Engine` exposes the watcher-invalidated `conditional_access` policy engine so `setjoin-auth` can evaluate login/issuance CA policies without a second engine or cache (#351).

`ThreatGate::check_account_lockout` (#355b) checks `lockout_state` (`user:`/`ip_user:`/`ip:`) for a resolved Kerberos user without double-incrementing `rate_limit_counters`; `ThreatGate::record_ip_failure` records an unattributed SPNEGO failure in `auth_attempts` and escalates `ip:` lockout on the reserved record pool.
