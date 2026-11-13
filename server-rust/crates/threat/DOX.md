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
verified user/groups with the shared policy engine. Protocols skip CAPTCHA.

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
three-second `queryTimeout`. A timeout continues the pipeline with no match;
cancelling the query must leave the request pool reusable. The blocked-table
`tasks::ip_rule_lookup_uses_go_three_second_query_budget` exercises that boundary.

`oracle/divergences.json` records the owner-requested immediate gateway session
reconciliation after a LISTEN gap; the auth-process cache keeps Go's independent
30-second schedule and no notification subscription.

HTTP adapters may reuse the exported `fingerprint`/`mask_ip` codecs (#339).
The OP oracle pins the same anonymous `agent|masked-IP` attempt metadata.

`registry` (ProtocolSessionRegistry) and `tracker` (per-user ConnTracker) moved here from
`setjoin-imap` (#501) so IMAP and SMTP submission share one implementation; IMAP re-exports them.
