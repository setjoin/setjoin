# HTTP threat admission oracle (#349a)

`setjoin-auth --test threat_oracle` drives the auth listener directly. While recording it talks to
the frozen Go authserverd (`GOFREE_RECORD_UPSTREAM`); on replay it talks to the native server
with no Go upstream (a forward would answer the owner 503 and fail the contract).
Routes: POST /auth/login, /auth/refresh and /auth/forgot-password/{begin,verify,reset}.

Cases are named `<preset>-<route>-<what>`; test names are `go_<preset>_*`. Presets mirror
scripts/gofree-record.sh:
- `off`: the five env controls off; `feature.rate_limit` is set per case.
- `threat`: everything on, no GeoIP, rate 3/min, captcha/spray 3, fixture CAPTCHA_SECRET,
  trusted proxy 127.0.0.1.
- `geo`: threat plus us.mmdb, which resolves every address to US.
- `tarpit`: geo with geo_block and captcha off and threshold 2.

Each case binds its own source address 127.0.0.(40+index). 203.0.113.5 is reached only through
X-Forwarded-For from 127.0.0.1. Per-case state is cleared before and after.

A Go-derived contract is checked in both modes: status and X-Threat-Reason per step, attempt
outcomes, and the delay header against the actual sleep. A recording that breaks the contract
is refused. Without a golden, replay checks the contract only (`GOLDEN-PENDING`).

Approved security divergences (divergences.json):
- Cases with a different Rust response (`threat-login-captcha-{wrong,expired}`: a failed
  token keeps the tarpit, 429) replay against Rust's contract. The Go golden is only checked
  for its recorded statuses (`GOLDEN-EVIDENCE`). `threat-login-captcha-solved` stays on Go's
  200 contract with default thresholds: a verified, claimed token skips the tarpit.
- Cases where only effects differ (`off-begin-lockout-divergence`, `off-refresh-jwt-email`,
  `off-login-captcha-bogus`) strip those effects, assert the Go half on the golden and the Rust
  half on the replay, and compare everything else.
- Long usernames (`attempt-username-bounded`): attempt rows and lockout keys store a bounded,
  distinct-preserving name on every protocol; authentication and captcha binding see the whole name.
- Refusal rows (`http-refusal-rows-bounded`): each source writes refusal rows per outcome under a
  budget (telemetry: one per 60 s; `captcha_needed`: max(tarpit threshold, 29)+1 per tarpit window,
  plus one replenishment row per window/(2*budget) seconds under sustained traffic, under fully concurrent bursts at most S + P*(2S+1) per window (P = request-pool size; sequential traffic at most 3S+1 per window)). Clustered expiry cannot empty the tarpit window only under continuous traffic of at least threshold × gap (gap = window/(2S)); before that a short burst's expiry can leave the window briefly below threshold rows; that dip closes at request rate, since below S rows every refused request writes a row. Budget-suppressed rows are counted, not logged per row: one stderr summary line per 60 s per process; counts left after a flood ends are reported with the next suppression at least 60 s after the previous report. Success and failure rows are unchanged.
- Replay mints #349 bound captcha tokens; recording mints Go-format ones.

Record with the dispatch-only `gofree-record.yml`: `go_upstream=authserverd`,
`package=setjoin-auth`, `test=threat_oracle`, one dispatch per preset
(`case_filter=go_<p>_`, `extra_env=GOFREE_RECORD_AUTH_PRESET=<p>` for p in off, threat, geo,
tarpit).

`native_*` tests pin:
- the missing-gate 503;
- preflight forwards and the CA read-error forward with zero admission rows;
- request-pool and worker-pool faults: 403, no handler, no forward, no row;
- forgot-password enumeration and timing parity;
- trailing-bytes keying, the empty-username `ip:` lock, and spray;
- refresh victim protection;
- bound and single-use captcha tokens, rate-limited failed checks, and no used-set slot for a
  rate-limited request;
- mapped peers and mapped forwarded sources;
- duplicate keys, tarpit concurrency, the 15 s body cut, atomic counters, config derivation;
- stamp and forward source checks.

## Known limits

Device headers (`lib.rs:1176-1187`), the `dpop_jwk` forward and guest-invite still hand the
whole request to frozen Go's admission. The Rust-only hardening (trailing-bytes username,
ip-only lockout, bound single-use CAPTCHA) can therefore be sidestepped through those paths
until #350, #352 and #349b land.
