# ADR: ARCH-023 — Connectivity-aware optional work boundary

**Status:** Accepted for E0 contract implementation; execution remains absent and
all future behavior defaults OFF

**Date:** 2026-08-11

**Authority:**
`retired-docs:superpowers/plans/2026-08-11-connectivity-aware-sync-resource-qos.md`

## Context

Setjoin already has reducer-authoritative offline policy, device registration,
JMAP delta/window sync, an encrypted native SQLCipher store, and shell bridges. It
does not yet have one bounded mechanism that decides when optional mail work may
run under weak or expensive connectivity. Adding trigger-specific retry loops or a
second native sync engine would duplicate policy, consume resources needed by send
and security paths, and make platform capability claims difficult to prove.

The first milestone must therefore freeze interfaces and evidence before adding a
feature key, schema, scheduler, token, or native execution path. Contract presence
is not capability presence: E0 may describe a later behavior but cannot report it
as implemented or enabled.

## Decision

### Authority and scope

PostgreSQL reducers remain the policy and authorization authority. The existing
JMAP/offline sync implementation remains the mail-data authority. A future client
scheduler may only admit, order, pause, cancel, and budget optional work after it
re-reads the reducer-derived projection. Native shells may report normalized
conditions and offer bounded execution opportunities; they never select accounts,
authorize blobs, widen policy, or create a second sync engine.

The first release is mail-only and foreground/reconnect-first. Browser offline,
Drive, Chat, Meet, updater traffic, location/station prediction, DSCP, `tc`, cgroup
shaping, Windows BITS, background URLSession, and persistent plaintext staging are
outside this program. A later unit may advertise background execution only in a new
signed shell build with retained physical-device proof.

### Work and rollout states

Optional work has exactly three ordered classes: `interactive`, `background`, and
`opportunistic`, with candidate deficit quanta 8/4/1. Policy rollout has exactly
`off`, `observe`, and `execute`; intersection always chooses the narrower mode.
`off` admits nothing. `observe` records privacy-safe decisions but performs no
automatic work. `execute` still requires effective policy, authenticated device,
runtime capability, resource eligibility, and the program flag.

Candidate bounds are frozen for measurement: global optional concurrency 2,
per-account concurrency 1, one transport/concurrency slot reserved from optional
work, a 64-record step ceiling, and yield after 2 MiB or five seconds. Queue age is
at most seven days. Retry begins at one second with full jitter and caps at five
minutes. Only committed progress or a materially new authenticated trigger resets
backoff.

### Critical activity invariant

Send/draft mutations, authentication and session/revocation work, outbox mutation,
and security-state requests remain outside the optional queue. Their existing seams
feed one process-local `criticalActivity` counter:

1. optional admission requires the counter to be zero;
2. a `0 → 1` transition aborts optional network I/O immediately;
3. only the last atomically committed checkpoint survives an abort;
4. optional admission remains closed until five seconds of uninterrupted Critical
   quiet; and
5. optional work can never allocate the reserved Critical slot.

No runtime percentile controller may relax this invariant. Later saturated-load
evidence must show Critical p95 regression at or below both 5% and 50 ms, p99 at or
below both 10% and 100 ms, and peak process CPU/RSS at or below 10% over the frozen
baseline.

### Bounded sync-step contract

`syncWindow` and `syncDelta` remain compatibility entry points. E2 may factor them
into `syncWindowStep` and `syncDeltaStep`, but one step must accept an
`AbortSignal`, injected monotonic deadline and budget, and a versioned
content-minimal checkpoint. It performs at most one query/changes page and 64
metadata records or the remaining byte/time quantum. It never advances the server
cursor before the matching local page commit. The frozen TypeScript contract is the
compile-time seam; E0 does not refactor the current sync implementation.

### Native capability truth

The optional `backgroundWork` bridge contract is versioned independently. Version
1 exposes only normalized network cost, power/charging/thermal state, storage
pressure, execution mode, and proven capability booleans. It carries no SSID,
carrier, IP address, location, user/account/content metadata, or authorization
decision. Unknown versions or enum values deny the capability and narrow execution
to `foregroundReconnectOnly`.

An opportunity/event is a hint. TypeScript reloads authoritative state before work.
Every acknowledged opportunity completes exactly once; expiration cancels work and
leaves the last committed checkpoint replayable. E0 defines this shape only and
does not add it to any production shell bridge.

### Attachment transfer boundary

A later native transfer uses one exact route,
`GET /mail-attachment/{sha256}`, and a five-minute one-blob bearer sent only in the
`Authorization` header over TLS. The token is generation-bound and every Range
request must recheck live session-family, device, blob-ownership, feature, and
policy authority. Token bytes never enter logs, URLs, checkpoints, analytics, or
support bundles. E0 freezes the route and transport contract; E3 owns all token,
authorization, Range, storage, and revocation implementation.

### Evidence truth

One manifest names every required case, owner, fixture, lane, state, timeout,
disposition, and retained artifact. Validators reject missing, duplicate, unknown,
skipped, failed, ambiguous, malformed, or flaky-after-retry required results.
Decision evidence is allowlisted and content-free. Cleanup evidence records each
owned resource before and after cleanup and treats a verified `already_clean` state
as idempotent success.

E0 may capture a pre-V209 baseline and freeze comparison rules. E1 alone may claim
that the retained pre-V209 binary works against V209/V210 and that feature-OFF
reducer/HTTP output is byte-for-byte compatible. Missing future browser, native,
Ubuntu, physical-device, or population evidence stays `NOT RUN` and keeps the
corresponding capability false.

## Migration and rollback sequencing

E0 adds no feature key, schema, reducer, route, bridge method, or runtime admission.
E1 must add the feature seed and custom additive DDL in V209, then generate the V210
registry projection from the completed catalog. V210 contains no hand-written DDL.
Rollback first sets the flag and winning mode OFF, drains/yields at a checkpoint,
then deploys the retained older binary; additive columns remain.

## Consequences

- E1 and E2 can proceed independently only after E0 contracts and baseline capture
  are accepted.
- UI and native adapters consume the same reducer-derived policy projection and
  cannot invent a second resolver.
- Unsupported or unproven background capability is a truthful product state, not a
  skipped test or operator override.
- Server host shaping requires separate measured evidence and a separate decision.
- Any future contract widening must update the scenario manifest, conformance
  evidence, owning DOX, and rollback proof in the same change.

## Alternatives rejected

- Trigger-specific background loops: duplicated admission, retry, and resource
  policy.
- Native authorization or a second sync engine: authority drift and replay risk.
- One-active-token database state: unnecessary for immutable, live-rechecked reads.
- Automatic host QoS: no measured contention evidence yet.
- Conditional platform promises: capability names without physical proof are not
  implementation.
