# Storage E3/E4 — bounded plaintext consumers

Date: 2026-09-08. Required integration contract before implementation; not an
envelope format, key-cache implementation, numerical score or runtime claim.
Owners: [Storage E3/E4/E5 work order](storage-specification-completion-map.md),
D11/D12 key admission
and [shared reader protection](storage-lifecycle-protection-contract.md).

## Observed seams

Root read `mailserver/internal/blob/handler.go:300–455`, whole-file SHA-256
`17702fdf0fd793ca77b3d3598af37e290dc87a7ac332f5785e8c73f50c220e53`.
The current handler checks Mail/HR ownership before its in-memory hash-keyed
plaintext cache lookup. Small non-Range responses can populate that cache; other
reads use a seekable object and HTTP Range handling. Preserve ownership-before-
cache and bounded-cache intent. These bodies do not establish future encryption-
generation/key-admission binding or authenticated-frame Range verification.

The preview/Office map,
sandbox/spool map and
export map identify other
plaintext consumers and explicit omissions. They are prior bounded evidence, not
fresh full-source reads in this packet. An S3-only envelope does not automatically
protect database text/indexes, HTTP client caches, converter temporary files or
externally submitted sandbox samples.

## Admission and cache identity

| Boundary | Required behavior |
| --- | --- |
| Every request | Revalidate current caller/domain authority and selected representation before returning cached or newly decoded bytes; physical protection is not read authorization |
| Cache identity | Bind security scope, exact immutable representation, placement/encoding identity and relevant key/admission epoch. Plaintext hash alone must not merge security scopes or revive a revoked generation |
| Cache hit | Same current admission requirements as a miss. Warm plaintext cache cannot bypass key revocation/expiry, an unavailable required dependency or an ineligible D12 scope |
| KMS grace | Only D12-eligible ordinary I/O under its unchanged active generation, valid required in-memory key material and original deadline may continue. Cached plaintext alone does not establish this eligibility; no deadline renewal through hit, retry or process restart |
| Revocation/expiry | Deny newly attempted affected access, invalidate affected cache entries/admission and terminate in-flight release according to the concrete E4 boundary. Keep unrelated authorized scopes independent; do not treat this as ciphertext deletion |
| Completed delivery | Do not promise recall or erasure of bytes already delivered to an authorized client, application or external service. Client-side offline policy remains its separate authority |

E4 must freeze exact admission/epoch invalidation, streaming checkpoints and
final durable-write checks. No future helper may silently accept a stale cached
authorization merely because its underlying object is unchanged. Invalidation
is an access/lifetime control, not a claim that every plaintext copy has been
cryptographically erased from RAM, swap, dumps, browser caches or third parties.

## Decode, Range and consumer lifetime

E3 must specify authenticated framing, verified length/termination and Range
mapping before replacing a seekable plaintext object with ciphertext. Client
offsets refer to the authorized plaintext representation, never ciphertext byte
offsets passed directly to existing consumers. Authenticate every released unit;
detect missing final framing and truncation. Incremental verified delivery must
not be misrepresented as verification of the entire object before completion.
After headers/partial delivery, use a detectable failed transfer and incomplete
operation receipt; a status200 cannot certify a complete verified file.

Seek/retry/Range must bind the same immutable representation and independent
reader protection until dependent physical access settles. Converter/scanner/
export adapters declare streaming, seek or whole-buffer requirements explicitly;
whole-buffer consumers receive finite per-item and aggregate memory limits,
concurrency/backpressure and timeout/cancellation behavior. Do not implement a
nominal streaming wrapper that still materializes every large object in RAM.

Temporary plaintext binds one task/operation and least-privilege location with
recorded ownership, bounded lifetime and cleanup/reconciliation after success,
failure or crash. Cleanup cannot delete another task's files, protected recovery
bytes or a file still used by an accepted worker. Age alone is not proof of
ownership or completion. Disk-encryption observation and explicit deployment
policy determine at-rest claims; object envelopes do not justify calling an
ordinary temporary directory encrypted.

External analyzers/editors require explicit admitted content scope and provider
retention/cleanup disposition. Local cancellation does not revoke already-
submitted content or prove external deletion. Logging/progress/errors carry safe
metadata and correlation identifiers, not raw document bytes, key material or
arbitrary provider response bodies. No new external submission is authorized here.

## Proposed cases — none executed

| Case | Required oracle |
| --- | --- |
| PC-01 cross-scope cache | Same plaintext hash in different security scopes cannot reuse unauthorized admission or expose another scope's existence/content |
| PC-02 warm-cache denial | Revoke permission/key, expire grace or change generation after cache fill; cached and uncached requests obey the same current policy |
| PC-03 grace and restart | Warm plaintext without eligible key material does not qualify; hit/retry/restart never extends deadline or unlocks another generation |
| PC-04 authenticated Range | Boundary/multi-range/seek/truncation/corruption cases release only verified admitted units with correct plaintext offsets and detectable incomplete transfer |
| PC-05 resource envelope | Concurrent converter/scanner/export requests, slow clients and cancellation stay within declared memory/temp/concurrency bounds without silently accepting incomplete output |
| PC-06 temporary ownership | Crash and retry preserve live-worker ownership while reclaiming only reconciled task residue; no blanket temporary-directory cleanup |
| PC-07 external lifetime | Already accepted external sample/edit task remains separately tracked after local cancellation; no false remote deletion or delivered-byte recall claim |

E9 binds cases to exact source consumers, profile, schema/format vectors and
retained evidence; aliases to existing LP/SB/EH cases must not inflate test counts.
Exact sizes, deadlines, cache epochs and crypto parameters remain joint engineering
outputs after E0 census, not arbitrary constants chosen in this integration packet.
