# Runtime request gates (#405)

`runtime_access::RuntimeAccess` is installed once by main, initialized before accepting
connections, and checked before every locally dispatched frozen-Go `requireAuth` route.
The route middleware inventory defines coverage; public SPA and auth routes stay outside.
Adapters still own credential/resource authorization. Terminal authentication and guest admission are installed alongside this chain by
#406; unported Basic/protocol strategies retain #420 ownership.

Order matches Go: signed device compliance, device revocation, conditional-access lockdown,
positive session revocation (even CAE OFF), then CAE cold-cache refusal, DPoP, sign-in frequency
and policy re-evaluation. Break-glass bypasses policy and lockdown only in Go's respective
places. Lockdown is active only with conditional_access and a nonempty break-glass exclusion.
Go supplies no runtime client type, completed factors or bound-device state to its evaluator;
Go main also installs no limited_web context projection. Preserve those facts.

`DB_DSN` request credential reads flags, org policy, membership and device proof reducers.
`DB_WORKER_DSN` supplies explicit cross-user session/device revocations and pending terms.
`DB_DIRECT_DSN` only LISTENs. No pooled SET ROLE. The runtime shares session caches with JMAP
and device caches with WS. With no explicitly configured session worker it owns a process-local
cache; it never disables Go's copy or performs singleton/shared side effects.

A subscribed `conditional_access` listener is acquired before initialization, invalidates on
NOTIFY and again after reconnect (subscribe first to close event gaps). Cache errors preserve
Go's startup fail mode and last-good break-glass. Raw metadata has a 30 s TTL; user memberships
60 s. Session listener retains its existing reconnect/refresh contract. A shutdown guard aborts
on gateway cancellation; normal shutdown signals and joins tasks with a bounded wait.

All runtime problem/map bodies are built in `problem.rs`, including Go's machine titles,
sorted map keys, empty remediation and newline. Device denial maps keep Go's JSON media type.
DPoP uses the external path without query; device HMAC uses Go's `/api`-stripped path+query.

Verification and recorded effects: [AUTHZGATES corpus](../../tests/conformance/authzgates/README.md).
`ca_remaining` proves 28 ON-gate cases (including NOTIFY), seven simulator cases and two
mutants, zero upstream metrics, exact headers/bodies/audit/rows. Transition oracles now use
the real CAE flag and request credential; their old private toggle view is removed.
`jmap_db` checks the native central chain independently of pilot route toggles.

Attachment runtime proofs use `authz::runtime::Proof::attachment`, which delegates to
`token::attachment` (dedicated HS256 kid/scope and existing HKDF verification). Only
GET/HEAD attachment paths, including the API mount, admit that proof. Main supplies
`JWT_MAIL_ATTACHMENT_SECRET` (fallback `JWT_SECRET`) and
`JWT_MAIL_ATTACHMENT_PREVIOUS_SECRET`, matching F16; device-HMAC secrets remain separate.
Signed device, derived JTI, family and issue time pass through the same gate order.
The adapter still owns origin-session, device, policy-generation and blob ownership checks.

Flag lookup precedes proof selection. A presented credential that cannot produce a
runtime proof is refused locally with401 when any runtime gate flag is enabled;
unsupported credentials cannot silently bypass a gate. Guest-status and flag read
errors refuse locally with503, using the canonical `problem.rs` struct encoder.
These refusals never dispatch the adapter or add a Go fallback. HTTP fault/control
coverage is `runtime_access_failures`; gated attachment recordings and the skipped-gate
mutant live in `attachment_transfer` and are described in the corpus README above.

The enabled device branch calls `DeviceCache::revoked_enabled` using the flag already
read for this request. It must not query the toggle again: a later read failure could
otherwise erase the authoritative ON decision. The shared cache still uses the worker
credential and Go's cold/stale behavior. `runtime_access_failures` injects a flag source
that succeeds once then errors, seeds a real revoked fingerprint, and checks the HTTP
refusal. Existing callers that need to resolve their own toggle retain `revoked`.
