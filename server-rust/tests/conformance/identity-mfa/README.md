# Identity MFA TOTP (#334)

`setjoin-auth --test mfa_oracle` records the actual front door against covered
frozen Go, then replays with both Go upstreams unset and zero Go-hop counters.
Use the assigned disposable DB, REQUIRE_DB=1 and `--test-threads=1`. Hold the
shared identity fixture advisory lock for the full lifetime; cleanup removes
only owned rows and restores the saved rate toggle. Existing goldens are
compared, never overwritten. Mutant mode cannot record.

Record a new case with GOFREE_RECORD_UPSTREAM pointing at the private covered
Go auth listener, using the synthetic signing key from identity-login/keys.json
and DB_ENCRYPTION_KEY of64 hexadecimal2s. Go must load that key before startup.
The corpus compares response bytes and headers plus committed user, step-up,
pending-enrollment, possession-grant and audit effects. Random credentials and
pending secrets are masked only after checking their persisted hash, ownership,
JTI, TTL and provisioning-secret linkage.

`totp_vectors.go.txt` is a test-only overlay of the public Go validator. Its
immutable `totp-vectors.json` pins the three accepted windows and malformed
codes at the recorded Unix time. Rust also checks the RFC6238 SHA-1 vectors
projected to Go's six-digit profile. Shared JWT/password/key vectors remain in
the foundation and existing identity-login suites.

Ownership is explicit: TOTP seven routes in #334; WebAuthn in #335;
push, recovery codes, possession proof issuers and forgot-password begin/verify
in #336. Stateful threat/device and conditional-access admission remain #420/
#405 whole-request forwards before effects. Completed shapes have no switch
back to Go, per the standing owner decision.

`goldens/` retains the immutable red-green tracer captures. `qualified/` contains
separate live-Go recordings with the complete adequacy format: full source hash,
normalised request, explicit admin/auth audit and real LISTEN drains (session
revocation and both mailboxes' tag channels), plus mailbox/factor state. When a
tracer exists, replay checks it strictly before checking the qualified document.
Every concrete TOTP route has success, cross-tenant denial, invalid input, repeat
and a real wire-status mutant. Resume repeats compare the exact pending envelope
and expiry before normalization. Dynamic foreign secrets exclude accidental TOTP
collisions; ownership tests keep JTI equal across principals to isolate user scope.

`catalog.py` appends the eight default-ON inventory registrations and their exact
per-case replay selectors. Native replay uses the bundled decisions unchanged;
recording alone forces the proxy target. The subtree capture retains real method
and path alongside its `* /auth/totp/` registration (unknown404 and wrong-method405).
`mfa_faults` checks real COMMIT loss and authenticated, actor-bound outcome lookup.
For the live swap proof, set GOFREE_MFA_SWAP_UPSTREAM to the private frozen-Go
listener and run `mfa_oracle verify_success -- --exact --nocapture`: Rust validates
both issued signatures and persisted links, then Go's `/auth/me` verifies the
actual Rust access/refresh tokens. No fixture keys rotate and no sessions reset.

`totp-secret-vectors.json` supplements the time-window vectors with fixed-time
frozen-Go public generator results for legacy base32 padding, unused bits,
whitespace, case and malformed Unicode. Its test-only overlay never enters Go's
runtime. Replay tests the public Rust TOTP algorithm; HMAC remains ring and
base32 validation remains the maintained data-encoding codec.

Owner-approved security fix 2026-11-05: revoked pending tokens cannot mint.
`divergences.json` pins the original Go bytes and independently authored complete
secure HTTP/effect expectations. The accepted cycle stays spent. A SQL mutant
removes only this check, reproduces Go success and fails the secure expectation.

Owner-approved security fix 2026-11-05 (#498): a TOTP time-step counter is single-use
per user and factor. Frozen Go re-accepts a still-valid code once its rolling 30-second
guard elapses (recorded against real Go as `verify-elapsed-code-replay`, source e6af2a7).
Rust claims the counter in V278 `totp_counter_claims` (FORCE RLS), so the replay and the
legacy rolling replay get 401. Mutants `mutant_elapsed_totp_replay_restores_go_bug` and
`mutant_legacy_totp_counter_gap_restores_go_bug` remove the `SECURITY-COUNTER` blocks,
reproduce Go's bytes and fail the secure expectation.
