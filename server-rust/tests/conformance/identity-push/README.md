# Push and possession HTTP oracle (#336)

`setjoin-auth --test push_oracle` records the actual front door against covered
frozen Go at `GOFREE_RECORD_UPSTREAM`, then replays with both Go upstreams unset
and verifies zero Go proxy hops. Use the assigned disposable database,
REQUIRE_DB=1 and one test thread. Recording refuses to overwrite captures.
The synthetic signing fixture is the existing identity-login key; VAPID uses
32 bytes of value 1 and database encryption uses 64 hexadecimal 2s.

VAPID discovery is public: foreign and malformed bearer/body input does not
restrict its public key (parity with Go). No identity mutation is performed.
Possession cases compare response bytes, full owned grant tuples, failure
budgets and audit effects; returned random grants are masked only after checking
the persisted hash, owner, JTI, operation, scope, generation, family and TTL.
The family advisory lock protects shared key/toggle fixtures for each case.

Recovery regeneration validates all ten returned eight-character hex codes
against the complete stored bcrypt array before masking codes/salts. It pins
Go's 2a/10 format, proof consumption, one generation and checked audit; repeats
preserve the newly stored array. Go does not constrain target_ref for this
operation (TargetBound is false when the consumer passes nil); the unused-target
capture pins that behavior rather than applying a stricter tuple interpretation.

Push verify's valid-input “success” is Go's410 refusal, including a correct answer
and valid pending proof. No challenge, binding, counter or token store changes.
The endpoint never completes a login; native approval and status polling own it.

Status captures verify the exact-token harvest before masking issued tokens.
Repeat, foreign owner/session, expired, legacy-AMR and burnt-but-unapproved
cases pin the security boundary. Native replay uses bundled inventory defaults;
only recording mode overrides entries to the frozen Go listener.

Approval fixtures generate a real device key and sign each current server-bound
assertion. Go acceptance proves interoperability before signature/time/device-ID
masking. Foreign device, malformed/extra fields, stale/bad signatures, signed
wrong codes, third-strike burn and replay compare exact responses and counters.

Send checks code/nonce shape, TTL and exact persisted pending binding before
masking random values. Cross-tenant caller identity fields are ignored: Go only
creates the signed principal's challenge. The IP-cap capture resets the owned Go
process first; saturated-user requests still consume its separate IP budget.
`push_delivery` tests the external native-device boundary: a decoder anchored to
the existing Go ECIES vector receives and decrypts the payload, signs approval,
harvests valid tokens once and checks revoked/unreadable/invalid/foreign exclusion.

Password-login observations are appended to #331's existing auth/gateway suites,
without replacing its cases or decisions. The pending signature, credential
version, principal and exact challenge binding are checked before masking.
Push-only, TOTP fallback, exhausted push-only and credential-denial cases pin
selection; failed credential events with NULL user_id are scoped by fixture email.

Management WebAuthn possession records the UV-required options and checks their
challenge hash against the complete owned server ceremony before masking it.
No transport cookie or grant is accepted as ceremony authority; response/effect
replay uses the same bundled inventory and zero-Go-hop assertions as push.

Namespace/HEAD qualification files preserve actual_method/actual_path alongside
the normalized registration, matching the adequacy catalog's route identity.
Original wire captures stay immutable; qualification captures are independent
Go observations and both are replayed. Every replay/mutant prints the integration
gate receipt after strict comparison, including zero-Go-hop namespace requests.

`push_oracle commit_*` uses the existing receipt-marked PG wire proxy for twelve
publishing commands, before and after COMMIT: no secret/success response, full
rollback before, domain effects after, fresh actor lookup and refusal for foreign,
disabled or revoked authority. Each test owns and reaps its proxy task. Recovery uses a multiplex tunnel for its
separate worker and revocation-reader pools; its earlier account budget is
independent of the factor commit.
Recovery handler qualification disables/restores the outer #420 threat controls;
its own enumeration IP budget, fixed account window and proof locks stay active.
Recorders should listen below the Linux ephemeral range (e.g.27336);47336 can
collide with a PostgreSQL client TIME_WAIT after restart. Unexpected502/503 or
outer captcha refusals are rejected before a recovery golden is written.

Cookie CSRF uses direct real Go/native auth HTTP for the controller capture,
plus an independent native front-door403 assertion (same body and the shared
no-store/nosniff envelope). All other route captures traverse the actual front
door to frozen Go; native replay proves zero Go hops. The final inventory census
contains31 default-ON MFA registrations:8 TOTP,8 WebAuthn and15 push/possession.
The retired return-to-Go switch is excluded by the owner decision2026-11-04.
