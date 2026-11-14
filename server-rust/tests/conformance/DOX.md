# Conformance fixture transaction boundaries

F21 SAML SP HTTP/binding, shared-link/COMMIT and worker seams (#341): [identity-saml](identity-saml/README.md); immutable qualification covers all10 entries and the all38 federation-ON audit.

The recorded-oracle contract remains in `../../DOX.md`. Fixture identities have
separate user/mailbox IDs and belong only to their disposable database.

`src/fixture.rs::remove` uses three separate PostgreSQL protocol calls: exact
append-only audit deletion with transaction-local replica mode; message deletion
committed on its own; atomic mailbox/user/domain deletion with normal FK cascades.
A `DELETE` followed by `BEGIN` in the same simple-query message belongs to that
transaction, so putting semicolons between them does not release partition locks.
Do not combine these calls. Do not suspend FK triggers for identity cleanup.

Verification: `setjoin-jmap --test set_seen_db` exercises cleanup after both
actual COMMIT-loss outcomes. The full Rust lane must leave the assigned database
empty for mailctl's bootstrap oracle. Shared cluster lock settings stay unchanged.

F12 Part B HTTP case ownership and recording seam: [chat-b/CASES.md](chat-b/CASES.md)
(#268). Its concrete registrations exclude the forwarded `/chat/` mount.

F12 user-channel HTTP/effect recordings and qualification: [channels](chat/CHANNELS.md) (#267).

F12 worker one-tick effects, cadence and recording inputs: [worker oracle](chat-b/WORKERS.md) (#268).

F22/F20/translate recordings, case kinds and the generated case table: [static1](static1/README.md) (#271).

F04 slice ownership and eDiscovery recordings: [family contract](../../crates/domains/compliance/DOX.md) (#289).
F07 MDM and lockdown HTTP/effect recordings, scope parity and serial fixture contract: [devices](devices/README.md) (#310).

F04 chat-compliance HTTP/effect corpus: [chat-compliance/CASES.md](chat-compliance/CASES.md) (#291).

F04 retention/audit/content-search HTTP/effect recordings: [case contract](retention-audit/CASES.md) (#290).

F07 MAM HTTP/effect recordings and checked post-commit notification parity: [mam](mam/README.md) (#311).

Catch-all mux and SPA HTTP oracle: [catchall](catchall/README.md) (#416).

Harness timing (#421): `Db::for_case` widens `SETJOIN_AUTHZ_PRECHECK_TIMEOUT_MS` (15 s) and `SETJOIN_PG_DEADLINE_MS` (30 s) unless set, so a starved host cannot forward an oracle request to Go; production defaults are unchanged ([authz](../../crates/authz/DOX.md), [pg](../../crates/pg/DOX.md)). Suites share one DB across the whole lane: every oracle must remove its residue (see the lane notes in the FIX9 ticket).

F18 JMAP recording and replay: [JMAP oracle](jmap/README.md) (#315). Recording
uses a proxy-only route table; retired pilot flags do not select Go. Native
replay installs the adapter with its Go upstream unset.

F18 live WebSocket and F12 presence transfer (#318), ON with live handshake/frame, lifetime, guest isolation, proxy-zero and route-mutant qualification: [push oracle](jmap/push/README.md).

JMAP2 (#316) adds the `jmap_other` HTTP target and new-tag ID registration to the
shared JMAP runner. Tag `imap_uid_validity` is wall-clock Unix seconds and follows
the corpus's timestamp substitution; counters and the presence of changes stay visible.

JMAP4 merged-method regressions (`jmap_push_recorded`) exercise Mailbox/set +
Mailbox/get + EmailSubmission/query with createdIds and zero Go proxies, and
whole-frame handoff before writes when submission attachments need #328.

F09 Rules (#329): immutable Go HTTP/effect observations live in `rules/goldens`;
recorder, replay and scope contracts: [Rules DOX](../../crates/domains/rules/DOX.md).

F18 SSE event source HTTP/frame oracle: [SSE recordings](jmap/sse/README.md) (#319), including explicit legacy and matching Host/Origin fixtures (#415).

SMTP inbound socket/storage and signed webhook recording (#348): [protocol contract](../../crates/protocols/smtp/DOX.md).

F21 login/key-custody recordings (#331): [identity-login](identity-login/README.md).

F21 token/chain and native Drive issuance (#333): `identity-token/` (front-door `setjoin-auth --test token_oracle`).
The #333 [token oracle contract](identity-token/README.md) also covers direct
chain LISTEN/reconnect admission, SIGHUP boot-mount stability and native Drive
interchange. Worker recording uses a test overlay; shipped Go stays frozen.

F21 established-session/refresh HTTP and revocation effects (#332): [oracle](identity-login/README.md#sessions-and-refresh-332).
F21 directory connector slice A (#337): [census and replay](identity-login/README.md#directory-connector-slice-a-337).

TLS/ALPN session recordings, Go-compatible tickets and reviewed ACME P-256 divergence (#413): [tlsfront](tlsfront/README.md).
Shared runtime gates, evaluator, device/DPoP/GeoIP and simulator corpus (#405): [AUTHZGATES](authzgates/README.md).

`authz-defer/` (#406) records shared terminal admission at the executable HTTP
boundary; [corpus contract](authz-defer/README.md).

Gateway configuration precedence and runtime reload recordings (#414):
[gateway-config](gateway-config/README.md).

F21 TOTP HTTP/effect and controlled-time validator recordings (#334): [MFA oracle](identity-mfa/README.md).

F21 push and possession HTTP/effect recordings (#336): [identity-push](identity-push/README.md).
F21 guest invitation acceptance HTTP/effect oracle (#342): [identity-guest-invite](identity-guest-invite/README.md).
F21 WebAuthn HTTP and stored-key algorithm oracle (#335): [corpus](identity-webauthn/README.md).
F21 owner-approved security fix 2026-11-05: hash-pinned Go baselines plus reviewed
full expectations for pending revocation and WebAuthn counter/replay refusal;
see each family's `divergences.json` and immutable `security/` expectations.

F16 conditional/range HTTP observations and HEAD qualification (#419): [Blobs case ledger](blobs/CASES.md).

F16 WORM PUT producer/cleanup retry oracle (#419): [family handoff contract](../../crates/domains/blobs/DOX.md#worm-retry-handoff-qualification-419).

F12 original presence floors replay natively with Go unset and zero proxy counters
in `gateway/tests/chat_deferred_recorded.rs` (#418); live registry cases remain
in `jmap_push_recorded` and `jmap_sse_recorded`.

F12 URL-send HTTP effects and detached fetch/image/receipt replays (#418):
[channels](chat/CHANNELS.md), [worker oracle](chat-b/WORKERS.md).

#418 immutable recording provenance: [receipt](chat-b/unfurl-recording-418.json).

Static/Assist leftovers, controlled DNS/TLS discovery and live health probes (#417): [static2](static2/README.md).
Discovery initializes its artifact parent on clean checkouts; each case directory
still requires exclusive creation and is removed by its fixture owner (#418).

F17 CalDAV HTTP recordings and real-client capture (#426): [CalDAV oracle](caldav/README.md).

F21 OIDC Provider HTTP/key oracle (#339): [recording contract](identity-oidc/README.md).
F17 CardDAV HTTP, commit outcomes and real-client recordings (#427): [CardDAV oracle](carddav/README.md).

F21 OIDC RP (#340): [identity-rp](identity-rp/README.md) owns the signed HTTPS
IdP/public HTTP/effect corpus, mechanical gateway-alias qualification, config
listener seed/tick, startup secret migration and first-party process-swap proofs.
F06 spam trainer whole-model and seed/tick recordings (#451): [spam-trainer](spam-trainer/README.md).

F08 recovery administration, signed airgap files and SSH deployment (#455):
[Platform qualification contract](../../crates/domains/platform/DOX.md#recovery-administration-455).
`platform/goldens` holds immutable HTTP/effect/SSH observations; `platform/security`
holds the reviewed #512 device-scope expectations, and `platform/ssh` holds the RSA test-key pair. The individually selectable floor target is `platform_qualification`.
F08 storage HTTP and seed-plus-one-run oracle (#459): [storage contract](../../crates/domains/platform/storage.DOX.md).

F21 mailserver-only self-service HTTP/effect recordings (#494): [oracle contract](identity-self-service/README.md).

F21 #494 qualification checkpoint and remaining owners: [closing census](identity-self-service/CLOSING-AUDIT.md); immutable sources and native-only admission invariants remain in the oracle contract.
