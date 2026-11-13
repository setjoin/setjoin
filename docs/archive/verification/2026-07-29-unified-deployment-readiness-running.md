# Unified deployment-readiness — retained-run evidence

**Date:** 2026-07-29
**Authorized host:** `linux-ci-host`
**Candidate branch:** `codex/unified-deployment-readiness`
**Owned prefix:** `sj-ready-20260729-1`
**Owned subnet:** `172.30.241.0/24`

This is a resumable evidence record for the retained A/B/C run. It is not yet
the terminal release verdict: the directory-source 24-hour interval has passed,
the distinct authentication-only OIDC interval is running, and the remaining
D4 transition/rollback and D6 terminal restore, chaos, browser, OFF-state, and
cleanup gates remain open.

No pre-existing host container was modified. No production credential,
certificate, customer data, or private key was used. Federation and LDAP
private keys stayed inside their exact prefixed environments; retained
cross-environment evidence contains public CA certificates only.

## Topology and versions

- A/B/C are independent privileged systemd containers at `.11`, `.12`, `.13`.
- Private authoritative DNS is `.53`; SMTP sink `.60`; TLS LDAP `.61`.
- A/B/C initially ran schema V173 and the same candidate `mailserverd`; the
  retained gates exposed upgrade and real OIDC defects subsequently closed by
  V174–V177. All three now run schema V177 and the same candidate binaries.
- Native-RLS roles and explicit app/worker/owner DSNs were retained from D2.
- Feature state during the composition soak on A:
  `guest_accounts=ON`, `identity_model_v2=ON`, `federation=ON`,
  `identity_normalized_reads=OFF`, `identity_transitions=OFF`.
  Guest remains OFF on B/C.

## Completed gates

### D2 — Native-RLS and disaster recovery

Passed role attributes, owner/worker/app separation, FORCE-RLS ownership,
cross-mailbox denial, database and blob backup, isolated restore, restored
ownership, dependency-order runtime health, and permissive/constrained restart
checks. Evidence:

```text
test-results/deployment-readiness/sj-ready-20260729-1/d2/
```

### D3 — Guest Accounts

Passed Guest-OFF baseline, isolated DNS/MX SMTP delivery, acceptance using the
real MIME URL, mandatory TOTP enrollment, constrained Chat/Meet app rail,
accepted/superseded/revoked/expired/legacy-unknown terminal handling,
re-invite/recovery, stale-token refusal, visible browser terminal states, and
Guest toggle restoration. Guest user 7 remained active and mailbox-less for
the later composition leg. Evidence and screenshots:

```text
test-results/deployment-readiness/sj-ready-20260729-1/d3/
```

### D4 — Identity canary, directory pass; authentication window running

- Real LDAPS bind/search and normalized sync passed.
- Source `ldap:d4-corp` is active in shadow mode at generation 4.
- Two exact LDAP people have active source links; Guest source links remain 0.
- A malformed `legacy:ad` source is isolated without suppressing the healthy
  LDAP worker.
- The directory observer passed `D4_WINDOW_PASS`: generation 4 accumulated
  more than 117 completed batches spanning more than 28 real hours, with zero
  nonterminal batches and zero Guest links.
- A real Setjoin-to-Setjoin OIDC authorization-code flow now passes from A
  (RP) to C (OP), including C password login, mandatory TOTP enrollment,
  authenticated authorization completion, code exchange, stable identity-link
  resolution, A session issuance, and `/auth/me`.
- The authentication-only source
  `oidc:1b4f2bebc780ae0a12c3fb335cbb7eaedfee506c68569345` has generation 1,
  four matching comparisons, zero mismatches, and zero open divergences. Its
  independent real-authentication window began around
  `2026-07-30T16:09:30Z`; the resumable observer supplies another real flow
  every four hours until the database reports eligibility.

Evidence:

```text
test-results/deployment-readiness/sj-ready-20260729-1/d4/
```

### D5 — three-stack Federation

Passed:

- private SRV discovery on production port 7443;
- per-environment CA/leaf keys and public-anchor-only exchange;
- wrong-anchor rejection after active old-stream eviction;
- A–B and A–C mTLS streams with no B–C allow-list/bypass;
- bilateral DM and hub/spoke room delivery with exact origin attribution;
- same numeric message ID from B and C while A was partitioned, exact-once
  relay after reconnect, ACK convergence, and zero inbox gaps;
- B CA/leaf rotation: old anchor rejected, explicit new public anchor approved,
  stream reconnected;
- room-scope downgrade to DM: visible revoke advisory, read-only mirror, and
  re-invite gap marker;
- partitioned kick: queued straggler poisoned, no A/C leakage, BZ213 after
  mirror closure, then explicit re-invite;
- bilateral A/C peer delete: allow-list, outbox, peer, inbox, and cursor rows
  all zero before clean re-add and new room delivery;
- cap=3 backpressure: depth warning occurred before park; explicit re-invite
  recovered the member; temporary configuration rows were removed.

Evidence:

```text
test-results/deployment-readiness/sj-ready-20260729-1/d5/
```

### D6 — composition soak, running

With Guest, Identity model v2, and Federation simultaneously enabled on A:

- the active Guest sent exactly one message in an allowed local channel;
- binding that Guest-bearing channel to Federation refused with exact BZ216;
- Guest mailbox count remained 0;
- Guest normalized identity-link count remained 0;
- Guest lifecycle-authority count remained 0;
- B/C Guest toggles remained OFF;
- Federation outstanding outbox count returned to 0.

Evidence:

```text
test-results/deployment-readiness/sj-ready-20260729-1/d6/
```

## Product and rehearsal defects found and closed

1. `mailctl` decoded `secretConfigured` as bool although the server may return
   a bool map. It now validates the exact bool-or-object JSON union.
2. Normalized source dry-run accepted TCP reachability without LDAP bind/search.
   It now invokes the production connector's bounded dry-run.
3. Stored source secrets were passed as Base64 text rather than decoded bytes.
   Runtime decoding now fails closed on malformed encoding.
4. One malformed active legacy source could crash-loop startup and suppress a
   healthy normalized source. Catalog snapshotting now isolates bad sources and
   starts healthy workers with explicit diagnostics.
5. AD/LDAP periodic cycles silently discarded returned sync errors. They now log
   failure and have unit coverage.
6. A Federation service statically configured while the feature was OFF exited
   its accept goroutine permanently. The accept loop now remains dormant while
   OFF and starts after a live enable; the boot-OFF/live-ON regression is pinned.
7. Private test DNS published Federation SRV port 443 instead of 7443.
8. Broad journal windows confused an old successful connection with the active
   wrong-anchor phase. D5 now uses exact journal cursors.
9. Four container heredocs omitted `docker exec -i`, allowing a false-success
   no-op. All are fixed and a red-first structural guard prevents recurrence.
10. Replacing the binary before applying V173 correctly caused startup refusal.
11. The real 24-hour identity cadence exposed that reducer-only changes are not
    carried by binary/schema upgrades unless versioned. V174 now embeds the
    corrected whole-rail shadow gate; no timestamps or batch rows were altered.
    The runbook now fixes the required schema-before-binary rolling order.
12. Normal systemd restart stalled 35 seconds because overseer did not release
    the inherited listener on SIGTERM. The gateway now signals the local
    overseer worker before HTTP shutdown. Live B measurement changed from
    `35s` to `0s` and logged `gateway stopped cleanly`.
13. The D6 evidence query used the nonexistent `chat_messages.user_id`; it now
    asserts the authoritative `author_id`.
14. The OP authorization request stored only its request ID while the OIDC
    library generated a separate bearer code. V176/V177 now bind completion to
    the authenticated subject and store only the generated code's SHA-256
    digest with one-use transactional consumption.
15. Nil client-scope callbacks panicked during token exchange. Stored clients
    now provide callable passthrough callbacks with regression coverage.
16. The RP library's default nonce verifier rejected a valid nonempty nonce
    before the handler's exact HttpOnly-cookie comparison. Library nonce
    verification is disabled only at that layer; the request-bound cookie
    verifier remains authoritative and tested.
17. OP email/profile claim lookup was unscoped under FORCE RLS and returned an
    empty email. It now parses the exact subject, enters a user-scoped database
    transaction, and selects only that user ID.
18. The OP client omitted the userinfo-in-ID-token assertion flag, causing the
    library to strip email claims from code-flow ID tokens. The flag is now set
    and an actual ID-token integration test pins email and `email_verified`.
19. The retained container lacked the installed `/opt/setjoin` upgrade helper,
    while the candidate source mount was read-only. The runbook now records the
    mounted-source helper fallback and writable-copy web build procedure.
20. Independent review found that same-user completion replay could overwrite
    the original OP `auth_time`/ACR/AMR before code exchange. Completion is now
    one-shot for every user and the DB integration test pins both same-user
    replay and cross-user takeover refusal.
21. The first auth observer trusted only a PID, so a recycled process number
    could falsely look alive. Its PID record now also carries Linux process
    start ticks; status and stop require both to match. It also refuses to
    reset the disposable IdP administrator unless exactly one active
    shadow-mode OIDC source remains, and rejects intervals above four hours.

## Independent review disposition

Claude Code Opus 5 at xhigh reviewed the OIDC/V175–V177 and observer diff
read-only after Codex's own analysis. Accepted and closed: one-shot completion,
PID-reuse-safe observer identity, source-mode precheck, and an explicit
four-hour maximum cadence. Rejected with code evidence: a claimed V176→V177
`code_hash` race (V176 has no such column; V177 adds the column and unique index
in one transactional migration, while row locking serializes consumption), a
claimed 28-hour cadence (seven observations at t=0 through t=24 use six
four-hour intervals), and making intentionally pre-code rows non-null. The
cookie-only RP nonce path remains intentionally fail-closed on cookie loss; the
user restarts the bounded login flow rather than accepting a server-side
fallback that weakens request binding. Per-source login-abuse controls remain
owned by the existing authentication threat/rate-limit rail rather than a new
security-definer counter in the shadow reducer.

After those corrections and the post-upgrade real flow, the same independent
reviewer withdrew the contradicted findings and returned **10/10, no remaining
blocker**. Its final basis was the one-shot completion integration proof,
digest-only/write-once/atomic code lifecycle, exact RLS claim scope,
fail-closed nonce binding, PID/start-tick observer identity, source-mode
precheck, 19/19 contract mutations, and four real matching authentications with
zero mismatch or divergence.

The new `scripts/check-unified-deployment-contracts.sh` and its red-first
self-test cover the recurrent script classes without needing a remote stack.
The reusable operator procedure is
`docs/guides/UNIFIED_DEPLOYMENT_READINESS.md`.

## Local verification

Passed on the candidate tree:

```text
go test ./cmd/mailserverd ./internal/federation ./internal/admin ./internal/ad ./internal/ldapsync
go test ./...  # mailctl
bash scripts/check-unified-deployment-contracts-selftest.sh
bash scripts/check-unified-deployment-contracts.sh
bash scripts/check-agent-context-budget.sh
bash scripts/check-deploy-doc-currency.sh
git diff --check
graphify update .
graphify hook-check
```

## Open terminal gates

1. Let the distinct OIDC authentication observer accumulate at least seven
   matching real logins spanning 24 hours, then run
   `unified-deployment-d4-auth-observer.sh verify-window`. The LDAP directory
   gate has already passed and its elapsed time is not reused.
2. Complete the documented normalized-read cohort, transition, attach/detach,
   reconnect, concurrency, protected-account, divergence pause, immutable
   rollback, and legacy-read legs.
3. Complete the remaining Federation receipt/quarantine/eDiscovery and
   dependency-order three-stack restart assertions.
4. Complete D6 stopped-target combined restore, bounded dependency failures,
   authenticated member/Guest/identity/Federation browser smoke, and terminal
   side-effect reconciliation.
5. Restore exact pre-run toggle/config/trust snapshots, prove all gated toggles
   OFF, remove only exact prefixed resources, and record single-host
   limitations.
