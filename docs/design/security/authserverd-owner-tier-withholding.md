# Decision memo: withholding the owner-tier credential from authserverd

- **Status:** Decision memo — recommendation recorded, implementation NOT authorized by this
  document. Per L2-C8 r2-2, owner-key withholding is "a standalone owner-visible decision,
  verified against authserverd's actual owner-pool use and recorded in the runbook." This memo
  performs that verification and makes the recommendation; the runbook edit and the deploy-lane
  change remain separately admitted work.
- **Date:** 2026-09-16
- **Origin:** L2 cluster C8 (deploy secret co-location, D-MAILSERVER-DEPLOY-004) residue —
  `retired-docs:glm-plan-review/nightly/packets/L2-C8-deploy-secrets-proposal/manifest.md`, r2 amendment
  item 2 (r2-2), carried unchanged through r3.
- **Scope of this memo:** documentation only. No code, no unit templates, no installer change.

## 1. Current state (post-C8 landing)

The C8 implementation split the privileged DB tiers out of `config.env` into
`/etc/setjoin/db-credentials.d/db-credentials.env` (0600 root:root, root-controlled ancestor
`/etc/setjoin` — r3 namespace posture):

- `mailserver/deploy/scripts/install.sh:120-121` defines `DB_CRED_DIR`/`DB_CRED_FILE`;
  `install.sh:783-785, 797-798` render the three privileged keys
  (`DB_WORKER_DSN`, `DB_OWNER_DSN`, `DB_DIRECT_OWNER_DSN`) exclusively into that file.
- **Both** internet-facing units currently receive the **full** file (all three keys):
  - `mailserver/deploy/authserver.service.template:73` — `EnvironmentFile={{DB_CREDENTIALS_FILE}}`
  - `mailserver/deploy/mailserver.service.template:85` — same

systemd parses `EnvironmentFile=` manager-side as root, so both units' processes carry the
owner-tier DSN in their environment for their entire lifetime.

## 2. Verification: what authserverd actually consumes

The r2-2 adjudication requires the decision to be "verified against authserverd's actual
owner-pool use." Verified against source at HEAD (2026-09-16):

| Tier | authserverd consumption | Evidence |
|---|---|---|
| `DB_WORKER_DSN` | **Load-bearing.** A dedicated worker pool is constructed when set and distinct, and is used by identity links, threat interception, push number-match, auth handlers, and guest invites — several against tables whose RLS deliberately excludes `setjoin_app` (`V156__identity_source_link_substrate.sql` FORCE RLS, "no general setjoin_app policy"). | `authserver/cmd/authserverd/main.go:225-233, 320, 528-529, 569, 585`; `authserver/internal/handlers/identity_links.go:512`; `authserver/internal/handlers/auth.go:299, 1505, 2123, 2214, 2805`; `guest_invite.go:132, 298` |
| `DB_OWNER_DSN` | **None.** The value is loaded into config by the shared base (`DatabaseOwner`, with fallback `DB_OWNER_DSN → DB_DSN`) but **no authserver code path ever reads `cfg.DatabaseOwner`**. No owner pool is constructed; the schema-version gate is a read-only `SELECT MAX(version) FROM schema_migrations` on the **app** pool. | `shared/config/base.go:56`; `authserver/cmd/authserverd/main.go:225-243` (worker pool only; schema check on `pool`); negative grep across `authserver/` for `DatabaseOwner`/owner-pool construction |
| `DB_DIRECT_OWNER_DSN` | **None.** authserverd's only direct-connection use is the LISTEN/NOTIFY listener, which consumes `cfg.DatabaseDirect` — the **app-tier** `DB_DIRECT_DSN` from `config.env`, not the owner tier from the credential file. | `authserver/cmd/authserverd/main.go:266` (`openConfigListener(listenerCtx, cfg.DatabaseDirect, ...)`) |

Contrast: the **gateway** (mailserverd) has a real owner-tier consumer — monthly partition DDL —
which is exactly the counterevidence that kept C8 a file-split rather than a credential-strip
(C8 manifest "Triage row vs today", delta 7). No analogous consumer exists in authserverd.

## 3. The proposal

Withhold `DB_OWNER_DSN` and `DB_DIRECT_OWNER_DSN` from authserverd. Per r2-2's binding shape,
authserverd would receive its **worker credential from its own file (or an
adjudication-approved subset)** rather than the full owner set — e.g. a sibling
`db-credentials.authserver.env` in the same root-controlled directory holding only
`DB_WORKER_DSN`, with `authserver.service.template` rendering that path; mailserverd keeps the
full file. `upgrade.sh`'s root-side SCHEMA_DSN probe is unaffected either way (it runs as root
against the full file and does not depend on what a unit's environment carries).

## 4. Pros (for withholding)

1. **Least privilege on the most exposed unit.** authserverd terminates unauthenticated and
   authentication traffic (login, MFA, WebAuthn, identity links, guest invites). `setjoin_owner`
   owns every table, and ownership bypasses ORDINARY row level security — but
   `FORCE ROW LEVEL SECURITY` exists precisely to remove that exemption, and the role is
   explicitly `NOSUPERUSER NOBYPASSRLS` (`scripts/provision-roles.sql:95`; the role's own
   comment at `scripts/provision-roles.sql:84-87` and the `NATIVE_RLS_FLIP_RUNBOOK.md` §2
   role table both record that FORCE re-subjects the owner). Under a live FORCE posture the
   owner holds no automatic RLS exemption — an earlier draft of this memo claimed exemption
   "by ownership" and is corrected here. The owner DSN is nonetheless effectively a full-data
   credential — by standing authority, not exemption: ownership carries unconditional table
   privileges, and the owner alone can reshape the RLS posture of its own tables
   (create/alter/drop policies, disable FORCE — after which the ownership bypass applies
   again), on top of DDL/migration/partition authority. Withholding removes that authority
   from the environment of every authserverd process — shrinkable exfiltration and escalation
   surface for `/proc/*/environ` reads, RCE follow-on dumping, and core/env capture.
2. **Closes the residual r2-2 named.** C8's whole finding (CWE-250, deployment privilege
   co-location) is that credentials flow to consumers that do not need them. Delivering the
   owner tier to a unit with zero owner consumption is the same defect at file granularity —
   the r2-2 adjudication explicitly left this last slice as an owner-visible decision rather
   than re-deciding C8's scope.
3. **Behavior-neutral today, verifiable cheaply.** The shared base falls back
   `DB_OWNER_DSN → DB_DSN` (`shared/config/base.go:56`), and no authserver code reads the
   owner tier, so withholding changes no runtime behavior on any current install — before or
   after the native-RLS flip. The verification cost is the Section 2 audit plus pins (§6).
4. **Aligns with the documented role model.** The runbook's role table assigns `setjoin_owner`
   to "migration/DDL tooling"; the AGENTS.md invariant assigns `DB_OWNER_DSN` to
   "partition/DDL ownership." A second internet-facing binary carrying the owner tier is an
   accident of file topology, not of design intent.
5. **Precedent-consistent delivery.** Per-unit credential files already exist in the same
   installer (`auth.env` for authserverd; the updater's root-only tree), and C8 r3 already
   established the root-controlled namespace these sibling files would live in.

## 5. Cons (against withholding, with mitigations)

1. **The r2-2 lesson inverted: silent fallback masking.** The same `DB_OWNER_DSN → DB_DSN`
   fallback that makes withholding behavior-neutral today also means a **future** authserverd
   owner-pool consumer would silently run as the app role instead of failing on a missing
   credential. That is fail-soft in the wrong direction. *Mitigation (required):* fail-loud pins
   — a render-lane assertion that authserver's unit never receives owner keys, and a
   startup/CI guard that authserverd constructs no owner pool — so the day someone adds one,
   a test names the missing credential instead of aliasing silently (mirroring how r2-2 caught
   r1's contradicted inert claim).
2. **Operational asymmetry.** Two units, two credential deliveries: install.sh's split
   migration, re-run `get_env`/`get_cred_env` recovery paths, and the rollback runbook must all
   track which unit gets which file. §4.6 rollback instructions currently tell the operator to
   point `DB_DSN` back at "the `DB_OWNER_DSN` value from the credential file" — that sentence
   must become unit-aware. *Mitigation:* one-way migration in install.sh's established
   idempotent style; runbook + install-summary + backup-guidance text updated in the same
   change (the surfaces C8 WP-1.6 already enumerates).
3. **Future owner-tier work in authserverd would need a deliberate re-grant.** If identity sync
   or threat policy ever legitimately needs owner authority, an operator must edit the
   credential delivery, not just a config key. *Assessment:* this is the intended friction of
   least privilege; the re-grant is a one-line render change inside an already
   root-controlled namespace.
4. **Not the documented-status-quo route.** The alternative disposition (declaring the
   co-location a documented posture violation) was explicitly rejected at C8 because it "would
   decide more than this packet should" (manifest delta 7). This memo keeps that boundary: it
   recommends; it does not strip a consumer that provably uses a credential — and Section 2 is
   the proof the worker tier (kept) and the owner tier (withheld) are correctly classified.

## 6. Recommendation

**Withhold `DB_OWNER_DSN`/`DB_DIRECT_OWNER_DSN` from authserverd.** Deliver `DB_WORKER_DSN` to
authserverd from its own adjudication-approved subset file in the existing root-controlled
`/etc/setjoin/db-credentials.d/` namespace (exact name/mode per the r3 posture rules); keep the
full file for mailserverd only. Conditions that must land with the change, in one package:

1. Section 2's verification is recorded (this memo) and re-run at implementation time —
   "split files; do NOT strip credentials from a consumer that provably uses them" (r2-2).
2. Fail-loud pins per §5.1 (render-lane owner-key assertion for authserver's unit; no-owner-pool
   guard for authserverd), non-vacuous per the C8 WP-3 genre.
3. Consumer sync: install.sh migration/rollback learns the subset file exactly-once and
   preserves credential values; `upgrade.sh` probe unchanged (root-side, full file).
4. `docs/guides/NATIVE_RLS_FLIP_RUNBOOK.md` §4.6 and the fresh-install note name which unit
   receives which file; install summary and backup guidance gain the new path.
5. Existing installs adopt via the installer's one-way migration; rollback remains the §4.6
   procedure, updated per (4).

## 7. Decision record

| Field | Value |
|---|---|
| Decision requested | Owner-tier withholding from authserverd (C8 r2-2 adjudication) |
| Verification result | Owner tiers unconsumed by authserverd; worker tier load-bearing (§2) |
| Recommendation | **Withhold** (§6), with the five landing conditions |
| Implementation authority | Not granted by this memo; deploy-lane change + runbook edit remain separately admitted |
