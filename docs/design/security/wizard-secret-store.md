# Design sketch: wizard-held encrypted secret store (cross-run S3 identity persistence)

- **Status:** Design sketch — C8 residue (the "C8 r2 gap"). Not an executable plan; no
  implementation is authorized by this document. Adoption requires an owner-approved plan
  packet and Astra review per standing rules.
- **Date:** 2026-09-16
- **Origin:** L2 cluster C8 (deploy secret co-location) r2 adjudication preserved the S3/sidecar
  work and its invariants; the residue this sketch addresses is that the deploy wizard has **no
  persistence of the S3 identity it deployed across runs** — cross-run identity continuity rests
  entirely on the gateway's config surface.

## 1. Current behavior and the gap

The wizard (`mailserver/internal/deploy/wizard.go`) provisions SeaweedFS with the **gateway's**
S3 client identity:

- `gatewayS3Credentials()` (`wizard.go:1014-1060`) resolves the pair fresh from the gateway's
  config merge contract (defaults → `SETJOIN_CONFIG` YAML → env, legacy `MINIO_*` fallback) on
  **every run**;
- `configureSeaweedFS` (`wizard.go:1090-1159`) renders that pair to every node's
  `SeaweedfsS3ConfigPath` (root:group 0640) and **refuses before any node is contacted** when the
  gateway has no pair (`wizard.go:1102`);
- the wizard **never regenerates** the pair — regeneration was the r2 HOLD scenario that
  stranded the gateway with a stale credential; rotation is explicit on the gateway config
  surface (`install.sh --force`), then the next run re-deploys (`wizard.go:1070-1089`).

The invariants are correct and this sketch preserves all of them. The **gap** is the missing
wizard-held memory of what was actually deployed:

1. **No independent record.** The wizard persists step *metadata* (`deployment_steps`,
   scrubbed at `persistStep`, `wizard.go:185-204`) but never the identity itself. What the
   nodes currently run is knowable only by re-deriving from the gateway config — i.e. the
   gateway config is a single point of memory.
2. **Gateway-config loss/regeneration.** If the gateway's S3 pair is lost or regenerated
   (`install.sh --force` rotates it) while nodes still run the prior identity, a wizard run
   before the gateway config is re-set hits the `wizard.go:1102` refusal with **no source to
   reconcile from** — the operator must reconstruct the old pair out of band or accept a
   new-identity redeploy without a deliberate handoff.
3. **No drift witness.** Nothing distinguishes "same identity, nothing to do" from "gateway
   config moved on, nodes need the new pair" except a fresh resolution; there is no record of
   which generation each run deployed, so audit of "what ran when" is limited to scrubbed step
   rows.

## 2. Goals and non-goals

**Goals**

- G1: The wizard persists the S3 identity it deployed, encrypted at rest, on the gateway host,
  so identity survives across wizard runs independent of the gateway config surface.
- G2: Preserve every landed invariant: the wizard never generates key material; the gateway
  config surface remains the rotation authority; fail-closed when no identity source exists;
  redaction boundaries (`redact.go`) hold.
- G3: A deliberate, operator-acknowledged restore leg can seed the gateway surface from the
  stored identity (closing gap 2) without making stored secrets a silent fallback.
- G4: Generation-attributed audit: each run records which identity generation it deployed.

**Non-goals**

- N1: No DB-persisted secrets. The wizard's existing posture is that deploy secret material is
  kept **out of the database** (`redact.go` purpose statement; `deployment_steps` scrubbing;
  the withheld-restore note). A table would put ciphertext within SQL/WAL/backup reach and
  contradict that decision. The store is a file.
- N2: No node-side read-back / remote drift detection (comparing node files against the store
  over SSH). Proposed out of scope; listed in §9.
- N3: No extension to pgpool or SSH secrets. The pgpool health-check password is per-run **by
  design** (its consumers are configs written in the same run, `wizard.go:1086-1089`); SSH node
  credentials are never persisted (`wizard.go:230`). The store is scoped to externally consumed
  identities — today that is exactly the S3 pair — with an extension point, not a bulk secret
  vault.
- N4: No change to `seaweedfs-s3.json`'s root:root posture or the node-side 0640 delivery
  (C8 r2 carried adjudication, WP-2.3).

## 3. Storage and file posture

- **Path:** `/etc/setjoin/wizard-secrets.d/s3-identity` — a dedicated directory beside
  `db-credentials.d/`, created and owned consciously by install.sh under the root:root 0755
  `/etc/setjoin` ancestor (C8 r3 namespace rule: the runtime account may traverse, never
  write, rename, or replace; no recursive `setjoin` chown may ever cover the directory).
- **Mode/owner:** the consumer is the gateway process (running as `setjoin`), so per the r2-1.3
  ownership ladder the file is **0640 root:setjoin** (readable by the runtime group, replaceable
  by root only because the parent denies `setjoin` write) with the r2-1.3 residual recorded in
  the guard comment: an owner can edit in place; what parent ownership closes is the
  unlink+recreate vector. Exact mode/owner is an adjudication detail, not a design constant.
- **The wizard runtime cannot write here — by design, twice over.** The wizard runs in-process
  in mailserverd (`deploy.NewWizard` at `mailserver/cmd/mailserverd/main.go:1388`) as the
  `setjoin` runtime account, and the unit denies it the path twice: `ProtectSystem=strict` with
  `ReadWritePaths` limited to the data dir and `/tmp` (`mailserver/deploy/mailserver.service.template:21`,
  `:53-58`), on top of the root:root parent's no-write rule above. An earlier draft of this
  sketch had the wizard temp-file-and-rename inside this same directory, contradicting its own
  boundary — that step is superseded by the protocol below.
- **Write protocol (privileged writer; the wizard only orchestrates):** inside the fenced run
  the wizard composes the complete new store content, but every byte written under
  `wizard-secrets.d/` is performed by a **root-owned privileged writer** — the installer's
  root-side setup actor (the same root path that already creates `db-credentials.d/`),
  invoked via a documented privileged-exec boundary. The writer performs: write to a temp file
  in the same directory → `fsync` → `chmod`/`chown` pinned → atomic `rename` → `fsync` the
  directory; the runtime account only ever reads the stable path. Never partial-state visible
  at the stable path. The exact privileged-exec mechanism (sudo policy, installer-provided
  root helper, or extending install.sh's one-way migration) is an adjudication item (§9) and
  must not hand the wizard a general root-exec surface.
- **Sandbox-compatible alternative (recorded, not the default):** relocating the store under
  the unit's writable data dir would let the wizard perform temp+rename itself, but surrenders
  the parent-ownership tamper resistance the r2-1.3 ladder buys — the gateway process could
  then edit or replace the store in place. Chosen against unless adjudication prefers
  availability of writes over the tamper posture.
- **Not in `deployment_steps`:** store writes carry no step-output bodies; step rows keep
  recording path + generation only.

## 4. Record schema

One file holds a versioned header (plaintext, auditable) plus exactly one sealed body per
generation entry. Sketch (JSON rendering; on-disk representation follows the envelope below):

```jsonc
{
  "version": 1,                       // store layout version
  "kind": "setjoin/deploy-wizard-secret-store",
  "records": [
    {
      "record_id": "s3-identity",     // stable purpose key; AAD input
      "generation": 7,                // monotonic per record_id; AAD input
      "alg": "EK01:0",                // shared/cryptokey envelope: magic + AlgorithmTag
      "status": "active",             // active | superseded | retired-unreadable
      "source": "gateway-config",     // where the plaintext came from (never a value)
      "created_at": "2026-09-16T09:00:00Z",
      "deployed_at": "2026-09-16T09:05:00Z",
      "nodes": ["10.0.0.11", "10.0.0.12", "10.0.0.13"],  // deployed-to witness
      "sealed": "<base64 EK01 envelope>"                  // see §5
    },
    { "record_id": "s3-identity", "generation": 6, "status": "superseded", "...": "..." }
  ]
}
```

Sealed body (plaintext inside the envelope) contains only the credential pair:

```jsonc
{ "access_key": "...", "secret_key": "..." }
```

- Statuses are `active | superseded | retired-unreadable`. Exactly one record per
  `record_id` has `status: "active"`; a `retired-unreadable` tombstone (lost sealing key,
  §6.2.3) is excluded from that one-active count by its status.
- Superseded generations are retained (default: last 2) for audit and reconciled-restore
  arbitration, then reaped by the same run that advances the generation. Retired-unreadable
  tombstones are never reaped — they are the durable audit evidence for a lost generation.
- The wizard's in-memory representation reuses `RenderSeaweedfsS3Config` /
  `ValidateS3IdentitiesConfig` so a stored pair must pass the same deployment-time validation
  before any restore leg may render it.

## 5. Key derivation and envelope

Reuse the repo's two established primitives rather than introducing a new crypto surface:

- **Envelope:** `shared/cryptokey` EK01 envelope (`SealEnvelope`/`OpenEnvelope`) — magic
  `EK01`, algorithm tag per crypto profile (`AlgoAES256GCM` default; `AlgoSM4GCM` under
  `ProfileSMx`), 12-byte nonce, GCM tag, AAD supported (`shared/cryptokey/envelope.go`).
- **Key derivation:** HKDF-SHA256 over the gateway's existing root key `DB_ENCRYPTION_KEY`
  (already mandatory at gateway boot, `shared/config/base.go:59`) with a purpose-separated
  info string, following `DeriveKey` (`mailserver/internal/migration/credentials.go:144-154`):

  ```
  storeKey = HKDF-SHA256(ikm=DB_ENCRYPTION_KEY, salt=nil, info="setjoin/deploy-wizard/secret-store/v1")
  ```

  Purpose separation means a compromise or reuse of other derived keys (migration credentials,
  `devices.hmac_secret_enc` sealing) does not expose the store, and vice versa.
- **AAD binding:** `aad = "s3-identity|" + generation` (record_id + generation). This makes
  ciphertext generation-bound: a superseded envelope cannot be substituted for the active one
  (generation tamper breaks the GCM tag), and records cannot be swapped across purposes if
  extension records are ever added.
- **No new root secret:** if `DB_ENCRYPTION_KEY` is absent the wizard cannot run its gateway
  host's other sealed surfaces either; the store simply reports "sealed, key unavailable" and
  fails closed. No passphrase prompt, no second key lifecycle.

## 6. Lifecycle and rotation protocol

Two distinct rotations must never be conflated:

### 6.1 Stored-credential rotation (the S3 pair changes)

1. Rotation stays **explicit on the gateway config surface** (`install.sh --force` or operator
   edit of `S3_ACCESS_KEY`/`S3_SECRET_KEY`), exactly as `wizard.go:1075-1089` documents. The
   store **never generates or mutates** the pair.
2. On each `configureSeaweedFS` run the wizard resolves the gateway pair, then:
   - **Match** against the active record (constant-time compare): no-op — the run is
     idempotent; generation unchanged; `deployed_at`/`nodes` refreshed if a deploy actually
     re-ran.
   - **Differ:** deploy the gateway pair to nodes first (existing failure ordering), then, only
     after the run's remote steps commit, append the new generation `status: "active"`, flip the
     prior to `superseded`, reap beyond retention — temp+fsync+rename atomic (§3). The
     generation advance checkpoints **after** the remote outcome is confirmed, so a crashed run
     leaves the prior generation active and the next run simply redoes the deploy+advance
     (exactly-once advance by monotonic generation).
3. **Restore leg (gap closure, opt-in):** a new explicit operator-acknowledged flag on the
   admin deploy start surface (mirroring the `AcknowledgeReconciled` consent style of
   `runlock.go`), e.g. "adopt stored identity": when the gateway resolves **no** pair
   (`wizard.go:1102` would refuse) and an active store record exists, the wizard renders the
   stored pair back onto the gateway config surface and proceeds with the normal path. Default
   remains the refusal; restore is never implicit, is recorded in the step log as an adopt
   event (no values), and requires the run fence (`Begin`) like any destructive run. If the
   stored envelope fails AAD/open or `ValidateS3IdentitiesConfig`, the leg fails closed before
   any node is contacted.

### 6.2 Store-sealing-key rotation (`DB_ENCRYPTION_KEY` changes)

1. **What the cited precedent actually does — and does not.** The startup re-seal gates
   (`ResealOIDCProviderClientSecrets`, called from the authserverd startup gate at
   `authserver/cmd/authserverd/main.go:644-658`; cf. mailserverd's `EnsureSecretEncryption`)
   are **not** a key-rotation mechanism: the OIDC re-seal validates already-sealed envelopes
   under the CURRENT key and aborts the whole migration without writing on any mismatch
   (`authserver/internal/federation/oidc_secret.go:99-107`; the validate-before-write loop at
   `:169-177`), and only seals LEGACY PLAINTEXT rows. No path anywhere decrypts old-key
   ciphertext and re-seals it under a new key. An earlier draft of this sketch claimed
   "startup with the new root key re-seals every record" — that contradicts the cited code
   (records sealed under the old key fail validation under the new one, by design) and is
   retracted; the protocol below is the corrected design requirement, **not implemented
   behavior**.
2. **Rotation requirement (design, unimplemented):** a `DB_ENCRYPTION_KEY` change must be an
   explicit **decrypt-then-reseal across a defined dual-key availability window**. Both the
   old derived `storeKey` (HKDF over the outgoing root key) and the new one exist for the
   window; every record is opened under the OLD key first — validate-before-write, mirroring
   the precedent's abort-on-mismatch discipline — then re-sealed under the new key and swapped
   in atomically (§3 privileged-writer discipline; two-phase so a crash cannot strand a
   half-resealed store). The store carries a key-generation marker so a partially rotated
   store reads as sealed-under-old and the pass completes idempotently; the window closes only
   when every record verifies under the new key — a record that cannot verify because its
   sealing key is lost does not block the window forever, but exits only through §6.2.3's
   retirement transition.
3. **Old key lost — explicit retirement transition (design, unimplemented).** Envelopes are
   GCM-authenticated: ciphertext sealed under a lost key is unrecoverable — no re-seal
   without plaintext, no brute-force — so the §6.2.2 decrypt-then-reseal window cannot run
   and an unreadable record can never reach `superseded`. Affected records fail closed until
   retired: an unopenable active record fails the restore leg and surfaces as a loud startup
   warning naming the path, generation, and key-generation marker — never a silent drop,
   never deletion. Retirement is explicit: records sealed under the lost key-generation
   marker are flipped to `status: "retired-unreadable"` — a tombstone preserving the audit
   evidence (record_id, generation, created_at/deployed_at, node witness, key-generation
   marker, and the undecryptable sealed body), never deleted, never reaped, never counted as
   superseded — while the fresh identity minted on the gateway config surface (the standing
   rotation authority, §6.1) is appended as the new sole active generation; both halves land
   in one atomic store write inside the fenced run (§3, §7). The supersede-only-after-reseal
   rule is thereby scoped to READABLE generations: `superseded` remains reachable only after
   a verified re-seal (§6.2.2); an unreadable record exits the active set only as
   `retired-unreadable`, which §4's exactly-one-active count excludes by status. Recovery is
   re-deployment, not decryption: the store's memory of the lost generation survives only as
   its tombstone; the deployment does not.
4. Old-key compromise does not require credential rotation (rotating `DB_ENCRYPTION_KEY` + a
   completed §6.2.2 re-seal re-protects at rest), but rotating the stored S3 pair (§6.1)
   remains the operator's blast-radius decision.

## 7. Concurrency, fencing, and crash-safety

- Store writes happen only inside a `Begin`-fenced deployment run (`runlock.go`: exactly one
  run; `ErrDeployUnreconciled` fence for unconfirmed remote outcomes), so generation advances
  are serialized by the wizard's existing mutex + run fence — no second locking scheme.
- Because the advance checkpoints after remote confirmation (§6.1.2), the crash windows are:
  - crash **before** advance: prior generation active; next run redeploys and advances — safe;
  - crash **after** advance, before reap: one extra superseded record — reaped next run — safe.
- The rename-level atomicity of §3 covers readers (an operator inspecting the file) and the
  startup re-seal pass racing a run: re-seal only runs outside an active run (same Begin gate).

## 8. Redaction and observability

- Secret values never reach logs, errors, argv, or `deployment_steps`. Store-sourced pairs join
  `RedactOutput`'s exact-replacement extras for every SSH run they are used in
  (`redact.go`, `wizard.go:521-563` pattern; `wizard_secret_redaction_test.go` genre extends to
  the store path).
- Logged/step-visible fields: path, `record_id`, `generation`, `status`, node list, adopt/reseed/retire
  events. That is also the audit trail for G4.
- The install summary and backup guidance surfaces that print "holds your secrets" path lists
  (the C8 WP-1.6 surfaces) gain `/etc/setjoin/wizard-secrets.d/`.

## 9. Open questions for adjudication

1. Exact directory name, mode, and owner (§3 posture vs r2-1.3 ladder) — adjudication detail.
2. Is the restore leg (§6.1.3) admitted at all? If standalone/failover wizard runs are not a
   supported topology, G3 shrinks to audit-only (G4) and the sketch still closes gaps 1 and 3.
3. Superseded-generation retention N (default 2) and whether reap needs an operator surface.
4. Node-side drift detection (N2): read-back and compare per node on each run — useful, but
   adds an SSH read surface; proposed as a follow-on, not part of this store.
5. Xinchuang profile interplay: confirm `AlgoSM4GCM` envelope acceptance in the render lanes
   when `CRYPTO_ALGORITHM_PROFILE=smx`.
6. Whether install.sh's one-way migration machinery should create the (empty) store directory
   on fresh installs or only on first wizard use (lazy creation inside the fenced run is the
   sketch's default).
7. The §3 privileged-writer mechanism (installer-provided root helper vs sudo policy vs
   extending install.sh's migration), its least-privilege scoping, and the invocation boundary
   that keeps the wizard from gaining a general root-exec surface.

## 10. Relationship to landed C8 work

Preserves: gateway-config as rotation authority; wizard never regenerates; fail-closed refusal
(`wizard.go:1102`); node-side `seaweedfs-s3.json` root:root and 0640 delivery; redaction
boundary and `deployment_steps` scrubbing; r3 root-controlled namespace discipline (extended to
a sibling directory). Adds: the wizard-held, generation-attributed, envelope-sealed memory the
r2 adjudication left as the open residue.
