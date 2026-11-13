# ADR: ARCH-019 — Transactional updater and recovery boundary

**Status:** Accepted — user direction and `/autoplan` review complete; U-1 through U7, portable rewind, and simulator gates verified; physical-device/operator U8 rows remain open; production execution and continuity flags OFF

**Date:** 2026-08-01

**Authority:** `retired-docs:superpowers/specs/2026-08-01-transactional-upgrade-continuity-design.md`

## Context

Setjoin currently has two incomplete server-update paths. The gateway's
`mailserver/internal/admin/admin_upgrade.go` can copy over its own executable,
while the newer Admin Portal server-update screen calls upload and history
routes that are not registered by `mailserverd`. The real deployment path is
`mailserver/deploy/scripts/upgrade.sh`, which stops services, copies artifacts,
runs migrations, probes readiness, and copies the previous binaries back on a
failure. None of these paths provides a crash-resumable transaction, a signed
multi-artifact release contract, or evidence that the backup used by the
upgrade gate can actually be restored.

A tenant-facing gateway is also the wrong place to hold root privileges. If it
can choose filesystem paths or commands for a privileged installer, compromise
of the HTTP process becomes arbitrary root execution. Conversely, the updater
cannot depend only on the gateway or PostgreSQL once it has intentionally
stopped or migrated them.

Whole-machine snapshot rollback creates a second problem: if the virtual
machine, database, and local journal all return to the same older point, the
server has no local evidence that newer mail ever existed. A client that holds
a server-signed receipt from the later timeline can provide such evidence, but
ordinary metadata caching cannot safely reconstruct mail.

## Decision

Setjoin will use a separate root-owned `setjoin-updater` coordinator. The Admin
Portal and gateway create and observe upgrade intents; they never install files,
invoke shell commands, receive systemd privileges, or select arbitrary paths.
The coordinator accepts only vendor-signed manifests and artifacts from its
configured Community or Enterprise source, enforces anti-rollback metadata and
compatibility cohorts, and persists a local append-only execution journal so an
interrupted transaction resumes deterministically.

The intent remains application authority in PostgreSQL reducers. The updater
claims an approved intent through a least-privilege database role and mirrors
progress and audit evidence there. During the bounded interval in which the
database is unavailable, the root-owned journal is execution authority only;
it reconciles its signed step evidence back to PostgreSQL after recovery. A
compromised gateway can at worst request installation of a currently eligible,
cryptographically approved release under the configured policy. It cannot
choose an executable, command, unit, or downgrade outside the manifest.

Releases are immutable directories under `/opt/setjoin/releases/<release-id>`.
The `current` symlink is the commit point. The core cohort — schema/reducers,
`mailserverd`, `authserverd`, `mailctl`, and webmail — advances together.
Sidecars may advance independently only when the signed manifest declares and
the updater proves an explicit compatibility range. Database changes follow an
expand/contract discipline; an ordinary executable rollback never silently
restores the database.

The required upgrade gate is an application **recovery point**: a database dump,
blob/config manifest, encrypted protected-config payload or externally-held-key
evidence, and hashes that all pass integrity checks. A separate isolated
**restore proof** records that a recovery point was restored and validated.
Proxmox, VMware, cloud, LVM, ZFS, and Btrfs snapshots are optional **platform
snapshots**. Setjoin calls one verified only when a provider adapter can query
it; otherwise it is clearly labeled operator-attested. No Linux storage UI is a
default prerequisite.

For rollback continuity, the server issues a signed installation/timeline token
and per-message recovery receipt. Native clients may opt in to retaining the
exact raw MIME and referenced attachment bytes in their existing encrypted
offline vault. If a client later presents a valid receipt that proves it has
observed a state newer than the restored server, Setjoin opens an administrator-
controlled recovery incident. Reingestion is disabled by default, time- and
account-bounded, user-confirmed, hash-verified, deduplicated, quarantined, and
performed through reducers. Recovered content is labeled as device recovery and
can never become an outbound-send or authentication authority.

Community and Enterprise are release and assurance channels over the same
manifest and data formats. Community receives signed current-line releases and
critical security fixes. Enterprise adds production-certified LTS artifacts,
longer backports, signed offline mirrors, certified upgrade/rollback evidence,
maintenance advisories, and contracted support. Entitlement expiry never stops
login, mail flow, ordinary data access, export, restore, or deletion.

This decision supersedes the unimplemented ten-seat Community proposal preserved
in `docs/design/clients/archive/phase12-client-architecture.md`; that archive is
historical, not current product authority. Online Enterprise artifact access is
enforced by the update service. A signed local entitlement is authoritative only
for offline/air-gapped artifact eligibility and never gates existing customer data.

## Consequences

- The gateway loses every self-modifying binary and caller-supplied path seam.
- Installation needs a small root-owned daemon, a least-privilege updater DB
  credential, systemd unit hardening, versioned release storage, and a durable
  transaction state machine.
- A release cannot claim arbitrary modularity. Compatibility is a signed,
  machine-checked contract; otherwise the core cohort moves together.
- Recovery-point creation and restore rehearsal become different evidence with
  different timestamps and operator expectations.
- Client-assisted recovery can recover only mail downloaded after the client
  began retaining raw bytes plus valid receipts. Existing metadata-only cache
  rows are explicitly ineligible.
- A complete VM rollback can be detected only after an external witness appears
  (normally a client receipt or an optional remote witness). The UI must say
  "possible older server timeline" rather than pretending local clocks prove it.
- Community-to-Enterprise switching does not migrate customer data or reinstall
  the product; it changes eligible signed metadata and support assurance.
- The archived ten-seat Community limit is non-authoritative; the Enterprise
  300-seat floor is a commercial minimum rather than a Community access ceiling.

## Alternatives rejected

- **Give `mailserverd` sudo or a root socket accepting commands/paths.** This
  turns the largest remote attack surface into a root control plane.
- **Run `upgrade.sh` from an HTTP handler.** A shell script is useful as a
  compatibility wrapper and break-glass tool, but it is not a resumable state
  machine and cannot be the web contract.
- **Require Proxmox/LVM/ZFS snapshots.** They are not portable, often cannot be
  queried from the guest, and burden ordinary Linux operators. Application
  recovery evidence is the portable gate.
- **Restore the database automatically after any failed release.** Expand-only
  migrations should permit executable rollback. Automated data restore can
  destroy writes accepted after the recovery point and is therefore a separate
  explicit disaster-recovery action.
- **Trust client-cached metadata or arbitrary `.eml` uploads.** That permits
  forgery, cross-account injection, silent duplication, and incomplete mail.
- **Charge by CPU/socket or remotely disable expired installations.** Setjoin's
  value and support load scale primarily with active people. Host-based pricing
  penalizes virtualization and remotely disabling an on-prem mail system creates
  unacceptable customer and safety leverage.
