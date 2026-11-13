# Release Maturity and First GA Boundary

**Date:** 2026-09-01  
**Status:** APPROVED PRODUCT DIRECTION — target boundary only; no current GA,
production enablement, implementation completion, or release evidence is claimed

2026-09-06: [Composable workplace positioning](../product-positioning.md) and the
refactor program
use this same capability-level maturity model. Being modular, installable or
API-addressable does not imply stable public contracts, third-party replacement,
hot reload or GA. Marketing must distinguish existing foundations from planned
platform capabilities; Core GA does not depend on generic marketplace completion.

## Decision

Setjoin uses capability-level maturity inside a product release. A Setjoin release
may be generally available while optional modules remain Beta or Experimental, but
the installer, administrator UI, documentation, support matrix and release notes must
show that distinction consistently. Product-level GA never promotes an individual
capability past its own implementation, security, compatibility, operations, load,
rollback and external-evidence gates.

The target boundary for the first formal public release is:

| Product area | Target maturity in first formal release |
|---|---|
| Mail, Calendar, Contacts and Drive core | Core GA |
| Identity/authentication, administration, security/audit, backup/restore and transactional update/continuity needed by Core | Core GA |
| Office editing and Drive History | Beta, after the real Collabora/Drive vertical closes its Beta gates |
| Meet | Beta or Experimental according to the exact shipped milestone; absence or immaturity does not block Core GA |
| Marketplace and public Extension Control Plane | Experimental until their own reference-app, security and compatibility gates pass; absence does not block Core GA |

This table is a target release contract, not a statement that those areas currently
meet the named maturity. Existing default-OFF flags and release-evidence gates remain
authoritative until separately promoted.

## Maturity semantics

- **Experimental:** contract and behavior may change; no production-support or
  compatibility promise. It is opt-in and visibly marked.
- **Beta:** intended workflow is usable in the named topology and support matrix, but
  compatibility, scale, platform, operational or customer evidence remains bounded.
  Limitations and rollback paths are explicit.
- **GA:** supported production behavior for an exact topology, scale, platform and
  compatibility range with retained upgrade, rollback, backup/restore, security and
  operator evidence.
- **Deprecated:** still within its published compatibility window, with replacement,
  migration and removal dates disclosed.

`implemented`, `test passed`, `default ON`, `Beta`, `GA`, `supported`, `certified`, and
`compliant` are independent facts. No UI or document may infer one from another.

## Release and UI rules

1. Every installable or configurable capability exposes its maturity, default state,
   supported topology/platform range, known limitations and owning evidence link.
2. A Core GA release can package Beta/Experimental modules, but they remain separately
   opt-in and cannot weaken Core readiness, upgrade, backup or security behavior.
3. Failure or removal of Office, Meet or an extension cannot strand Mail, Calendar,
   Contacts, Drive originals, identity, audit, backup or updater authority.
4. Release notes carry a machine-derived capability matrix. Marketing and comparison
   documents consume the same source rather than describing the whole suite as one
   undifferentiated maturity level.
5. A security issue may fence an unsafe optional capability under its governed policy
   without changing unrelated Core maturity. A compromised Core invariant blocks the
   affected Core GA claim.

## Sequencing

Mandatory security remediation remains a horizontal prerequisite. The next product
vertical is the real Office/Drive Collabora workflow; Meet M0-M3 follows it. The
Extension Control Plane remains at paper-reference-extension validation until the
Office vertical supplies real requirements. This implementation order does not make
Office a prerequisite for the eventual Core GA boundary.

## Deployment profiles

The first Core GA formally supports a single-node production profile only within
the capacity, durability, maintenance interruption, backup/restore time and recovery
objectives proved by retained evidence. The supported upper user/data/workload bound
is derived from that evidence rather than selected as a marketing number. Installation
and administration must display the shared failure domains and planned-maintenance
contract of the actual topology.

HA remains Beta until an exact supported topology passes real multi-node quorum and
failure tests, rolling update and rollback, storage/database failover, network
partition, backup/restore, load/soak and independent-operator drills. Community users
are not technically prevented from constructing or testing HA, but that does not
create an official HA support claim. Enterprise HA becomes a separate GA profile only
after those gates pass; architecture diagrams and simulators cannot substitute.

## Client profiles

The first Core GA includes the web application, standards-based SMTP/IMAP/CalDAV/
CardDAV access within each protocol's retained conformance matrix, and desktop-client
cells that pass their exact supported-OS install, authentication, synchronization,
offline/reconnect, local-key, update/rollback and removal evidence. A passing web cell
or simulator cannot promote a desktop operating-system cell.

Setjoin's native iOS, Android and HarmonyOS clients remain independently labeled Beta
until each platform passes physical-device synchronization, process suspension and
background recovery, protected key storage, Push MFA, revocation/offboarding,
upgrade/rollback, loss/reinstall and accessibility evidence. Each platform may advance
independently; a missing mobile GA cell does not block Core service GA. Standards-based
third-party client support is stated per protocol and must not be expanded into an
unsupported full-client compatibility claim.

## Exchange-replacement claims

Core GA and Exchange Replacement are independent claims. Core GA certifies only the
named Setjoin services, deployment profile, clients and standards contracts. It does
not imply MAPI, EWS server, Exchange ActiveSync, Outlook feature, hybrid coexistence,
migration, delegated-permission or operational parity.

An Exchange Replacement claim is issued for an exact source estate, client/workflow,
deployment and migration/coexistence profile only after the canonical outcome matrix,
controlled source execution, retained compatibility/load/rollback evidence and real
customer decision-use gates pass. A documented Setjoin-native or standards-based
alternative may satisfy an outcome when the comparison contract says so, but it must
be named as an alternative rather than protocol compatibility. EWS used as a migration
client never establishes that Setjoin is an EWS server. No umbrella “complete Exchange
replacement” statement may be derived from Core GA or from a partial matrix.

## Migration baseline

First Core GA requires a supported migration floor for existing standards-based
estates: resumable and idempotent IMAP mail migration plus standard calendar,
contact and directory import/export using applicable ICS, vCard and CSV contracts.
Every supported path provides dry-run or inventory, bounded credentials, progress,
retry/resume, duplicate handling, per-item or aggregate failure accounting, audit,
cancel/restart and an explicit source-preservation/rollback story. A one-shot importer
without recovery or truthful partial-result reporting does not satisfy this gate.

Exchange EWS, Microsoft 365 Graph, PST, hybrid coexistence, transport/rule conversion,
delegated permissions and other proprietary migrations retain independent Beta and
Exchange Replacement qualification. Existing connector code does not promote a path;
each claim needs its exact source versions, data classes, limits, credentials,
compatibility and retained migration/reconciliation evidence.

## Server platform profiles

The first Core GA server profile is Ubuntu 24.04 LTS on x86_64. Its claim requires
native install, service management, filesystem/storage, cryptographic dependency,
upgrade/rollback, backup/restore, load/soak and operator evidence on that exact profile.

Ubuntu arm64, Kylin, UOS, openEuler, Anolis and LoongArch profiles remain independently
labeled Beta until their exact operating-system release and architecture pass the
same applicable real-machine evidence. Cross-compilation, QEMU, a CI build, a FAQ or
success on another distribution cannot promote them. They may advance independently
without blocking Ubuntu x86_64 Core GA. macOS and Windows may host development,
clients, runners or interoperability tests but are not first-release server GA
profiles.

## Data-service profiles

The complete first Core GA default stack uses Setjoin-managed, manifest-pinned
PostgreSQL 18, PgBouncer and the bundled local SeaweedFS profile. Setjoin owns their
configuration schema, required extensions and roles, startup order, health, backup/
restore integration, coordinated update and supported rollback boundary. “Managed”
does not permit silent destructive database or filesystem operations.

External PostgreSQL remains Beta until an exact service/product and version proves
extension availability, owner/worker roles, RLS and SECURITY DEFINER behavior,
transaction/listen semantics, PgBouncer mode, backup/restore, upgrade, latency and
failure handling. A successful DSN connection is not qualification.

External object storage may independently reach GA for an exact provider, version,
topology and capability profile after the Storage Provider conformance, durability,
consistency, range, checksum, retry, Object Lock where claimed, load, migration and
recovery gates pass. The phrase `S3-compatible` describes an API family only and is
never a blanket support promise. An unqualified custom endpoint remains available
only with an honest Beta/unsupported profile and cannot inherit another provider's
evidence.

## Rolling release channels

Setjoin does not maintain annual product releases or long-lived feature branches.
Community and Enterprise consume one forward-only code lineage through two promotion
channels:

- Community receives each signed current build first after its required automated
  gates pass.
- Enterprise receives an artifact from the same lineage only after the declared
  additional integration, real-environment and soak evidence passes. A critical
  security correction may use an audited fast-track that bypasses ordinary soak but
  not signature, compatibility or recovery gates.
- Ordinary fixes and features move forward. Setjoin does not routinely backport them
  to older builds or maintain a separate Enterprise LTS fork.
- On-premise administrators choose an approved maintenance window. Feature updates
  are never silently forced, and the offline bundle carries the same signed manifest
  and evidence identity as the connected channel.

“No named product versions” does not mean anonymous or mutable software. Every
artifact still has an immutable monotonic build ID, source commit, digest, schema and
API levels, compatibility range, migration prerequisites and recovery boundary. The
update service and support UI always identify the exact installed build. Switching
Community/Enterprise eligibility changes promotion timing and assurance, not data
format, feature licensing or installed lineage. Entitlement expiry does not stop the
installed service or block access, export or restore.

The normal production target is to deploy an approved build within 14–30 days. Ninety
days is the maximum supported normal drift. After that boundary the installed service
continues operating and customer data remains accessible, but the build is marked
unsupported; admitted automatic routes may require declared bridges, while absence of an admitted route requires a separately reviewed recovery/migration procedure and support notice under the managed-dependency plan §25.5. A high-risk
security correction targets seven days; an actively exploited emergency targets
24–72 hours or an approved temporary Emergency Mitigation when immediate installation
is unsafe.

For an admitted automatic route, the administrator requests **upgrade to latest approved build** once. The
reducer selects the signed path for display before confirmation; the updater executes only the approved order:

- within one compatibility/schema epoch it installs the latest build directly and
  executes only its ordered missing migrations;
- across a `contract` or `irreversible` boundary it automatically traverses the
  minimum declared bridge checkpoint set, rechecking recovery and health gates at
  each boundary;
- it never requires an administrator to discover or manually install every
  intermediate release.

Publisher conformance must prove every advertised source range and path. A bridge is
a retained compatibility checkpoint, not a second maintained product branch.

### Confirmed pre-release baseline reset (2026-09-05)

The owner confirms there are no production installations and permits a clean first
supported baseline for all first-party development version namespaces. This is a
planning decision, not permission in this review to reset data or execute a migration.
Product/build, API, schema/migration, manifest, updater/journal and component versions
may be rebased together before formal release; they remain independently versioned
contracts, not one forced numeric value. Concrete starting numbers and a complete
old-to-new namespace map are frozen in the baseline implementation plan.

The first supported installer must contain the qualified dependency profile, capable
updater and prerequisite SQL/API contracts together. There is no required automatic
upgrade path from unpublished development/test builds. Test environments may be
reinstalled or explicitly migrated by a separately scoped, recoverable procedure after
data/ownership inspection; nothing is silently wiped or marked compatible. Existing
retained-version obligations need explicit disposition in each owning plan: replace
obsolete pre-release compatibility cases with baseline-to-next-candidate cases, but
preserve unrelated security, physical-device and independent recovery gates.

Do not renumber upstream PostgreSQL/SeaweedFS/Collabora versions or digests, immutable
Drive/file identities, customer data, old signatures or historical evidence. A numeric
reset must use an explicit new release namespace/epoch, never reuse an existing signed
identity or lower a trust counter in place. Any retained installation needs an explicit
authenticated transition or a fresh installation identity; old artifacts fail closed
outside their declared namespace. No global anti-rollback or signature bypass.

Before calling the baseline supported, retain its signed artifacts and prove installation,
baseline-to-next signed upgrade, updater replacement/reboot recovery, schema ordering,
cross-epoch rejection and allowed rollback with data integrity. From that baseline
onward the rolling-update support and compatibility obligations above apply normally.
Implementation sequencing is owned by the
managed dependency plan.

### Artifact transport, compatibility groups and startup

Release transport is artifact-granular and content-addressed. The updater downloads
only digests absent from the local verified cache, then reuses unchanged bytes to
materialize a complete immutable release directory. Partial download never means a
partially defined installation: the signed manifest still proves the full target
inventory, compatibility facts and recovery material.

Activation is atomic per declared compatibility group. Core `mailserverd`,
`authserverd`, matching Webmail, `mailctl`, migrations and recovery contract remain
one group unless retained mixed-version evidence proves a smaller safe group.
Provider/sidecar artifacts may activate independently only inside their signed core,
protocol, configuration and data-format ranges. The updater never overwrites an
executable in place; it verifies and syncs an immutable target before switching the
group's release pointer and restarting or draining only the affected processes.

An administrator may configure system startup to resume or begin an already approved
upgrade automatically. This is orchestration, not migration authority for a business
process. The root-owned `setjoin-updater` acquires the installation lock, verifies the
manifest and recovery point, stages the compatibility group, drains/stops affected
processes and applies signed migrations through its distinct owner credential before
starting the target group. The gateway and other business processes perform only a
read-only schema/contract check and fail closed when the database is behind, ahead or
otherwise outside their declared range. They never hold DDL credentials, repair an
upgrade journal or mutate schema during startup.

The updater must resume idempotently after host restart and publish one bounded state
for download, staging, migration, activation, readiness, commit, rollback or
recovery-required. A systemd restart loop cannot create a second migration attempt;
the durable updater journal and local/database installation locks remain the only
execution authority.

### External model check

This resembles current subscription software, but Setjoin's on-premise boundary is
stricter than a SaaS backend. Microsoft 365 cloud services progressively validate
changes through Targeted and Standard release audiences. Teams desktop normally
auto-updates twice each month through a staggered rollout and can fast-track a
critical update. Microsoft 365 Apps uses Current and Monthly Enterprise channels,
while still assigning exact version/build numbers and finite support/rollback
windows. Setjoin adopts the shared-lineage and promotion-ring pattern, not the SaaS
assumption that a vendor may silently force every customer host forward.

Primary sources:

- <https://learn.microsoft.com/en-us/microsoft-365/admin/manage/release-options-in-office-365>
- <https://learn.microsoft.com/en-us/microsoftteams/teams-client-update>
- <https://learn.microsoft.com/en-us/microsoft-365-apps/updates/overview-update-channels>
- <https://learn.chatgpt.com/docs/enterprise/manage-app-updates>
