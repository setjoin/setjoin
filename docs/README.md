# SetJoin Documentation

## For operators

| Document | What it covers |
|----------|---------------|
| [Deployment Guide](guides/HA_OVERVIEW.md) | High-availability deployment architecture and setup |
| [Unified deployment-readiness rehearsal](guides/UNIFIED_DEPLOYMENT_READINESS.md) | Reusable three-stack Guest, Identity, Federation, Native-RLS, DR, browser, and cleanup verification; the July 2026 run is complete |
| [Client-assisted mail recovery](guides/CLIENT_ASSISTED_MAIL_RECOVERY.md) | Consent, incident, quarantine, portable-rewind, simulator, and remaining physical-device gates |
| [DNSSEC + DANE Setup](guides/DNSSEC_DANE_SETUP.md) | DNSSEC signing and DANE TLSA record configuration |
| [M365 Migration](guides/M365_MIGRATION.md) | Microsoft 365 → SetJoin migration guide |
| [Upgrade Guide](guides/UPGRADE.md) | Server upgrade runbook |
| [Compliance](compliance/WORM_COMPLIANCE.md) | WORM immutability (SEC 17a-4(f), FINRA, CFTC, MiFID II) |
| [Security Features](ref/SECURITY.md) | Complete email security reference |
| [Webmail Reference](ref/WEBMAIL.md) | Webmail feature reference |

## For developers

| Document | What it covers |
|----------|---------------|
| [Architecture](architecture.md) | System diagram, technology choices, data flows |
| [Phases](phases.md) | Historical master phase ledger with dependency ordering |
| [Standards: DB Security](standards/DATABASE_SECURITY.md) | Enforced 4-rule query security standard |
| [Standards: Input Validation](standards/INPUT_VALIDATION.md) | Form validation patterns and limits |
| [Standards: Dependencies](standards/DEPENDENCIES.md) | Dependency policy and upgrade rules |
| [Feature registry and focused architecture checks](guides/FEATURE_REGISTRY_DEVELOPMENT.md) | Route/app/worker/feature/native recipes, V183+ generation, N-1 rollback, evidence, and timing gates |
| [JMAP Reference](ref/JMAP.md) | RFC 8620/8621 compliance and wire format |
| [LDAP Identity](ref/LDAP_IDENTITY.md) | Identity source modes, AD sync, field ownership |
| [Crash Recovery](ref/CRASH_RECOVERY.md) | Startup recovery procedure |
| [Rules Engine](ref/RULES.md) | Condition grammar, action catalog, execution order |
| [Error Codes](reducer-error-codes.md) | PL/pgSQL ERRCODE + HINT contract |
| [Quarantine](ref/QUARANTINE.md) | Virus quarantine architecture |

## For auditors

| Document | What it covers |
|----------|---------------|
| [Audit: Architecture](audit/architecture-review.md) | Deferred architecture items |
| [Audit: Bugs](audit/bug-audit.md) | Consolidated bug audit |
| [Audit: Benchmarks](audit/benchmarks.md) | Performance baselines |
| [Transactional continuity U5–U8 evidence](verification/2026-08-02-transactional-continuity-u5-u8.md) | Deterministic, security, Ubuntu rewind, simulator, cleanup, and remaining release-gate evidence |

## Decisions

| Document | Status |
|----------|--------|
| [ARCH-002: Shared DB Architecture](adr/ARCH-002-shared-db-architecture.md) | Accepted |
| [DES-005: SMTP Outbound Auth](adr/DES-005-smtp-outbound-auth.md) | Accepted |

## Design specs

Organized by domain in [design/](design/).

## Chinese documentation

[中文文档](zh/README.md) — admin console guide, deployment, compliance, security, FAQ.

## Retired material

Internal planning and review material was removed from this repository (#555):
`retired-docs:superpowers/`, most of `docs/verification/`, the agent-context archive, and
several local agent scratch trees. Citations of the form `retired-docs:<path>` in
code comments and documents name one of those removed documents; they are historical
labels and do not resolve. `docs/verification/` keeps only the files that guards and
tests read. Those files are hash-bound or frozen records, so they keep their
original citations byte-for-byte, as do the scripts they fingerprint.

Retired with that removal: `scripts/check-deep-security-remediation.sh` no longer
runs the ledger `--check`/`--self-test` path, which read the removed sealed triage
handoff. The transition-grammar tests still run.
