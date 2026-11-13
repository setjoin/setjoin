# WORM Immutability — Design Spec

> **Roadmap item:** Stage 2.3 — "Regulated-Industry Ready" compliance pillar
> **Date:** 2026-05-31 | **Effort:** ~8 weeks + certification | **Filed under:** `mailserver/gateway/internal/storage/`, SeaweedFS, `docs/specs/WORM.md`

## Goal

SEC 17a-4(f), FINRA Rule 4511(c), and CFTC Rule 1.31(c)-(d) compliant WORM (Write Once Read Many) storage. Every email blob written to the object store becomes permanently immutable — non-erasable, non-rewritable — until its retention period expires. Legal hold overrides retention: a held object cannot be deleted even after its retention clock runs out. Even root administrators and operators with direct filesystem access cannot bypass immutability. EXO requires E5 + Purview Preservation Lock for this; we offer it built-in at no per-seat markup.

## Architecture

Three layers of defense, from application down to object store:

1. **Application layer (gateway).** The storage driver already writes `ObjectLockMode` and `ObjectLockRetainUntilDate` on every `PutObject` when configured (`s3_driver.go:74-79`). This spec extends that foundation: the driver gains a `PutObjectLegalHold` method, the mailbox `blobs` table gains a `legal_hold_until` column, and the compliance module gains legal-hold CRUD operations.

2. **Bucket layer (SeaweedFS / S3).** The blob bucket is created with Object Lock enabled at bucket creation time. This is a one-time irreversible configuration — once a bucket has Object Lock, it cannot be disabled. Governance mode allows the `s3:BypassGovernanceRetention` permission; compliance mode does not. We use compliance mode for the blob bucket so that NO principal — not even the root account — can delete a locked object.

3. **Physical layer (customer hardware).** Since the product is on-premise, the customer controls physical access. WORM compliance assumes the customer follows operational best practices: locked server rooms, access logging, tamper-evident hardware. We document these in `docs/specs/WORM.md` as a shared-responsibility model.

```
Inbound email → SMTP pipeline → reducer commit → blob written to SeaweedFS
                                                       ↓
                                              PutObject with:
                                              - ObjectLockMode=COMPLIANCE
                                              - ObjectLockRetainUntilDate=now()+retention_days
                                              - optional LegalHold=ON
                                                       ↓
                                              Object immutable until retention_date
                                              (even root DeleteObject returns 403)
```

## Files to Create/Modify

| File | Action | Purpose |
|------|--------|---------|
| `mailserver/gateway/internal/storage/driver.go` | **Modify** | Add `PutObjectLegalHold(ctx, key, status)`, `GetObjectLegalHold(ctx, key)`, `PutObjectRetention(ctx, key, mode, until)` to `Driver` interface |
| `mailserver/gateway/internal/storage/s3_driver.go` | **Modify** | Implement legal hold + retention override S3 calls; add `EnsureBucketObjectLock()` for bucket creation with Object Lock enabled |
| `mailserver/gateway/internal/storage/oss_driver.go` | **Modify** | OSS also supports WORM mode — implement matching interface; or return `ErrWORMNotSupported` if the backing OSS does not support it |
| `mailserver/gateway/internal/storage/worm.go` | **Create** | WORM configuration validation: enforce that Object Lock bucket creation is acknowledged, retention range boundaries, compliance mode confirmation |
| `mailserver/gateway/internal/storage/worm_test.go` | **Create** | Unit tests for legal hold lifecycle, retention expiry edge cases, immutability assertion (DeleteObject must fail on locked objects) |
| `mailserver/gateway/internal/handlers/admin_compliance.go` | **Modify** | Admin API for legal hold: `POST /admin/legal-hold` (place hold), `DELETE /admin/legal-hold/{id}` (release hold), `GET /admin/legal-hold` (list holds), `GET /admin/legal-hold/audit` (immutable audit log) |
| `mailserver/sql/migrations/V0NN__worm_legal_hold.sql` | **Create** | `legal_holds` table (id, description, filter_spec JSONB, created_by, created_at, released_at, released_by), `blob_legal_holds` junction, `legal_hold_audit_log` table (append-only, no UPDATE/DELETE permission) |
| `mailserver/gateway/internal/config/config.go` | **Modify** | Add env vars: `WORM_RETENTION_DAYS` (default 2557 = 7 years for SEC broker-dealer), `WORM_MODE` (governance/compliance), `WORM_LEGAL_HOLD_ENABLED` |
| `mailserver/sql/reducers/worm_*.sql` | **Create** | PL/pgSQL reducers: `place_legal_hold`, `release_legal_hold`, `list_legal_holds`, `audit_legal_hold_access` |
| `docs/specs/WORM.md` | **Create** | Customer-facing WORM compliance guide: architecture, shared responsibility model, audit procedures, retention schedule configuration, Cohasset certification path |
| `scripts/verify-worm.sh` | **Create** | Operational verification script: confirm bucket Object Lock status, test immutability (attempt DeleteObject → expect 403), list objects approaching retention expiry |

## Key Design Decisions

- **Compliance mode, not governance.** Governance mode allows a blessed IAM principal to bypass retention with `s3:BypassGovernanceRetention`. Compliance mode does not — no API call, by any principal, can delete a locked object. This is the correct choice for SEC 17a-4(f) because the regulation requires that records be "non-rewritable and non-erasable." Governance mode is for internal policy enforcement; compliance mode is for legal mandates.

- **Bucket-level Object Lock is irreversible.** Once a bucket is created with Object Lock enabled, it cannot be disabled. The `EnsureBucketObjectLock` call during startup checks that the blob bucket exists with Object Lock enabled; if it does not, the gateway refuses to start until the operator confirms the bucket was created correctly. This is a safety rail, not a runtime toggle.

- **Legal hold is additive, not gating.** A held object remains immutable even after its retention date passes. Legal hold is applied via S3 Object Lock Legal Hold (a separate mechanism from retention periods) and is independently auditable. Releasing a legal hold is a logged, audited operation — not a simple DELETE.

- **Default retention: 7 years (2557 days).** SEC 17a-4(f) requires broker-dealers to retain records for 6 years; FINRA 4511(c) requires 7 years for certain records. We default to 7 years to cover the strictest rule. Shorter or longer periods are configurable per-domain for non-SEC-regulated customers.

- **Audit log is append-only at the database level.** The `legal_hold_audit_log` table has `SELECT` and `INSERT` grants only — no `UPDATE`, no `DELETE`. RLS prevents any user from modifying audit records. Combined with S3 Object Lock compliance mode, this creates a dual-layer immutability guarantee.

- **Root admin cannot delete.** This is the core WORM property. Compliance mode S3 Object Lock means no AWS IAM principal — not `root`, not `AdministratorAccess` — can `DeleteObject` on a locked object. Since SeaweedFS implements S3 Object Lock semantics, the same guarantee holds. The only way to destroy a locked object is to physically destroy the storage volume, which is addressed by the physical security layer (customer responsibility).

## Dependencies

- **SeaweedFS ≥ 3.70** — S3 Object Lock support (compliance mode). Earlier versions lack this; the gateway health check verifies version at startup.
- **S3 Object Lock API** — already implemented in `aws-sdk-go-v2/service/s3` (in use). Legal hold calls (`PutObjectLegalHold`, `GetObjectLegalHold`) are standard S3 operations available in the same SDK.
- **Storage driver interface** — `driver.go` already defines `ObjectLockMode` and `ObjectLockRetentionDays` in `DriverConfig`. The S3 driver already applies retention on `PutObject`. This spec extends that foundation, not replaces it.
- **Compliance module (Phase 14)** — `admin_compliance.go` exists and handles journaling, retention hooks, and eDiscovery. Legal hold fits naturally alongside these.
- **Cohasset Associates** — the recognized third-party auditor for SEC 17a-4(f) compliance certification. Their assessment is a separate engagement (not part of the engineering timeline). We provide the technical evidence package; they issue the certification report. Typical engagement: 6-8 weeks after implementation complete.
- **Competitive context** (roadmap line 96-100): EXO requires E5 for Purview Preservation Lock. Gmail's Vault retention is E5-equivalent. No Chinese competitor documents WORM compliance. We are the only on-premise platform offering certified WORM at no per-seat markup.

## Effort Estimate

| Component | Effort |
|-----------|--------|
| Storage driver: legal hold + retention override + `EnsureBucketObjectLock` | 1 week |
| `worm.go` — configuration validation, startup checks, safety rails | 1 week |
| `legal_holds` schema + PL/pgSQL reducers | 1 week |
| Admin API for legal hold CRUD + audit log | 1 week |
| Unit tests + integration tests + WORM property assertions | 1 week |
| Operational verification script (`verify-worm.sh`) + SeaweedFS WORM setup guide | 1 week |
| `docs/specs/WORM.md` — compliance guide, shared-responsibility model, certification prep | 1 week |
| Cohasset Associates engagement (out of band, not engineering time) | 6-8 weeks |
| **Total engineering** | **~8 weeks** |
