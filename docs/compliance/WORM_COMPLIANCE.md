# WORM Compliance — SEC 17a-4(f), FINRA 4511(c), CFTC 1.31(c)-(d)

> **Status:** Implemented — S3 Object Lock compliance mode at the blob storage layer.
> **Code:** `mailserver/gateway/internal/storage/worm.go`, `retention.go`, `s3_driver.go`
> **Config:** `mailserver/gateway/internal/config/config.go` (`WORM_MODE`, `WORM_RETENTION_DAYS`, `WORM_LEGAL_HOLD_ENABLED`)
> **References:** `docs/specs/SECURITY.md` (email security), `docs/specs/DATABASE_SECURITY.md` (query security)

---

## What Is WORM?

**WORM** (Write Once, Read Many) is a data immutability guarantee: once written, data cannot be modified, overwritten, or deleted for a prescribed retention period. It is the foundational technical control required by the three principal electronic-records regulations:

| Regulation | Jurisdiction | Retention Period | Scope |
|---|---|---|---|
| **SEC Rule 17a-4(f)** | United States | 6 years | Broker-dealers — electronic records must be preserved in "non-erasable, non-rewritable" format |
| **FINRA Rule 4511(c)** | United States | 7 years | Securities firms — books and records preservation; stricter than 17a-4(f) |
| **CFTC Rule 1.31(c)-(d)** | United States | 5 years | Commodities firms — regulatory records must be maintained in WORM-compliant storage |

Additional regulations with WORM requirements include:
- **MiFID II** (EU) — 5–7 years for investment firms
- **HIPAA** (US) — 6 years for medical records (45 CFR 164.316)
- **FDA 21 CFR Part 11** — Electronic signatures and records

### Key WORM Properties

1. **Non-erasable:** No principal — not even the root/administrator — can delete a locked object before its retention period expires.
2. **Non-rewritable:** Once written, the object's content cannot be modified.
3. **Time-bound:** The retention lock has a fixed duration. After expiry, the object is no longer protected and can be deleted normally.
4. **Tamper-evident:** Any attempt to modify or delete a locked object returns a clear error response (`403 Forbidden` or equivalent).

### Legal Hold

A **legal hold** (also called a litigation hold) suspends the normal retention expiry clock. When a legal hold is placed on an object, it cannot be deleted even after its retention period expires. Legal holds are used when an organization is subject to litigation, regulatory investigation, or audit.

---

## How Our Implementation Works

### Architecture

WORM immutability is enforced at the **blob storage layer** through **S3 Object Lock in compliance mode**. Every email attachment, raw message blob, and backup artifact written to the storage backend is locked immediately on write.

```
Email arrives
    │
    ▼
SMTP/JMAP gateway writes raw message + attachments to S3
    │
    ▼
PutObject called with ObjectLockMode=COMPLIANCE + RetainUntilDate=<now + retention_days>
    │
    ▼
S3-compatible backend (SeaweedFS / AWS S3 / MinIO) enforces the lock
    │
    ▼
Any DeleteObject call on a locked blob → HTTP 403 AccessDenied
```

### Components

| Component | File | Role |
|---|---|---|
| `Driver` interface | `driver.go:11` | Common storage interface with retention + legal hold methods |
| `s3Driver` | `s3_driver.go:29` | S3-compatible implementation. Sets `ObjectLockMode` + `ObjectLockRetainUntilDate` on every `PutObject`. Exposes `PutObjectRetention`, `GetObjectRetention`, `PutObjectLegalHold`, `GetObjectLegalHold`. |
| `ossDriver` | `oss_driver.go:20` | Aliyun OSS stub — returns `ErrRetentionNotSupported`. OSS WORM must be configured via Aliyun console. |
| `WORMRetentionPolicy` | `retention.go:49` | Policy engine: `Apply` (lock new objects), `Verify` (check status), `Release` (governance only). |
| `RetentionPolicyRegistry` | `retention.go:116` | Composes multiple policies, applies in registration order. |
| `ValidateWORMConfig` | `worm.go:36` | Startup validation: mode must be "compliance" or "governance", retention days must match mode. |
| `StartupWORMCheck` | `worm.go:68` | Fatal startup check: gateway refuses to start if bucket Object Lock config does not match `WORM_MODE`. |
| `RetentionDaysBelowMinimum` | `worm.go:91` | Warns (does not block) if retention is below the 2557-day regulatory minimum. |

### Compliance Mode vs Governance Mode

| Property | Compliance | Governance |
|---|---|---|
| Delete locked object | **Never** — even root/administrator | Requires `BypassGovernanceRetention` permission |
| Regulatory suitability | Required for SEC/FINRA/CFTC | Not sufficient for regulatory mandates |
| Administration | Irreversible within retention period | Reversible by authorized principals |
| Bypass header | Not accepted | `x-amz-bypass-governance-retention: true` |

**Compliance mode is the only mode that satisfies SEC 17a-4(f), FINRA 4511(c), and CFTC 1.31(c)-(d).** Governance mode is a softer alternative for internal retention policies that do not have regulatory immutability requirements.

### Startup Safety Check

When `WORM_MODE` is set, the gateway runs a fatal startup check:

1. **Config validation** (`ValidateWORMConfig`): mode must be "compliance" or "governance"; retention days must be >= 1.
2. **Bucket Object Lock check** (`StartupWORMCheck`): the blob bucket must have Object Lock enabled in the configured mode. If not, the gateway exits with a fatal error and instructions to recreate the bucket.
3. **Retention minimum warning** (`RetentionDaysBelowMinimum`): if retention is below 2557 days, a `WARN` is logged but startup proceeds — non-regulated deployments may use shorter periods.

The gateway **never starts** with a WORM configuration mismatch. This prevents a misconfigured bucket from silently accepting writes without immutability protection.

---

## Shared Responsibility Model

WORM compliance is a **shared responsibility** between the software platform and the deploying organization.

### Platform Responsibility (Prism Mailserver)

- **Mechanism**: Provides S3 Object Lock in compliance mode at the blob storage layer.
- **Correctness**: Every `PutObject` call sets the retention lock. Startup safety checks prevent misconfiguration.
- **Verifiability**: `GetObjectRetention` and `GetObjectLegalHold` APIs return the current lock state for audit.
- **Configuration**: Environment variables (`WORM_MODE`, `WORM_RETENTION_DAYS`, `WORM_LEGAL_HOLD_ENABLED`) control the policy.
- **Documentation**: This document describes the mechanism, configuration, and certification path.

### Customer Responsibility

- **Physical security**: The storage backend (SeaweedFS, AWS S3, MinIO) must be physically secured and access-controlled.
- **Credential management**: S3 access keys must be rotated, scoped to least privilege, and never hardcoded.
- **Network security**: The S3 endpoint must be protected by firewall rules, TLS, and VPC boundaries where applicable.
- **Audit logging**: S3 access logs must be enabled, shipped to a SIEM, and retained for the regulatory period.
- **Third-party certification**: An independent auditor (e.g., Cohasset Associates) must review the deployment and certify compliance with the applicable regulation.
- **Legal hold procedures**: The organization must define and follow procedures for placing, tracking, and releasing legal holds.
- **Database records**: Message metadata (subject, from, to, timestamps) in PostgreSQL is not WORM-protected by this mechanism. The customer must implement PostgreSQL-level protections (audit logging, restricted access, replication) as part of their compliance posture.

### Not Included by This Mechanism

- **PostgreSQL records**: The `messages`, `message_tags`, and related tables are not protected by S3 Object Lock. They reside in a separate database and are subject to normal database access controls. See `docs/specs/DATABASE_SECURITY.md` for database query security standards.
- **Email headers**: While raw message blobs are WORM-protected at the storage layer, parsed headers stored in PostgreSQL are not.
- **User metadata**: Account records, login history, and configuration data are not WORM-protected.

---

## Configuration Guide

### Environment Variables

| Variable | Default | Description |
|---|---|---|
| `WORM_MODE` | `""` (empty — WORM disabled) | Object Lock mode: `"compliance"` or `"governance"`. Compliance mode is required for SEC/FINRA/CFTC. |
| `WORM_RETENTION_DAYS` | `2557` (7 years) | Retention period in days. Covers the strictest regulation (FINRA 4511(c) = 7 years). SEC 17a-4(f) requires 6 years (2192 days); CFTC 1.31(c)-(d) requires 5 years (1827 days). |
| `WORM_LEGAL_HOLD_ENABLED` | `true` (when `WORM_MODE` is set) | Enable legal hold API. When `true`, administrators can place/release legal holds on individual objects via the S3 Object Lock legal hold mechanism. |

### Enabling WORM

```bash
# Compliance mode — required for SEC/FINRA/CFTC
export WORM_MODE=compliance
export WORM_RETENTION_DAYS=2557   # 7 years
export WORM_LEGAL_HOLD_ENABLED=true
```

### Custom Retention Periods

```bash
# CFTC minimum (5 years)
export WORM_MODE=compliance
export WORM_RETENTION_DAYS=1827

# SEC minimum (6 years)
export WORM_MODE=compliance
export WORM_RETENTION_DAYS=2192

# Short retention for non-regulated deployments (triggers startup WARN)
export WORM_MODE=compliance
export WORM_RETENTION_DAYS=365
```

### Non-Regulated Deployments

For internal retention policies where regulatory immutability is not required:

```bash
export WORM_MODE=governance
export WORM_RETENTION_DAYS=365
```

### Disabling WORM

Leave `WORM_MODE` unset (the default). All retention and legal hold methods return `ErrRetentionNotSupported`.

### Bucket Setup (One-Time)

The blob bucket must be created with Object Lock enabled **before** the gateway starts with `WORM_MODE` set. Object Lock cannot be enabled on an existing bucket (S3 limitation).

Using the AWS CLI (for SeaweedFS, use `weed s3` or the equivalent API call):

```bash
# Create bucket with Object Lock enabled
aws s3api create-bucket \
    --bucket mailblobs \
    --endpoint-url http://127.0.0.1:9000 \
    --object-lock-enabled-for-bucket

# Apply default retention configuration
aws s3api put-object-lock-configuration \
    --bucket mailblobs \
    --endpoint-url http://127.0.0.1:9000 \
    --object-lock-configuration '{
        "ObjectLockEnabled": "Enabled",
        "Rule": {
            "DefaultRetention": {
                "Mode": "COMPLIANCE",
                "Days": 2557
            }
        }
    }'
```

If the bucket does not have Object Lock enabled, the gateway will refuse to start with a fatal error:
```
WORM startup check: bucket does not have Object Lock enabled.
Create the blob bucket with Object Lock enabled in compliance mode, then restart the gateway.
```

---

## Verification

### Testing Immutability

#### 1. Write a blob and attempt deletion

```bash
# Write an object (through the gateway — any email attachment triggers this)
# Then attempt deletion through the S3 API:
aws s3api delete-object \
    --bucket mailblobs \
    --key <blob-key> \
    --endpoint-url http://127.0.0.1:9000

# Expected: HTTP 403 AccessDenied
# Error: "The object was stored using a form of Object Lock."
```

#### 2. Check retention status

```bash
aws s3api get-object-retention \
    --bucket mailblobs \
    --key <blob-key> \
    --endpoint-url http://127.0.0.1:9000

# Expected output:
# {
#     "Retention": {
#         "Mode": "COMPLIANCE",
#         "RetainUntilDate": "2033-06-01T00:00:00Z"
#     }
# }
```

#### 3. Check legal hold status

```bash
aws s3api get-object-legal-hold \
    --bucket mailblobs \
    --key <blob-key> \
    --endpoint-url http://127.0.0.1:9000

# Expected: {"LegalHold": {"Status": "OFF"}}
```

#### 4. Attempt legal hold placement

```bash
aws s3api put-object-legal-hold \
    --bucket mailblobs \
    --key <blob-key> \
    --legal-hold '{"Status": "ON"}' \
    --endpoint-url http://127.0.0.1:9000

# Should succeed. Then deletion is blocked even after retention expiry.
```

#### 5. Verify the gateway will not start with mismatched config

```bash
# Set WORM_MODE=compliance but use a bucket created without Object Lock
export WORM_MODE=compliance
./gateway

# Expected: Fatal error
# "WORM startup check: bucket does not have Object Lock enabled."
```

### Automated Verification (Unit Tests)

The WORM subsystem is covered by unit tests in:
- `mailserver/gateway/internal/storage/retention_test.go` — policy engine unit tests
- `mailserver/gateway/internal/config/config_test.go` — `TestWORMConfigDefaults`, `TestWORMConfigFromEnv`, `TestWORMConfigLegalHoldDefaultsOn`
- `mailserver/gateway/internal/storage/worm_test.go` — `ValidateWORMConfig` and `StartupWORMCheck` tests

Run with:
```bash
cd mailserver/gateway && go test ./internal/storage/... ./internal/config/... -v -run WORM
```

### Integration Test

```bash
# Requires a test S3 bucket with Object Lock enabled
cd mailserver/gateway && go test -tags e2e -run TestWORMIntegration -v -count=1 ./internal/storage/...
```

---

## Certification Path

WORM compliance for SEC 17a-4(f), FINRA 4511(c), and CFTC 1.31(c)-(d) requires a **third-party auditor certification**. The software platform cannot self-certify.

### Recommended Auditor

**[Cohasset Associates](https://www.cohasset.com/)** is the industry-standard auditor for electronic records compliance under SEC and FINRA rules. Their assessments evaluate:

1. **Storage medium**: Is the storage technology truly non-erasable and non-rewritable?
2. **Retention enforcement**: Does the system prevent deletion during the retention period?
3. **Audit trail**: Are all access and modification attempts logged?
4. **Legal hold**: Can litigation holds be placed and tracked?
5. **Disaster recovery**: Is WORM protection preserved across backup and restore operations?

### What the Auditor Will Examine

| Area | Our Implementation | Auditor Verifies |
|---|---|---|
| Immutability mechanism | S3 Object Lock compliance mode | Bucket configuration, API responses to delete attempts |
| Retention configuration | `WORM_RETENTION_DAYS` | Retention period matches regulatory requirement |
| Startup safety | `StartupWORMCheck` | Gateway will not start with misconfigured bucket |
| Delete denial | `DeleteObject` → 403 on locked objects | Test: attempt deletion of in-retention object |
| Legal hold | S3 Object Lock legal hold API | Test: place hold, verify deletion blocked after expiry |
| Audit logging | S3 access logs (customer-configured) | Log completeness, retention, tamper evidence |

### Certification Process

1. **Engage** Cohasset Associates (or equivalent auditor) for an SEC 17a-4(f) / FINRA 4511(c) assessment.
2. **Configure** WORM as described above (`WORM_MODE=compliance`, appropriate retention days).
3. **Enable** S3 access logging on the blob bucket.
4. **Demonstrate** the verification steps in the Verification section.
5. **Document** the deployment architecture, access controls, and operational procedures.
6. **Receive** the auditor's assessment report certifying compliance.

### Important Note

This platform provides the **technical mechanism** for WORM immutability. The certification report is issued by the auditor to the deploying organization, not to the platform vendor. Each deployment must be individually certified because the physical, network, and operational controls vary by installation.

---

## Limitations

### Blob Storage Only

WORM protection applies exclusively to objects stored in the S3-compatible blob backend (SeaweedFS, AWS S3, MinIO, etc.). The following are **not** WORM-protected:

| Data | Location | Protected by WORM? | Mitigation |
|---|---|---|---|
| Email raw body blobs | S3 (mailblobs bucket) | Yes — S3 Object Lock | — |
| Email attachments | S3 (mailblobs bucket) | Yes — S3 Object Lock | — |
| Message metadata | PostgreSQL `messages` table | No | RLS, audit logging, replication |
| Parsed headers | PostgreSQL `message_headers` table | No | RLS, audit logging, replication |
| Tags and folders | PostgreSQL `message_tags` table | No | RLS, audit logging, replication |
| User accounts | PostgreSQL `users` table | No | RLS, audit logging, replication |
| Audit log | PostgreSQL `audit_log` table | No | WAL archiving, external replication |
| Configuration | PostgreSQL `system_config` table | No | Change tracking, version history |
| Backups (optional) | S3 (backup bucket) | Yes — if `BACKUP_OBJECT_LOCK` is configured | — |

### Provider Compatibility

| Provider | Object Lock Support | Notes |
|---|---|---|
| **AWS S3** | Full (compliance + governance) | Native support. Object Lock must be enabled at bucket creation. |
| **SeaweedFS** | Compliance mode via `weed s3` | Requires SeaweedFS with Object Lock configuration. Verify with SeaweedFS documentation for your version. |
| **MinIO** | Full (compliance + governance) | Requires MinIO with `MINIO_API_OBJECT_LOCK` and a backend filesystem that supports extended attributes (XFS, ZFS, etc.). |
| **Backblaze B2** | Governance only | Compliance mode is not available. Cannot be used for SEC/FINRA/CFTC. |
| **Cloudflare R2** | Governance only | Compliance mode is not available. Cannot be used for SEC/FINRA/CFTC. |
| **Wasabi** | Compliance mode | Verify with Wasabi documentation. |
| **Aliyun OSS** | Console-only | OSS WORM must be configured via the Aliyun console. The gateway's OSS driver returns `ErrRetentionNotSupported` for programmatic lock operations — the lock is enforced by OSS itself, not by the gateway. |

### Object Lock Must Be Enabled at Bucket Creation

S3 Object Lock cannot be enabled on an existing bucket. If WORM is needed for an existing deployment, a new bucket must be created with Object Lock enabled, and data must be migrated.

### Retention Period Cannot Be Shortened

Once an object is locked in compliance mode, its retention period cannot be reduced — only extended. This is inherent to the S3 Object Lock specification and is the defining characteristic of compliance mode.

### No Cryptographic Chain of Custody

This implementation does not include a Merkle tree or blockchain-based chain of custody. It relies on S3 Object Lock as the immutability primitive. For deployments requiring cryptographic proof of non-tampering, an external blockchain anchoring service would need to be integrated.

---

## Operational Procedures

### Placing a Legal Hold

When litigation or investigation requires preserving specific objects beyond their normal retention period:

```bash
aws s3api put-object-legal-hold \
    --bucket mailblobs \
    --key <object-key> \
    --legal-hold '{"Status": "ON"}' \
    --endpoint-url $S3_ENDPOINT
```

A legal hold overrides the retention expiry clock: even after `RetainUntilDate` passes, a held object cannot be deleted.

### Releasing a Legal Hold

```bash
aws s3api put-object-legal-hold \
    --bucket mailblobs \
    --key <object-key> \
    --legal-hold '{"Status": "OFF"}' \
    --endpoint-url $S3_ENDPOINT
```

### Extending Retention

In compliance mode, the retention period can be **extended** (but not shortened):

```bash
aws s3api put-object-retention \
    --bucket mailblobs \
    --key <object-key> \
    --retention '{"Mode": "COMPLIANCE", "RetainUntilDate": "2035-01-01T00:00:00Z"}' \
    --endpoint-url $S3_ENDPOINT
```

Attempting to shorten the retention period returns an error.

### Monitoring WORM Status

The gateway exposes retention policy metadata through the admin API:

```
GET /admin/storage/retention
```

Response:
```json
{
  "policies": [
    {
      "type": "worm_s3_object_lock",
      "mode": "compliance",
      "description": "S3 Object Lock compliance mode — non-erasable, non-rewritable. No principal can delete locked objects. Required for SEC 17a-4(f)."
    }
  ]
}
```

---

## References

- [SEC Rule 17a-4(f)](https://www.ecfr.gov/current/title-17/chapter-II/part-240/section-240.17a-4) — Electronic records retention for broker-dealers
- [FINRA Rule 4511(c)](https://www.finra.org/rules-guidance/rulebooks/finra-rules/4511) — Books and records preservation
- [CFTC Rule 1.31(c)-(d)](https://www.ecfr.gov/current/title-17/chapter-I/part-1/section-1.31) — Regulatory records
- [AWS S3 Object Lock Documentation](https://docs.aws.amazon.com/AmazonS3/latest/userguide/object-lock.html)
- [Cohasset Associates](https://www.cohasset.com/) — Industry-standard SEC/FINRA electronic records auditor
- `docs/specs/SECURITY.md` — Email security implementation status
- `docs/specs/DATABASE_SECURITY.md` — Database query security standards
