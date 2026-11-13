# mailctl Restore, Cloud Object Lock & Multi-Region Replication — Design Spec

> **Target:** Extensions to Phase 37.4 storage HA system. Three independent features.

**Goal:** Add CLI-driven disaster recovery (`mailctl restore`), ransomware-protected backup buckets (S3/OSS object lock with governance/compliance modes), and cross-region backup replication for geographic resilience.

**Architecture:** All three extend existing code — no new packages or interfaces. `mailctl restore` calls the already-built restore engine via `storage.Driver`. Object lock is a configuration option on the existing S3/OSS driver `CreateBucket` + `PutObject` paths. Multi-region replication adds a second `storage.Driver` to the backup engine's `Worker` goroutine, with best-effort async copy after each successful primary backup.

---

## 1. mailctl restore

### 1.1 Command Interface

```bash
# Full platform restore
mailctl restore --provider s3 --bucket mailserver-backup \
                --access-key AKIA... --secret-key ... \
                --endpoint s3.amazonaws.com --type full

# Config-only
mailctl restore --provider s3 --bucket mailserver-backup \
                --access-key AKIA... --secret-key ... --type config

# Partial blob restore (specific hashes from integrity report)
mailctl restore --provider s3 --bucket mailserver-backup \
                --access-key AKIA... --secret-key ... \
                --type blobs --hashes abc123,def456

# Preview only (dry-run)
mailctl restore --provider s3 --bucket mailserver-backup \
                --access-key AKIA... --secret-key ... --type full --dry-run
```

### 1.2 Implementation

```go
func cmdRestore() {
    provider := flag.String("provider", "", "Backup provider: s3 or oss")
    endpoint := flag.String("endpoint", "", "Backup endpoint")
    bucket := flag.String("bucket", "", "Backup bucket")
    accessKey := flag.String("access-key", "", "Access key")
    secretKey := flag.String("secret-key", "", "Secret key")
    restoreType := flag.String("type", "full", "full, config, or blobs")
    hashes := flag.String("hashes", "", "Comma-separated blob hashes (type=blobs)")
    dryRun := flag.Bool("dry-run", false, "Preview only, no data restored")
    flag.Parse()

    // Create backup driver from flags
    driver, err := storage.NewDriver(storage.DriverConfig{
        Provider: *provider, Endpoint: *endpoint,
        Bucket: *bucket, AccessKey: *accessKey, SecretKey: *secretKey,
    })
    if err != nil { /* fatal */ }

    // Download and display backup manifest
    r, err := driver.GetObject(ctx, "backup-manifest.json")
    if err != nil { /* fatal */ }
    var bm BackupManifest
    json.NewDecoder(r).Decode(&bm)
    fmt.Printf("Backup: %s\n  DB size: %d\n  Blobs: %d (%d bytes)\n",
        bm.Timestamp, bm.ConfigSize, bm.BlobCount, bm.BlobTotalSize)

    if *dryRun { return }

    // Execute restore using the existing restore engine
    // (same code path as the web setup wizard)
    switch *restoreType {
    case "full":
        restoreFull(ctx, driver, &bm)
    case "config":
        restoreConfig(ctx, driver)
    case "blobs":
        restoreBlobs(ctx, driver, strings.Split(*hashes, ","))
    }
}
```

### 1.3 Error Handling

- Missing flags → print usage, exit 1
- Driver connection failure → exit 1 with error message
- Corrupt backup-manifest.json → exit 1
- Partial blob restore failure → print per-hash errors, exit 1 if any failed

### 1.4 Scope

- Reuses `storage.Driver` (S3/OSS), `restore.Engine`, and `backup.BackupManifest` — no new types
- No auth required — backup bucket credentials ARE the auth
- ~50 lines added to `mailserver/cmd/mailctl/main.go`

---

## 2. Cloud Object Lock

### 2.1 Retention Modes

| Mode | Behavior | AWS S3 API | Aliyun OSS API |
|---|---|---|---|
| `none` | No lock (current) | No change | No change |
| `governance` | Locked for N days. Root can override with `s3:BypassGovernanceRetention` | `ObjectLockEnabled: true`, `ObjectLockRetainUntilDate` on PutObject | `x-oss-object-lock: GOVERNANCE`, `PutBucketWorm` |
| `compliance` | Locked for N days. NO ONE can delete. | Same as governance, mode=COMPLIANCE | `x-oss-object-lock: COMPLIANCE`, `ExtendBucketWorm` |

### 2.2 S3 Driver Changes

```go
func NewS3Driver(cfg DriverConfig) (Driver, error) {
    // ... existing setup ...

    // Create bucket with object lock if retention is configured
    if cfg.ObjectLockRetentionDays > 0 {
        client.CreateBucket(ctx, &s3.CreateBucketInput{
            Bucket: aws.String(cfg.Bucket),
            ObjectLockEnabledForBucket: aws.Bool(true),
        })
    }
}

func (d *s3Driver) PutObject(ctx context.Context, key string, data io.Reader, size int64) error {
    input := &s3.PutObjectInput{
        Bucket: aws.String(d.bucket), Key: aws.String(key),
        Body: data, ContentLength: aws.Int64(size),
    }
    if d.objectLockDays > 0 {
        retainUntil := time.Now().AddDate(0, 0, d.objectLockDays)
        input.ObjectLockMode = types.ObjectLockMode(d.lockMode)
        input.ObjectLockRetainUntilDate = aws.Time(retainUntil)
    }
    _, err := d.client.PutObject(ctx, input)
    return err
}
```

### 2.3 OSS Driver Changes

```go
func NewOSDriver(cfg DriverConfig) (Driver, error) {
    // ... existing setup ...
    if cfg.ObjectLockRetentionDays > 0 {
        client.PutBucketWorm(ctx, &oss.PutBucketWormRequest{
            Bucket: oss.Ptr(cfg.Bucket),
            WormId: oss.Ptr(fmt.Sprintf("mailserver-worm-%d", time.Now().Unix())),
            RetentionPeriodInDays: oss.Ptr(int32(cfg.ObjectLockRetentionDays)),
        })
    }
}
```

### 2.4 Admin UI

Add to the backup config section on the system page:

```svelte
<div class="form-group">
    <label for="backup-lock">Object Lock</label>
    <select id="backup-lock" bind:value={backupLock}>
        <option value="none">None</option>
        <option value="governance">Governance (admins can override)</option>
        <option value="compliance">Compliance (no one can delete)</option>
    </select>
</div>
{#if backupLock !== 'none'}
    <div class="form-group">
        <label for="backup-lock-days">Retention (days)</label>
        <input id="backup-lock-days" class="input" type="number" min="1" max="3650"
            bind:value={backupLockDays} />
    </div>
{/if}
```

### 2.5 Config

| Env var | Default | Description |
|---|---|---|
| `BACKUP_OBJECT_LOCK` | `none` | `none`, `governance`, or `compliance` |
| `BACKUP_OBJECT_LOCK_DAYS` | `30` | Retention period in days |

---

## 3. Multi-Region Backup Replication

### 3.1 How It Works

After each successful backup run, the worker copies new manifests and blobs to a replica bucket:

```
Primary backup (S3 us-east-1):
  blobs/abc123...   ← written by backup engine
  manifests/full-001.json

Replica (B2 eu-central):
  blobs/abc123...   ← copied by replication goroutine
  manifests/full-001.json
```

The replica is async and best-effort. If replication fails, the primary backup is still valid — the worker logs a warning and retries next run. HEAD checks make it idempotent.

### 3.2 Engine Changes

```go
type Engine struct {
    pool    *pgxpool.Pool
    primary storage.Driver // SeaweedFS
    backup  storage.Driver // primary S3 backup
    replica storage.Driver // optional cross-region replica
    logger  *slog.Logger
}

func (e *Engine) replicateToBackup(ctx context.Context, manifest Manifest, blobs []BlobRef) {
    if e.replica == nil { return }

    // Copy manifest
    data, _ := json.Marshal(manifest)
    e.replica.PutObject(ctx, "manifests/"+manifestName, bytes.NewReader(data), int64(len(data)))

    // Copy new blobs
    for _, b := range blobs {
        if _, err := e.replica.HeadObject(ctx, "blobs/"+b.Hash); err == nil {
            continue // already there
        }
        r, err := e.backup.GetObject(ctx, "blobs/"+b.Hash)
        if err != nil { continue }
        e.replica.PutObject(ctx, "blobs/"+b.Hash, r, b.Size)
        r.Close()
    }
}
```

### 3.3 Config

| Env var | Default | Description |
|---|---|---|
| `BACKUP_REPLICA_PROVIDER` | — | `s3` or `oss`. Empty = disabled |
| `BACKUP_REPLICA_ENDPOINT` | — | Replica endpoint |
| `BACKUP_REPLICA_REGION` | `us-east-1` | Replica region |
| `BACKUP_REPLICA_BUCKET` | — | Replica bucket name |
| `BACKUP_REPLICA_ACCESS_KEY` | — | Replica access key |
| `BACKUP_REPLICA_SECRET_KEY` | — | Replica secret key |

### 3.4 Restore UI Changes

The setup wizard and admin restore page gain a "Source Region" dropdown:

```svelte
<div class="form-group">
    <label for="restore-source">Restore From</label>
    <select id="restore-source" bind:value={restoreSource}>
        <option value="primary">Primary (us-east-1)</option>
        <option value="replica">Replica (eu-central)</option>
    </select>
</div>
```

Selecting `replica` creates the driver with replica endpoint/bucket/keys instead of primary.

---

## 4. Implementation Order

All three are independent — no shared dependencies. Build in any order.

| # | Feature | Lines | Files | New deps |
|---|---|---|---|---|
| 1 | mailctl restore | ~50 | `cmd/mailctl/main.go` | None |
| 2 | Cloud object lock | ~60 | `storage/s3_driver.go`, `storage/oss_driver.go`, `config.go`, system page | None |
| 3 | Multi-region replication | ~120 | `backup/engine.go`, `config.go`, system page, setup page | None |
| **Total** | | **~230** | **7 files** | **0** |

---

## 5. Testing

- **mailctl restore:** Unit test for flag parsing + `storage.Driver` creation. Integration test against a real backup bucket (flagged with `//go:build integration`).
- **Object lock:** Unit test verifies `CreateBucket` is called with `ObjectLockEnabledForBucket: true` when retention days > 0. OSS equivalent for `PutBucketWorm`.
- **Replication:** Unit test verifies replica driver is called after successful backup. Mock replica `HeadObject` returns 404 → `PutObject` is called. Mock returns 200 → skip.
