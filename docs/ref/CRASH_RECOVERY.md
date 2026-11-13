# Crash Recovery Design

## What Can Fail and How We Handle Each

### 1. PostgreSQL Crash (most common)

PostgreSQL already recovers itself via WAL replay on restart — this is built-in and
requires nothing from us. However, two things need special handling:

**Unlogged tables are TRUNCATED on crash recovery (by design).**
This is the trade-off for speed. We handle each unlogged table differently:

| Unlogged Table | On Crash | Recovery Action |
|---|---|---|
| `sessions` | Truncated | Users re-authenticate. Acceptable. |
| `ws_subscriptions` | Truncated | Gateway reconnects rebuild subscriptions. |
| `outbound_queue` | Truncated | PROBLEM — see below |
| `greylist` | Truncated | Rebuilt from scratch. Minor disruption (some legit mail delayed briefly). |
| `rate_limit_counters` | Truncated | Reset to zero. Slightly permissive briefly. Acceptable. |
| `smtp_sessions` | Truncated | In-progress SMTP connections dropped. Senders retry. |

**Outbound queue problem**: Mail queued but not yet sent is lost if stored in an
unlogged table. Solution: outbound_queue is a LOGGED table (durability matters) but
we use an unlogged `outbound_queue_hot` staging table as a fast write buffer, drained
every 10 seconds by pg_cron into the logged `outbound_queue`. Worst case on crash:
10 seconds of queued mail needs to be re-submitted by clients.

### 2. Go Gateway Crash

The gateway is stateless — all state lives in PostgreSQL. On restart:
- All WebSocket connections are dropped; clients reconnect with exponential backoff
- JMAP clients detect StateChange gaps on reconnect and fetch missed changes
- Sessions persist in PostgreSQL (logged table); users stay authenticated
- No data loss — gateway held no state

**Restart policy:**
- systemd: `Restart=always` with `RestartSec=5`

### 3. Power Loss

Worst case: power cuts mid-fsync.

PostgreSQL with `fsync=on` (default) guarantees no committed transaction is lost.
WAL ensures partial writes are replayed or rolled back correctly.

**In-flight states that need recovery on startup:**

| State | Detection | Recovery |
|---|---|---|
| Outbound queue items with `status='sending'` for > 5 min | Startup recovery query | Reset to `status='pending'` |
| SeaweedFS multipart uploads > 1 hour old | S3 ListMultipartUploads on startup | Abort and delete incomplete uploads |
| DKIM-signed messages mid-delivery | Check outbound_queue for `dkim_signed=true, delivered=false` | Re-attempt delivery (idempotent — message-ID deduplication at recipient) |
| Calendar invite emails mid-send | outbound_queue recovery above covers this | Same |
| Blob ref_count drift | DR integrity scan (`/admin/system` → "Storage DR Scan") | See post-outage procedure below |
| Orphaned SeaweedFS objects | DR integrity scan | Re-import via scan reconcile or manual cleanup |

**Post-outage blob storage integrity scan:**

After a power outage, crash, or failover, run the Storage DR Scan from `/admin/system` → "Storage DR Scan". The scan runs three phases:

1. **Orphan detection** — objects in SeaweedFS with no corresponding row in the `blobs` table. These leaked because the DB row was deleted but the S3 delete didn't complete before the crash. Use "Reconcile" to re-import them (they get `ref_count=0`, queued for deferred GC).

2. **Missing detection** — rows in `blobs` with no backing object in SeaweedFS. These leaked because the SeaweedFS delete completed but the DB cleanup didn't. Restore from backup or re-import the missing blobs individually.

3. **ref_count reconciliation** — compares `blobs.ref_count` against the actual `COUNT(*)` of `message_attachments` rows. Any mismatch is a drifted counter (possible after power loss during a multi-table transaction that touched both `blobs` and `message_attachments`). The scan reports each drift with expected vs. actual counts. To repair: update `blobs.ref_count` to match `COUNT(*)` for the affected SHA-256.

The scan is non-blocking and runs in the background. Results persist in `storage_dr_scans` for audit. Schedule it after any unplanned restart, or run it weekly as a health check.

### 4. PostgreSQL Primary Failover (Primary goes down)

Pgpool-II's health check detects the primary failure and the watchdog moves the
VIP; pgpool's `failover_command` promotes the most up-to-date standby.
Gateway reconnects via PgBouncer which retries connection.

Timeline:
- Primary failure detected: ~3 seconds (Pgpool-II health check)
- Replica promoted: ~5 seconds
- Pgpool-II VIP moved: ~2 seconds
- PgBouncer reconnects: ~3 seconds
- Total downtime: ~8-15 seconds

During failover: write operations fail with connection errors. JMAP clients queue
changes locally (IndexedDB) and retry on reconnect.

### 5. SeaweedFS Crash

Attachments are stored in SeaweedFS. PostgreSQL only holds refs (SHA-256 + object path).
On SeaweedFS restart, it recovers its own state (Raft-based HA handles master failover automatically).
No action needed from us unless a SeaweedFS data volume is corrupted — that's a restore-from-backup scenario.

---

## Startup Recovery Procedure

On every gateway startup, before accepting connections, run:

```
1. Check PostgreSQL connectivity → if fail, wait and retry (do not start)
2. Check SeaweedFS connectivity → log warning if fail, continue (mail works without attachments)
3. Call PostgreSQL startup_recovery() function:
   a. Reset outbound_queue items stuck in 'sending' → 'pending'
   b. Clean up sessions older than max_session_age
   c. Log all recovery actions to crash_events table
   d. Return summary: {reset_count, cleaned_sessions, ...}
4. If recovery found anything, send admin alert email
5. Write startup event to crash_events table
6. Begin accepting connections
```

---

## Crash Event Log Schema

```sql
CREATE TABLE crash_events (
  id              BIGSERIAL PRIMARY KEY,
  occurred_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
  component       TEXT NOT NULL,  -- 'postgresql', 'gateway', 'pgpool', 'seaweedfs'
  severity        TEXT NOT NULL CHECK (severity IN ('warn','error','fatal')),
  description     TEXT NOT NULL,
  previous_state  JSONB,          -- snapshot of relevant state before crash
  recovery_action TEXT,           -- what startup_recovery() did
  recovered_at    TIMESTAMPTZ,
  admin_notified  BOOL DEFAULT FALSE,
  notes           TEXT
);
-- Append-only enforced via trigger (no UPDATE or DELETE allowed)
```

---

## Health Check System

pg_cron runs `health_check()` every 5 minutes. It checks:

| Check | Failure Threshold | Action |
|---|---|---|
| PostgreSQL replication lag | > 60 seconds | Alert admin |
| Outbound queue depth | > 500 messages | Alert admin |
| Outbound queue oldest item | > 1 hour | Alert admin |
| Disk space (data volume) | < 10% free | Alert admin |
| Disk space (WAL volume) | < 15% free | Alert admin (WAL full = crash) |
| SeaweedFS connectivity | Any failure | Alert admin |
| ClamAV definitions age | > 24 hours | Alert admin |
| DKIM key expiry | < 30 days remaining | Alert admin |
| TLS cert expiry | < 21 days remaining | Alert admin |
| Failed auth attempts | > 100/hour | Alert admin + auto-block IPs |

Results written to `health_history` table. Admin dashboard shows last 24 hours.
Three consecutive failures of any check triggers an email alert to all admin users.

---

## Client-Side Crash Resilience

JMAP clients (web, iOS, Android) are designed to handle server unavailability:

- All pending actions queued in IndexedDB/local storage
- Exponential backoff reconnect: 1s → 2s → 4s → 8s → max 60s
- On reconnect: send last known `state` token → server sends only missed changes
- No data loss from client perspective — JMAP's state machine handles gaps cleanly
- User sees a "Reconnecting..." banner, not an error page
