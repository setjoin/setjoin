# High Availability Deployment Guide

> **Pick your deployment size:**
> - **< 100 users → single-node.** One host, no failover overhead. Use
>   [`SINGLE_NODE_SETUP.md`](SINGLE_NODE_SETUP.md) (runbook) + `deploy/scripts/install.sh` (installer).
> - **100+ users, or you need HA** (zero single points of failure, automatic
>   failover) → **this guide.**
>
> **Profile (this guide): 3 Full Nodes.** Zero single points of failure.
> Automatic failover for all components.

---

## Architecture

```
┌──────────────────────────────────────────────────────────────┐
│  Server 1 (mail1)     Server 2 (mail2)    Server 3 (mail3)  │
│                                                              │
│  PostgreSQL (primary)◄──►PostgreSQL (standby)◄──►PostgreSQL │
│      │  sync replication    │                     (standby)  │
│      │                      │  async replication             │
│  Pgpool-II ◄────────► Pgpool-II ◄────────► Pgpool-II       │
│  (watchdog)  heartbeat  (watchdog)  heartbeat  (watchdog)    │
│      │                      │                      │         │
│  SeaweedFS #1 ◄────────► SeaweedFS #2 ◄────────► SeaweedFS  │
│  (Raft master)   Raft    (Raft peer)    Raft    (Raft peer)  │
│  +volume+filer            +volume+filer          +volume     │
│      │                      │                      │         │
│  Gateway                  (standby)             (standby)    │
│  (active via VIP)                                             │
└──────────────────────────────────────────────────────────────┘
```

### Connection Flow

```
Clients → Pgpool-II VIP (:9999) → PostgreSQL (any of 3 nodes)
       → SeaweedFS S3 (localhost:9000) → SeaweedFS cluster
Gateway → LISTEN/NOTIFY → Pgpool-II VIP → Primary PostgreSQL
```

### Component HA Summary

| Component | HA Mechanism | Failover Time | Data Loss |
|---|---|---|---|
| PostgreSQL | Streaming replication (1 sync + 1 async standby) | 8-15s | Zero (sync standby) |
| Pgpool-II | Watchdog majority (2/3 votes for VIP) | 15-30s | Zero (connection pooling) |
| SeaweedFS | Raft consensus (3 masters) | <3s | Zero (volume replication 001) |
| Gateway | VIP via Pgpool-II, stateless | Instant (new connections) | Zero |

---

## Split-Brain Prevention

### Scenario 1: Network Partition (2 nodes isolated from 1)

```
              ┌──────────────┐
  mail1 ◄────►│  Partition 1 │◄────► mail2   ← 2 votes = quorum
              │  (2 nodes)   │               VIP stays here
              └──────────────┘
                    │
              ┌─────▼──────┐
              │  Partition 2│                  ← 1 vote = no quorum
              │  (1 node)  │                  drops VIP, demotes PG
              │    mail3    │
              └────────────┘
```

### Scenario 2: Primary PG Crash

1. Pgpool-II health check detects primary down (3s)
2. Watchdog elects new leader to hold VIP
3. New leader's Pgpool-II promotes most up-to-date standby via `failover_command`
4. `pg_ctl promote` on standby → new primary
5. Remaining standby reconnects to new primary
6. Gateway reconnects via VIP → Pgpool-II routes to new primary

**Total recovery: 8-15 seconds.**

### Scenario 3: SeaweedFS Master Crash

1. Raft detects leader heartbeat timeout (<1s)
2. Remaining 2 masters elect new leader (<1s)
3. Volume servers reconnect to new leader with heartbeat

**Total recovery: <3 seconds.**

---

## Hardware Requirements

| Component | Minimum Per Node | Recommended |
|---|---|---|
| CPU | 4 cores | 8 cores |
| RAM | 8 GB | 16 GB |
| Disk (PG) | Used DB size × 1.5 | NVMe SSD |
| Disk (SeaweedFS) | Equal across all 3 nodes | NVMe SSD |
| Network | 1 Gbps, <1ms latency | 10 Gbps, <0.5ms |

---

## Deployment Quick Reference

```bash
# ---- Node 1 (Primary) ----
# PostgreSQL (already running as primary)

# Pgpool-II
pgpool -n -f /etc/pgpool2/pgpool.conf

# SeaweedFS
weed server \
  -master.peers=mail1:9333,mail2:9333,mail3:9333 \
  -master.port=9333 -master.defaultReplication=001 \
  -volume.port=8080 -volume.max=100 -dir=/data/seaweedfs \
  -filer -s3 -s3.port=9000 -s3.config=/etc/mail/seaweedfs-s3.json

# ---- Node 2 (Standby) ----
systemctl start postgresql  # already configured as standby

pgpool -n -f /etc/pgpool2/pgpool.conf

weed server \
  -master.peers=mail1:9333,mail2:9333,mail3:9333 \
  -master.port=9333 -volume.port=8080 -volume.max=100 -dir=/data/seaweedfs \
  -filer -s3 -s3.port=9000 -s3.config=/etc/mail/seaweedfs-s3.json

# ---- Node 3 (Standby) ----
systemctl start postgresql

pgpool -n -f /etc/pgpool2/pgpool.conf

weed server \
  -master.peers=mail1:9333,mail2:9333,mail3:9333 \
  -master.port=9333 -volume.port=8080 -volume.max=100 -dir=/data/seaweedfs \
  -s3 -s3.port=9000 -s3.config=/etc/mail/seaweedfs-s3.json
```

### Gateway Configuration

```bash
export DB_DSN="postgres://mail:pass@pgpool_vip:9999/mailserver"
export DB_DIRECT_DSN="postgres://mail:pass@pgpool_vip:9999/mailserver"
export S3_ENDPOINT="localhost:9000"
```

---

## Zabbix Monitoring

**Gateway `/metrics` is authenticated.** It fails closed (401) unless `METRICS_TOKEN`
is set on the gateway; configure the Zabbix/Prometheus scraper with
`Authorization: Bearer $METRICS_TOKEN`. If the scraper runs on a trusted
management network with no way to send a bearer token, set
`METRICS_ALLOW_UNAUTHENTICATED=1` on the gateway instead (loud startup WARN,
opt-in only — see `config.env.sample`).

### Single-Node Metrics (available today)

| Metric | Zabbix Key | Trigger | Source |
|---|---|---|---|
| HTTP request rate | `gateway_http_requests_total[5m]` | >1000/min | Gateway :443/metrics |
| Mail queue depth | `mail_queue_depth` | >1000 pending | Gateway :443/metrics |
| Auth failures | `mail_auth_failures_total[5m]` | >20/min | Gateway :443/metrics |
| Database size | `pg_database_size_bytes` | >90% disk | Pgpool-II metrics |
| SeaweedFS storage | `seaweedfs_volume_used_bytes` | >80% capacity | SeaweedFS :9333/metrics |

### HA Metrics (enabled with 3-node deployment)

| Metric | Zabbix Key | Trigger | Source |
|---|---|---|---|
| Replication lag | `pg_replication_lag_bytes` | >1GB or >30s behind | Pgpool-II metrics |
| Backend status | `pgpool_backend_status` | Any backend down >1min | Pgpool-II metrics |
| Watchdog quorum | `pgpool_watchdog_status` | Any node isolated | Pgpool-II metrics |
| SeaweedFS leader | `seaweedfs_master_leader` | Leader count = 0 | SeaweedFS :9333/cluster/status |

### Sample Zabbix Trigger Template

```xml
<trigger>
    <name>PG replication lag >1GB on {HOST.NAME}</name>
    <expression>{last()} > 1073741824</expression>
    <priority>HIGH</priority>
    <description>Standby is >1GB behind primary. Check network and disk I/O.</description>
</trigger>
```

---

## Failover Test Procedure

```bash
# 1. Check current state
psql -h pgpool_vip -p 9999 -U mail -d mailserver -c "SELECT pg_is_in_recovery();"
# → false on primary, true on standbys

# 2. Kill primary PostgreSQL
ssh mail1 "systemctl stop postgresql"

# 3. Watch Pgpool-II log
tail -f /var/log/pgpool/pgpool.log
# → "failover: set new primary node 1" (the standby index)

# 4. Verify new primary
psql -h pgpool_vip -p 9999 -U mail -d mailserver -c "SELECT pg_is_in_recovery();"
# → false (one of the standbys is now primary)

# 5. Recover old primary
ssh mail1 "systemctl start postgresql"
# → Old primary comes back as standby

# 6. Verify all 3 nodes healthy
psql -h pgpool_vip -p 9999 -U mail -d mailserver -c "SHOW pool_nodes;"
# → status=2 for all 3 nodes
```

---

## Deployment Checklist

- [ ] 3 servers provisioned (identical specs recommended)
- [ ] Network latency <1ms between all pairs (verified via `ping`)
- [ ] PostgreSQL 18+ installed on all 3 nodes
- [ ] Streaming replication configured (1 sync + 1 async standby)
- [ ] Pgpool-II installed on all 3 nodes with watchdog enabled
- [ ] SeaweedFS installed on all 3 nodes (3-node Raft)
- [ ] Gateway `DB_DSN` and `DB_DIRECT_DSN` point to Pgpool-II VIP
- [ ] Gateway `S3_ENDPOINT` points to localhost:9000
- [ ] Failover tested: primary killed → standby promoted → gateway continues
- [ ] Failback tested: old primary recovers as standby
- [ ] Zabbix monitoring configured (8 metrics)
- [ ] Alerting tested (simulated queue backlog)

---

*Last updated: May 2026*
