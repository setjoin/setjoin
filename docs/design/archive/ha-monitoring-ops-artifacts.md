# HA Monitoring & Ops Artifacts — Design Spec

Date: 2026-06-05
Status: Design

## Goal

Complete Phase 15 by creating the remaining monitoring dashboards (Grafana + Zabbix), the missing `config.env.sample`, and formalizing the deferred Patroni/HAProxy configs as ops playbook templates. The `/metrics` endpoint, health checks, and 3-node HA design are already implemented — this spec covers what's missing.

## What already exists (no work needed)

| Component | File | Status |
|-----------|------|:---:|
| Prometheus `/metrics` endpoint | `mailserver/internal/metrics/handler.go` (258 lines) | ✅ |
| Metrics HTTP middleware | `mailserver/internal/middleware/metrics.go` | ✅ |
| Health endpoints `/health` `/ready` | `mailserver/internal/health/handler.go` | ✅ |
| DB health checks (9 checks) | `mailserver/sql/reducers/health_check.sql` | ✅ |
| 3-node HA design | `docs/guides/HA_OVERVIEW.md` (225 lines) | ✅ |
| Pgpool-II config template | `mailserver/deploy/pgpool.conf.template` | ✅ |
| Failover script | `mailserver/deploy/failover.sh.template` | ✅ |
| SeaweedFS HA planner | `mailserver/internal/deploy/seaweedfs_ha.go` | ✅ |
| systemd units | `mailserver/deploy/mailserver.service` | ✅ |
| Deploy scripts | `mailserver/deploy/scripts/install.sh` `backup.sh` `upgrade.sh` | ✅ |

## What we're building

### 1. Grafana Dashboards

Four importable JSON templates that read from the existing `/metrics` endpoint:

| Dashboard | Panels | Audience |
|-----------|--------|----------|
| **Gateway Overview** | Request rate, error rate (4xx/5xx), latency p50/p95/p99, active connections, goroutines, memory | On-call |
| **Protocol Breakdown** | SMTP/IMAP/JMAP/LDAP request rates, TCP connections per protocol, TLS handshake rate/duration | Operations |
| **Storage & Queue** | S3 blob count/size, outbound queue depth + age, SeaweedFS volume status | Operations |
| **Security** | Auth failure rate, spam classifier accuracy, MAM non-compliant devices, TLS error rate, geo-blocked requests | Security |

All dashboards use `$instance` and `$interval` variables. Time range: default 6h with preset options (1h, 6h, 24h, 7d, 30d).

### 2. Zabbix Template

A single XML template (`setjoin-gateway.xml`) covering the 9 metrics already defined in `HA_OVERVIEW.md`:

| Metric key | Type | Trigger |
|-----------|------|---------|
| `gateway.health` | Simple check | `/health` != 200 → high |
| `gateway.queue.depth` | Numeric (float) | >500 → average, >1000 → high |
| `gateway.queue.oldest` | Numeric (float) | >60min → warning, >120min → high |
| `gateway.db.replication_lag` | Numeric (float) | >10s → warning, >60s → high |
| `gateway.db.connections` | Numeric (unsigned) | >80% pool → warning |
| `gateway.s3.latency` | Numeric (float) | >500ms → warning |
| `gateway.auth.failures` | Numeric (unsigned) | >10/min → warning, >50/min → high |
| `gateway.tls.expiry` | Numeric (float) | <30 days → warning, <7 days → high |
| `gateway.mam.noncompliant` | Numeric (unsigned) | >0 → info → warning if >5 |

Zabbix agent reads these via a userparameter script that curls the gateway's `/metrics` endpoint and parses Prometheus text format with `grep`/`awk`.

### 3. config.env.sample

A comprehensive environment variable template at `mailserver/deploy/config.env.sample` documenting every configuration option with defaults, descriptions, and HA-specific notes. This file is referenced by `install.sh` and `docs/guides/HA_OVERVIEW.md` but doesn't currently exist.

### 4. Patroni + HAProxy Playbook Templates

Formalized YAML templates in `mailserver/deploy/` for Patroni and HAProxy. These were "deferred to ops playbook" in Phase 15.2 — we're now creating the templates with documentation, but they remain deployment-specific (admin customizes IPs, passwords, SSL certs).

### 5. Features.md Update

Mark Phase 15 items as done: Prometheus metrics, HA deployment, production deployment.

---

## References

- `mailserver/internal/metrics/handler.go` — existing Prometheus metrics (13 metric families)
- `mailserver/internal/health/handler.go` — `/health` + `/ready` endpoints
- `mailserver/sql/reducers/health_check.sql` — PL/pgSQL health checks
- `docs/guides/HA_OVERVIEW.md` — 3-node HA design, Zabbix metrics reference
- `mailserver/deploy/pgpool.conf.template` — Pgpool-II 3-node config
- `mailserver/internal/deploy/seaweedfs_ha.go` — SeaweedFS HA planner
- Prometheus data model: https://prometheus.io/docs/concepts/data_model/
- Grafana dashboard JSON model: https://grafana.com/docs/grafana/latest/dashboards/build-dashboards/
- Zabbix template XML format: https://www.zabbix.com/documentation/current/en/manual/xml_export_import
