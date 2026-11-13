# PolarDB for PostgreSQL 兼容性评估

> **日期:** 2026-06-01
> **参考:** PolarDB for PostgreSQL (阿里云，基于 PostgreSQL 15.x)
> **定位:** 信创数据库首选方案

## 本质

PolarDB for PostgreSQL 不是 PostgreSQL 分叉——它是**增强版托管 PostgreSQL 15**。阿里云在 PG 内核上加了自己的存储引擎（PolarStore）、读写分离和一写多读架构，但 SQL 层 100% 兼容 PG 15。

## 结论先行

**零迁移成本。** 如果用的是 PolarDB for PostgreSQL (不是 Oracle 兼容版)，所有代码、SQL、扩展都不需要改动。

---

## 扩展兼容性

我们依赖的每个 PG 扩展在 PolarDB 上的情况：

| 扩展 | 状态 | 说明 |
|------|------|------|
| **plpgsql** | ✅ 内置 | PG 默认语言，PolarDB 完全支持 |
| **pg_trgm** | ✅ 支持 | `CREATE EXTENSION pg_trgm` 直接可用。`similarity()`、`show_trgm()` 等函数完全兼容 |
| **pgcrypto** | ✅ 支持 | `pgp_sym_encrypt`/`pgp_sym_decrypt`、`gen_random_bytes` 等完全兼容 |
| **btree_gin** | ✅ 支持 | 标准扩展 |
| **btree_gist** | ✅ 支持 | 标准扩展 |
| **pg_cron** | ✅ 不需要（Go cron worker 已替代）| 无依赖 |
| **PostGIS / GANOS** | ✅ 支持 | PolarDB 用自研 GANOS 替代 PostGIS，空间查询兼容 |

## 核心功能

| 功能 | 状态 | 说明 |
|------|------|------|
| **JSONB** | ✅ 完全支持 | PG 15 原生类型，所有操作符 (`->`, `->>`, `@>`, `?`) 和函数可用 |
| **LISTEN/NOTIFY** | ✅ 完全支持 | PG 标准行为，`pg_notify()` 带 payload |
| **PL/pgSQL** | ✅ 完全支持 | 所有 reducer 函数无需修改 |
| **INSERT ON CONFLICT (UPSERT)** | ✅ 完全支持 | PG 9.5+ 标准语法 |
| **物化视图 + CONCURRENTLY** | ✅ 完全支持 | `REFRESH MATERIALIZED VIEW CONCURRENTLY` |
| **TSVECTOR / 全文搜索** | ✅ 完全支持 | `plainto_tsquery` 等完全兼容 |
| **RETURNING 子句** | ✅ 完全支持 | INSERT/UPDATE/DELETE RETURNING |
| **CTE / WITH RECURSIVE** | ✅ 完全支持 | 标准 PG 行为 |
| **窗口函数** | ✅ 完全支持 | PG 15 级别 |
| **正则 `~` / `~*`** | ✅ 完全支持 | PG 标准 |
| **pgx Go 驱动** | ✅ 完全兼容 | 标准 PG 协议，我们的 pgx v5 直接可用 |
| **GIN/GiST 索引** | ✅ 完全支持 | 标准 PG 索引 |

## 需注意的差异

### 1. pg_cron

不再需要 pg_cron 扩展。Go cron worker（`mailserver/gateway/internal/cron/worker.go`）已替代所有 pg_cron 调度，无需外部扩展依赖。

### 2. 连接池 — 双连接架构

我们的架构需要两个数据库连接：
- `DB_DSN`: 通过连接池（事务模式）— PolarDB 自带连接代理
- `DB_DIRECT_DSN`: 直连主节点（LISTEN 需要长连接）

```
┌─ Go Gateway ──────────────────────────────────┐
│                                                │
│  DB_DSN ──────► PolarDB 连接代理 (事务模式)     │
│  DB_DIRECT_DSN ─► PolarDB 主节点直连 (LISTEN)  │
│                                                │
└────────────────────────────────────────────────┘
```

确保 `DB_DIRECT_DSN` 指向**主节点**（读写端点），不是只读节点。LISTEN/NOTIFY 只在主节点上工作。

### 3. 读写分离

PolarDB 一写多读架构。读请求可以走只读节点，但所有写操作和 LISTEN 必须走主节点。我们的 `DB_DSN` 配置需要区分：
- 连接池 DSN → 读写端点（主节点）
- 直连 DSN → 读写端点（主节点，LISTEN 需要）

### 4. 备份

PolarDB 有自己的自动备份机制，不需要我们自己做 pg_dump 调度。但 SeaweedFS/S3 blob 备份仍然需要我们的 `internal/backup/` 模块处理。

## 不兼容点

| 层面 | 是否有差异 | 说明 |
|------|----------|------|
| SQL 语法 | ❌ 无 | 100% PG 兼容 |
| 存储过程 | ❌ 无 | PL/pgSQL 完全兼容 |
| 扩展 API | ❌ 无 | 标准 PG 扩展均可用 |
| 客户端协议 | ❌ 无 | pgx 直接可用 |
| 性能 | ⚠️ 可能更好 | PolarDB 存储引擎优化了写放大 |
| 计费 | ⚠️ 按量付费 | 不是自建 PG 那种一次性采购 |

## 和自建 PostgreSQL 的对比

| 方面 | 自建 PG | PolarDB for PG |
|------|--------|---------------|
| 兼容性 | 基准 | 100% |
| 高可用 | 需要 Pgpool-II/HAProxy | 内置 |
| 备份恢复 | 需要 pg_dump + WAL | 内置 PITR |
| 扩容 | 停服升级 | 在线扩容 |
| pg_cron | ❌ 已移除 | ✅ 不需要（Go cron worker）|
| 许可证 | 开源 | 云服务费 |
| 信创认证 | 无 | 有（阿里云国产化） |

---

## 迁移检查清单

- [x] pg_cron 已由 Go cron worker 替代（无外部扩展依赖）
- [ ] `DB_DSN` 和 `DB_DIRECT_DSN` 都指向主节点读写端点
- [ ] 运行完整回归测试套件
- [ ] 验证 LISTEN/NOTIFY 实时推送正常
- [ ] 验证所有 JSONB 操作符输出一致
- [ ] 性能基准测试（对比自建 PG）
- [ ] 确认 PolarDB 版本 ≥ 15（我们的代码依赖 PG 15+）
