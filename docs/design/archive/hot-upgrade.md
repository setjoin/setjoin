# 热更新系统 — Admin UI + CLI + overseer

> **日期:** 2026-06-01 | **状态:** Spec
> **目标:** 所有升级操作通过 Admin UI 或 `mailctl` CLI 完成，保留最小化脚本，支持自动回退

## 设计原则

1. **Admin UI 是主要操作界面** — 人类管理员点按钮完成升级
2. **`mailctl` CLI 是 AI 操作界面** — Agent 通过命令行完成升级
3. **Shell 脚本只做包装** — `upgrade.sh` 只调 `mailctl`，不留复杂逻辑
4. **热更新优先** — 无 schema 变更时零停机
5. **回退一击完成** — 保留上一个版本，一键回滚

---

## 架构

```
┌─ Admin UI (/admin/system) ──────────────────────────────┐
│                                                          │
│  Current version: v2.1.3 (2026-06-01 14:30)             │
│  Previous:        v2.1.2 (2026-05-28 09:15) [Rollback]  │
│                                                          │
│  ┌─ Upgrade ───────────────────────────────────────┐    │
│  │  Binary: [/opt/mailserver/gateway_v2.1.4    ]   │    │
│  │  Schema:  No changes detected                    │    │
│  │  Mode:    Hot reload (zero downtime)             │    │
│  │  [ ] Force full restart even if no schema change │    │
│  │  [Upgrade Now]                                  │    │
│  └──────────────────────────────────────────────────┘    │
│                                                          │
│  Upgrade History:                                        │
│  v2.1.3  2026-06-01  successful  0s downtime            │
│  v2.1.2  2026-05-28  successful  3s downtime (schema)   │
│  v2.1.1  2026-05-25  failed      auto-rolled back       │
│                                                          │
└──────────────────────────────────────────────────────────┘

┌─ CLI (for AI agents) ────────────────────────────────────┐
│                                                          │
│  $ mailctl upgrade check /opt/new/gateway                │
│  Schema: no changes. Hot reload possible.                │
│                                                          │
│  $ mailctl upgrade apply /opt/new/gateway                │
│  ✓ Binary validated (sha256: abc123...)                  │
│  ✓ Hot reload triggered (pid 1234 → 5678)                │
│  ✓ Health check passed                                   │
│  Upgrade complete. v2.1.3 → v2.1.4                       │
│                                                          │
│  $ mailctl upgrade rollback                              │
│  ✓ Rolling back to v2.1.3                                │
│  ✓ Hot reload triggered                                  │
│  Rollback complete.                                      │
│                                                          │
│  $ mailctl upgrade status                                │
│  Current:  v2.1.3 (2026-06-01 14:30)                    │
│  Previous: v2.1.2 (2026-05-28 09:15)                    │
│  Status:   healthy                                       │
│                                                          │
└──────────────────────────────────────────────────────────┘
```

---

## 组件

### 1. Admin API

| 端点 | 方法 | 说明 |
|------|------|------|
| `/admin/system/upgrade/check` | POST | 检查二进制：版本号、schema 变化、可用模式 |
| `/admin/system/upgrade/apply` | POST | 执行升级（热更新或计划重启） |
| `/admin/system/upgrade/rollback` | POST | 回退到上一个版本 |
| `/admin/system/upgrade/status` | GET | 当前版本、历史记录 |
| `/admin/system/upgrade/history` | GET | 完整的升级历史 |

请求体：

```json
{
  "binary_path": "/opt/mailserver/gateway_new",
  "force_restart": false
}
```

响应体：

```json
{
  "from_version": "v2.1.3",
  "to_version": "v2.1.4",
  "mode": "hot_reload",
  "ddl_classification": "additive_only",
  "new_migrations": ["V032__add_avatar_url.sql"],
  "breaking_changes": [],
  "status": "success",
  "downtime_ms": 0
}
```

### 2. overseer 集成

```go
// cmd/gateway/main.go
import "github.com/jpillora/overseer"

func main() {
    overseer.Run(overseer.Config{
        Program:   runGateway,    // 实际 gateway 逻辑
        Address:   cfg.ListenAddr,
        Debug:     cfg.LogLevel == "debug",
        Fetcher:   nil,           // 不自动拉取，通过 API 触发
    })
}

func runGateway(state overseer.State) {
    // state.Listener — overseer 管理的 listener
    // 正常的 gateway 初始化逻辑
    pool, _ := pgxutil.OpenPool(...)
    chain, _ := auth.NewChain(...)
    // ...
    http.Serve(state.Listener, mux)
}
```

### 3. mailctl CLI

```
mailctl upgrade
├── check    <binary_path>    检查升级可行性 + DDL 分析
├── apply    <binary_path>    执行升级（自动选择热更新/停服）
├── rollback                  回退到上一个版本
├── status                    当前状态
└── history                   升级历史

$ mailctl upgrade check /opt/new/gateway

  Binary:        v2.1.4 (sha256: abc123...)
  Current:       v2.1.3
  SQL migrations: 1 new file(s)
    V032__add_avatar_url.sql  → additive (ALTER TABLE ADD COLUMN)
  DDL analysis:  additive_only — no breaking changes
  Mode:          hot_reload (zero downtime)
  Plan:          psql -f V032, then systemctl reload

$ mailctl upgrade check /opt/new/gateway  # 另一个场景

  Binary:        v2.2.0 (sha256: def456...)
  Current:       v2.1.3
  SQL migrations: 1 new file(s)
    V033__restructure_users.sql → BREAKING (ALTER TABLE RENAME COLUMN)
      Statement: ALTER TABLE users RENAME COLUMN login TO username
      Reason:    RENAME — old Go code uses old column name
  DDL analysis:  has_breaking — full restart required
  Mode:          full_restart (~3-5s downtime)
  Plan:          systemctl stop → psql -f V033 → systemctl start
```

### 4. Schema 变更智能分析

升级前必须分析 SQL 迁移类型，决定用热更新还是停服。

#### DDL 分类

| 类型 | 操作 | 需要重启 | 原因 |
|------|------|---------|------|
| **加法** | `CREATE TABLE`, `ALTER TABLE ADD COLUMN`, `CREATE INDEX`, `CREATE EXTENSION` | ❌ 不需要 | 旧 Go 不用新列/新表，pgx 按列名扫描自动跳过 |
| **替换** | `CREATE OR REPLACE FUNCTION` | ❌ 不需要 | PG 原子替换函数，新调用走新逻辑 |
| **破坏** | `ALTER TABLE DROP COLUMN`, `ALTER TABLE RENAME COLUMN`, `ALTER TABLE ALTER COLUMN TYPE` | ✅ 需要 | 旧 Go 代码引旧列名，新表没有 → 崩溃 |
| **数据迁移** | `UPDATE`, `INSERT INTO ... SELECT` | ❌ 不需要 | PG 事务原子完成 |

#### 分析算法

```go
// AnalyzeMigration reads a SQL migration file and classifies every DDL statement.
func AnalyzeMigration(sqlContent string) DDLClassification {
    result := DDLClassification{Additive: true}

    for _, stmt := range parseDDLStatements(sqlContent) {
        switch {
        case strings.Contains(stmt, "CREATE OR REPLACE FUNCTION"),
             strings.Contains(stmt, "CREATE OR REPLACE PROCEDURE"):
            result.Repls = append(result.Repls, extractFunctionName(stmt))

        case strings.Contains(stmt, "ALTER TABLE") && strings.Contains(stmt, "DROP COLUMN"):
            result.Additive = false
            result.Breaking = append(result.Breaking, BreakingChange{
                Statement: stmt,
                Reason:    "DROP COLUMN — old Go code references this column",
            })

        case strings.Contains(stmt, "ALTER TABLE") && strings.Contains(stmt, "RENAME"):
            result.Additive = false
            result.Breaking = append(result.Breaking, BreakingChange{
                Statement: stmt,
                Reason:    "RENAME — old Go code uses old column/table name",
            })

        case strings.Contains(stmt, "ALTER COLUMN") && strings.Contains(stmt, "TYPE"):
            result.Additive = false
            result.Breaking = append(result.Breaking, BreakingChange{
                Statement: stmt,
                Reason:    "TYPE change — old Go code expects old type",
            })

        default:
            result.Additions = append(result.Additions, stmt)
        }
    }
    return result
}
```

#### 决策逻辑

```go
func determineUpgradeMode(migrations []MigrationFile) UpgradeMode {
    for _, m := range migrations {
        if m.AlreadyApplied { continue }
        classification := AnalyzeMigration(m.Content)
        if !classification.Additive {
            return FullRestart  // 有任何破坏性 DDL → 必须停服
        }
    }
    return HotReload  // 全是加法+替换 → 热更新
}
```

#### 升级流程（综合）

```
POST /admin/system/upgrade/apply
  │
  ├─ 1. Validate binary
  │
  ├─ 2. Scan migrations
  │     └─ AnalyzeMigration() 每个未执行的 .sql 文件
  │
  ├─ 3. 决策
  │     │
  │     ├─ 全是加法+替换 (90% 场景):
  │     │   ├─ psql -f new_migration.sql    ← 先执行 SQL
  │     │   ├─ cp 新二进制到位
  │     │   ├─ kill -USR2 (overseer 热更新)   ← Go 代码零停机
  │     │   └─ ✅ 零停机完成
  │     │
  │     └─ 有破坏性 DDL (10% 场景):
  │         ├─ 通知 "maintenance window: ~5s downtime"
  │         ├─ systemctl stop mailserver
  │         ├─ psql -f new_migration.sql
  │         ├─ cp 新二进制到位
  │         ├─ systemctl start mailserver
  │         └─ ✅ ~3-5s 停机完成
  │
  ├─ 4. Health check → 失败自动回退
  │
  └─ 5. 记录 upgrade_history
```

#### 为什么 90% 是加法

我们的架构把业务逻辑放在 PL/pgSQL reducer 里。改逻辑 = `CREATE OR REPLACE FUNCTION` = 替换 = 不需要重启。只有改数据模型（删列、改名）才需要停服——而这种事在成熟产品中极少发生。

#### 回退的 Schema 处理

回退时，如果带有 schema 迁移，处理很微妙：

| 升级类型 | 回退场景 | 处理 |
|---------|---------|------|
| 加法 DDL + 热更新 | 回退到旧 Go | 新列留在 DB 里，旧 Go 不用它 → 安全。下一版本把列删掉 |
| 破坏 DDL + 停服 | 回退到旧 Go | 需要反向迁移。**必须提前写好 `DOWN` 脚本。** |

```sql
-- V032__add_avatar_url.sql (加法)
ALTER TABLE users ADD COLUMN avatar_url TEXT;

-- V032__add_avatar_url.down.sql (回退脚本，由开发者提供)
-- 注意：加法 DDL 的回退脚本是可选的（旧 Go 不引用这列）
ALTER TABLE users DROP COLUMN IF EXISTS avatar_url;
```

对于破坏性 DDL，回退脚本**必须**提供，否则拒绝回退。

### 5. DB 表

```sql
CREATE TABLE upgrade_history (
    id SERIAL PRIMARY KEY,
    from_version TEXT NOT NULL,
    to_version TEXT NOT NULL,
    binary_sha256 TEXT NOT NULL,
    mode TEXT NOT NULL,              -- 'hot_reload' | 'full_restart'
    ddl_classification TEXT NOT NULL, -- 'additive_only' | 'has_breaking'
    breaking_changes JSONB,          -- [{statement, reason}] — 破坏性 DDL 详情
    new_migrations TEXT[],           -- 新增的迁移文件名
    status TEXT NOT NULL,            -- 'success' | 'failed' | 'rolled_back'
    started_at TIMESTAMPTZ NOT NULL,
    completed_at TIMESTAMPTZ,
    downtime_ms INTEGER DEFAULT 0,
    error_message TEXT,
    previous_binary_path TEXT        -- 回退时用的旧二进制路径
);

CREATE TABLE upgrade_config (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
-- 存储: current_version, previous_version, previous_binary_path
```

### 5. 升级流程

```
POST /admin/system/upgrade/apply
  │
  ├─ 1. Validate binary
  │     ├─ 文件存在？
  │     ├─ 是有效 ELF/Mach-O？
  │     ├─ 版本号 > 当前版本？
  │     └─ sha256 校验
  │
  ├─ 2. Schema check
  │     ├─ 扫描新二进制的 migrations 目录
  │     ├─ 对比当前数据库的 schema_version
  │     └─ 有新迁移 → mode = "full_restart"
  │
  ├─ 3. 备份
  │     └─ cp 当前二进制 → /opt/mailserver/gateway.prev
  │
  ├─ 4. 执行升级 (根据 mode)
  │     │
  │     ├─ hot_reload:
  │     │   └─ kill -USR2 <pid> → overseer 热更新
  │     │
  │     └─ full_restart:
  │         ├─ 通知 "maintenance window starting"
  │         ├─ systemctl stop mailserver
  │         ├─ psql -f new_migration.sql
  │         ├─ cp 新二进制到位
  │         └─ systemctl start mailserver
  │
  ├─ 5. Health check
  │     └─ GET /health → 200 OK？
  │
  ├─ 6. 记录到 upgrade_history
  │
  └─ 7. 如果 health check 失败：
        └─ 自动回退：cp gateway.prev → gateway，重试启动
```

### 6. 回退流程

```
POST /admin/system/upgrade/rollback
  │
  ├─ 1. 确认有 previous_binary_path
  ├─ 2. 检查 previous 版本是否有 schema 回退需求
  │     └─ 如果 previous 版本在同一个 schema 上 → hot_reload
  │     └─ 如果有 schema 差异 → 需要手动处理（危险，拒绝自动回退）
  ├─ 3. cp previous → current
  ├─ 4. kill -USR2 (hot_reload) 或 systemctl restart
  └─ 5. Health check
```

---

## 脚本精简

之前计划写的复杂 `upgrade.sh` 现在变成：

```bash
#!/bin/bash
# upgrade.sh — 一行包装，供 cron/Ansible 调
exec mailctl upgrade apply "$@"
```

```bash
#!/bin/bash
# install.sh — 首次安装
cp /opt/mailserver/gateway /usr/local/bin/
cp /opt/mailserver/mailserver.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable mailserver
systemctl start mailserver
```

所有复杂逻辑在 `mailctl` 里。Admin UI 调 API，CLI 是同一套 API 的客户端。

---

## 文件

| 文件 | 职责 |
|------|------|
| `mailserver/gateway/cmd/gateway/main.go` | 包一层 overseer |
| `mailserver/gateway/internal/admin/admin_upgrade.go` | 升级 API 处理器 |
| `mailserver/gateway/internal/admin/admin_upgrade_test.go` | 测试 |
| `mailserver/cmd/mailctl/upgrade.go` | mailctl upgrade 子命令 |
| `mailserver/webmail/src/lib/admin/client.ts` | 前端 API 类型 |
| `mailserver/webmail/src/routes/admin/system/+page.svelte` | 升级 UI 组件（追加到现有 system 页面） |
| `scripts/upgrade.sh` | 一行包装 → `mailctl upgrade apply` |
| `scripts/install.sh` | 首次安装 |

---

## 工时

| 阶段 | 内容 | 工时 |
|------|------|------|
| 1 | overseer 集成 + main.go 改造 | 2h |
| 2 | Admin API + upgrade_history 表 | 3h |
| 3 | mailctl upgrade 子命令 | 2h |
| 4 | Admin UI 组件 | 2h |
| 5 | 测试 + 文档 | 2h |
| **合计** | | **~11h** |

---

## Admin System 页面完整功能

### 页面布局

```
┌─ /admin/system ───────────────────────────────────────────┐
│                                                            │
│  ── Service Status ───────────────────────────────────    │
│  Service:  ● Running (pid 1234, uptime 14d 3h 12m)       │
│  Version:  v2.1.3 / schema V031                           │
│  Health:   All 8 checks passing                           │
│  Memory:   342 MB / 1.2 GB                                │
│  Goroutines: 47                                            │
│                                                            │
│  [Graceful Restart]  [Stop Service]                        │
│  (hot reload, 0s)    (drain connections, then stop)       │
│                                                            │
│  ── Version Control ──────────────────────────────────    │
│                                                            │
│  Current:  v2.1.3  (2026-06-01 14:30)  sha256:abc123     │
│  Previous: v2.1.2  (2026-05-28 09:15)  [Rollback]        │
│                                                            │
│  ┌─ Upgrade ─────────────────────────────────────────┐   │
│  │  Binary path: [/opt/mailserver/gateway_v2.1.4 ]   │   │
│  │  [Analyze]  →  DDL: additive only                 │   │
│  │  Mode: Hot reload (0s downtime)                   │   │
│  │  [Apply Upgrade Now]                              │   │
│  │  [Schedule Upgrade...]                             │   │
│  └───────────────────────────────────────────────────┘   │
│                                                            │
│  ── Upgrade History ──────────────────────────────────    │
│  Date         From     To       Mode          Status      │
│  2026-06-01   v2.1.2  v2.1.3   hot_reload    ● success   │
│  2026-05-28   v2.1.1  v2.1.2   full_restart  ● success   │
│  2026-05-25   v2.1.0  v2.1.1   hot_reload    ● failed    │
│    └─ Auto-rolled back to v2.1.0                          │
│  [View Full History]                                      │
│                                                            │
│  ── Maintenance Window ───────────────────────────────    │
│                                                            │
│  Schedule upgrades during low-traffic periods:            │
│                                                            │
│  ○ No maintenance window (manual only)                    │
│  ○ Specific time window                                  │
│    Every [Sunday      ▼] at [03:00 ▼] — [05:00 ▼]      │
│    Timezone: [UTC+8      ▼]                              │
│  ○ Idle-time detection                                    │
│    Restart when connections < [5    ] for [10 min ▼]     │
│    Max wait: [2 hours ▼] (force after timeout)           │
│                                                            │
│  ── Auto-Update ──────────────────────────────────────    │
│                                                            │
│  ☐ Check for updates automatically                        │
│    Interval: [Daily ▼] (Daily / Weekly / Monthly)        │
│    Channel:  [Stable ▼] (Stable / Beta / Nightly)        │
│    Source:   [/opt/mailserver/releases/              ]   │
│                                                            │
│  ☐ Auto-apply if safe (hot_reload only, no breaking DDL) │
│  ☐ Notify admin when new version available               │
│  ☒ Require confirmation for full_restart upgrades        │
│                                                            │
│  [Save Settings]                                          │
│                                                            │
└──────────────────────────────────────────────────────────┘
```

### 开关机操作

#### API

| 端点 | 方法 | 说明 |
|------|------|------|
| `/admin/system/restart` | POST | 热重启（overseer）或冷重启（systemd），取决于 `mode` 参数 |
| `/admin/system/stop` | POST | 优雅停机：排空连接 → 停止接受新请求 → 关闭 |

```json
// POST /admin/system/restart
{
  "mode": "hot_reload"     // "hot_reload" (默认) | "full_restart"
}

// 响应
{
  "status": "restarting",
  "new_pid": 5678,
  "downtime_ms": 0
}
```

```json
// POST /admin/system/stop
{
  "drain_timeout_sec": 30  // 最长等待存量连接排空
}

// 响应
{
  "status": "stopping",
  "active_connections": 3,
  "will_drain_by": "2026-06-01T15:00:30Z"
}
```

#### 优雅停机流程

```
POST /admin/system/stop
  │
  ├─ 1. 返回 202 "stopping" 立即响应（不阻塞 API）
  ├─ 2. 停止 accept() 新连接
  ├─ 3. 等待存量连接排空（最多 drain_timeout_sec）
  ├─ 4. 关闭 DB 连接池
  ├─ 5. 关闭 SeaweedFS 客户端
  ├─ 6. os.Exit(0) → systemd 检测到进程退出
  └─ 7. systemd 不会自动重启（ExecStop 后不 Restart=always 因为这是人工停机）
```

#### systemd 配置

```ini
[Unit]
Description=Mail Server Gateway
After=network.target postgresql.service

[Service]
Type=notify
ExecStart=/opt/mailserver/gateway
ExecReload=/bin/kill -USR2 $MAINPID
ExecStop=/bin/kill -SIGTERM $MAINPID
Restart=on-failure
RestartSec=5
WatchdogSec=30

# 环境变量
EnvironmentFile=/opt/mailserver/config.env

# 安全沙箱
User=mail
Group=mail
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=/opt/mailserver /var/cache/mailserver /tmp

[Install]
WantedBy=multi-user.target
```

**关键：** `Restart=on-failure` 不是 `Restart=always`——人工关机后不自动重启。但崩溃时自动重启。

### 维护窗口

#### 三种模式

```go
type MaintenanceWindow struct {
    Mode string `json:"mode"` // "manual" | "scheduled" | "idle_detect"

    // 定时窗口
    DayOfWeek string `json:"day_of_week,omitempty"` // "sunday", "monday", ...
    StartTime string `json:"start_time,omitempty"`  // "03:00"
    EndTime   string `json:"end_time,omitempty"`    // "05:00"
    Timezone  string `json:"timezone,omitempty"`    // "Asia/Shanghai"

    // 闲时检测
    MaxConnections int    `json:"max_connections,omitempty"` // 低于此值认为空闲
    IdleDuration   string `json:"idle_duration,omitempty"`   // 持续空闲多久才执行
    MaxWait        string `json:"max_wait,omitempty"`        // 最长等待时间
}
```

#### 闲时检测逻辑

```go
func (w *MaintenanceWindow) ShouldExecuteNow(connCount int, idleSince time.Time) (bool, string) {
    switch w.Mode {
    case "manual":
        return false, "manual mode — admin must trigger"

    case "scheduled":
        now := time.Now().In(w.timezone)
        if now.Weekday() != w.dayOfWeek {
            return false, fmt.Sprintf("not %s", w.dayOfWeek)
        }
        if now.Before(w.startTime) || now.After(w.endTime) {
            return false, "outside maintenance window"
        }
        return true, "within maintenance window"

    case "idle_detect":
        if connCount <= w.maxConnections && time.Since(idleSince) >= w.idleDuration {
            return true, fmt.Sprintf("idle: %d connections for %v", connCount, time.Since(idleSince))
        }
        if time.Since(idleSince) >= w.maxWait {
            return true, fmt.Sprintf("max wait reached: %v", time.Since(idleSince))
        }
        return false, fmt.Sprintf("waiting: %d connections, idle for %v", connCount, time.Since(idleSince))
    }
    return false, ""
}
```

### 自动更新

#### 配置存储

```sql
INSERT INTO system_config (key, value) VALUES
    ('auto_update.enabled', 'true'),
    ('auto_update.channel', '"stable"'),
    ('auto_update.check_interval', '"daily"'),
    ('auto_update.source_path', '"/opt/mailserver/releases"'),
    ('auto_update.auto_apply_safe', 'true'),
    ('auto_update.notify_admin', 'true'),
    ('auto_update.require_confirm_breaking', 'true');
```

#### 检查流程

```go
func (h *UpgradeHandler) checkForUpdates() {
    cfg := h.loadAutoUpdateConfig()
    if !cfg.Enabled { return }

    releases := h.scanReleaseDir(cfg.SourcePath)
    latest := h.findLatest(releases, cfg.Channel)
    if latest.Version <= h.currentVersion { return }

    // 有新版本 → 分析 DDL
    analysis := AnalyzeMigration(latest.Migrations)

    if cfg.AutoApplySafe && analysis.Additive {
        // 安全自动升级（热更新，零停机）
        h.applyUpgrade(latest, "hot_reload")
        h.notifyAdmin("Auto-upgraded to " + latest.Version)
    } else if cfg.RequireConfirmBreaking && !analysis.Additive {
        // 破坏性变更 → 只能人工确认
        h.notifyAdmin("New version available: " + latest.Version + " (requires full restart — breaking DDL)")
    } else {
        h.notifyAdmin("New version available: " + latest.Version)
    }
}
```

#### 四种自动程度

| 模式 | 配置 | 行为 |
|------|------|------|
| **完全手动** | `auto_update.enabled = false` | 人去 `/admin/system` 上传二进制 → Analyze → Apply |
| **通知 + 手动** | `enabled + notify_admin + !auto_apply` | 自动检查 → 通知 → 人去 Apply（默认） |
| **安全自动** | `auto_apply_safe = true` | 加法/替换 DDL → 自动热更新。破坏性 → 通知人 |
| **维护窗口** | + maintenance_window | 在上述基础上，只在指定时间窗口/闲时执行 |

### mailctl CLI

```
mailctl system
├── status                    服务状态
├── restart [--full]          重启（默认热重启，--full 冷重启）
├── stop [--timeout 30s]      优雅停机

mailctl upgrade
├── check    <binary_path>    检查升级可行性 + DDL 分析
├── apply    <binary_path>    立即执行升级
├── schedule <binary_path> --at "Sunday 03:00"  计划升级
├── rollback                  回退到上一个版本
├── status                    当前版本 + 自动更新状态
├── history                   升级历史

mailctl auto-update
├── enable  [--channel stable] [--safe-only]   开启自动更新
├── disable                   关闭自动更新
├── status                    自动更新配置
├── check-now                 立即检查新版本
└── window  [--sunday 03:00-05:00] [--idle 5 10m 2h]  设置维护窗口
```

---

## 文件汇总

| 文件 | 职责 |
|------|------|
| `mailserver/gateway/cmd/gateway/main.go` | 包一层 overseer |
| `mailserver/gateway/internal/admin/admin_upgrade.go` | 升级/回退/分析 API |
| `mailserver/gateway/internal/admin/admin_system.go` | 服务状态/重启/关机 API |
| `mailserver/gateway/internal/admin/admin_autoupdate.go` | 自动更新检查 + 维护窗口判断 |
| `mailserver/cmd/mailctl/upgrade.go` | mailctl upgrade 子命令 |
| `mailserver/cmd/mailctl/system.go` | mailctl system 子命令 |
| `mailserver/cmd/mailctl/autoupdate.go` | mailctl auto-update 子命令 |
| `mailserver/webmail/src/lib/admin/client.ts` | 前端 API 类型 |
| `mailserver/webmail/src/routes/admin/system/+page.svelte` | 完整 System 页面 |
| `mailserver/sql/migrations/V032__upgrade_history.sql` | upgrade_history + auto_update_config 表 |
| `scripts/upgrade.sh` | 一行包装 → `mailctl upgrade apply "$@"` |
| `scripts/install.sh` | 首次安装 |
| `mailserver.service` | systemd unit（含 ExecReload） |

## 工时

| 阶段 | 工时 |
|------|------|
| overseer 集成 + main.go | 2h |
| 升级/回退 API + DDL 分析引擎 | 3h |
| 服务状态/开关机 API | 2h |
| 自动更新 + 维护窗口 | 3h |
| mailctl CLI (system + upgrade + auto-update) | 3h |
| Admin System 页面 | 4h |
| systemd unit + 脚本 | 1h |
| 测试 + 文档 | 2h |
| **合计** | **~20h (3天)** |
