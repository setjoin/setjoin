# Go Cron Worker — 替代 pg_cron

> **日期:** 2026-06-01 | **状态:** Spec
> **目标:** 用 Go cron worker 替代 PostgreSQL pg_cron 扩展，消除数据库扩展依赖

## 动机

1. **PolarDB 上 pg_cron 可能需单独开通** — 不是所有实例默认安装
2. **Go 实现更可控** — 可观测性、故障隔离、调试能力远超 PG 扩展

## 现状

24 个 pg_cron 任务，分布在 12 个 SQL 文件中。频率从"每 2 秒"到"每月一次"。

### 所有任务清单

| # | 任务名 | 频率 | 函数 | 类型 |
|---|--------|------|------|------|
| 1 | `process-snoozed` | 每分钟 | `process_snoozed_messages()` | 实时 |
| 2 | `process-scheduled` | 每分钟 | `process_scheduled_messages()` | 实时 |
| 3 | `process-message-timers` | 每分钟 | `process_message_timers()` | 实时 |
| 4 | `drain-outbound-hot` | 每 2 秒 | `drain_outbound_hot()` | 热路径 |
| 5 | `retry-outbound-queue` | 每分钟 | `drain_outbound_queue(true)` | 实时 |
| 6 | `drain-journal-queue` | 每分钟 | `drain_journal_queue()` | 实时 |
| 7 | `prune-ws-subscriptions` | 每分钟 | `prune_ws_subscriptions()` | 清理 |
| 8 | `health-check` | 每 5 分钟 | `health_check()` | 监控 |
| 9 | `refresh-antiphish-contact-graph` | 每 5 分钟 | `REFRESH MATERIALIZED VIEW contact_graph_mview` | 维护 |
| 10 | `reset-sending-quotas` | 每小时 | `reset_sending_quotas()` | 维护 |
| 11 | `purge-deleted-messages` | 每天 02:30 | `purge_deleted_messages()` | 清理 |
| 12 | `enforce-retention` | 每天 02:05 | `enforce_retention()` | 清理 |
| 13 | `prune-dmarc-reports` | 每天 03:00 | `prune_dmarc_reports()` | 清理 |
| 14 | `prune-log-tables` | 每天 03:30 | `prune_log_tables()` | 清理 |
| 15 | `prune-health-history` | 每天 03:00 | `prune_health_history()` | 清理 |
| 16 | `prune-greylist` | 每天 03:30 | `prune_greylist_entries()` | 清理 |
| 17 | `prune-vacation-replies` | 每天 04:00 | `prune_vacation_replies()` | 清理 |
| 18 | `mark-orphaned-blobs` | 每天 04:00 | `mark_orphaned_blobs()` | 清理 |
| 19 | `prune-spam` | 每天 03:15 | `prune_spam()` | 清理 |
| 20 | `purge-expired-tokens` | 每周日 04:00 | `purge_expired_tokens()` | 清理 |
| 21 | `purge-saml-assertions` | 每周一 04:15 | `purge_saml_assertions()` | 清理 |
| 22 | `create-message-partitions` | 每月 25 日 | `create_message_partitions()` | 维护 |
| 23 | `create-message-tags-partitions` | 每月 25 日 | `create_message_tags_partitions()` | 维护 |
| 24 | `drop-old-message-tags-partitions` | 每月 1 日 03:00 | `drop_old_message_tags_partitions()` | 清理 |

---

## 设计

### 架构

```
┌─ Gateway main.go ───────────────────────────────────────┐
│                                                          │
│  cronWorker := cron.New(pool, logger)                    │
│  cronWorker.Register(task1, task2, ...)                  │
│  go cronWorker.Run(ctx)                                  │
│                                                          │
│  ┌─ CronWorker ────────────────────────────────────┐    │
│  │                                                  │    │
│  │  tasks []*Task                                   │    │
│  │  ticker: 1s tick                                 │    │
│  │                                                  │    │
│  │  for each tick:                                  │    │
│  │    for each task:                                │    │
│  │      if task.Due():                              │    │
│  │        go task.Run(pool, logger)  // goroutine   │    │
│  │  ────────────────────────────────────────────────│    │
│  │  Task.Run():                                     │    │
│  │    1. panic recovery (fault isolation)           │    │
│  │    2. timeout context (hang protection)          │    │
│  │    3. pool.Exec(SQL)                             │    │
│  │    4. record metrics (duration, success/fail)    │    │
│  │    5. write to cron_run_log                      │    │
│  │                                                  │    │
│  └──────────────────────────────────────────────────┘    │
│                                                          │
└──────────────────────────────────────────────────────────┘
```

### Task 定义

```go
type Task struct {
    Name     string        // 唯一标识，对应 pg_cron jobname
    Schedule string        // cron 表达式或 @every 语法
    SQL      string        // 要执行的 SQL（通常是 SELECT function()）
    Timeout  time.Duration // 单个任务最大执行时间
    Enabled  bool          // 是否启用（可通过 system_config 动态关闭）
}
```

**Schedule 支持两种格式：**
- `@every 5m` — 简单间隔（Go 标准 time.Ticker 风格）
- `30 3 * * *` — 标准 5 字段 cron 表达式（需要 `robfig/cron` 库，或自己做简易解析器）

### 故障隔离

```go
func (t *Task) Run(ctx context.Context, pool *pgxpool.Pool, logger *slog.Logger) {
    start := time.Now()
    defer func() {
        if r := recover(); r != nil {
            logger.Error("cron task panicked", "task", t.Name, "panic", r)
            metrics.RecordCronPanic(t.Name)
        }
        metrics.RecordCronDuration(t.Name, time.Since(start))
    }()

    taskCtx, cancel := context.WithTimeout(ctx, t.Timeout)
    defer cancel()

    _, err := pool.Exec(taskCtx, t.SQL)
    if err != nil {
        logger.Error("cron task failed", "task", t.Name, "error", err, "duration", time.Since(start))
        metrics.RecordCronFailure(t.Name)
        return
    }

    metrics.RecordCronSuccess(t.Name)
}
```

**保护措施：**
- Panic recovery per task — 一个任务挂了不影响其他
- Timeout — 防止函数跑飞
- 下次执行不受影响 — 上次失败不会阻止下次调度

### 可观测性

#### 1. Prometheus Metrics（`/metrics` 端点已有）

```
cron_task_last_run_seconds{task="process-snoozed"}    1717200000
cron_task_duration_seconds{task="process-snoozed"}     0.042
cron_task_success_total{task="process-snoozed"}        1440
cron_task_failure_total{task="process-snoozed"}        2
cron_task_panic_total{task="process-snoozed"}          0
```

#### 2. 运行日志 (`cron_run_log` 表)

```sql
CREATE UNLOGGED TABLE cron_run_log (
    id BIGSERIAL PRIMARY KEY,
    task_name TEXT NOT NULL,
    started_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    duration_ms INTEGER,
    status TEXT NOT NULL, -- 'success', 'error', 'panic', 'timeout'
    error_message TEXT,
    sql_text TEXT
);
-- 自动清理：保留 30 天
```

#### 3. 健康检查

每 5 分钟检查：如果某个 `@every 1m` 的任务超过 2 分钟没有成功运行记录 → `health_check()` 报 warn。

```
cron_task_stale{task="process-snoozed", last_ok="2026-06-01T10:15:00Z"}
```

#### 4. Admin UI

在 `/admin/system/health` 页面上显示每个 cron 任务的状态：
- 上次成功时间
- 上次失败时间/原因
- 最近 10 次执行历史

### 配置

每个任务可以通过 `system_config` 动态开关：

```sql
INSERT INTO system_config (key, value) VALUES
    ('cron.process-snoozed.enabled', 'true'),
    ('cron.process-snoozed.timeout_sec', '30');
```

不需要重启——worker 每次检查前读取配置。

---

## 对比 pg_cron

| | pg_cron | Go Cron Worker |
|---|---|---|
| 部署 | `CREATE EXTENSION pg_cron` | gateway 内置，零依赖 |
| 可观测性 | PG 日志 | Prometheus metrics + 运行日志 + Admin UI |
| 调试 | `SELECT * FROM cron.job_run_details` | Go pprof + slog + trace |
| 故障隔离 | 共享 PG 进程 | 独立 goroutine + panic recovery |
| 超时保护 | 无 | 每个任务独立 timeout |
| 动态开关 | 需要 `cron.unschedule()` | `system_config` 一行 |
| 迁移 | 换数据库 = 重写 | 同一套代码，所有数据库通用 |

---

## 迁移策略

### 阶段 1: 双跑

1. Go cron worker 注册所有 24 个任务
2. pg_cron 保持运行
3. 两个调度器并行跑同一批函数
4. 对比 cron_run_log 和 pg_cron.job_run_details，确认 Go 侧结果一致

### 阶段 2: 切换

1. 通过 `system_config cron.*.enabled` 逐个关闭 pg_cron 任务
2. Go cron worker 承担全部调度
3. `CREATE EXTENSION pg_cron` 变为可选（删除 `V001__initial_schema.sql` 中的强制创建）

### 阶段 3: 清理

1. 删除所有 `SELECT cron.schedule(...)` SQL 迁移语句
2. 在文档中标注 pg_cron 不再是必需依赖

---

## 文件

| 文件 | 职责 |
|------|------|
| `mailserver/gateway/internal/cron/worker.go` | CronWorker 主逻辑：调度循环、任务注册 |
| `mailserver/gateway/internal/cron/task.go` | Task 结构体 + Run() 方法（panic recovery、timeout、metrics） |
| `mailserver/gateway/internal/cron/tasks.go` | 24 个任务的注册表（静态定义） |
| `mailserver/gateway/internal/cron/metrics.go` | Prometheus metrics 注册 |
| `mailserver/gateway/internal/cron/worker_test.go` | 单元测试 |
| `mailserver/gateway/cmd/gateway/main.go` | 初始化并启动 cronWorker |
| `mailserver/sql/migrations/V031__cron_run_log.sql` | cron_run_log 表 |

---

## 工时估算

| 阶段 | 内容 | 工时 |
|------|------|------|
| 1 | CronWorker + Task 核心 + 单元测试 | 4h |
| 2 | 24 个任务注册 + Prometheus metrics | 2h |
| 3 | cron_run_log 表 + 健康检查集成 | 2h |
| 4 | Admin UI 展示 | 2h |
| 5 | 双跑验证 + 切换 | 2h |
| 6 | 清理 pg_cron 依赖 | 1h |
| **合计** | | **~13h (2天)** |
