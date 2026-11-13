package cron

import "time"

// AllTasks returns the complete set of cron tasks that replace pg_cron jobs.
func AllTasks() []*Task {
	return []*Task{
		// ── Hot-path (real-time) ──
		{Name: "drain-outbound-hot", Schedule: "@every 2s", SQL: "SELECT drain_outbound_hot()", Timeout: 10 * time.Second, enabled: true},

		// ── Real-time (per-minute) ──
		// Scheduled Actions (A6): one deferred-action dispatcher replaces the legacy
		// process-snoozed / process-scheduled / process-message-timers trio. It claims
		// due scheduled_actions (exactly-once, FOR UPDATE SKIP LOCKED) and routes each
		// to its per-kind handler. scan-due-reminders enqueues `remind` actions for
		// due event-VALARM / task-reminder / flag-due sources.
		{Name: "dispatch-scheduled-actions", Schedule: "@every 1m", SQL: "SELECT dispatch_scheduled_actions('cron')", Timeout: 30 * time.Second, enabled: true},
		{Name: "scan-due-reminders", Schedule: "@every 1m", SQL: "SELECT scan_due_reminders()", Timeout: 30 * time.Second, enabled: true},
		{Name: "retry-outbound-queue", Schedule: "@every 1m", SQL: "SELECT drain_outbound_queue(true)", Timeout: 30 * time.Second, enabled: true},
		{Name: "drain-journal-queue", Schedule: "@every 1m", SQL: "SELECT drain_journal_queue()", Timeout: 30 * time.Second, enabled: true},
		{Name: "retry-journal-queue", Schedule: "@every 1m", SQL: "SELECT drain_journal_queue(100, true)", Timeout: 30 * time.Second, enabled: true},
		{Name: "prune-ws-subscriptions", Schedule: "@every 1m", SQL: "SELECT prune_ws_subscriptions()", Timeout: 10 * time.Second, enabled: true},
		// med-shard3-003: consumed forgot-password reset-token tombstones
		// (used_password_reset_tokens) only need to outlive the reset-token
		// JWT's 5-minute validity; past that the hash is pure liability and
		// previously grew unbounded (the promised pruner existed nowhere).
		// 5-minute sweep, 10-minute default window (2x the JWT validity);
		// the reducer refuses windows below the validity floor (BZ040).
		// Reducer owned by authserver (authserver/sql/reducers/
		// prune_used_password_reset_tokens.sql) — deliberately not
		// purge_expired_tokens' job.
		{Name: "prune-used-password-reset-tokens", Schedule: "@every 5m", SQL: "SELECT prune_used_password_reset_tokens()", Timeout: 10 * time.Second, enabled: true},

		// Approval expiry sweep (formerly its own internal/approvaljobs
		// package — a bare 3s-ticker calling one idempotent, audited
		// reducer, exactly the shape this registry exists for; arch
		// review #A5). Expires overdue pending approval_requests, NDRs
		// held outbound sends, and drops held inbound messages.
		{Name: "approval-expire-due", Schedule: "@every 3s", SQL: "SELECT approval_expire_due()", Timeout: 10 * time.Second, enabled: true},

		// ── Health ──
		{Name: "health-check", Schedule: "@every 5m", SQL: "SELECT health_check()", Timeout: 30 * time.Second, enabled: true},

		// ── Maintenance ──
		{Name: "refresh-antiphish-contact-graph", Schedule: "@every 5m", SQL: "REFRESH MATERIALIZED VIEW antiphish_contact_graph", Timeout: 60 * time.Second, enabled: true},
		{Name: "reset-sending-quotas", Schedule: "0 * * * *", SQL: "SELECT reset_sending_quotas()", Timeout: 30 * time.Second, enabled: true},
		// auth_lockouts lifecycle (threat ip/user lockouts + push-MFA
		// counters): the documented pg_cron job never landed a Go-registry
		// replacement, so even expired rows were never removed. prune_old_lockouts
		// is the ONE cleanup path: expired threshold locks go immediately,
		// sub-threshold failure counters only after the reducer's default 24h
		// retention (long vs the 8h max lock window), so an active attacker's
		// recent failure history is never erased by a prune cycle.
		{Name: "prune-auth-lockouts", Schedule: "@every 5m", SQL: "SELECT prune_old_lockouts()", Timeout: 10 * time.Second, enabled: true},

		// ── Daily cleanup (staggered between 2-5 AM) ──
		{Name: "enforce-retention", Schedule: "5 2 * * *", SQL: "SELECT enforce_retention()", Timeout: 60 * time.Second, enabled: true},
		{Name: "purge-deleted-messages", Schedule: "30 2 * * *", SQL: "SELECT purge_deleted_messages()", Timeout: 60 * time.Second, enabled: true},
		// Chat A4a Task 9: the daily chain anchor — digests each channel's new
		// past-day messages into chat_audit_log and notarizes every channel's
		// chain head on the separate, append-only, HMAC-chained admin_audit_log
		// (defeats tail-truncation, FIX 1). Inert until feature.chat_compliance
		// flips ON (chat_chain_anchor's own guard). MUST run before the purge
		// (02:50): retention_days>0 forbids same-day create-and-purge, so every
		// purged row is anchored the same night before it dies.
		{Name: "chat-chain-anchor", Schedule: "40 2 * * *", SQL: "SELECT chat_chain_anchor()", Timeout: 120 * time.Second, enabled: true},
		// Chat A4a Task 6: the ONE true destruction path for chat content, inert
		// until feature.chat_compliance flips ON (chat_purge_expired's own guard).
		// 02:50 — after chat-chain-anchor's 02:40 slot above: retention_days>0
		// forbids same-day create-and-purge, so every purged row is anchored the
		// same night before it dies. Drains within a 90s budget (chat_purge_run,
		// verify N7) rather than nibbling a fixed row count.
		{Name: "chat-purge-expired", Schedule: "50 2 * * *", SQL: "SELECT chat_purge_run()", Timeout: 300 * time.Second, enabled: true},
		{Name: "prune-dmarc-reports", Schedule: "0 3 * * *", SQL: "SELECT prune_dmarc_reports()", Timeout: 30 * time.Second, enabled: true},
		{Name: "prune-spam", Schedule: "15 3 * * *", SQL: "SELECT prune_spam()", Timeout: 60 * time.Second, enabled: true},
		{Name: "prune-log-tables", Schedule: "30 3 * * *", SQL: "SELECT prune_log_tables()", Timeout: 60 * time.Second, enabled: true},
		// ponytail: COALESCE default 30 days; upgrade path = set ca_signin_log_retain_days in system_config.
		{Name: "prune-ca-signin-log", Schedule: "45 3 * * *", SQL: "SELECT ca_signin_log_prune(COALESCE((SELECT (value #>> '{}')::int FROM system_config WHERE key = 'ca_signin_log_retain_days'), 30))", Timeout: 30 * time.Second, enabled: true},
		// ponytail: COALESCE default 180 days (matches V028 seed); upgrade path = set login_events_retain_days in system_config.
		{Name: "prune-login-events", Schedule: "0 4 * * *", SQL: "SELECT login_events_prune(COALESCE((SELECT (value #>> '{}')::int FROM system_config WHERE key = 'login_events_retain_days'), 180))", Timeout: 30 * time.Second, enabled: true},
		// ponytail: 7-day session_activity TTL; upgrade path = system_config key. Runs on workerPool (BYPASSRLS) — FORCE RLS on both tables blocks non-worker deletes.
		{Name: "prune-session-runtime", Schedule: "15 4 * * *", SQL: "SELECT prune_session_runtime()", Timeout: 30 * time.Second, enabled: true},
		// F7 retention invariant (offline #3 Task 9): retain >= MAX(configured offline window, 30d RFC floor).
		// p_max_window_days = MAX(enabled offline-policy cap) so retention always covers the widest real client
		// window; the reducer's GREATEST(..., 30) is the backstop floor. p_high_water caps All-window accounts.
		// ponytail: reads offline_policies.max_offline_days (always >= any device window, enforced by offline_device_opt_in);
		//           high-water configurable via system_config; defaults keep the journal bounded if no policy is active.
		{Name: "prune-changes-journal", Schedule: "30 4 * * *", SQL: "SELECT prune_changes_journal(COALESCE((SELECT MAX(max_offline_days) FROM offline_policies WHERE enabled), 30), COALESCE((SELECT (value #>> '{}')::int FROM system_config WHERE key = 'offline_journal_high_water'), 50000))", Timeout: 60 * time.Second, enabled: true},
		// RBAC bulk-role job retention: drop terminal jobs after 30 days.
		{Name: "prune-bulk-role-jobs", Schedule: "45 3 * * *", SQL: `DELETE FROM bulk_role_jobs WHERE status IN ('done','error') AND updated_at < now() - interval '30 days'`, Timeout: 30 * time.Second, enabled: true},
		{Name: "prune-greylist", Schedule: "30 3 * * *", SQL: "SELECT prune_greylist_entries()", Timeout: 30 * time.Second, enabled: true},
		{Name: "prune-health-history", Schedule: "0 3 * * *", SQL: "SELECT prune_health_history()", Timeout: 30 * time.Second, enabled: true},
		{Name: "prune-vacation-replies", Schedule: "0 4 * * *", SQL: "SELECT prune_vacation_replies()", Timeout: 30 * time.Second, enabled: true},
		// mark-orphaned-blobs (SELECT mark_orphaned_blobs(), a function that was
		// never implemented) is intentionally NOT here. Draining
		// orphaned_message_blobs means deleting an object from SeaweedFS/MinIO —
		// an HTTP call, which a PL/pgSQL function run through this pool.Exec-only
		// cron path can never make. The drain lives in the Go blob worker instead,
		// on the same ticker as blob_cleanup_queue: see
		// blob.Handler.processOrphanedBlobs (internal/blob/handler.go StartCleanup).

		// ── Weekly cleanup ──
		{Name: "purge-expired-tokens", Schedule: "0 4 * * 0", SQL: "SELECT purge_expired_tokens()", Timeout: 30 * time.Second, enabled: true},
		{Name: "purge-saml-assertions", Schedule: "15 4 * * 1", SQL: "SELECT purge_saml_assertions()", Timeout: 30 * time.Second, enabled: true},

		// ── Monthly maintenance ──
		// ONE partition rotator for every month-partitioned table (c11): the
		// reducer derives the table set from pg_partitioned_table (RANGE +
		// single timestamptz key), so new partitioned tables are covered
		// automatically. (1) = offsets 0..1, current + next month — same call
		// boot makes (startup.EnsureMonthlyPartitions, owner pool). The audit
		// trio has NO DEFAULT partition, so a gateway running past the month
		// boundary without a partition hard-fails audit/auth logging.
		{Name: "create-monthly-partitions", Schedule: "0 0 25 * *", SQL: "SELECT create_monthly_partitions(1)", Timeout: 60 * time.Second, enabled: true},
	}
}
