//! #407: seed-plus-one-tick oracle for the Go cron catalog. For every task,
//! frozen Go's real cron `Worker` (overlay `tests/conformance/cron/`) runs one
//! tick over a seeded database, once with `GO_WORKERS_OFF=cron:<task>` (no
//! effect) and once on; the Rust callback, driven by the real scheduler, must
//! leave the same rows, audit rows and NOTIFY events. Replay needs no Go.
//!
//! Record: `GOFREE_RECORD_CRON=all|task,task` (+ `GOFREE_GO_SOURCE`); goldens
//! are never replaced, delete one to re-record it. Replay filter:
//! `GOFREE_CRON_ONLY=task,task`.
mod common;
use chrono::TimeZone;
use common::BoxError;
use serde_json::{json, Map, Value};
use setjoin_conformance::harness::{Db, Listener};
use setjoin_gateway::cron_catalog::{cron_action, CronDatabases};
use setjoin_gateway::workers::CronScheduler;
use setjoin_pg::workers::WorkerDatabase;
use tokio_postgres::{Client, SimpleQueryMessage};

const HMAC: &str = "gofree-cron-catalog-oracle-hmac-key";
const CHANNELS: [&str; 6] = [
    "config_changed",
    "user_disabled",
    "user_deleted",
    "rules_changed",
    "spam_train",
    "admin:alert",
];
static SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// `$MB`, `$USER` and `$DOM` in seeds and observations are the fixture ids.
struct Case {
    task: &'static str,
    /// Local wall-clock time of the tick.
    at: &'static str,
    seed: &'static [&'static str],
    observe: &'static [(&'static str, &'static str)],
    cleanup: &'static [&'static str],
}

const EVERY: &str = "2026-10-25 12:00";

const CASES: &[Case] = &[
    Case {
        task: "drain-outbound-hot",
        at: EVERY,
        seed: &["INSERT INTO outbound_queue_hot(message_id,from_addr,rcpt_addrs,raw_ref,mailbox_id) VALUES ('gofree-cron-hot','a@x.test',ARRAY['b@x.test'],'ref-hot',$MB)"],
        observe: &[
            ("hot", "SELECT message_id FROM outbound_queue_hot WHERE message_id='gofree-cron-hot'"),
            ("queue", "SELECT message_id||':'||status||':'||attempt_count FROM outbound_queue WHERE message_id='gofree-cron-hot'"),
        ],
        cleanup: &["DELETE FROM outbound_queue_hot WHERE message_id='gofree-cron-hot'", "DELETE FROM outbound_queue WHERE message_id='gofree-cron-hot'"],
    },
    Case {
        task: "dispatch-scheduled-actions",
        at: EVERY,
        seed: &[
            "INSERT INTO scheduled_actions(action_kind,fire_at,payload,mailbox_id) VALUES ('snooze', now()-interval '1 minute','{\"_test_outcome\":\"ok\",\"marker\":\"gofree-cron-dispatch-1ok\"}',$MB), ('snooze', now()-interval '1 minute','{\"_test_outcome\":\"retry\",\"marker\":\"gofree-cron-dispatch-2retry\"}',$MB), ('snooze', now()-interval '1 minute','{\"_test_outcome\":\"permanent_fail\",\"marker\":\"gofree-cron-dispatch-3fail\"}',$MB), ('snooze', now()+interval '1 hour','{\"_test_outcome\":\"ok\",\"marker\":\"gofree-cron-dispatch-4future\"}',$MB)",
        ],
        observe: &[
            ("actions", "SELECT payload->>'marker'||':'||status||':'||attempts||':'||coalesce(last_error,'')||':'||(fire_at>now()+interval '30 seconds') FROM scheduled_actions WHERE mailbox_id=$MB ORDER BY payload->>'marker'"),
            ("log", "SELECT a.payload->>'marker'||':'||l.from_status||'>'||l.to_status||':'||l.worker||':'||l.outcome||':'||coalesce(l.note,'') FROM scheduled_action_log l JOIN scheduled_actions a ON a.id=l.action_id WHERE a.mailbox_id=$MB ORDER BY a.payload->>'marker', l.id"),
        ],
        cleanup: &["DELETE FROM scheduled_action_log WHERE action_id IN (SELECT id FROM scheduled_actions WHERE mailbox_id=$MB)", "DELETE FROM scheduled_actions WHERE mailbox_id=$MB"],
    },
    Case {
        task: "scan-due-reminders",
        at: EVERY,
        seed: &["INSERT INTO messages(mailbox_id,folder_id,message_id,from_addr,thread_id,raw_ref,size_bytes,subject,flag_due_at) VALUES ($MB,1,'gofree-cron-flag','a@x.test','t','ref-flag',1,'gofree-cron-flag',now()-interval '1 hour')"],
        observe: &[("reminders", "SELECT (payload->>'source_type')||':'||(payload->>'title')||':'||status||':'||action_kind FROM scheduled_actions WHERE mailbox_id=$MB ORDER BY id")],
        cleanup: &["DELETE FROM scheduled_action_log WHERE action_id IN (SELECT id FROM scheduled_actions WHERE mailbox_id=$MB)", "DELETE FROM scheduled_actions WHERE mailbox_id=$MB", "DELETE FROM messages WHERE mailbox_id=$MB"],
    },
    Case {
        task: "retry-outbound-queue",
        at: EVERY,
        seed: &["INSERT INTO outbound_queue(message_id,from_addr,rcpt_addrs,raw_ref,mailbox_id,status,attempt_count,next_attempt_at) VALUES ('gofree-cron-q1','a@x.test',ARRAY['b@x.test'],'r1',$MB,'deferred',1,now()-interval '1 minute'), ('gofree-cron-q2','a@x.test',ARRAY['b@x.test'],'r2',$MB,'deferred',20,now()-interval '1 minute'), ('gofree-cron-q3','a@x.test',ARRAY['b@x.test'],'r3',$MB,'deferred',1,now()+interval '1 hour')"],
        observe: &[("queue", "SELECT message_id||':'||status||':'||attempt_count||':'||coalesce((next_attempt_at IS NULL)::text,'') FROM outbound_queue WHERE message_id LIKE 'gofree-cron-q%' ORDER BY message_id")],
        cleanup: &["DELETE FROM outbound_queue WHERE message_id LIKE 'gofree-cron-q%'"],
    },
    Case {
        task: "drain-journal-queue",
        at: EVERY,
        seed: &["INSERT INTO journal_queue(message_id,envelope_from,envelope_to,raw_ref,journal_mailbox_id,status) VALUES ('gofree-cron-j1','a@x.test','b@x.test','jr1',$MB,'pending'), ('gofree-cron-j2','a@x.test','b@x.test','jr2',$MB,'deferred')"],
        observe: &[
            ("journal", "SELECT message_id||':'||status||':'||attempt_count||':'||replace(coalesce(last_error,''),$MB::text,'MB')||':'||coalesce((next_attempt_at>now())::text,'') FROM journal_queue WHERE message_id LIKE 'gofree-cron-j%' ORDER BY message_id"),
            ("materialised", "SELECT message_id||':'||is_read||':'||held FROM messages WHERE mailbox_id=$MB ORDER BY 1"),
        ],
        cleanup: &["DELETE FROM journal_queue WHERE message_id LIKE 'gofree-cron-j%'", "DELETE FROM messages WHERE mailbox_id=$MB"],
    },
    Case {
        task: "retry-journal-queue",
        at: EVERY,
        seed: &["INSERT INTO journal_queue(message_id,envelope_from,envelope_to,raw_ref,journal_mailbox_id,status,attempt_count,next_attempt_at) VALUES ('gofree-cron-j1','a@x.test','b@x.test','jr1',$MB,'pending',0,NULL), ('gofree-cron-j2','a@x.test','b@x.test','jr2',$MB,'deferred',1,now()-interval '1 minute'), ('gofree-cron-j3','a@x.test','b@x.test','jr3',$MB,'deferred',1,now()+interval '1 hour')"],
        observe: &[
            ("journal", "SELECT message_id||':'||status||':'||attempt_count||':'||replace(coalesce(last_error,''),$MB::text,'MB')||':'||coalesce((next_attempt_at>now()+interval '5 minutes')::text,'') FROM journal_queue WHERE message_id LIKE 'gofree-cron-j%' ORDER BY message_id"),
            ("materialised", "SELECT message_id||':'||is_read||':'||held FROM messages WHERE mailbox_id=$MB ORDER BY 1"),
        ],
        cleanup: &["DELETE FROM journal_queue WHERE message_id LIKE 'gofree-cron-j%'", "DELETE FROM messages WHERE mailbox_id=$MB"],
    },
    Case {
        task: "prune-ws-subscriptions",
        at: EVERY,
        seed: &["INSERT INTO ws_subscriptions(connection_id,session_id,user_id,last_ping_at) VALUES ('gofree-cron-ws-stale','s',$USER,now()-interval '10 minutes'), ('gofree-cron-ws-fresh','s',$USER,now())"],
        observe: &[("subscriptions", "SELECT connection_id FROM ws_subscriptions WHERE connection_id LIKE 'gofree-cron-ws-%' ORDER BY 1")],
        cleanup: &["DELETE FROM ws_subscriptions WHERE connection_id LIKE 'gofree-cron-ws-%'"],
    },
    Case {
        task: "prune-used-password-reset-tokens",
        at: EVERY,
        seed: &["INSERT INTO used_password_reset_tokens(token_hash,created_at) VALUES ('gofree-cron-pw-old',now()-interval '1 hour'), ('gofree-cron-pw-new',now())"],
        observe: &[("tokens", "SELECT token_hash FROM used_password_reset_tokens WHERE token_hash LIKE 'gofree-cron-pw-%' ORDER BY 1")],
        cleanup: &["DELETE FROM used_password_reset_tokens WHERE token_hash LIKE 'gofree-cron-pw-%'"],
    },
    Case {
        task: "approval-expire-due",
        at: EVERY,
        seed: &["INSERT INTO approval_requests(consumer_type,subject,payload,approver_kind,approver_ref,expires_at,status) VALUES ('rbac.jit_activation','gofree-cron-approval-1due','{}','user',$USER,now()-interval '1 minute','pending'), ('rbac.jit_activation','gofree-cron-approval-2open','{}','user',$USER,now()+interval '1 hour','pending')"],
        observe: &[("approvals", "SELECT subject||':'||status FROM approval_requests WHERE subject LIKE 'gofree-cron-approval-%' ORDER BY subject")],
        cleanup: &["DELETE FROM approval_requests WHERE subject LIKE 'gofree-cron-approval-%'"],
    },
    Case {
        task: "health-check",
        at: EVERY,
        // The partition rows come out in catalog scan order, which drifts as other suites
        // churn pg_partitioned_table; the observation orders them by name (login_events last,
        // as in the recording) so the recorded sequence stays the reference.
        // The recorded run had this month's and next month's partitions; a fresh
        // schema load carries only the migrations' fixed months, so create the
        // rolling window first (the same reducer the create-monthly-partitions task runs).
        seed: &["SELECT create_monthly_partitions()", "DELETE FROM health_history WHERE checked_at > now() - interval '5 minutes'"],
        observe: &[("health", "SELECT regexp_replace(check_name,'[0-9]{4}_[0-9]{2}','YYYY_MM')||':'||status FROM health_history WHERE checked_at > now() - interval '5 minutes' ORDER BY (check_name LIKE 'partition:%'), (check_name LIKE 'partition:login_events%'), CASE WHEN check_name LIKE 'partition:%' THEN check_name COLLATE \"C\" END, id")],
        cleanup: &["DELETE FROM health_history WHERE checked_at > now() - interval '5 minutes'"],
    },
    Case {
        task: "refresh-antiphish-contact-graph",
        at: EVERY,
        seed: &["INSERT INTO messages(mailbox_id,folder_id,message_id,from_addr,from_name,thread_id,raw_ref,size_bytes) VALUES ($MB,1,'gofree-cron-mv','gofree-cron-mv@x.test','Gofree Cron','t','ref-mv',1)"],
        observe: &[("graph", "SELECT sender_email||':'||sender_name||':'||message_count FROM antiphish_contact_graph WHERE sender_email LIKE 'gofree-cron-mv@%'")],
        cleanup: &["DELETE FROM messages WHERE mailbox_id=$MB", "REFRESH MATERIALIZED VIEW antiphish_contact_graph"],
    },
    Case {
        task: "reset-sending-quotas",
        at: "2026-10-25 12:00",
        seed: &["UPDATE mailboxes SET sending_sent_today=7, sending_quota_reset_at=current_date-1 WHERE id=$MB"],
        observe: &[("mailbox", "SELECT sending_sent_today||':'||(sending_quota_reset_at=current_date) FROM mailboxes WHERE id=$MB")],
        cleanup: &[],
    },
    Case {
        task: "prune-auth-lockouts",
        at: EVERY,
        seed: &["INSERT INTO auth_lockouts(lockout_key,failed_count,locked_until,updated_at) VALUES ('gofree-cron-lock-1expired-threshold',5,now()-interval '1 hour',now()-interval '2 hours'), ('gofree-cron-lock-2expired-fresh-counter',2,now()-interval '1 hour',now()), ('gofree-cron-lock-3expired-stale-counter',2,now()-interval '1 hour',now()-interval '2 days'), ('gofree-cron-lock-4active',5,now()+interval '10 minutes',now()), ('gofree-cron-lock-5toolong',5,now()+interval '30 hours',now())"],
        observe: &[("lockouts", "SELECT lockout_key||':'||failed_count||':'||(locked_until>now()+interval '8 hours 1 minute') FROM auth_lockouts WHERE lockout_key LIKE 'gofree-cron-lock-%' ORDER BY 1")],
        cleanup: &["DELETE FROM auth_lockouts WHERE lockout_key LIKE 'gofree-cron-lock-%'"],
    },
    Case {
        task: "enforce-retention",
        at: "2026-10-25 02:05",
        seed: &[
            "INSERT INTO retention_policies(name,retain_days,action,is_default) VALUES ('gofree-cron-retention',1,'delete',false)",
            "INSERT INTO messages(mailbox_id,folder_id,message_id,from_addr,thread_id,raw_ref,size_bytes,received_at) VALUES ($MB,1,'gofree-cron-ret-1expired','a@x.test','t','ref-r1',1,now()), ($MB,1,'gofree-cron-ret-2live','a@x.test','t','ref-r2',1,now())",
            "INSERT INTO message_retention_tags(message_id,received_at,policy_id,expires_at) SELECT m.id,m.received_at,(SELECT id FROM retention_policies WHERE name='gofree-cron-retention'),CASE WHEN m.message_id LIKE '%1expired' THEN now()-interval '1 hour' ELSE now()+interval '1 day' END FROM messages m WHERE m.mailbox_id=$MB",
        ],
        observe: &[
            ("messages", "SELECT message_id FROM messages WHERE mailbox_id=$MB ORDER BY 1"),
            ("tags", "SELECT count(*)::text FROM message_retention_tags t JOIN retention_policies p ON p.id=t.policy_id WHERE p.name='gofree-cron-retention'"),
            ("trace", "SELECT event||':'||message_id FROM message_trace WHERE message_id LIKE 'gofree-cron-ret-%' ORDER BY 1"),
        ],
        cleanup: &["DELETE FROM message_retention_tags WHERE policy_id IN (SELECT id FROM retention_policies WHERE name='gofree-cron-retention')", "DELETE FROM messages WHERE mailbox_id=$MB", "DELETE FROM message_trace WHERE message_id LIKE 'gofree-cron-ret-%'", "DELETE FROM retention_policies WHERE name='gofree-cron-retention'"],
    },
    Case {
        task: "purge-deleted-messages",
        at: "2026-10-25 02:30",
        seed: &["INSERT INTO messages(mailbox_id,folder_id,message_id,from_addr,thread_id,raw_ref,size_bytes,is_deleted,deleted_at) VALUES ($MB,1,'gofree-cron-del-1old','a@x.test','t','gofree-cron-ref-old',1,true,now()-interval '2 months'), ($MB,1,'gofree-cron-del-2recent','a@x.test','t','gofree-cron-ref-recent',1,true,now()-interval '1 day')"],
        observe: &[
            ("messages", "SELECT message_id FROM messages WHERE mailbox_id=$MB ORDER BY 1"),
            ("orphans", "SELECT raw_ref FROM orphaned_message_blobs WHERE raw_ref LIKE 'gofree-cron-ref-%' ORDER BY 1"),
        ],
        cleanup: &["DELETE FROM messages WHERE mailbox_id=$MB", "DELETE FROM orphaned_message_blobs WHERE raw_ref LIKE 'gofree-cron-ref-%'"],
    },
    Case {
        task: "prune-dmarc-reports",
        at: "2026-10-25 03:00",
        seed: &["INSERT INTO dmarc_reports(domain,report_uri,begin_time,end_time) VALUES ('gofree-cron-dmarc-old.test','u',now()-interval '201 days',now()-interval '200 days'), ('gofree-cron-dmarc-new.test','u',now()-interval '2 days',now()-interval '1 day')"],
        observe: &[("reports", "SELECT domain FROM dmarc_reports WHERE domain LIKE 'gofree-cron-dmarc-%' ORDER BY 1")],
        cleanup: &["DELETE FROM dmarc_reports WHERE domain LIKE 'gofree-cron-dmarc-%'"],
    },
    Case {
        task: "prune-spam",
        at: "2026-10-25 03:15",
        seed: &["DELETE FROM user_spam_model WHERE user_id=$USER", "INSERT INTO user_spam_model(user_id,model_bytes,trained_at,disabled) VALUES ($USER,'\\x00',now()-interval '400 days',false)"],
        observe: &[("models", "SELECT 'model:'||disabled FROM user_spam_model WHERE user_id=$USER")],
        cleanup: &["DELETE FROM user_spam_model WHERE user_id=$USER"],
    },
    Case {
        task: "prune-log-tables",
        at: "2026-10-25 03:30",
        seed: &[
            "INSERT INTO system_config(key,value) VALUES ('log_retention_message_trace_days','1') ON CONFLICT(key) DO UPDATE SET value='1'",
            "INSERT INTO message_trace(message_id,event,from_addr,rcpt_addr,occurred_at) VALUES ('gofree-cron-trace-old','received','a','b',now()-interval '3 days'), ('gofree-cron-trace-new','received','a','b',now())",
        ],
        observe: &[("trace", "SELECT message_id FROM message_trace WHERE message_id LIKE 'gofree-cron-trace-%' ORDER BY 1")],
        cleanup: &["DELETE FROM message_trace WHERE message_id LIKE 'gofree-cron-trace-%'", "UPDATE system_config SET value='30' WHERE key='log_retention_message_trace_days'"],
    },
    Case {
        task: "prune-ca-signin-log",
        at: "2026-10-25 03:45",
        seed: &["INSERT INTO ca_signin_log(occurred_at,decision,correlation_id) VALUES (now()-interval '40 days','allow','gofree-cron-ca-old'), (now(),'allow','gofree-cron-ca-new')"],
        observe: &[("signins", "SELECT correlation_id FROM ca_signin_log WHERE correlation_id LIKE 'gofree-cron-ca-%' ORDER BY 1")],
        cleanup: &["SELECT set_config('ca.signin_log_prune','on',false)", "DELETE FROM ca_signin_log WHERE correlation_id LIKE 'gofree-cron-ca-%'"],
    },
    Case {
        task: "prune-login-events",
        at: "2026-10-25 04:00",
        seed: &["DROP TABLE IF EXISTS login_events_2020_01", "CREATE TABLE login_events_2020_01 PARTITION OF login_events FOR VALUES FROM ('2020-01-01') TO ('2020-02-01')"],
        observe: &[("partition", "SELECT (to_regclass('login_events_2020_01') IS NOT NULL)::text")],
        cleanup: &["DROP TABLE IF EXISTS login_events_2020_01"],
    },
    Case {
        task: "prune-session-runtime",
        at: "2026-10-25 04:15",
        seed: &[
            "INSERT INTO session_revocations(user_id,scope,jti,reason,expires_at) VALUES ($USER,'jti','gofree-cron-rev-expired','r',now()-interval '1 hour'), ($USER,'jti','gofree-cron-rev-live','r',now()+interval '1 hour')",
            "INSERT INTO session_activity(jti,user_id,last_activity) VALUES ('gofree-cron-act-old',$USER,now()-interval '8 days'), ('gofree-cron-act-new',$USER,now())",
        ],
        observe: &[
            ("revocations", "SELECT jti FROM session_revocations WHERE jti LIKE 'gofree-cron-rev-%' ORDER BY 1"),
            ("activity", "SELECT jti FROM session_activity WHERE jti LIKE 'gofree-cron-act-%' ORDER BY 1"),
        ],
        cleanup: &["DELETE FROM session_revocations WHERE jti LIKE 'gofree-cron-rev-%'", "DELETE FROM session_activity WHERE jti LIKE 'gofree-cron-act-%'"],
    },
    Case {
        task: "prune-changes-journal",
        at: "2026-10-25 04:30",
        seed: &["INSERT INTO jmap_changes_journal(mailbox_id,state_seq,entity_id,op,created_at,datatype) VALUES ($MB,900001,1,'created',now()-interval '40 days','Email'), ($MB,900002,2,'created',now(),'Email')"],
        observe: &[("journal", "SELECT state_seq::text FROM jmap_changes_journal WHERE mailbox_id=$MB ORDER BY 1")],
        cleanup: &["DELETE FROM jmap_changes_journal WHERE mailbox_id=$MB"],
    },
    Case {
        task: "prune-bulk-role-jobs",
        at: "2026-10-25 03:45",
        seed: &["INSERT INTO bulk_role_jobs(op,error,role_id,actor_id,user_ids,total,status,updated_at) VALUES ('assign','gofree-cron-1done-old',1,1,ARRAY[1]::bigint[],1,'done',now()-interval '40 days'), ('assign','gofree-cron-2error-old',1,1,ARRAY[1]::bigint[],1,'error',now()-interval '40 days'), ('assign','gofree-cron-3pending-old',1,1,ARRAY[1]::bigint[],1,'queued',now()-interval '40 days'), ('assign','gofree-cron-4done-new',1,1,ARRAY[1]::bigint[],1,'done',now())"],
        observe: &[("jobs", "SELECT error||':'||status FROM bulk_role_jobs WHERE error LIKE 'gofree-cron-%' ORDER BY 1")],
        cleanup: &["DELETE FROM bulk_role_jobs WHERE error LIKE 'gofree-cron-%'"],
    },
    Case {
        task: "prune-greylist",
        at: "2026-10-25 03:30",
        seed: &["INSERT INTO greylist(ip,sender,recipient,last_seen,whitelisted) VALUES ('192.0.2.1','gofree-cron-grey-1old','r',now()-interval '30 days',false), ('192.0.2.1','gofree-cron-grey-2old-white','r',now()-interval '30 days',true), ('192.0.2.1','gofree-cron-grey-3new','r',now(),false)"],
        observe: &[("greylist", "SELECT sender FROM greylist WHERE sender LIKE 'gofree-cron-grey-%' ORDER BY 1")],
        cleanup: &["DELETE FROM greylist WHERE sender LIKE 'gofree-cron-grey-%'"],
    },
    Case {
        task: "prune-health-history",
        at: "2026-10-25 03:00",
        seed: &["INSERT INTO health_history(checked_at,check_name,status) VALUES (now()-interval '200 days','gofree-cron-hh-old','ok'), (now(),'gofree-cron-hh-new','ok')"],
        observe: &[("history", "SELECT check_name FROM health_history WHERE check_name LIKE 'gofree-cron-hh-%' ORDER BY 1")],
        cleanup: &["DELETE FROM health_history WHERE check_name LIKE 'gofree-cron-hh-%'"],
    },
    Case {
        task: "prune-vacation-replies",
        at: "2026-10-25 04:00",
        seed: &["INSERT INTO vacation_replies(sender_email,mailbox_id,vacation_start,replied_at) VALUES ('gofree-cron-vac-old@x.test',$MB,current_date,now()-interval '60 days'), ('gofree-cron-vac-new@x.test',$MB,current_date,now())"],
        observe: &[("replies", "SELECT sender_email FROM vacation_replies WHERE mailbox_id=$MB ORDER BY 1")],
        cleanup: &["DELETE FROM vacation_replies WHERE mailbox_id=$MB"],
    },
    Case {
        task: "purge-expired-tokens",
        at: "2026-10-25 04:00",
        seed: &[
            "INSERT INTO oauth_tokens(user_id,token_hash,token_type,expires_at) VALUES ($USER,'\\x676f667265652d63726f6e2d6f6c64','access',now()-interval '60 days'), ($USER,'\\x676f667265652d63726f6e2d6e6577','access',now()+interval '1 day')",
            "INSERT INTO scim_tokens(name,token_hash,expires_at) VALUES ('gofree-cron-scim-old','h1',now()-interval '60 days'), ('gofree-cron-scim-new','h2',now()+interval '1 day')",
        ],
        observe: &[
            ("oauth", "SELECT encode(token_hash,'escape') FROM oauth_tokens WHERE user_id=$USER ORDER BY 1"),
            ("scim", "SELECT name FROM scim_tokens WHERE name LIKE 'gofree-cron-scim-%' ORDER BY 1"),
        ],
        cleanup: &["DELETE FROM oauth_tokens WHERE user_id=$USER", "DELETE FROM scim_tokens WHERE name LIKE 'gofree-cron-scim-%'"],
    },
    Case {
        task: "purge-saml-assertions",
        at: "2026-10-26 04:15",
        seed: &["INSERT INTO used_saml_assertions(assertion_id,used_at) VALUES ('gofree-cron-saml-old',now()-interval '60 days'), ('gofree-cron-saml-new',now())"],
        observe: &[("assertions", "SELECT assertion_id FROM used_saml_assertions WHERE assertion_id LIKE 'gofree-cron-saml-%' ORDER BY 1")],
        cleanup: &["DELETE FROM used_saml_assertions WHERE assertion_id LIKE 'gofree-cron-saml-%'"],
    },
    Case {
        task: "create-monthly-partitions",
        at: "2026-10-25 00:00",
        seed: &["DROP TABLE IF EXISTS login_events_nextmonth_probe", "DO $$ BEGIN EXECUTE format('DROP TABLE IF EXISTS %I', 'login_events_'||to_char(now()+interval '1 month','YYYY_MM')); END $$"],
        observe: &[("partition", "SELECT (to_regclass('login_events_'||to_char(now()+interval '1 month','YYYY_MM')) IS NOT NULL)::text")],
        cleanup: &[],
    },
];

#[tokio::test]
async fn cron_catalog_seed_plus_one_tick() -> Result<(), BoxError> {
    let _serial = SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let Some(db) = Db::for_case("cron-catalog-tick") else {
        return Ok(());
    };
    let owner = db.connect().await?;
    let record = std::env::var("GOFREE_RECORD_CRON").ok();
    let only = std::env::var("GOFREE_CRON_ONLY").ok();
    let listed = |filter: &Option<String>, task: &str| {
        filter
            .as_deref()
            .is_none_or(|f| f == "all" || f.split(',').any(|t| t == task))
    };
    let (user, mailbox) = fixture(&owner).await?;
    let mut failures = Vec::new();
    let mut ran = 0;
    for case in CASES {
        let recording = record.is_some() && listed(&record, case.task);
        if record.is_some() && !recording || !listed(&only, case.task) {
            continue;
        }
        ran += 1;
        let ids = (user, mailbox);
        let result = run_case(&db, &owner, case, ids, recording).await;
        for sql in case.cleanup {
            let _ = owner.simple_query(&substitute(sql, ids)).await;
        }
        if let Err(error) = result {
            failures.push(format!("{}: {error}", case.task));
        }
    }
    owner
        .batch_execute(&format!(
            "DELETE FROM mailboxes WHERE id={mailbox}; DELETE FROM users WHERE id={user}; DELETE FROM domains WHERE name='gofree-cron.test'"
        ))
        .await?;
    assert!(failures.is_empty(), "{}", failures.join("\n"));
    assert!(ran > 0, "no case selected");
    Ok(())
}

async fn fixture(owner: &Client) -> Result<(i64, i64), BoxError> {
    owner.batch_execute("DELETE FROM mailboxes WHERE email='gofree-cron@gofree-cron.test'; DELETE FROM users WHERE username='gofree-cron'; DELETE FROM domains WHERE name='gofree-cron.test'").await?;
    let domain: i64 = owner
        .query_one(
            "INSERT INTO domains(name) VALUES ('gofree-cron.test') RETURNING id",
            &[],
        )
        .await?
        .get(0);
    let user: i64 = owner.query_one("INSERT INTO users(username,domain_id,email,display_name) VALUES ('gofree-cron',$1,'gofree-cron@gofree-cron.test','Gofree Cron') RETURNING id", &[&domain]).await?.get(0);
    let mailbox: i64 = owner.query_one("INSERT INTO mailboxes(user_id,domain_id,email,display_name,is_primary) VALUES ($1,$2,'gofree-cron@gofree-cron.test','Gofree Cron',true) RETURNING id", &[&user, &domain]).await?.get(0);
    Ok((user, mailbox))
}

fn substitute(sql: &str, (user, mailbox): (i64, i64)) -> String {
    sql.replace("$MB", &mailbox.to_string())
        .replace("$USER", &user.to_string())
}

async fn run_case(
    db: &Db,
    owner: &Client,
    case: &Case,
    ids: (i64, i64),
    recording: bool,
) -> Result<(), BoxError> {
    for sql in case.cleanup {
        let _ = owner.simple_query(&substitute(sql, ids)).await;
    }
    for sql in case.seed {
        owner
            .simple_query(&substitute(sql, ids))
            .await
            .map_err(|e| format!("seed `{sql}`: {}", db_text(&e)))?;
    }
    let mut listeners = Vec::new();
    for channel in CHANNELS {
        listeners.push(db.listen(channel).await?);
    }
    let audit_base: i64 = owner
        .query_one("SELECT coalesce(max(id),0) FROM admin_audit_log", &[])
        .await?
        .get(0);
    let mut phases = Vec::new();
    for phase in ["go-off-skips", "tick"] {
        if recording {
            let go_off = if phase == "go-off-skips" {
                format!("cron:{}", case.task)
            } else {
                String::new()
            };
            record_go_tick(db, case, &go_off)?;
        } else if phase == "tick" {
            native_tick(db, case).await?;
        }
        phases.push(
            json!({"phase":phase,"after":observe(owner,&mut listeners,case,ids,audit_base).await?}),
        );
    }
    let observation = json!({ "phases": phases });
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/conformance/cron/goldens")
        .join(format!("{}.json", case.task));
    if recording {
        let _ = std::fs::remove_file(&path);
        // Go's tick must have a visible effect, or the seed proves nothing.
        if phases[0]["after"] == phases[1]["after"] && case.task != "health-check" {
            return Err(format!("Go's tick changed nothing: {observation}").into());
        }
        setjoin_conformance::golden::record(
            &path,
            &json!({"format":1,"case":case.task,"go_source":std::env::var("GOFREE_GO_SOURCE")?,"observation":observation}),
        )?;
    } else {
        let Ok(bytes) = std::fs::read(&path) else {
            return Err(format!("no golden; native observation: {observation}").into());
        };
        let golden: Value = serde_json::from_slice(&bytes)?;
        setjoin_conformance::golden::compare(&golden["observation"], &observation)?;
        println!("GOLDEN-REPLAY: cron {} :: seed-plus-one-tick", case.task);
    }
    Ok(())
}

/// Rows, audit rows and NOTIFY payloads visible after a phase.
async fn observe(
    owner: &Client,
    listeners: &mut [Listener],
    case: &Case,
    ids: (i64, i64),
    audit_base: i64,
) -> Result<Value, BoxError> {
    let mut rows = Map::new();
    for (label, sql) in case.observe {
        rows.insert(
            (*label).into(),
            json!(text_rows(owner, &substitute(sql, ids)).await?),
        );
    }
    let audit = text_rows(
        owner,
        &format!("SELECT action||':'||coalesce(target_type,'')||':'||coalesce(notes,'') FROM admin_audit_log WHERE id>{audit_base} AND action<>'chat.chain_notary' ORDER BY id"),
    )
    .await?;
    let mut notifies = Vec::new();
    for listener in listeners {
        for payload in listener.drain(owner).await? {
            notifies.push(payload);
        }
    }
    notifies.sort();
    Ok(json!({"rows":rows,"audit":audit,"notifies":notifies}))
}

async fn text_rows(owner: &Client, sql: &str) -> Result<Vec<String>, BoxError> {
    let mut out = Vec::new();
    for message in owner
        .simple_query(sql)
        .await
        .map_err(|e| format!("`{sql}`: {}", db_text(&e)))?
    {
        if let SimpleQueryMessage::Row(row) = message {
            out.push(row.get(0).unwrap_or("<null>").to_string());
        }
    }
    Ok(out)
}

fn db_text(error: &tokio_postgres::Error) -> String {
    error.as_db_error().map_or_else(
        || error.to_string(),
        |d| format!("{} ({})", d.message(), d.code().code()),
    )
}

fn local(at: &str) -> chrono::DateTime<chrono::Local> {
    let naive = chrono::NaiveDateTime::parse_from_str(at, "%Y-%m-%d %H:%M").unwrap();
    chrono::Local.from_local_datetime(&naive).single().unwrap()
}

/// One tick of the real Rust scheduler, with Go's copy listed off.
async fn native_tick(db: &Db, case: &Case) -> Result<(), BoxError> {
    let worker = WorkerDatabase::new(&db.dsn)?.with_audit_keys(String::new(), HMAC.into());
    let dbs = CronDatabases {
        worker: worker.clone(),
        owner: worker.clone(),
    };
    let mut scheduler = CronScheduler::per_task(worker);
    scheduler
        .register_transferred(
            case.task,
            cron_action(case.task, &dbs).expect("catalog action"),
            &format!("cron:{}", case.task),
        )
        .await?;
    scheduler.tick(local(case.at)).await?;
    scheduler.wait_idle().await;
    scheduler.shutdown().await?;
    Ok(())
}

fn record_go_tick(db: &Db, case: &Case, go_off: &str) -> Result<(), BoxError> {
    use std::io::Write;
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../..")
        .canonicalize()?;
    let folder = root.join("test-results/gofree-croncat");
    std::fs::create_dir_all(&folder)?;
    std::fs::write(
        folder.join("overlay.json"),
        serde_json::to_vec(
            &json!({"Replace":{"/src/mailserver/internal/cron/gofree_cron_catalog_tick_test.go":"/src/server-rust/tests/conformance/cron/cron_tick_test.go.txt"}}),
        )?,
    )?;
    let name = format!("gofree-croncat-oracle-{}", std::process::id());
    if let Ok(ledger) = std::env::var("GOFREE_RESOURCE_LEDGER") {
        writeln!(
            std::fs::OpenOptions::new().append(true).open(ledger)?,
            "Planned {name}, local Docker, go cache {}/go-cache; assigned DB only; --rm",
            folder.display()
        )?;
    }
    let output = std::process::Command::new("docker")
        .args(["run", "--rm", "--name", &name, "--network", "host", "-v"])
        .arg(format!("{}:/src", root.display()))
        .args([
            "-v",
            &gofree_go_mod_mount(),
            "-w",
            "/src/mailserver",
            "-e",
        ])
        .arg(format!("GOFREE_CRON_DSN={}", db.dsn))
        .args(["-e", &format!("GOFREE_CRON_HMAC={HMAC}")])
        .args(["-e", &format!("GOFREE_CRON_TASK={}", case.task)])
        .args(["-e", &format!("GOFREE_CRON_AT={}", case.at)])
        .args(["-e", &format!("GO_WORKERS_OFF={go_off}")])
        .args([
            "-e",
            "GOMAXPROCS=1",
            "-e",
            "GOGC=50",
            "-e",
            "GOMEMLIMIT=768MiB",
        ])
        .args(["-e", "GOCACHE=/src/test-results/gofree-croncat/go-cache"])
        .args([
            "setjoin-ci-linux-tc:local-amd64",
            "go",
            "test",
            "-p=1",
            "-vet=off",
            "-overlay=/src/test-results/gofree-croncat/overlay.json",
            "./internal/cron",
            "-run",
            "^TestGoFreeCronCatalogTick$",
            "-count=1",
        ])
        .output()?;
    if !output.status.success() {
        std::fs::write(
            folder.join("go-record.log"),
            [output.stdout.as_slice(), output.stderr.as_slice()].concat(),
        )?;
        return Err(format!(
            "frozen Go cron tick failed: {}",
            String::from_utf8_lossy(&output.stdout)
                .lines()
                .rev()
                .take(6)
                .collect::<Vec<_>>()
                .join(" | ")
        )
        .into());
    }
    Ok(())
}

/// Host Go module cache for the Go recorder container (GOFREE_GO_MOD_CACHE, default $HOME/go/pkg/mod).
#[allow(dead_code)]
fn gofree_go_mod_mount() -> String {
    let host = std::env::var("GOFREE_GO_MOD_CACHE").unwrap_or_else(|_| {
        format!(
            "{}/go/pkg/mod",
            std::env::var("HOME").unwrap_or_else(|_| "/root".into())
        )
    });
    format!("{host}:/root/go/pkg/mod")
}
