//! Wave 2.6 (#553) live-DB integration tests:
//! - `GET /api/chat/channels/{id}/changes?since=<seq>&limit=<n>` delta replay
//! - Compliance `chat_purge_expired` `'resync'` sentinel → HTTP 409 `{"type":"cannotCalculateChanges"}`
//! - `tombstoneFloorExceeded` flag after `prune_scope_revocations` advances `sync_tombstone_floor`
//! - Unauthorized non-member → HTTP 403
//! - `WorkerSupervisor` `wave2_maintenance_tasks` schedule registration (`prune-scope-revocations`,
//!   `prune-chat-changes`)

mod common;

use common::BoxError;
use futures_util::FutureExt;
use hyper::{Method, Request, StatusCode};
use serde_json::Value;
use setjoin_conformance::{fixture, harness::Db};
use setjoin_gateway::supervisor::schedule::{
    wave2_maintenance_tasks, ScheduleRunner, ScheduleRunnerConfig,
};
use setjoin_gateway::{Config, Gateway, RouteTable, TrustedProxies};
use setjoin_pg::ScopedExecutor;
use setjoin_workqueue::ScheduleStore;
use std::panic::AssertUnwindSafe;
use std::sync::Arc;
use tokio::net::TcpListener;

static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

fn bearer_for(user_id: i64) -> String {
    format!("Bearer {}", common::recovery_token(user_id))
}

#[tokio::test]
async fn chat_changes_http_delta_resync_tombstone_and_schedule_registration() -> Result<(), BoxError>
{
    let _serial = SERIAL.lock().await;
    let Some(db) = Db::for_case("chat-changes-553") else {
        return Err("database required (set TEST_DB_DSN/DB_DSN)".into());
    };
    let owner = db.connect().await?;
    let app_dsn = db.app.as_deref().unwrap_or(&db.dsn);
    let exec =
        ScopedExecutor::from_dsn(app_dsn, 8)?.with_audit_keys("22".repeat(32), String::new());

    // Save & enable feature.chat and feature.chat_compliance for this test case.
    let saved_toggles: Vec<(String, bool)> = owner
        .query(
            "SELECT key, enabled FROM feature_toggles WHERE key IN ('feature.chat', 'feature.chat_compliance')",
            &[],
        )
        .await?
        .into_iter()
        .filter_map(|r| Some((r.try_get::<_, String>(0).ok()?, r.try_get::<_, bool>(1).ok()?)))
        .collect();
    owner
        .batch_execute(
            "UPDATE feature_toggles SET enabled = TRUE WHERE key IN ('feature.chat', 'feature.chat_compliance');",
        )
        .await?;

    let saved_floor: (String, i64) = {
        let row = owner
            .query_one(
                "SELECT pruned_before_at::text, pruned_before_revocation_id FROM public.sync_tombstone_floor WHERE id = 1",
                &[],
            )
            .await?;
        (row.try_get(0)?, row.try_get(1)?)
    };
    let saved_schedules_json: String = owner
        .query_one(
            "SELECT COALESCE(jsonb_agg(to_jsonb(ws)), '[]'::jsonb)::text \
             FROM public.worker_schedules ws \
             WHERE ws.task_name IN ('prune-scope-revocations', 'prune-chat-changes')",
            &[],
        )
        .await?
        .try_get(0)?;

    let member = fixture::account(&owner, "cc553-http-member").await?;
    let outsider = fixture::account(&owner, "cc553-http-outsider").await?;

    let adapter = setjoin_gateway::chat_channels::ChannelRoute {
        exec: exec.clone(),
        keys: Arc::new(common::recovery_keys()),
        issuer: "mailserver".into(),
        federation_local_domain: String::new(),
        unfurl: None,
        federation_typing: None,
    };
    let gateway = Gateway::new(
        Config {
            upstream: None,
            trusted_proxies: TrustedProxies::parse("")?,
            upstream_header_timeout: setjoin_gateway::proxy::DEFAULT_HEADER_TIMEOUT,
            edge_limit: None,
        },
        RouteTable::proxy_all().with(adapter),
    )?;
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let server = tokio::spawn(gateway.serve(listener));
    let mut created_channel_id: Option<i64> = None;

    let test_outcome: Result<Result<(), BoxError>, Box<dyn std::any::Any + Send>> =
        AssertUnwindSafe(async {
            // 1. Create channel + send/edit/pin messages as member.
            let ch_id: i64 = owner
                .query_one(
                    "SELECT chat_channel_create($1, 'cc553-http-ch', NULL, 'private')",
                    &[&member.user],
                )
                .await?
                .try_get(0)?;
            created_channel_id = Some(ch_id);
        let sent_json: String = owner
            .query_one(
                "SELECT chat_message_send($1, $2, 'msg one')::text",
                &[&member.user, &ch_id],
            )
            .await?
            .try_get(0)?;
        let sent_val: Value = serde_json::from_str(&sent_json)?;
        let msg_id = sent_val["messageId"]
            .as_i64()
            .ok_or("missing messageId")?;
        owner
            .query_one(
                "SELECT chat_message_edit($1, $2, 'msg one edited')",
                &[&member.user, &msg_id],
            )
            .await?;
        owner
            .query_one("SELECT chat_pin_toggle($1, $2)", &[&member.user, &msg_id])
            .await?;

        let member_auth = bearer_for(member.user);
        let outsider_auth = bearer_for(outsider.user);

        // 2. Delta replay over HTTP: GET /api/chat/channels/{id}/changes?since=0&limit=2
        let resp = common::send(
            addr,
            Request::builder()
                .method(Method::GET)
                .uri(format!("/api/chat/channels/{ch_id}/changes?since=0&limit=2"))
                .header("host", "mail.test")
                .header("authorization", &member_auth)
                .body(common::full(""))?,
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let page1: Value = serde_json::from_slice(&common::body_bytes(resp).await)?;
        assert_eq!(page1["channelId"].as_i64(), Some(ch_id));
        assert_eq!(page1["oldState"].as_str(), Some("0"));
        assert_eq!(page1["newState"].as_str(), Some("2"));
        assert_eq!(page1["hasMoreChanges"].as_bool(), Some(true));
        assert_eq!(page1["tombstoneFloorExceeded"].as_bool(), Some(false));
        let changes1 = page1["changes"]
            .as_array()
            .ok_or("changes must be array")?;
        assert_eq!(changes1.len(), 2);
        assert_eq!(changes1[0]["op"].as_str(), Some("created"));
        assert_eq!(changes1[1]["op"].as_str(), Some("updated"));

        // Page 2 from since=2
        let resp = common::send(
            addr,
            Request::builder()
                .method(Method::GET)
                .uri(format!("/api/chat/channels/{ch_id}/changes?since=2&limit=10"))
                .header("host", "mail.test")
                .header("authorization", &member_auth)
                .body(common::full(""))?,
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let page2: Value = serde_json::from_slice(&common::body_bytes(resp).await)?;
        assert_eq!(page2["newState"].as_str(), Some("3"));
        assert_eq!(page2["hasMoreChanges"].as_bool(), Some(false));
        let changes2 = page2["changes"]
            .as_array()
            .ok_or("changes2 must be array")?;
        assert_eq!(changes2.len(), 1);
        assert_eq!(changes2[0]["op"].as_str(), Some("pinned"));

        // 3. Unauthorized non-member -> HTTP 403
        let resp = common::send(
            addr,
            Request::builder()
                .method(Method::GET)
                .uri(format!("/api/chat/channels/{ch_id}/changes?since=0"))
                .header("host", "mail.test")
                .header("authorization", &outsider_auth)
                .body(common::full(""))?,
        )
        .await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);

        // 3b. Strict query parameter validation -> HTTP 400 Bad Request
        for bad_query in [
            "since=",
            "since=-1",
            "since=abc",
            "since=%ZZ",
            "limit=",
            "limit=0",
            "limit=-5",
            "limit=%2",
            "since=-1&since=5",
            "since=1&since=2",
            "limit=0&limit=10",
            "limit=5&limit=10",
        ] {
            let resp = common::send(
                addr,
                Request::builder()
                    .method(Method::GET)
                    .uri(format!("/api/chat/channels/{ch_id}/changes?{bad_query}"))
                    .header("host", "mail.test")
                    .header("authorization", &member_auth)
                    .body(common::full(""))?,
            )
            .await;
            assert_eq!(
                resp.status(),
                StatusCode::BAD_REQUEST,
                "expected 400 for query {bad_query:?}"
            );
        }

        // 4. tombstoneFloorExceeded after prune_scope_revocations(90) advances sync_tombstone_floor
        owner
            .execute(
                "INSERT INTO public.scope_revocations (occurred_at, user_id, scope_kind, scope_id, reason) \
                 VALUES (now() - interval '95 days', $1, 'channel', $2, 'cc553_http_tombstone')",
                &[&outsider.user, &ch_id],
            )
            .await?;
        owner
            .query_one("SELECT public.prune_scope_revocations(90)", &[])
            .await?;
        owner
            .execute(
                "UPDATE public.chat_changes SET created_at = now() - interval '92 days' \
                 WHERE channel_id = $1 AND change_seq = 1",
                &[&ch_id],
            )
            .await?;

        let resp = common::send(
            addr,
            Request::builder()
                .method(Method::GET)
                .uri(format!("/api/chat/channels/{ch_id}/changes?since=1"))
                .header("host", "mail.test")
                .header("authorization", &member_auth)
                .body(common::full(""))?,
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let tomb_body: Value = serde_json::from_slice(&common::body_bytes(resp).await)?;
        assert_eq!(tomb_body["tombstoneFloorExceeded"].as_bool(), Some(true));

        // Restore sync_tombstone_floor before step 5 (cleanup also restores on panic).
        owner
            .execute(
                "UPDATE public.sync_tombstone_floor SET pruned_before_at = $1::text::timestamptz, pruned_before_revocation_id = $2 WHERE id = 1",
                &[&saved_floor.0, &saved_floor.1],
            )
            .await?;

        // 5. Compliance purge appends 'resync' sentinel -> HTTP 409 {"type":"cannotCalculateChanges"}
        owner
            .execute(
                "UPDATE public.chat_channels SET retention_days = 10 WHERE id = $1",
                &[&ch_id],
            )
            .await?;
        owner
            .execute(
                "UPDATE public.chat_messages SET created_at = now() - interval '15 days' WHERE id = $1",
                &[&msg_id],
            )
            .await?;
        owner
            .query("SELECT * FROM public.chat_purge_expired(1000, FALSE)", &[])
            .await?;

        let resp = common::send(
            addr,
            Request::builder()
                .method(Method::GET)
                .uri(format!("/api/chat/channels/{ch_id}/changes?since=1"))
                .header("host", "mail.test")
                .header("authorization", &member_auth)
                .body(common::full(""))?,
        )
        .await;
        assert_eq!(resp.status(), StatusCode::CONFLICT);
        let conflict_body: Value = serde_json::from_slice(&common::body_bytes(resp).await)?;
        assert_eq!(
            conflict_body["type"].as_str(),
            Some("cannotCalculateChanges")
        );

        // 6. WorkerSupervisor wave2_maintenance_tasks registers prune-chat-changes
        //    and prune-scope-revocations cleanly in worker_schedules (disjoint from
        //    cron_catalog::CATALOG's prune-changes-journal).
        let worker_pool = setjoin_pg::WorkerPool::from_dsn(&db.dsn, 4)?;
        let store = ScheduleStore::new(worker_pool);
        let runner = ScheduleRunner::new(
            wave2_maintenance_tasks("UTC"),
            ScheduleRunnerConfig::default(),
        );
        runner.register_all(&store).await?;
        let registered: Vec<String> = owner
            .query(
                "SELECT task_name FROM public.worker_schedules \
                 WHERE task_name IN ('prune-scope-revocations', 'prune-chat-changes') \
                 ORDER BY task_name",
                &[],
            )
            .await?
            .into_iter()
            .filter_map(|r| r.try_get::<_, String>(0).ok())
            .collect();
        assert_eq!(
            registered,
            vec![
                "prune-chat-changes".to_owned(),
                "prune-scope-revocations".to_owned(),
            ]
        );

        Ok(())
    })
    .catch_unwind()
    .await;

    server.abort();
    let _ = server.await;
    if let Some(ch_id) = created_channel_id {
        let _ = owner
            .execute("DELETE FROM public.chat_channels WHERE id = $1", &[&ch_id])
            .await;
    }
    let _ = owner
        .execute(
            "UPDATE public.sync_tombstone_floor \
             SET pruned_before_at = $1::text::timestamptz, pruned_before_revocation_id = $2 \
             WHERE id = 1",
            &[&saved_floor.0, &saved_floor.1],
        )
        .await;
    let _ = owner
        .execute(
            "DELETE FROM public.worker_schedules \
             WHERE task_name IN ('prune-scope-revocations', 'prune-chat-changes')",
            &[],
        )
        .await;
    let _ = owner
        .execute(
            "INSERT INTO public.worker_schedules \
             SELECT * FROM jsonb_populate_recordset(NULL::public.worker_schedules, $1::text::jsonb) \
             ON CONFLICT (task_name) DO NOTHING",
            &[&saved_schedules_json],
        )
        .await;
    for (key, enabled) in saved_toggles {
        let _ = owner
            .execute(
                "UPDATE feature_toggles SET enabled = $2 WHERE key = $1",
                &[&key, &enabled],
            )
            .await;
    }
    let _ = fixture::remove(&owner, &member).await;
    let _ = fixture::remove(&owner, &outsider).await;
    match test_outcome {
        Ok(res) => res,
        Err(panic_payload) => std::panic::resume_unwind(panic_payload),
    }
}
