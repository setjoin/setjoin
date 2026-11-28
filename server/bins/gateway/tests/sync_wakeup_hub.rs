//! Wave 2.5 (#552): Scope-keyed `SyncWakeup` Push Hub end-to-end live-DB tests.
//!
//! Exercises:
//! 1. `GET /.well-known/jmap` `X-Setjoin-Sync-Wakeup: 1` opt-in header + intact
//!    JSON body + zero unsolicited frames on `/jmap/ws` connect.
//! 2. `ScopeAttach` / `ScopeDetach` authorization, `"primary"` alias round-trip
//!    (string `scopeId`, `seq: 0`), unauthorized denials (foreign mailbox,
//!    `send_as`-only delegate, non-member channel/space), and >512 cap partial
//!    denials.
//! 3. Granular `calendar_acls` DataType filtering (calendar-only delegate never
//!    receives `Email`/`Mailbox`/`Thread` wakeups).
//! 4. Immediate live `ScopeRevoked` detachment (single WS frame, subsequent
//!    wakeups dropped) across ALL revocation surfaces:
//!    - `mailbox_delegate_revoke`
//!    - `jmap_calendar_share_set` (downgrade to `freebusy` + full revoke)
//!    - `drive_member_revoke`
//!    - `chat_member_remove` (+ bound Drive space)
//!    - `meeting_kick` (provisioned chat channel + bound Drive space)
//!    - `mailbox_lifecycle_transition('suspend')` (effects worker paused)
//!    - `group_membership_changed` (Drive space via group membership removal)
//! 5. Re-grant race safety: delayed `scope_revoked` after re-grant does NOT
//!    detach the re-granted scope.
//! 6. Drive subtree ACL revoke vs `'tree_move'` (`tree_move` never detaches;
//!    subtree revoke emits string `subtreeAnchorId` while keeping space attached).
//! 7. 1,000-revocation burst & `ResyncRequired` reconnect recovery.
//! 8. Multi-replica HA fanout: two independent `SyncWakeupHub` instances sharing
//!    one PostgreSQL `DB_DIRECT_DSN` with zero external broker.
//! 9. Guest SSE (`/jmap/eventsource`): auto-attaches authorized Chat channel +
//!    bound Drive space, receives `event: sync_wakeup` and priority
//!    `event: scope_revoked` on `guest_set_status(..., 'disable', NULL)`.

use crate::common;

use common::BoxError;
use futures_util::{SinkExt, StreamExt};
use http_body_util::BodyExt;
use hyper::{Request, Response};
use serde_json::{json, Value};
use setjoin_conformance::{fixture, harness::Db};
use setjoin_gateway::jmap::{
    push::WebSocketRoute,
    sse::EventSourceRoute,
    sync_hub::{ControlMessage, ScopeDescriptor, ScopeKind, SyncWakeupHub},
    JmapCommands, JmapRoute, JmapServices,
};
use setjoin_gateway::notify_drain::NotifyIntentDrain;
use setjoin_gateway::{Config, Gateway, RouteTable, TrustedProxies};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::oneshot;
use tokio_tungstenite::tungstenite::{client::IntoClientRequest, Message};

static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

struct DrainGuard {
    stop: Option<oneshot::Sender<()>>,
    task: tokio::task::JoinHandle<()>,
}

impl DrainGuard {
    fn start(worker_dsn: &str) -> Result<Self, BoxError> {
        let (tx, rx) = oneshot::channel::<()>();
        let worker = NotifyIntentDrain::new(setjoin_pg::workers::WorkerDatabase::new(worker_dsn)?);
        let task = tokio::spawn(async move {
            worker
                .run_until(async move {
                    let _ = rx.await;
                })
                .await;
        });
        Ok(Self {
            stop: Some(tx),
            task,
        })
    }

    async fn stop(mut self) {
        if let Some(tx) = self.stop.take() {
            let _ = tx.send(());
        }
        let _ = tokio::time::timeout(Duration::from_secs(3), self.task).await;
    }
}

struct GatewayHarness {
    addr: SocketAddr,
    hub: Arc<SyncWakeupHub>,
    server: tokio::task::JoinHandle<()>,
    drain: DrainGuard,
}

impl GatewayHarness {
    async fn start(db: &Db) -> Result<Self, BoxError> {
        let app_dsn = db.app.as_deref().unwrap_or(&db.dsn);
        let exec = common::patient_exec(app_dsn, 8)?;
        let worker = common::patient_exec(&db.dsn, 8)?;
        let hub = SyncWakeupHub::from_direct_dsn(&db.direct, exec.clone(), worker.clone())
            .ok_or("failed to initialize SyncWakeupHub")?;
        assert!(
            hub.wait_ready(Duration::from_secs(5)).await,
            "SyncWakeupHub did not become ready within 5s"
        );

        let services = Arc::new(JmapServices::new(
            worker.clone(),
            "mail.test".into(),
            50_000_000,
        ));
        let commands = Arc::new(JmapCommands {
            services: Some(services),
            worker: Some(worker.clone()),
            exec,
            keys: common::recovery_keys(),
            issuer: "mailserver".into(),
            denylist: None,
        });
        let ws =
            WebSocketRoute::new(commands.clone(), db.direct.clone()).with_sync_hub(hub.clone());
        let sse = EventSourceRoute::new(&ws).with_sync_hub(hub.clone());

        let routes = RouteTable::proxy_all()
            .with(ws)
            .with(sse)
            .with(JmapRoute(commands));
        let gateway = Gateway::new(
            Config {
                upstream: None,
                trusted_proxies: TrustedProxies::parse("")?,
                upstream_header_timeout: Duration::from_secs(30),
                edge_limit: None,
            },
            routes,
        )?;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        let server = tokio::spawn(gateway.serve(listener));
        let drain = DrainGuard::start(&db.dsn)?;
        Ok(Self {
            addr,
            hub,
            server,
            drain,
        })
    }

    async fn shutdown(self) {
        self.hub.shutdown();
        self.server.abort();
        let _ = self.server.await;
        self.drain.stop().await;
    }
}

type WsStream =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

async fn connect_ws(addr: SocketAddr, user_id: i64) -> Result<WsStream, BoxError> {
    let token = common::recovery_token_with(user_id, json!({}));
    let mut req = format!("ws://{addr}/jmap/ws").into_client_request()?;
    req.headers_mut()
        .insert("cookie", format!("access_token={token}").parse()?);
    let (socket, _) = tokio_tungstenite::connect_async(req).await?;
    Ok(socket)
}

async fn next_ws_json(socket: &mut WsStream, timeout: Duration) -> Result<Value, BoxError> {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        let rem = deadline.saturating_duration_since(tokio::time::Instant::now());
        if rem.is_zero() {
            return Err("timed out waiting for WS JSON frame".into());
        }
        let msg = tokio::time::timeout(rem, socket.next())
            .await
            .map_err(|_| "timed out waiting for WS frame")?
            .ok_or("WS stream ended unexpectedly")??;
        match msg {
            Message::Text(txt) => return Ok(serde_json::from_str(txt.trim())?),
            Message::Ping(_) | Message::Pong(_) => continue,
            other => return Err(format!("unexpected WS frame: {other:?}").into()),
        }
    }
}

async fn next_ws_matching<F>(
    socket: &mut WsStream,
    timeout: Duration,
    mut pred: F,
) -> Result<Value, BoxError>
where
    F: FnMut(&Value) -> bool,
{
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        let rem = deadline.saturating_duration_since(tokio::time::Instant::now());
        if rem.is_zero() {
            return Err("timed out waiting for matching WS JSON frame".into());
        }
        let frame = next_ws_json(socket, rem).await?;
        if pred(&frame) {
            return Ok(frame);
        }
    }
}

async fn assert_no_ws_frame_matching<F>(
    socket: &mut WsStream,
    window: Duration,
    mut pred: F,
) -> Result<(), BoxError>
where
    F: FnMut(&Value) -> bool,
{
    let deadline = tokio::time::Instant::now() + window;
    loop {
        let rem = deadline.saturating_duration_since(tokio::time::Instant::now());
        if rem.is_zero() {
            return Ok(());
        }
        match tokio::time::timeout(rem, socket.next()).await {
            Err(_) => return Ok(()),
            Ok(Some(Ok(Message::Text(txt)))) => {
                let v: Value = serde_json::from_str(txt.trim())?;
                if pred(&v) {
                    return Err(format!("unexpected forbidden WS frame: {v}").into());
                }
            }
            Ok(Some(Ok(Message::Ping(_) | Message::Pong(_)))) => continue,
            Ok(other) => return Err(format!("unexpected WS event while quiet: {other:?}").into()),
        }
    }
}

async fn send_attach(
    socket: &mut WsStream,
    req_id: &str,
    scopes: Value,
) -> Result<Value, BoxError> {
    let payload = json!({
        "@type": "ScopeAttach",
        "id": req_id,
        "scopes": scopes,
    });
    socket
        .send(Message::Text(payload.to_string().into()))
        .await?;
    next_ws_matching(socket, Duration::from_secs(5), |v| {
        v["@type"] == "ScopeAttachResponse" && v["requestId"] == req_id
    })
    .await
}

async fn send_detach(
    socket: &mut WsStream,
    req_id: &str,
    scopes: Value,
) -> Result<Value, BoxError> {
    let payload = json!({
        "@type": "ScopeDetach",
        "id": req_id,
        "scopes": scopes,
    });
    socket
        .send(Message::Text(payload.to_string().into()))
        .await?;
    next_ws_matching(socket, Duration::from_secs(5), |v| {
        v["@type"] == "ScopeDetachResponse" && v["requestId"] == req_id
    })
    .await
}

async fn enable_toggle(owner: &tokio_postgres::Client, key: &str) -> Result<bool, BoxError> {
    let prev: bool = owner
        .query_one(
            "SELECT enabled FROM feature_toggles WHERE key = $1",
            &[&key],
        )
        .await?
        .get(0);
    owner
        .execute(
            "UPDATE feature_toggles SET enabled = TRUE WHERE key = $1",
            &[&key],
        )
        .await?;
    Ok(prev)
}

async fn restore_toggle(owner: &tokio_postgres::Client, key: &str, prev: bool) {
    let _ = owner
        .execute(
            "UPDATE feature_toggles SET enabled = $1 WHERE key = $2",
            &[&prev, &key],
        )
        .await;
}

async fn cleanup_drive_spaces(owner: &tokio_postgres::Client, space_ids: &[i64]) {
    if space_ids.is_empty() {
        return;
    }
    let list = space_ids
        .iter()
        .map(i64::to_string)
        .collect::<Vec<_>>()
        .join(",");
    let _ = owner
        .batch_execute(&format!(
            "BEGIN; SET LOCAL session_replication_role = replica; \
             DELETE FROM drive_audit_log WHERE space_id IN ({list}); \
             DELETE FROM drive_access_invalidations WHERE space_id IN ({list}); \
             DELETE FROM drive_nodes WHERE space_id IN ({list}); \
             DELETE FROM drive_space_members WHERE space_id IN ({list}); \
             DELETE FROM drive_spaces WHERE id IN ({list}); \
             COMMIT;"
        ))
        .await;
}

async fn cleanup_channels(owner: &tokio_postgres::Client, ch_ids: &[i64]) {
    if ch_ids.is_empty() {
        return;
    }
    let list = ch_ids
        .iter()
        .map(i64::to_string)
        .collect::<Vec<_>>()
        .join(",");
    let _ = owner
        .batch_execute(&format!(
            "BEGIN; SET LOCAL session_replication_role = replica; \
             DELETE FROM chat_audit_log WHERE channel_id IN ({list}); \
             DELETE FROM chat_channels WHERE id IN ({list}); \
             COMMIT;"
        ))
        .await;
}

async fn cleanup_user_refs(owner: &tokio_postgres::Client, user_ids: &[i64]) {
    if user_ids.is_empty() {
        return;
    }
    let list = user_ids
        .iter()
        .map(i64::to_string)
        .collect::<Vec<_>>()
        .join(",");
    let _ = owner
        .batch_execute(&format!(
            "BEGIN; SET LOCAL session_replication_role = replica; \
             DELETE FROM admin_role_assignments WHERE user_id IN ({list}) OR granted_by IN ({list}); \
             DELETE FROM mailbox_delegates WHERE user_id IN ({list}) OR granted_by IN ({list}); \
             DELETE FROM calendar_acls WHERE user_id IN ({list}); \
             DELETE FROM user_app_entitlements WHERE user_id IN ({list}); \
             COMMIT;"
        ))
        .await;
}

async fn cleanup_account_safe(
    owner: &tokio_postgres::Client,
    acc: &fixture::Account,
) -> Result<(), BoxError> {
    let _ = owner
        .batch_execute(&format!(
            "BEGIN; SET LOCAL session_replication_role = replica; \
             DELETE FROM calendars WHERE mailbox_id = {mb}; \
             DELETE FROM jmap_entity_state WHERE mailbox_id = {mb}; \
             DELETE FROM mailbox_lifecycle_effects WHERE mailbox_id = {mb}; \
             DELETE FROM mailbox_lifecycle_outbox WHERE operation_id IN (SELECT operation_id FROM mailbox_lifecycle_operations WHERE mailbox_id = {mb}); \
             DELETE FROM mailbox_lifecycle_operations WHERE mailbox_id = {mb}; \
             DELETE FROM mailbox_audit_log WHERE mailbox_id = {mb}; \
             DELETE FROM admin_audit_log WHERE user_id = {u}; \
             COMMIT;",
            mb = acc.mailbox,
            u = acc.user
        ))
        .await;
    fixture::remove(owner, acc).await
}

#[tokio::test]
async fn session_header_and_ws_no_unsolicited_frames() -> Result<(), BoxError> {
    let _serial = SERIAL.lock().await;
    let Some(db) = Db::for_case("sync-wakeup-session-header") else {
        return Ok(());
    };
    let owner = db.connect().await?;
    let account = fixture::account(&owner, "sw-session").await?;
    let harness = GatewayHarness::start(&db).await?;

    let result = async {
        // 1. GET /.well-known/jmap emits X-Setjoin-Sync-Wakeup: 1 header with intact JSON body.
        let token = common::recovery_token_with(account.user, json!({}));
        let resp = common::send(
            harness.addr,
            Request::builder()
                .method("GET")
                .uri("/.well-known/jmap")
                .header("host", "mail.test")
                .header("authorization", format!("Bearer {token}"))
                .body(common::full(""))?,
        )
        .await;
        assert_eq!(resp.status(), 200);
        assert_eq!(
            resp.headers()
                .get("x-setjoin-sync-wakeup")
                .and_then(|v| v.to_str().ok()),
            Some("1"),
            "/.well-known/jmap must advertise X-Setjoin-Sync-Wakeup: 1"
        );
        let body: Value = serde_json::from_slice(&common::body_bytes(resp).await)?;
        assert!(body["accounts"].is_object());
        assert!(body.get("syncWakeup").is_none());

        // 2. WS connect sends ZERO unsolicited frames (preserves ws-controls.json).
        let mut ws = connect_ws(harness.addr, account.user).await?;
        assert_no_ws_frame_matching(&mut ws, Duration::from_millis(200), |_| true).await?;
        let _ = ws.close(None).await;
        Ok::<_, BoxError>(())
    }
    .await;

    harness.shutdown().await;
    fixture::remove(&owner, &account).await?;
    result
}

#[tokio::test]
async fn scope_attach_authorization_cap_and_primary_alias() -> Result<(), BoxError> {
    let _serial = SERIAL.lock().await;
    let Some(db) = Db::for_case("sync-wakeup-attach-authz") else {
        return Ok(());
    };
    let owner = db.connect().await?;
    let a = fixture::account(&owner, "sw-attach-a").await?;
    let b = fixture::account(&owner, "sw-attach-b").await?;

    // Grant send_as ONLY on B's mailbox to A (must be denied — no read/calendar access).
    owner
        .execute(
            "INSERT INTO mailbox_delegates (mailbox_id, user_id, permission, granted_by) \
             VALUES ($1, $2, 'send_as', $3) ON CONFLICT DO NOTHING",
            &[&b.mailbox, &a.user, &b.user],
        )
        .await?;
    // Create a private channel owned by B and a Drive space owned by B (A is NOT a member).
    let b_ch: i64 = owner
        .query_one(
            "SELECT chat_channel_create($1, 'sw-b-private', NULL, 'private')",
            &[&b.user],
        )
        .await?
        .get(0);
    let b_space: i64 = owner
        .query_one(
            "SELECT drive_space_create($1, 'sw-b-space', 'regular')",
            &[&b.user],
        )
        .await?
        .get(0);

    let harness = GatewayHarness::start(&db).await?;
    let result = async {
        let mut ws = connect_ws(harness.addr, a.user).await?;

        // Attach "primary" + unauthorized foreign scopes in one batch.
        let resp = send_attach(
            &mut ws,
            "att-1",
            json!([
                {"scopeKind": "mailbox", "scopeId": "primary"},
                {"scopeKind": "mailbox", "scopeId": b.mailbox.to_string()},
                {"scopeKind": "channel", "scopeId": b_ch.to_string()},
                {"scopeKind": "space", "scopeId": b_space.to_string()},
                {"scopeKind": "bogus", "scopeId": "1"}
            ]),
        )
        .await?;

        let attached = resp["attached"]
            .as_array()
            .ok_or("attached array missing")?;
        let denied = resp["denied"].as_array().ok_or("denied array missing")?;
        assert_eq!(
            attached.len(),
            1,
            "only primary mailbox should attach: {resp}"
        );
        assert_eq!(attached[0]["scopeKind"], "mailbox");
        assert_eq!(attached[0]["scopeId"], "primary");
        assert_eq!(
            denied.len(),
            4,
            "all 4 unauthorized/invalid scopes must be denied: {resp}"
        );

        // Trigger email state change on A's mailbox -> must receive SyncWakeup with scopeId "primary" & seq 0.
        owner
            .execute(
                "SELECT notify_state_change($1, NULL::bigint)",
                &[&a.mailbox],
            )
            .await?;
        let wakeup = next_ws_matching(&mut ws, Duration::from_secs(5), |v| {
            v["@type"] == "SyncWakeup"
        })
        .await?;
        assert_eq!(wakeup["event"]["scopeKind"], "mailbox");
        assert_eq!(wakeup["event"]["scopeId"], "primary");
        assert_eq!(wakeup["event"]["seq"], 0);
        let dts = wakeup["event"]["dataTypes"]
            .as_array()
            .ok_or("dataTypes array missing")?;
        assert!(
            dts.iter().any(|d| d == "Email"),
            "expected Email in dataTypes: {wakeup}"
        );

        // Unauthorized B scopes firing must NEVER reach A.
        owner
            .execute(
                "SELECT notify_state_change($1, NULL::bigint)",
                &[&b.mailbox],
            )
            .await?;
        owner
            .execute(
                "SELECT notify_chat_state($1, 'message_created', 1, 5)",
                &[&b_ch],
            )
            .await?;
        owner
            .execute("SELECT drive_notify_change($1, 0, 'member')", &[&b_space])
            .await?;
        assert_no_ws_frame_matching(&mut ws, Duration::from_millis(300), |v| {
            v["@type"] == "SyncWakeup"
        })
        .await?;

        // Test >512 scope cap returns partial denials without closing socket.
        let mut many_scopes = Vec::with_capacity(515);
        for i in 1..=515 {
            many_scopes
                .push(json!({"scopeKind": "channel", "scopeId": (900_000_000 + i).to_string()}));
        }
        let cap_resp = send_attach(&mut ws, "att-cap", Value::Array(many_scopes)).await?;
        let cap_denied = cap_resp["denied"].as_array().ok_or("denied missing")?;
        assert_eq!(cap_denied.len(), 515);
        assert!(
            cap_denied
                .iter()
                .any(|d| d["reason"] == "scope_limit_exceeded"),
            "expected scope_limit_exceeded partial denial past 512 cap"
        );

        // Detach "primary" -> subsequent notify_state_change delivers zero SyncWakeup.
        let det = send_detach(
            &mut ws,
            "det-1",
            json!([{"scopeKind": "mailbox", "scopeId": "primary"}]),
        )
        .await?;
        assert_eq!(det["detached"].as_array().map(Vec::len), Some(1));
        owner
            .execute(
                "SELECT notify_state_change($1, NULL::bigint)",
                &[&a.mailbox],
            )
            .await?;
        assert_no_ws_frame_matching(&mut ws, Duration::from_millis(300), |v| {
            v["@type"] == "SyncWakeup"
        })
        .await?;

        let _ = ws.close(None).await;
        Ok::<_, BoxError>(())
    }
    .await;

    harness.shutdown().await;
    cleanup_drive_spaces(&owner, &[b_space]).await;
    cleanup_channels(&owner, &[b_ch]).await;
    cleanup_user_refs(&owner, &[a.user, b.user]).await;
    cleanup_account_safe(&owner, &b).await?;
    cleanup_account_safe(&owner, &a).await?;
    result
}

#[tokio::test]
async fn calendar_delegate_data_type_filtering() -> Result<(), BoxError> {
    let _serial = SERIAL.lock().await;
    let Some(db) = Db::for_case("sync-wakeup-calendar-filter") else {
        return Ok(());
    };
    let owner = db.connect().await?;
    let host = fixture::account(&owner, "sw-cal-host").await?;
    let viewer = fixture::account(&owner, "sw-cal-viewer").await?;

    let cal_id: i64 = owner
        .query_one(
            "INSERT INTO calendars (mailbox_id, name, color) VALUES ($1, 'SW Cal', '#112233') RETURNING id",
            &[&host.mailbox],
        )
        .await?
        .get(0);
    let viewer_email: String = owner
        .query_one("SELECT email FROM users WHERE id = $1", &[&viewer.user])
        .await?
        .get(0);
    owner
        .execute(
            "SELECT jmap_calendar_share_set($1, $2, jsonb_build_array(jsonb_build_object('userEmail', $3::text, 'level', 'read')), '[]'::jsonb)",
            &[&host.mailbox, &cal_id, &viewer_email],
        )
        .await?;

    let harness = GatewayHarness::start(&db).await?;
    let result = async {
        let mut ws = connect_ws(harness.addr, viewer.user).await?;
        let att = send_attach(
            &mut ws,
            "cal-att",
            json!([{"scopeKind": "mailbox", "scopeId": host.mailbox.to_string()}]),
        )
        .await?;
        assert_eq!(att["attached"].as_array().map(Vec::len), Some(1));

        // Fire Email change on host mailbox -> calendar-only delegate must NEVER receive Email/Mailbox wakeup!
        owner
            .execute(
                "SELECT notify_state_change($1, NULL::bigint)",
                &[&host.mailbox],
            )
            .await?;
        assert_no_ws_frame_matching(&mut ws, Duration::from_millis(300), |v| {
            v["@type"] == "SyncWakeup"
                && v["event"]["dataTypes"]
                    .as_array()
                    .is_some_and(|dts| dts.iter().any(|d| d == "Email" || d == "Mailbox"))
        })
        .await?;

        // Fire Calendar change -> calendar-only delegate MUST receive ONLY Calendar wakeup!
        owner
            .execute(
                "SELECT notify_calendar_state($1, 0::bigint, $2, 'updated')",
                &[&host.mailbox, &cal_id],
            )
            .await?;
        let wakeup = next_ws_matching(&mut ws, Duration::from_secs(5), |v| {
            v["@type"] == "SyncWakeup"
        })
        .await?;
        assert_eq!(wakeup["event"]["scopeKind"], "mailbox");
        assert_eq!(wakeup["event"]["scopeId"], host.mailbox.to_string());
        let dts = wakeup["event"]["dataTypes"]
            .as_array()
            .ok_or("missing dataTypes")?;
        assert!(dts.iter().any(|d| d == "Calendar"));
        assert!(!dts.iter().any(|d| d == "Email" || d == "Mailbox"));

        let _ = ws.close(None).await;
        Ok::<_, BoxError>(())
    }
    .await;

    harness.shutdown().await;
    cleanup_user_refs(&owner, &[host.user, viewer.user]).await;
    cleanup_account_safe(&owner, &viewer).await?;
    cleanup_account_safe(&owner, &host).await?;
    result
}

#[tokio::test]
async fn live_revocation_across_all_surfaces() -> Result<(), BoxError> {
    let _serial = SERIAL.lock().await;
    let Some(db) = Db::for_case("sync-wakeup-live-revocations") else {
        return Ok(());
    };
    let owner = db.connect().await?;
    let admin = fixture::account(&owner, "sw-rev-admin").await?;
    let host = fixture::account(&owner, "sw-rev-host").await?;
    let target = fixture::account(&owner, "sw-rev-target").await?;
    let lc_target = fixture::account(&owner, "sw-rev-lc").await?;

    let saved_chat_toggle = enable_toggle(&owner, "feature.chat").await?;
    let saved_lc_toggle = enable_toggle(&owner, "feature.mailbox_lifecycle_retention").await?;
    owner
        .execute(
            "INSERT INTO admin_role_assignments (user_id, role_group_id, granted_by) \
             VALUES ($1, 1, $1) ON CONFLICT DO NOTHING",
            &[&admin.user],
        )
        .await?;

    // 1. Mailbox delegate
    owner
        .execute(
            "INSERT INTO mailbox_delegates (mailbox_id, user_id, permission, granted_by) \
             VALUES ($1, $2, 'full_access', $3)",
            &[&host.mailbox, &target.user, &host.user],
        )
        .await?;

    // 2. Drive space + direct member
    let space_id: i64 = owner
        .query_one(
            "SELECT drive_space_create($1, 'sw-rev-space', 'regular')",
            &[&host.user],
        )
        .await?
        .get(0);
    owner
        .execute(
            "SELECT drive_member_grant($1, $2, $3, 'editor')",
            &[&host.user, &space_id, &target.user],
        )
        .await?;

    // 3. Chat channel + bound Drive space
    let ch_id: i64 = owner
        .query_one(
            "SELECT chat_channel_create($1, 'sw-rev-chan')",
            &[&host.user],
        )
        .await?
        .get(0);
    owner
        .execute(
            "SELECT chat_member_add($1, $2, $3)",
            &[&host.user, &ch_id, &target.user],
        )
        .await?;
    let bound_space: i64 = owner
        .query_one("SELECT chat_space_ensure($1, $2)", &[&host.user, &ch_id])
        .await?
        .get(0);

    // 4. Meeting with provisioned chat channel + bound Drive space
    let m_raw: String = owner
        .query_one(
            "SELECT meeting_create($1, 'SW Rev Meeting')::text",
            &[&host.user],
        )
        .await?
        .get(0);
    let m_json: Value = serde_json::from_str(&m_raw)?;
    let meeting_id: i64 = m_json["meetingId"]
        .as_i64()
        .or_else(|| m_json["meetingId"].as_str().and_then(|s| s.parse().ok()))
        .ok_or("meetingId missing")?;
    let meet_ch: i64 = m_json["chatChannelId"]
        .as_i64()
        .or_else(|| {
            m_json["chatChannelId"]
                .as_str()
                .and_then(|s| s.parse().ok())
        })
        .ok_or("chatChannelId missing")?;
    let meet_space: i64 = owner
        .query_one("SELECT chat_space_ensure($1, $2)", &[&host.user, &meet_ch])
        .await?
        .get(0);
    owner
        .execute("SELECT meeting_join($1, $2)", &[&target.user, &meeting_id])
        .await?;

    // 5. Calendar share on host's calendar (separate mailbox for clean test: admin.mailbox)
    let cal_id: i64 = owner
        .query_one(
            "INSERT INTO calendars (mailbox_id, name, color) VALUES ($1, 'SW Rev Cal', '#445566') RETURNING id",
            &[&admin.mailbox],
        )
        .await?
        .get(0);
    let target_email: String = owner
        .query_one("SELECT email FROM users WHERE id = $1", &[&target.user])
        .await?
        .get(0);
    owner
        .execute(
            "SELECT jmap_calendar_share_set($1, $2, jsonb_build_array(jsonb_build_object('userEmail', $3::text, 'level', 'read')), '[]'::jsonb)",
            &[&admin.mailbox, &cal_id, &target_email],
        )
        .await?;

    let harness = GatewayHarness::start(&db).await?;
    let result = async {
        let mut ws = connect_ws(harness.addr, target.user).await?;
        let att = send_attach(
            &mut ws,
            "rev-att",
            json!([
                {"scopeKind": "mailbox", "scopeId": host.mailbox.to_string()},
                {"scopeKind": "mailbox", "scopeId": admin.mailbox.to_string()},
                {"scopeKind": "space", "scopeId": space_id.to_string()},
                {"scopeKind": "channel", "scopeId": ch_id.to_string()},
                {"scopeKind": "space", "scopeId": bound_space.to_string()},
                {"scopeKind": "channel", "scopeId": meet_ch.to_string()},
                {"scopeKind": "space", "scopeId": meet_space.to_string()},
            ]),
        )
        .await?;
        assert_eq!(
            att["attached"].as_array().map(Vec::len),
            Some(7),
            "all 7 scopes should attach: {att}"
        );

        // (a) mailbox_delegate_revoke -> single ScopeRevoked frame
        owner
            .execute(
                "SELECT mailbox_delegate_revoke($1, $2, $3)",
                &[&host.user, &host.mailbox, &target.user],
            )
            .await?;
        let rev = next_ws_matching(&mut ws, Duration::from_secs(5), |v| {
            v["@type"] == "ScopeRevoked"
                && v["event"]["scopeKind"] == "mailbox"
                && v["event"]["scopeId"] == host.mailbox.to_string()
        })
        .await?;
        assert_eq!(rev["event"]["scopeId"], host.mailbox.to_string());
        // Subsequent wakeup on revoked mailbox must be dropped.
        owner
            .execute(
                "SELECT notify_state_change($1, NULL::bigint)",
                &[&host.mailbox],
            )
            .await?;
        assert_no_ws_frame_matching(&mut ws, Duration::from_millis(250), |v| {
            v["@type"] == "SyncWakeup"
                && v["event"]["scopeKind"] == "mailbox"
                && v["event"]["scopeId"] == host.mailbox.to_string()
        })
        .await?;

        // (b) jmap_calendar_share_set downgrade read -> freebusy -> ScopeRevoked!
        owner
            .execute(
                "SELECT jmap_calendar_share_set($1, $2, jsonb_build_array(jsonb_build_object('userEmail', $3::text, 'level', 'freebusy')), '[]'::jsonb)",
                &[&admin.mailbox, &cal_id, &target_email],
            )
            .await?;
        let _ = next_ws_matching(&mut ws, Duration::from_secs(5), |v| {
            v["@type"] == "ScopeRevoked"
                && v["event"]["scopeKind"] == "mailbox"
                && v["event"]["scopeId"] == admin.mailbox.to_string()
        })
        .await?;

        // (c) drive_member_revoke -> ScopeRevoked!
        owner
            .execute(
                "SELECT drive_member_revoke($1, $2, $3)",
                &[&host.user, &space_id, &target.user],
            )
            .await?;
        let _ = next_ws_matching(&mut ws, Duration::from_secs(5), |v| {
            v["@type"] == "ScopeRevoked"
                && v["event"]["scopeKind"] == "space"
                && v["event"]["scopeId"] == space_id.to_string()
        })
        .await?;

        // (d) chat_member_remove -> revokes BOTH channel AND bound Drive space!
        owner
            .execute(
                "SELECT chat_member_remove($1, $2, $3)",
                &[&host.user, &ch_id, &target.user],
            )
            .await?;
        let mut saw_ch = false;
        let mut saw_bound = false;
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        while !(saw_ch && saw_bound) {
            let rem = deadline.saturating_duration_since(tokio::time::Instant::now());
            let f = next_ws_json(&mut ws, rem).await?;
            if f["@type"] == "ScopeRevoked" {
                if f["event"]["scopeKind"] == "channel"
                    && f["event"]["scopeId"] == ch_id.to_string()
                {
                    saw_ch = true;
                }
                if f["event"]["scopeKind"] == "space"
                    && f["event"]["scopeId"] == bound_space.to_string()
                {
                    saw_bound = true;
                }
            }
        }

        // (e) meeting_kick -> revokes provisioned chat channel AND bound Drive space!
        owner
            .execute(
                "SELECT meeting_kick($1, $2, $3)",
                &[&host.user, &meeting_id, &format!("u:{}", target.user)],
            )
            .await?;
        let mut saw_mch = false;
        let mut saw_msp = false;
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        while !(saw_mch && saw_msp) {
            let rem = deadline.saturating_duration_since(tokio::time::Instant::now());
            let f = next_ws_json(&mut ws, rem).await?;
            if f["@type"] == "ScopeRevoked" {
                if f["event"]["scopeKind"] == "channel"
                    && f["event"]["scopeId"] == meet_ch.to_string()
                {
                    saw_mch = true;
                }
                if f["event"]["scopeKind"] == "space"
                    && f["event"]["scopeId"] == meet_space.to_string()
                {
                    saw_msp = true;
                }
            }
        }

        // (f) mailbox_lifecycle_transition('suspend') WITH effects worker paused ->
        //     immediate scope-wide (user_id IS NULL) ScopeRevoked on lc_target's "primary" alias!
        let mut lc_ws = connect_ws(harness.addr, lc_target.user).await?;
        let lc_att = send_attach(
            &mut lc_ws,
            "lc-att",
            json!([{"scopeKind": "mailbox", "scopeId": "primary"}]),
        )
        .await?;
        assert_eq!(lc_att["attached"].as_array().map(Vec::len), Some(1));
        let lc_gen: i64 = owner
            .query_one(
                "SELECT (mailbox_lifecycle_read($1) ->> 'generation')::bigint",
                &[&lc_target.mailbox],
            )
            .await?
            .get(0);
        owner
            .execute(
                "SELECT mailbox_lifecycle_transition($1, $2, gen_random_uuid(), 'suspend', $3, repeat('a', 64), 'live detach test')",
                &[&admin.user, &lc_target.mailbox, &lc_gen],
            )
            .await?;
        let lc_rev = next_ws_matching(&mut lc_ws, Duration::from_secs(5), |v| {
            v["@type"] == "ScopeRevoked"
                && v["event"]["scopeKind"] == "mailbox"
                && v["event"]["scopeId"] == "primary"
        })
        .await?;
        assert_eq!(lc_rev["event"]["scopeId"], "primary");

        // (g) group_membership_changed triggers immediate re-verification & detach
        //     for a Drive space granted through directory group membership.
        let grp_space: i64 = owner
            .query_one(
                "SELECT drive_space_create($1, 'sw-grp-space', 'regular')",
                &[&host.user],
            )
            .await?
            .get(0);
        owner
            .execute("SELECT drive_member_grant($1, $2, $3, 'viewer')", &[&host.user, &grp_space, &target.user])
            .await?;
        let g_att = send_attach(
            &mut ws,
            "grp-att",
            json!([{"scopeKind": "space", "scopeId": grp_space.to_string()}]),
        )
        .await?;
        assert_eq!(g_att["attached"].as_array().map(Vec::len), Some(1));
        // Remove membership silently (simulating group-derived revocation) and fire group_membership_changed.
        owner
            .execute(
                "DELETE FROM drive_space_members WHERE space_id = $1 AND user_id = $2",
                &[&grp_space, &target.user],
            )
            .await?;
        owner
            .execute(
                "SELECT pg_notify('group_membership_changed', json_build_object('user_id', $1::bigint)::text)",
                &[&target.user],
            )
            .await?;
        let _ = next_ws_matching(&mut ws, Duration::from_secs(5), |v| {
            v["@type"] == "ScopeRevoked"
                && v["event"]["scopeKind"] == "space"
                && v["event"]["scopeId"] == grp_space.to_string()
        })
        .await?;

        cleanup_drive_spaces(&owner, &[grp_space]).await;
        let _ = lc_ws.close(None).await;
        let _ = ws.close(None).await;
        Ok::<_, BoxError>(())
    }
    .await;

    harness.shutdown().await;
    restore_toggle(
        &owner,
        "feature.mailbox_lifecycle_retention",
        saved_lc_toggle,
    )
    .await;
    restore_toggle(&owner, "feature.chat", saved_chat_toggle).await;
    cleanup_drive_spaces(&owner, &[space_id, bound_space, meet_space]).await;
    let _ = owner
        .execute("DELETE FROM meetings WHERE id = $1", &[&meeting_id])
        .await;
    cleanup_channels(&owner, &[ch_id, meet_ch]).await;
    cleanup_user_refs(
        &owner,
        &[admin.user, host.user, target.user, lc_target.user],
    )
    .await;
    cleanup_account_safe(&owner, &lc_target).await?;
    cleanup_account_safe(&owner, &target).await?;
    cleanup_account_safe(&owner, &host).await?;
    cleanup_account_safe(&owner, &admin).await?;
    result
}

#[tokio::test]
async fn regrant_race_does_not_detach_regranted_scope() -> Result<(), BoxError> {
    let _serial = SERIAL.lock().await;
    let Some(db) = Db::for_case("sync-wakeup-regrant-race") else {
        return Ok(());
    };
    let owner = db.connect().await?;
    let saved_chat_toggle = enable_toggle(&owner, "feature.chat").await?;
    let host = fixture::account(&owner, "sw-rg-host").await?;
    let member = fixture::account(&owner, "sw-rg-mem").await?;

    let ch_id: i64 = owner
        .query_one(
            "SELECT chat_channel_create($1, 'sw-rg-chan')",
            &[&host.user],
        )
        .await?
        .get(0);
    owner
        .execute(
            "SELECT chat_member_add($1, $2, $3)",
            &[&host.user, &ch_id, &member.user],
        )
        .await?;

    // Pause drain while we perform revoke + immediate re-grant, then replay the stale revocation ID!
    let harness = GatewayHarness::start(&db).await?;
    let result = async {
        let mut ws = connect_ws(harness.addr, member.user).await?;
        let att = send_attach(
            &mut ws,
            "rg-att",
            json!([{"scopeKind": "channel", "scopeId": ch_id.to_string()}]),
        )
        .await?;
        assert_eq!(att["attached"].as_array().map(Vec::len), Some(1));

        // Insert a stale scope_revocations row directly while membership is LIVE (simulates
        // a delayed scope_revoked notification arriving AFTER a rapid revoke + re-grant).
        let stale_rev_id: i64 = owner
            .query_one(
                "INSERT INTO public.scope_revocations (user_id, scope_kind, scope_id, reason) \
                 VALUES ($1, 'channel', $2, 'stale_before_regrant') RETURNING id",
                &[&member.user, &ch_id],
            )
            .await?
            .get(0);
        owner
            .execute(
                "SELECT pg_notify('scope_revoked', $1)",
                &[&stale_rev_id.to_string()],
            )
            .await?;

        // Hub re-verifies live membership -> must NOT detach!
        assert_no_ws_frame_matching(&mut ws, Duration::from_millis(300), |v| {
            v["@type"] == "ScopeRevoked"
        })
        .await?;

        // Subsequent wakeup on the still-attached channel MUST still be delivered!
        owner
            .execute(
                "SELECT chat_message_send($1, $2, 'still attached')",
                &[&host.user, &ch_id],
            )
            .await?;
        let wakeup = next_ws_matching(&mut ws, Duration::from_secs(5), |v| {
            v["@type"] == "SyncWakeup" && v["event"]["scopeId"] == ch_id.to_string()
        })
        .await?;
        assert!(wakeup["event"]["seq"].as_i64().unwrap_or(0) > 0);

        let _ = ws.close(None).await;
        Ok::<_, BoxError>(())
    }
    .await;

    harness.shutdown().await;
    restore_toggle(&owner, "feature.chat", saved_chat_toggle).await;
    cleanup_channels(&owner, &[ch_id]).await;
    cleanup_user_refs(&owner, &[host.user, member.user]).await;
    cleanup_account_safe(&owner, &member).await?;
    cleanup_account_safe(&owner, &host).await?;
    result
}

#[tokio::test]
async fn drive_subtree_acl_revoke_vs_tree_move() -> Result<(), BoxError> {
    let _serial = SERIAL.lock().await;
    let Some(db) = Db::for_case("sync-wakeup-drive-subtree") else {
        return Ok(());
    };
    let owner = db.connect().await?;
    let host = fixture::account(&owner, "sw-sub-host").await?;
    let member = fixture::account(&owner, "sw-sub-mem").await?;

    let space_id: i64 = owner
        .query_one(
            "SELECT drive_space_create($1, 'sw-sub-space', 'regular')",
            &[&host.user],
        )
        .await?
        .get(0);
    owner
        .execute(
            "SELECT drive_member_grant($1, $2, $3, 'editor')",
            &[&host.user, &space_id, &member.user],
        )
        .await?;
    let folder_a: i64 = owner
        .query_one(
            "SELECT drive_node_create($1, $2, NULL, 'folder', 'folder-a')",
            &[&host.user, &space_id],
        )
        .await?
        .get(0);

    let harness = GatewayHarness::start(&db).await?;
    let result = async {
        let mut ws = connect_ws(harness.addr, member.user).await?;
        let att = send_attach(
            &mut ws,
            "sub-att",
            json!([{"scopeKind": "space", "scopeId": space_id.to_string()}]),
        )
        .await?;
        assert_eq!(att["attached"].as_array().map(Vec::len), Some(1));

        // 1. tree_move invalidation on drive_access must NOT detach or emit ScopeRevoked!
        let move_cursor: i64 = owner
            .query_one(
                "INSERT INTO public.drive_access_invalidations \
                 (space_id, principal_kind, principal_id, anchor_node_id, resulting_epoch, reason) \
                 VALUES ($1, 'user', $2, $3, 1, 'tree_move') RETURNING cursor",
                &[&space_id, &member.user, &folder_a],
            )
            .await?
            .get(0);
        owner
            .execute(
                "SELECT pg_notify('drive_access', json_build_object('cursor', $1::bigint, 'space_id', $2::bigint, 'reason', 'tree_move')::text)",
                &[&move_cursor, &space_id],
            )
            .await?;
        assert_no_ws_frame_matching(&mut ws, Duration::from_millis(300), |v| {
            v["@type"] == "ScopeRevoked"
        })
        .await?;

        // 2. Subtree ACL revoke while member still has space access -> emits ScopeRevoked
        //    with string subtreeAnchorId AND keeps the space attached for future wakeups!
        let rev_cursor: i64 = owner
            .query_one(
                "INSERT INTO public.drive_access_invalidations \
                 (space_id, principal_kind, principal_id, anchor_node_id, resulting_epoch, reason) \
                 VALUES ($1, 'user', $2, $3, 2, 'revoke') RETURNING cursor",
                &[&space_id, &member.user, &folder_a],
            )
            .await?
            .get(0);
        owner
            .execute(
                "SELECT pg_notify('drive_access', json_build_object('cursor', $1::bigint, 'space_id', $2::bigint, 'reason', 'revoke')::text)",
                &[&rev_cursor, &space_id],
            )
            .await?;
        let sub_rev = next_ws_matching(&mut ws, Duration::from_secs(5), |v| {
            v["@type"] == "ScopeRevoked"
                && v["event"]["scopeKind"] == "space"
                && v["event"]["scopeId"] == space_id.to_string()
        })
        .await?;
        assert_eq!(
            sub_rev["event"]["subtreeAnchorId"],
            folder_a.to_string(),
            "subtreeAnchorId must be emitted as JSON string: {sub_rev}"
        );

        // Space MUST still be attached -> subsequent space wakeup still arrives!
        owner
            .execute("SELECT drive_notify_change($1, 0, 'member')", &[&space_id])
            .await?;
        let wakeup = next_ws_matching(&mut ws, Duration::from_secs(5), |v| {
            v["@type"] == "SyncWakeup"
                && v["event"]["scopeKind"] == "space"
                && v["event"]["scopeId"] == space_id.to_string()
        })
        .await?;
        assert_eq!(wakeup["event"]["scopeId"], space_id.to_string());

        let _ = ws.close(None).await;
        Ok::<_, BoxError>(())
    }
    .await;

    harness.shutdown().await;
    cleanup_drive_spaces(&owner, &[space_id]).await;
    cleanup_user_refs(&owner, &[host.user, member.user]).await;
    cleanup_account_safe(&owner, &member).await?;
    cleanup_account_safe(&owner, &host).await?;
    result
}

#[tokio::test]
async fn revocation_burst_and_resync_required_recovers_all() -> Result<(), BoxError> {
    let _serial = SERIAL.lock().await;
    let Some(db) = Db::for_case("sync-wakeup-burst-resync") else {
        return Ok(());
    };
    let owner = db.connect().await?;
    let saved_chat_toggle = enable_toggle(&owner, "feature.chat").await?;
    let host = fixture::account(&owner, "sw-burst-host").await?;
    let member = fixture::account(&owner, "sw-burst-mem").await?;

    let mut ch_ids = Vec::new();
    for i in 0..5 {
        let cid: i64 = owner
            .query_one(
                "SELECT chat_channel_create($1, $2)",
                &[&host.user, &format!("sw-burst-ch-{i}")],
            )
            .await?
            .get(0);
        owner
            .execute(
                "SELECT chat_member_add($1, $2, $3)",
                &[&host.user, &cid, &member.user],
            )
            .await?;
        ch_ids.push(cid);
    }

    // Also create a Drive space + folder where member retains space access,
    // so we prove ResyncRequired replays drive_access_invalidations subtree
    // revocations even when live space access is still held!
    let resync_space: i64 = owner
        .query_one(
            "SELECT drive_space_create($1, 'sw-burst-sub-space', 'regular')",
            &[&host.user],
        )
        .await?
        .get(0);
    owner
        .execute(
            "SELECT drive_member_grant($1, $2, $3, 'editor')",
            &[&host.user, &resync_space, &member.user],
        )
        .await?;
    let resync_folder: i64 = owner
        .query_one(
            "SELECT drive_node_create($1, $2, NULL, 'folder', 'resync-sub-folder')",
            &[&host.user, &resync_space],
        )
        .await?
        .get(0);

    let harness = GatewayHarness::start(&db).await?;
    let result = async {
        let mut ws = connect_ws(harness.addr, member.user).await?;
        let mut scopes: Vec<Value> = ch_ids
            .iter()
            .map(|id| json!({"scopeKind": "channel", "scopeId": id.to_string()}))
            .collect();
        scopes.push(json!({"scopeKind": "space", "scopeId": resync_space.to_string()}));
        let att = send_attach(&mut ws, "burst-att", Value::Array(scopes)).await?;
        assert_eq!(att["attached"].as_array().map(Vec::len), Some(6));

        // Insert 1,000 unrelated noise revocation rows + real removals for all 5 channels
        // + a revoking drive_access_invalidations subtree row (NO pg_notify!), then
        // trigger ListenHub ResyncRequired recovery!
        owner
            .execute(
                "INSERT INTO public.scope_revocations (user_id, scope_kind, scope_id, reason) \
                 SELECT $1, 'channel', 800000000 + g, 'burst_noise' \
                   FROM generate_series(1, 1000) g",
                &[&host.user],
            )
            .await?;
        for &cid in &ch_ids {
            owner
                .execute(
                    "DELETE FROM chat_channel_members WHERE channel_id = $1 AND user_id = $2",
                    &[&cid, &member.user],
                )
                .await?;
            owner
                .execute(
                    "INSERT INTO public.scope_revocations (user_id, scope_kind, scope_id, reason) \
                     VALUES ($1, 'channel', $2, 'burst_revoked')",
                    &[&member.user, &cid],
                )
                .await?;
        }
        owner
            .execute(
                "INSERT INTO public.drive_access_invalidations \
                 (space_id, principal_kind, principal_id, anchor_node_id, resulting_epoch, reason) \
                 VALUES ($1, 'user', $2, $3, 3, 'revoke')",
                &[&resync_space, &member.user, &resync_folder],
            )
            .await?;

        // Trigger ResyncRequired recovery (replays >1,000 scope_revocations + drive subtree invalidations).
        harness.hub.handle_revocation_resync().await;

        let mut detached_set = std::collections::HashSet::new();
        let mut saw_subtree_revoked = false;
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        while detached_set.len() < ch_ids.len() || !saw_subtree_revoked {
            let rem = deadline.saturating_duration_since(tokio::time::Instant::now());
            let f = next_ws_json(&mut ws, rem).await?;
            if f["@type"] == "ScopeRevoked" && f["event"]["scopeKind"] == "channel" {
                if let Some(sid) = f["event"]["scopeId"].as_str() {
                    detached_set.insert(sid.to_owned());
                }
            }
            if f["@type"] == "ScopeRevoked"
                && f["event"]["scopeKind"] == "space"
                && f["event"]["scopeId"] == resync_space.to_string()
                && f["event"]["subtreeAnchorId"] == resync_folder.to_string()
            {
                saw_subtree_revoked = true;
            }
        }
        for &cid in &ch_ids {
            assert!(
                detached_set.contains(&cid.to_string()),
                "channel {cid} missed during 1,000-row burst resync"
            );
        }
        assert!(
            saw_subtree_revoked,
            "drive subtree revocation missed during ResyncRequired replay"
        );

        let _ = ws.close(None).await;
        Ok::<_, BoxError>(())
    }
    .await;

    harness.shutdown().await;
    restore_toggle(&owner, "feature.chat", saved_chat_toggle).await;
    cleanup_drive_spaces(&owner, &[resync_space]).await;
    cleanup_channels(&owner, &ch_ids).await;
    let _ = owner
        .execute(
            "DELETE FROM public.scope_revocations WHERE reason IN ('burst_noise', 'burst_revoked')",
            &[],
        )
        .await;
    cleanup_user_refs(&owner, &[host.user, member.user]).await;
    cleanup_account_safe(&owner, &member).await?;
    cleanup_account_safe(&owner, &host).await?;
    result
}

#[tokio::test]
async fn two_replica_ha_fanout_over_pg_listen() -> Result<(), BoxError> {
    let _serial = SERIAL.lock().await;
    let Some(db) = Db::for_case("sync-wakeup-two-replica-ha") else {
        return Ok(());
    };
    let owner = db.connect().await?;
    let saved_chat_toggle = enable_toggle(&owner, "feature.chat").await?;
    let host = fixture::account(&owner, "sw-ha-host").await?;
    let member = fixture::account(&owner, "sw-ha-mem").await?;

    let ch_id: i64 = owner
        .query_one(
            "SELECT chat_channel_create($1, 'sw-ha-chan')",
            &[&host.user],
        )
        .await?
        .get(0);
    owner
        .execute(
            "SELECT chat_member_add($1, $2, $3)",
            &[&host.user, &ch_id, &member.user],
        )
        .await?;

    let app_dsn = db.app.as_deref().unwrap_or(&db.dsn);
    let hub_a = SyncWakeupHub::from_direct_dsn(
        &db.direct,
        common::patient_exec(app_dsn, 4)?,
        common::patient_exec(&db.dsn, 4)?,
    )
    .ok_or("hub_a failed")?;
    let hub_b = SyncWakeupHub::from_direct_dsn(
        &db.direct,
        common::patient_exec(app_dsn, 4)?,
        common::patient_exec(&db.dsn, 4)?,
    )
    .ok_or("hub_b failed")?;
    assert!(hub_a.wait_ready(Duration::from_secs(5)).await);
    assert!(hub_b.wait_ready(Duration::from_secs(5)).await);

    let drain = DrainGuard::start(&db.dsn)?;
    let noop_restart: Arc<dyn Fn(&'static str) + Send + Sync> = Arc::new(|_| {});

    let result = async {
        let mut conn_a = hub_a.register_connection(
            member.user,
            Some(member.mailbox),
            false,
            noop_restart.clone(),
        );
        let mut conn_b =
            hub_b.register_connection(member.user, Some(member.mailbox), false, noop_restart);
        let desc = [ScopeDescriptor {
            kind: ScopeKind::Channel,
            raw_id: ch_id.to_string(),
        }];
        assert_eq!(conn_a.attach_scopes(&desc).await.attached.len(), 1);
        assert_eq!(conn_b.attach_scopes(&desc).await.attached.len(), 1);

        // Single DB write fans out SyncWakeup to BOTH independent replicas!
        owner
            .execute(
                "SELECT chat_message_send($1, $2, 'ha hello')",
                &[&host.user, &ch_id],
            )
            .await?;
        let wa = tokio::time::timeout(Duration::from_secs(5), conn_a.wakeups.next_batch())
            .await
            .map_err(|_| "replica A missed SyncWakeup")?;
        let wb = tokio::time::timeout(Duration::from_secs(5), conn_b.wakeups.next_batch())
            .await
            .map_err(|_| "replica B missed SyncWakeup")?;
        assert_eq!(wa[0].scope_id, ch_id.to_string());
        assert_eq!(wb[0].scope_id, ch_id.to_string());

        // Single revocation fans out ScopeRevoked to BOTH replicas!
        owner
            .execute(
                "SELECT chat_member_remove($1, $2, $3)",
                &[&host.user, &ch_id, &member.user],
            )
            .await?;
        let ca = tokio::time::timeout(Duration::from_secs(5), conn_a.control_rx.recv())
            .await
            .map_err(|_| "replica A missed ScopeRevoked")?
            .ok_or("replica A control_rx closed")?;
        let cb = tokio::time::timeout(Duration::from_secs(5), conn_b.control_rx.recv())
            .await
            .map_err(|_| "replica B missed ScopeRevoked")?
            .ok_or("replica B control_rx closed")?;
        assert!(
            matches!(ca, ControlMessage::ScopeRevoked(ref e) if e.scope_id == ch_id.to_string())
        );
        assert!(
            matches!(cb, ControlMessage::ScopeRevoked(ref e) if e.scope_id == ch_id.to_string())
        );

        Ok::<_, BoxError>(())
    }
    .await;

    hub_a.shutdown();
    hub_b.shutdown();
    drain.stop().await;
    restore_toggle(&owner, "feature.chat", saved_chat_toggle).await;
    cleanup_channels(&owner, &[ch_id]).await;
    cleanup_user_refs(&owner, &[host.user, member.user]).await;
    cleanup_account_safe(&owner, &member).await?;
    cleanup_account_safe(&owner, &host).await?;
    result
}

#[tokio::test]
async fn guest_sse_auto_attach_wakeup_and_priority_revoke() -> Result<(), BoxError> {
    let _serial = SERIAL.lock().await;
    let Some(db) = Db::for_case("sync-wakeup-guest-sse") else {
        return Ok(());
    };
    let owner = db.connect().await?;
    let host_admin = fixture::account(&owner, "sw-gsse-admin").await?;

    let saved_chat_toggle = enable_toggle(&owner, "feature.chat").await?;
    let saved_guest_toggle = enable_toggle(&owner, "feature.guest_accounts").await?;

    let host_domain_id: i64 = owner
        .query_one(
            "SELECT domain_id FROM users WHERE id = $1",
            &[&host_admin.user],
        )
        .await?
        .get(0);
    let guest_domain_id: i64 = owner
        .query_one("SELECT id FROM domains WHERE name = 'guest.invalid'", &[])
        .await?
        .get(0);
    let suffix = host_admin.user;
    let guest_email = format!("sw-guest-{suffix}@ext.example");
    let guest_user_id: i64 = owner
        .query_one(
            "INSERT INTO users (username, domain_id, email, display_name, enabled) \
             VALUES ($1, $2, $1, 'SW Guest', TRUE) RETURNING id",
            &[&guest_email, &guest_domain_id],
        )
        .await?
        .get(0);
    owner
        .execute(
            "INSERT INTO admin_role_assignments (user_id, role_group_id, granted_by) \
             VALUES ($1, 1, $1) ON CONFLICT DO NOTHING",
            &[&host_admin.user],
        )
        .await?;
    let host_email: String = owner
        .query_one("SELECT email FROM users WHERE id = $1", &[&host_admin.user])
        .await?
        .get(0);
    owner
        .execute(
            "INSERT INTO guest_accounts \
             (user_id, invited_email, invited_by, invited_by_email, sponsor_user_id, host_domain_id, status, expires_at) \
             VALUES ($1, $2, $3, $4, $3, $5, 'active', now() + interval '1 day')",
            &[&guest_user_id, &guest_email, &host_admin.user, &host_email, &host_domain_id],
        )
        .await?;

    owner
        .execute(
            "INSERT INTO user_app_entitlements (user_id, app, enabled) \
             VALUES ($1, 'chat', TRUE), ($1, 'drive', TRUE) \
             ON CONFLICT (user_id, app) DO UPDATE SET enabled = TRUE",
            &[&guest_user_id],
        )
        .await?;

    let ch_id: i64 = owner
        .query_one(
            "SELECT chat_channel_create($1, 'sw-guest-ch')",
            &[&host_admin.user],
        )
        .await?
        .get(0);
    let ch2_id: i64 = owner
        .query_one(
            "SELECT chat_channel_create($1, 'sw-guest-ch-2')",
            &[&host_admin.user],
        )
        .await?
        .get(0);
    owner
        .execute(
            "INSERT INTO chat_channel_members (channel_id, user_id, role) \
             VALUES ($1, $2, 'member'), ($3, $2, 'member')",
            &[&ch_id, &guest_user_id, &ch2_id],
        )
        .await?;
    let bound_space: i64 = owner
        .query_one(
            "SELECT chat_space_ensure($1, $2)",
            &[&host_admin.user, &ch_id],
        )
        .await?
        .get(0);

    let harness = GatewayHarness::start(&db).await?;
    let result = async {
        let guest_token = common::recovery_token_with(guest_user_id, json!({"acct": "guest"}));
        let tcp = tokio::net::TcpStream::connect(harness.addr).await?;
        let io = hyper_util::rt::TokioIo::new(tcp);
        let (mut sender, conn) = hyper::client::conn::http1::handshake(io).await?;
        let conn_task = tokio::spawn(async move {
            let _ = conn.await;
        });

        let req = Request::builder()
            .method("GET")
            .uri("/jmap/eventsource?types=*&ping=0")
            .header("host", "mail.test")
            .header("authorization", format!("Bearer {guest_token}"))
            .body(common::full(""))?;
        let resp: Response<hyper::body::Incoming> = sender.send_request(req).await?;
        assert_eq!(resp.status(), 200);
        let mut body = resp.into_body();

        // Give SSE handler a moment to finish attach_guest_default_scopes().
        tokio::time::sleep(Duration::from_millis(200)).await;

        // Fire both a Chat message AND a Drive change on the bound space!
        owner
            .execute(
                "SELECT chat_message_send($1, $2, 'guest sse ping')",
                &[&host_admin.user, &ch_id],
            )
            .await?;
        owner
            .execute(
                "SELECT drive_notify_change($1, 0, 'member')",
                &[&bound_space],
            )
            .await?;

        let mut buf = String::new();
        let mut saw_ch_wakeup = false;
        let mut saw_sp_wakeup = false;
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        while !(saw_ch_wakeup && saw_sp_wakeup) {
            let rem = deadline.saturating_duration_since(tokio::time::Instant::now());
            let frame = tokio::time::timeout(rem, body.frame())
                .await
                .map_err(|_| format!("timed out waiting for guest SSE sync_wakeup; got:\n{buf}"))?
                .ok_or("guest SSE closed early")??;
            if let Ok(bytes) = frame.into_data() {
                buf.push_str(&String::from_utf8_lossy(&bytes));
                if buf.contains("event: sync_wakeup")
                    && buf.contains(&format!("\"scopeId\":\"{ch_id}\""))
                {
                    saw_ch_wakeup = true;
                }
                if buf.contains("event: sync_wakeup")
                    && buf.contains(&format!("\"scopeId\":\"{bound_space}\""))
                {
                    saw_sp_wakeup = true;
                }
            }
        }

        // 1. Remove guest from channel 1 -> must receive priority `event: scope_revoked`
        //    for both channel 1 and its bound Drive space while SSE stream remains open!
        //    Clear `buf` first so assertions only match frames emitted AFTER the remove.
        buf.clear();
        owner
            .execute(
                "SELECT chat_member_remove($1, $2, $3)",
                &[&host_admin.user, &ch_id, &guest_user_id],
            )
            .await?;

        let mut saw_ch_revoked = false;
        let mut saw_sp_revoked = false;
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        while !(saw_ch_revoked && saw_sp_revoked) {
            let rem = deadline.saturating_duration_since(tokio::time::Instant::now());
            match tokio::time::timeout(rem, body.frame()).await {
                Ok(Some(Ok(frame))) => {
                    if let Ok(bytes) = frame.into_data() {
                        buf.push_str(&String::from_utf8_lossy(&bytes));
                        for block in buf.split("\n\n") {
                            if block.contains("event: scope_revoked")
                                && block.contains(&format!("\"scopeId\":\"{ch_id}\""))
                                && block.contains("\"scopeKind\":\"channel\"")
                            {
                                saw_ch_revoked = true;
                            }
                            if block.contains("event: scope_revoked")
                                && block.contains(&format!("\"scopeId\":\"{bound_space}\""))
                                && block.contains("\"scopeKind\":\"space\"")
                            {
                                saw_sp_revoked = true;
                            }
                        }
                    }
                }
                Ok(None) => break,
                _ => break,
            }
        }
        assert!(
            saw_ch_revoked && saw_sp_revoked,
            "guest SSE must receive priority event: scope_revoked for channel + bound space; got:\n{buf}"
        );

        // 2. Disable the guest WHILE still an active member of channel 2 ->
        //    commits durable guest_disabled scope_revocations row AND closes SSE promptly!
        owner
            .execute(
                "SELECT guest_set_status($1, $2, 'disable', NULL)",
                &[&host_admin.user, &guest_user_id],
            )
            .await?;
        let rev_cnt: i64 = owner
            .query_one(
                "SELECT count(*) FROM public.scope_revocations \
                  WHERE user_id = $1 AND scope_kind = 'channel' \
                    AND scope_id = $2 AND reason = 'guest_disabled'",
                &[&guest_user_id, &ch2_id],
            )
            .await?
            .get(0);
        assert_eq!(
            rev_cnt, 1,
            "guest_set_status('disable') must commit scope_revocations for still-active channel 2"
        );
        let closed = tokio::time::timeout(Duration::from_secs(5), async {
            while let Some(Ok(_)) = body.frame().await {}
        })
        .await;
        assert!(
            closed.is_ok(),
            "guest SSE must close on guest_set_status('disable')"
        );

        conn_task.abort();
        Ok::<_, BoxError>(())
    }
    .await;

    harness.shutdown().await;
    restore_toggle(&owner, "feature.guest_accounts", saved_guest_toggle).await;
    restore_toggle(&owner, "feature.chat", saved_chat_toggle).await;
    cleanup_drive_spaces(&owner, &[bound_space]).await;
    cleanup_channels(&owner, &[ch_id, ch2_id]).await;
    cleanup_user_refs(&owner, &[host_admin.user, guest_user_id]).await;
    let _ = owner
        .execute(
            "DELETE FROM guest_accounts WHERE user_id = $1",
            &[&guest_user_id],
        )
        .await;
    let _ = owner
        .execute("DELETE FROM users WHERE id = $1", &[&guest_user_id])
        .await;
    cleanup_account_safe(&owner, &host_admin).await?;
    result
}

#[tokio::test]
async fn sync_hub_none_ws_and_sse_fallback_stay_open() -> Result<(), BoxError> {
    let _serial = SERIAL.lock().await;
    let Some(db) = Db::for_case("sync-wakeup-none-fallback") else {
        return Ok(());
    };
    let owner = db.connect().await?;
    let acc = fixture::account(&owner, "sw-none-fb").await?;

    let app_dsn = db.app.as_deref().unwrap_or(&db.dsn);
    let exec = common::patient_exec(app_dsn, 4)?;
    let worker = common::patient_exec(&db.dsn, 4)?;
    let commands = Arc::new(JmapCommands {
        services: None,
        worker: Some(worker),
        exec,
        keys: common::recovery_keys(),
        issuer: "mailserver".into(),
        denylist: None,
    });
    // Explicit without_sync_hub() -> sync_hub resolves to None while PushHub stays live (legacy fallback mode).
    let ws = WebSocketRoute::new(commands.clone(), db.direct.clone()).without_sync_hub();
    let sse = EventSourceRoute::new(&ws);
    let routes = RouteTable::proxy_all().with(ws).with(sse);
    let gateway = Gateway::new(
        Config {
            upstream: None,
            trusted_proxies: TrustedProxies::parse("")?,
            upstream_header_timeout: Duration::from_secs(30),
            edge_limit: None,
        },
        routes,
    )?;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let server = tokio::spawn(gateway.serve(listener));

    let result = async {
        // 1. WS must stay open and answer {"@type":"ready"} with unknownType instead of closing!
        let mut socket = connect_ws(addr, acc.user).await?;
        socket
            .send(Message::Text(r#"{"@type":"ready"}"#.into()))
            .await?;
        let reply = next_ws_json(&mut socket, Duration::from_secs(3)).await?;
        assert_eq!(reply["@type"], "error");
        assert_eq!(reply["type"], "urn:ietf:params:jmap:error:unknownType");
        let _ = socket.close(None).await;

        // 2. SSE must stay open past initial StateChange (never immediately close!).
        let token = common::recovery_token_with(acc.user, json!({}));
        let tcp = tokio::net::TcpStream::connect(addr).await?;
        let io = hyper_util::rt::TokioIo::new(tcp);
        let (mut sender, conn) = hyper::client::conn::http1::handshake(io).await?;
        let conn_task = tokio::spawn(async move {
            let _ = conn.await;
        });
        let req = Request::builder()
            .method("GET")
            .uri("/jmap/eventsource?types=*&ping=1")
            .header("host", "mail.test")
            .header("authorization", format!("Bearer {token}"))
            .body(common::full(""))?;
        let resp: Response<hyper::body::Incoming> = sender.send_request(req).await?;
        assert_eq!(resp.status(), 200);
        let mut body = resp.into_body();
        let mut buf = String::new();
        let deadline = tokio::time::Instant::now() + Duration::from_secs(4);
        while !buf.contains("event: ping") {
            let rem = deadline.saturating_duration_since(tokio::time::Instant::now());
            let frame = tokio::time::timeout(rem, body.frame())
                .await
                .map_err(|_| format!("SSE closed or missed ping under sync_hub=None; got:\n{buf}"))?
                .ok_or("SSE stream closed prematurely under sync_hub=None")??;
            if let Ok(bytes) = frame.into_data() {
                buf.push_str(&String::from_utf8_lossy(&bytes));
            }
        }
        assert!(buf.contains("event: state"));
        assert!(buf.contains("event: ping"));
        conn_task.abort();
        Ok::<_, BoxError>(())
    }
    .await;

    server.abort();
    let _ = server.await;
    cleanup_account_safe(&owner, &acc).await?;
    result
}

#[tokio::test]
async fn drive_member_revoke_with_secondary_access_succeeds_without_42501() -> Result<(), BoxError>
{
    let _serial = SERIAL.lock().await;
    let Some(db) = Db::for_case("sync-wakeup-drive-secondary-revoke") else {
        return Ok(());
    };
    let owner = db.connect().await?;
    let host = fixture::account(&owner, "sw-sec-host").await?;
    let admin = fixture::account(&owner, "sw-sec-admin").await?;
    owner
        .execute(
            "INSERT INTO admin_role_assignments (user_id, role_group_id, granted_by) \
             VALUES ($1, 1, $1) ON CONFLICT DO NOTHING",
            &[&admin.user],
        )
        .await?;
    let space_id: i64 = owner
        .query_one(
            "SELECT drive_space_create($1, 'sw-sec-space', 'regular')",
            &[&host.user],
        )
        .await?
        .get(0);
    owner
        .execute(
            "SELECT drive_member_grant($1, $2, $3, 'viewer')",
            &[&host.user, &space_id, &admin.user],
        )
        .await?;

    // Must succeed cleanly (no false 42501) even though admin retains drive.view access!
    let revoke_res = owner
        .execute(
            "SELECT drive_member_revoke($1, $2, $3)",
            &[&host.user, &space_id, &admin.user],
        )
        .await;

    cleanup_drive_spaces(&owner, &[space_id]).await;
    cleanup_user_refs(&owner, &[host.user, admin.user]).await;
    cleanup_account_safe(&owner, &admin).await?;
    cleanup_account_safe(&owner, &host).await?;
    revoke_res?;
    Ok(())
}

#[tokio::test]
async fn mailbox_narrowing_all_to_calendar_only_emits_scope_revoked() -> Result<(), BoxError> {
    let _serial = SERIAL.lock().await;
    let Some(db) = Db::for_case("sync-wakeup-mailbox-narrowing") else {
        return Ok(());
    };
    let owner = db.connect().await?;
    let host = fixture::account(&owner, "sw-nar-host").await?;
    let delegate = fixture::account(&owner, "sw-nar-del").await?;

    // Delegate holds BOTH full_access mailbox delegate AND calendar_acls('read').
    owner
        .execute(
            "INSERT INTO mailbox_delegates (mailbox_id, user_id, permission, granted_by) \
             VALUES ($1, $2, 'full_access', $3)",
            &[&host.mailbox, &delegate.user, &host.user],
        )
        .await?;
    let cal_id: i64 = owner
        .query_one(
            "INSERT INTO calendars (mailbox_id, name, color) VALUES ($1, 'Nar Cal', '#abcdef') RETURNING id",
            &[&host.mailbox],
        )
        .await?
        .get(0);
    let del_email: String = owner
        .query_one("SELECT email FROM users WHERE id = $1", &[&delegate.user])
        .await?
        .get(0);
    owner
        .execute(
            "SELECT jmap_calendar_share_set($1, $2, jsonb_build_array(jsonb_build_object('userEmail', $3::text, 'level', 'read')), '[]'::jsonb)",
            &[&host.mailbox, &cal_id, &del_email],
        )
        .await?;

    let harness = GatewayHarness::start(&db).await?;
    let result = async {
        let mut ws = connect_ws(harness.addr, delegate.user).await?;
        let att = send_attach(
            &mut ws,
            "nar-att",
            json!([{"scopeKind": "mailbox", "scopeId": host.mailbox.to_string()}]),
        )
        .await?;
        assert_eq!(att["attached"].as_array().map(Vec::len), Some(1));

        // Revoke mailbox_delegate while calendar_acls('read') remains -> privilege narrows
        // from All to CalendarOnly: MUST emit ScopeRevoked so client purges Email cache!
        owner
            .execute(
                "SELECT mailbox_delegate_revoke($1, $2, $3)",
                &[&host.user, &host.mailbox, &delegate.user],
            )
            .await?;
        let rev = next_ws_matching(&mut ws, Duration::from_secs(5), |v| {
            v["@type"] == "ScopeRevoked"
                && v["event"]["scopeKind"] == "mailbox"
                && v["event"]["scopeId"] == host.mailbox.to_string()
        })
        .await?;
        assert_eq!(rev["event"]["scopeId"], host.mailbox.to_string());

        // Subsequent Email wakeup must be suppressed, while Calendar wakeup STILL arrives!
        owner
            .execute(
                "SELECT notify_state_change($1, NULL::bigint)",
                &[&host.mailbox],
            )
            .await?;
        assert_no_ws_frame_matching(&mut ws, Duration::from_millis(250), |v| {
            v["@type"] == "SyncWakeup"
                && v["event"]["dataTypes"]
                    .as_array()
                    .is_some_and(|dts| dts.iter().any(|d| d == "Email" || d == "Mailbox"))
        })
        .await?;
        owner
            .execute(
                "SELECT notify_calendar_state($1, 0::bigint, $2, 'updated')",
                &[&host.mailbox, &cal_id],
            )
            .await?;
        let cal_w = next_ws_matching(&mut ws, Duration::from_secs(5), |v| {
            v["@type"] == "SyncWakeup" && v["event"]["scopeId"] == host.mailbox.to_string()
        })
        .await?;
        assert!(cal_w["event"]["dataTypes"]
            .as_array()
            .is_some_and(|dts| dts.iter().any(|d| d == "Calendar")));

        let _ = ws.close(None).await;
        Ok::<_, BoxError>(())
    }
    .await;

    harness.shutdown().await;
    cleanup_user_refs(&owner, &[host.user, delegate.user]).await;
    cleanup_account_safe(&owner, &delegate).await?;
    cleanup_account_safe(&owner, &host).await?;
    result
}

#[tokio::test]
async fn scope_attach_then_immediate_detach_never_resurrects_scope() -> Result<(), BoxError> {
    let _serial = SERIAL.lock().await;
    let Some(db) = Db::for_case("sync-wakeup-attach-detach-order") else {
        return Ok(());
    };
    let owner = db.connect().await?;
    let acc = fixture::account(&owner, "sw-ord").await?;
    let harness = GatewayHarness::start(&db).await?;

    let result = async {
        let noop: Arc<dyn Fn(&'static str) + Send + Sync> = Arc::new(|_| {});
        let conn = harness
            .hub
            .register_connection(acc.user, Some(acc.mailbox), false, noop);
        let desc = [ScopeDescriptor {
            kind: ScopeKind::Mailbox,
            raw_id: "primary".into(),
        }];

        // Capture attach op_seq BEFORE a synchronous detach arrives, then run
        // attach_scopes_with_seq afterwards (simulating an in-flight async attach
        // completing AFTER a client sent ScopeDetach).
        let attach_seq = harness.hub.begin_attach_op(conn.id);
        let _ = conn.detach_scopes(&desc);
        let res = harness
            .hub
            .attach_scopes_with_seq(conn.id, &desc, attach_seq)
            .await;
        assert!(
            res.attached.is_empty(),
            "in-flight ScopeAttach started before ScopeDetach must never resurrect the scope: {res:?}"
        );
        assert!(
            res.denied
                .iter()
                .any(|d| d.reason == "detached_during_attach"),
            "expected detached_during_attach denial: {res:?}"
        );
        assert!(
            harness.hub.attached_scopes_for(conn.id).is_empty(),
            "scope must remain detached in registry"
        );
        Ok::<_, BoxError>(())
    }
    .await;

    harness.shutdown().await;
    cleanup_account_safe(&owner, &acc).await?;
    result
}
