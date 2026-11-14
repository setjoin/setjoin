//! A cross-site safe-method request still passes the runtime gate (#413).
//!
//! Frozen Go: `shared/middleware/csrf.go` `CSRF()` returns at once for GET/HEAD/OPTIONS, so
//! `Sec-Fetch-Site: cross-site` never refuses them there, and the authenticated chain
//! (`mailserver/internal/middleware/device_trust_gate.go` `deviceLockdownGate`) still runs.
//! The refusal body below is that gate's literal 403/BZ095 JSON. Observed through the real
//! gateway router over HTTP; nothing internal is asserted.
mod common;
use hyper::{Request, Response};
use setjoin_conformance::{fixture, harness::Db};
use setjoin_gateway::{
    runtime_access::RuntimeAccess, Body, BoxFuture, Config, Gateway, Intercept, RequestContext,
    RouteTable, TrustedProxies,
};
use setjoin_pg::ScopedExecutor;
use std::sync::Arc;

const PATH: &str = "/api/admin/conditional-access/break-glass";
const FLAGS: [&str; 5] = [
    "feature.cae_runtime",
    "feature.conditional_access",
    "feature.device_trust_enforcement",
    "feature.device_lockdown",
    "feature.token_binding",
];

struct HealthyAdapter;
impl Intercept for HealthyAdapter {
    fn matches(&self, r: &Request<Body>) -> bool {
        r.uri().path() == PATH
    }
    fn handle(&self, _: Request<Body>, _: RequestContext) -> BoxFuture<Response<Body>> {
        Box::pin(async { Response::new(common::full("adapter ran")) })
    }
}

#[tokio::test]
async fn cross_site_get_for_a_locked_down_account_is_refused() -> Result<(), common::BoxError> {
    let _serial = common::recovery::SERIAL.lock().await;
    let Some(db) = Db::for_case("runtime-cross-site-lockdown") else {
        return Ok(());
    };
    let owner = db.connect().await?;
    let account = fixture::account(&owner, "cross-site-lockdown").await?;
    let foreign = fixture::account(&owner, "cross-site-lockdown-bg").await?;
    let flags = owner
        .query(
            "SELECT key,enabled FROM feature_toggles WHERE key=ANY($1)",
            &[&FLAGS.to_vec()],
        )
        .await?;
    let config = owner
        .query(
            "SELECT key,value::text FROM system_config WHERE key=ANY($1)",
            &[&vec!["ca_break_glass_user_ids", "ca_fail_mode"]],
        )
        .await?;
    let result = async {
        for key in FLAGS {
            owner
                .execute(
                    "INSERT INTO feature_toggles(key,enabled) VALUES($1,$2) ON CONFLICT(key) DO UPDATE SET enabled=EXCLUDED.enabled",
                    &[&key, &matches!(key, "feature.conditional_access" | "feature.device_lockdown")],
                )
                .await?;
        }
        // Lockdown enforces only with a non-empty break-glass list; this account is not on it.
        owner
            .execute(
                "INSERT INTO system_config(key,value) VALUES('ca_break_glass_user_ids',$1::text::jsonb),('ca_fail_mode','\"closed\"'::jsonb) ON CONFLICT(key) DO UPDATE SET value=EXCLUDED.value",
                &[&serde_json::json!([foreign.user]).to_string()],
            )
            .await?;
        let runtime = RuntimeAccess::new(
            ScopedExecutor::from_dsn(db.app.as_deref().unwrap_or(&db.dsn), 2).map_err(|e| e.0)?,
            Arc::new(common::recovery_keys()),
            "mailserver".into(),
        );
        let gateway = Gateway::new(
            Config {
                upstream: None,
                trusted_proxies: TrustedProxies::parse("")?,
                upstream_header_timeout: setjoin_gateway::proxy::DEFAULT_HEADER_TIMEOUT,
                edge_limit: None,
            },
            RouteTable::proxy_all()
                .with(HealthyAdapter)
                .with_runtime(runtime),
        )?;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let server = tokio::spawn(gateway.serve(listener));
        let response = common::send(
            address,
            Request::get(PATH)
                .header("host", "mail.test")
                .header("sec-fetch-site", "cross-site")
                .header(
                    "authorization",
                    format!("Bearer {}", common::recovery_token(account.user)),
                )
                .body(common::full(""))?,
        )
        .await;
        let status = response.status().as_u16();
        let body = String::from_utf8(common::body_bytes(response).await.to_vec())?;
        server.abort();
        let _ = server.await;
        // Go's deviceLockdownGate body, byte for byte (encoding/json sorts map keys).
        let expected = "{\"code\":\"BZ095\",\"detail\":\"device not enrolled — contact your administrator\",\"status\":403,\"title\":\"Forbidden\"}\n";
        if status != 403 || body != expected {
            return Err(format!("cross-site GET was served, not refused: {status} {body:?}").into());
        }
        Ok::<_, common::BoxError>(())
    }
    .await;
    for key in FLAGS {
        match flags.iter().find(|r| r.get::<_, String>(0) == key) {
            Some(row) => {
                owner
                    .execute(
                        "UPDATE feature_toggles SET enabled=$2 WHERE key=$1",
                        &[&key, &row.get::<_, bool>(1)],
                    )
                    .await?;
            }
            None => {
                owner
                    .execute("DELETE FROM feature_toggles WHERE key=$1", &[&key])
                    .await?;
            }
        }
    }
    for key in ["ca_break_glass_user_ids", "ca_fail_mode"] {
        match config.iter().find(|r| r.get::<_, String>(0) == key) {
            Some(row) => {
                owner
                    .execute(
                        "INSERT INTO system_config(key,value) VALUES($1,$2::text::jsonb) ON CONFLICT(key) DO UPDATE SET value=EXCLUDED.value",
                        &[&key, &row.get::<_, String>(1)],
                    )
                    .await?;
            }
            None => {
                owner
                    .execute("DELETE FROM system_config WHERE key=$1", &[&key])
                    .await?;
            }
        }
    }
    fixture::remove(&owner, &account).await?;
    fixture::remove(&owner, &foreign).await?;
    result
}
