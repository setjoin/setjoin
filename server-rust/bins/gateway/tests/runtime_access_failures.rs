//! Runtime admission must refuse uncertainty before a healthy local adapter runs.
mod common;
use futures_util::FutureExt;
use hyper::{Request, Response};
use serde_json::json;
use setjoin_conformance::{fixture, harness::Db};
use setjoin_gateway::{
    runtime_access::RuntimeAccess, Body, BoxFuture, Config, Gateway, Intercept, RequestContext,
    RouteTable, TrustedProxies,
};
use setjoin_pg::ScopedExecutor;
use std::sync::Arc;

struct HealthyAdapter;
impl Intercept for HealthyAdapter {
    fn matches(&self, r: &Request<Body>) -> bool {
        r.uri().path() == "/api/admin/conditional-access/break-glass"
    }
    fn handle(&self, _: Request<Body>, _: RequestContext) -> BoxFuture<Response<Body>> {
        Box::pin(async { Response::new(common::full("adapter ran")) })
    }
}

#[tokio::test]
async fn guest_status_lookup_failure_refuses_the_request() -> Result<(), common::BoxError> {
    run_fault("guest", "feature.device_trust_enforcement").await
}

#[tokio::test]
async fn toggle_lookup_failure_refuses_the_request() -> Result<(), common::BoxError> {
    run_fault("flags", "feature.device_trust_enforcement").await
}

#[tokio::test]
async fn unverifiable_credentials_cannot_skip_any_enabled_gate() -> Result<(), common::BoxError> {
    for flag in [
        "feature.cae_runtime",
        "feature.conditional_access",
        "feature.device_trust_enforcement",
        "feature.device_lockdown",
        "feature.token_binding",
    ] {
        for credential in [
            "unverified-bearer",
            "unverified-cookie",
            "unverified-basic",
            "unverified-empty-bearer",
            "unverified-scope",
        ] {
            run_fault(credential, flag).await?;
        }
    }
    Ok(())
}

#[tokio::test]
async fn verified_member_still_reaches_a_healthy_adapter() -> Result<(), common::BoxError> {
    run_fault("allow", "feature.device_trust_enforcement").await
}

#[tokio::test]
async fn enabled_device_gate_survives_a_later_toggle_read_failure() -> Result<(), common::BoxError>
{
    run_fault("device-flags", "feature.device_trust_enforcement").await
}

/// Every case creates and drops the same fault schema: libtest's threads must take turns.
static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

async fn run_fault(fault: &str, flag: &str) -> Result<(), common::BoxError> {
    let _serial = SERIAL.lock().await;
    let Some(db) = Db::for_case("runtime-admission-fault") else {
        return Ok(());
    };
    let owner = db.connect().await?;
    // A private search_path prevents public objects from masking either fault.
    owner.batch_execute("CREATE SCHEMA authzgates_runtime_fault; GRANT USAGE ON SCHEMA authzgates_runtime_fault TO setjoin_app;").await?;
    let account = if fault == "device-flags" {
        let account = fixture::account(&owner, "authzgates-toggle-fault").await?;
        owner.execute("INSERT INTO user_devices(user_id,device_name,platform,fingerprint_hash,offline_approval) VALUES($1,'Revoked device','desktop',sha256('runtime-fingerprint'::bytea),'revoked')", &[&account.user]).await?;
        // Model a lookup that succeeds once, then becomes unavailable. The
        // refusal is observed through HTTP; no query text or call count is asserted.
        owner.batch_execute("CREATE SEQUENCE authzgates_runtime_fault.flag_reads;
            GRANT USAGE ON SEQUENCE authzgates_runtime_fault.flag_reads TO setjoin_app;
            CREATE FUNCTION authzgates_runtime_fault.enabled() RETURNS boolean LANGUAGE plpgsql AS $$
            BEGIN IF nextval('authzgates_runtime_fault.flag_reads')>1 THEN RAISE EXCEPTION 'toggle lookup unavailable'; END IF; RETURN true; END $$;
            CREATE VIEW authzgates_runtime_fault.feature_toggles AS SELECT 'feature.device_trust_enforcement'::text AS key,authzgates_runtime_fault.enabled() AS enabled;
            GRANT SELECT ON authzgates_runtime_fault.feature_toggles TO setjoin_app;").await?;
        Some(account)
    } else {
        None
    };
    if fault != "flags" && fault != "device-flags" {
        owner
            .batch_execute(
                "CREATE TABLE authzgates_runtime_fault.feature_toggles(key text,enabled boolean);
            GRANT SELECT ON authzgates_runtime_fault.feature_toggles TO setjoin_app;",
            )
            .await?;
        owner
            .execute(
                "INSERT INTO authzgates_runtime_fault.feature_toggles VALUES($1,true)",
                &[&flag],
            )
            .await?;
    }
    if fault != "guest" {
        owner.batch_execute("CREATE FUNCTION authzgates_runtime_fault.guest_account_status(bigint) RETURNS TABLE(user_id bigint) LANGUAGE sql AS 'SELECT $1 WHERE false';").await?;
    }
    let result = std::panic::AssertUnwindSafe(async {
        let app = db.app.as_deref().ok_or("DB_APP_DSN required")?;
        let separator = if app.contains('?') { '&' } else { '?' };
        let dsn = format!(
            "{app}{separator}options=-csearch_path%3Dauthzgates_runtime_fault%2Cpg_catalog"
        );
        let mut runtime = RuntimeAccess::new(
            ScopedExecutor::from_dsn(&dsn, 2).map_err(|e| e.0)?,
            Arc::new(common::recovery_keys()),
            "mailserver".into(),
        );
        if fault == "device-flags" {
            runtime = runtime.with_workers(ScopedExecutor::from_dsn(&db.dsn,2).map_err(|e|e.0)?,setjoin_pg::workers::WorkerDatabase::new(&db.dsn)?);
        }
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
        let token = common::recovery_token_with(account.as_ref().map_or(42,|a|a.user), json!({"device":{"id":if fault=="device-flags"{"runtime-fingerprint"}else{""},"trust_tier":"compliant"}}));
        let (header, credential) = match fault {
            "unverified-bearer" => ("authorization", "Bearer cannot-be-verified".into()),
            "unverified-cookie" => ("cookie", "access_token=cannot-be-verified".into()),
            "unverified-basic" => ("authorization", "Basic dXNlcjpwYXNz".into()),
            "unverified-empty-bearer" => ("authorization", "Bearer ".into()),
            "unverified-scope" => (
                "authorization",
                format!(
                    "Bearer {}",
                    common::recovery_token_with(42, json!({"scp":"mail-attachment"}))
                ),
            ),
            _ => ("authorization", format!("Bearer {token}")),
        };
        let response = common::send(
            address,
            Request::get("/api/admin/conditional-access/break-glass")
                .header(header, credential)
                .body(common::full(""))?,
        )
        .await;
        let status = response.status();
        let body = common::body_bytes(response).await;
        let metrics = common::send(
            address,
            Request::get("/_gateway/metrics").body(common::full(""))?,
        )
        .await;
        let metrics = String::from_utf8(common::body_bytes(metrics).await.to_vec())?;
        server.abort();
        let _ = server.await;
        let expected = if fault == "device-flags" {403} else if fault == "allow" {
            200
        } else if fault.starts_with("unverified-") {
            401
        } else {
            503
        };
        if status.as_u16() != expected {
            return Err(
                format!("{fault}/{flag} expected {expected}, got {status}: {body:?}").into(),
            );
        }
        if expected == 200 {
            if body.as_ref() != b"adapter ran" {
                return Err("healthy adapter response changed".into());
            }
        } else {
            let body: serde_json::Value = serde_json::from_slice(&body)?;
            let detail = if expected == 403 {"This device's access has been revoked. Contact your administrator."} else if expected == 503 {
                "Runtime access verification unavailable."
            } else {
                "Authentication required."
            };
            if body["detail"] != detail {
                return Err(format!("wrong refusal: {body}").into());
            }
        }
        if !metrics
            .lines()
            .any(|l| l == "setjoin_gateway_proxied_to_go_total 0")
        {
            return Err(format!("uncertain admission forwarded: {metrics}").into());
        }
        Ok::<_, common::BoxError>(())
    })
    .catch_unwind()
    .await;
    owner
        .batch_execute("DROP SCHEMA authzgates_runtime_fault CASCADE")
        .await?;
    if let Some(account) = account {
        fixture::remove(&owner, &account).await?;
    }
    result.map_err(|_| "runtime HTTP probe panicked")?
}
