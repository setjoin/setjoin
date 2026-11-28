//! Runtime admission must enforce policy and refuse uncertainty before local dispatch.
use crate::common;
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

#[tokio::test]
async fn cross_site_get_still_requires_lockdown_enrollment() -> Result<(), common::BoxError> {
    run_fault("cross-site-lockdown", "feature.device_lockdown").await
}

#[tokio::test]
async fn cross_site_get_still_requires_device_trust() -> Result<(), common::BoxError> {
    run_fault("cross-site-trust", "feature.device_trust_enforcement").await
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
    let mut server = None;
    let result = std::panic::AssertUnwindSafe(async {
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
        if fault == "cross-site-lockdown" {
            // Keep another account on the break-glass list so lockdown is active for uid 42.
            owner.batch_execute("INSERT INTO authzgates_runtime_fault.feature_toggles VALUES('feature.conditional_access',true);
                CREATE VIEW authzgates_runtime_fault.system_config AS SELECT 'ca_break_glass_user_ids'::text AS key,'[43]'::jsonb AS value;
                GRANT SELECT ON authzgates_runtime_fault.system_config TO setjoin_app;").await?;
        }
        if fault != "guest" {
            owner.batch_execute("CREATE FUNCTION authzgates_runtime_fault.guest_account_status(bigint) RETURNS TABLE(user_id bigint) LANGUAGE sql AS 'SELECT $1 WHERE false';").await?;
        }
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
        server = Some(tokio::spawn(gateway.serve(listener)));
        let device_id = if fault == "device-flags" {
            "runtime-fingerprint"
        } else {
            ""
        };
        let trust_tier = if fault == "cross-site-trust" {
            "quarantined"
        } else {
            "compliant"
        };
        let token = common::recovery_token_with(
            account.as_ref().map_or(42, |a| a.user),
            json!({"device": {"id": device_id, "trust_tier": trust_tier}}),
        );
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
        let mut request = Request::get("/api/admin/conditional-access/break-glass")
            .header(header, credential);
        if fault.starts_with("cross-site-") {
            request = request.header("sec-fetch-site", "cross-site");
        }
        let response = common::send(address, request.body(common::full(""))?).await;
        let status = response.status();
        let body = common::body_bytes(response).await;
        let metrics = common::send(
            address,
            Request::get("/_gateway/metrics").body(common::full(""))?,
        )
        .await;
        let metrics = String::from_utf8(common::body_bytes(metrics).await.to_vec())?;
        Ok::<_, common::BoxError>((status, body, metrics))
    })
    .catch_unwind()
    .await;
    if let Some(server) = server {
        server.abort();
        let _ = server.await;
    }
    owner
        .batch_execute("DROP SCHEMA authzgates_runtime_fault CASCADE")
        .await?;
    if let Some(account) = account {
        fixture::remove(&owner, &account).await?;
    }
    let (status, body, metrics) = result.map_err(|_| "runtime HTTP probe panicked")??;
    let expected = match fault {
        "device-flags" | "cross-site-lockdown" | "cross-site-trust" => 403,
        "allow" => 200,
        _ if fault.starts_with("unverified-") => 401,
        _ => 503,
    };
    if status.as_u16() != expected {
        return Err(format!("{fault}/{flag} expected {expected}, got {status}").into());
    }
    if expected == 200 {
        if body.as_ref() != b"adapter ran" {
            return Err("healthy adapter response changed".into());
        }
    } else {
        let body: serde_json::Value = serde_json::from_slice(&body)?;
        let detail = match fault {
            "device-flags" => "This device's access has been revoked. Contact your administrator.",
            "cross-site-lockdown" => "device not enrolled — contact your administrator",
            "cross-site-trust" => "Device is quarantined. Check compliance status in device settings.",
            _ if expected == 503 => "Runtime access verification unavailable.",
            _ => "Authentication required.",
        };
        if body["detail"] != detail {
            return Err(format!("{fault}/{flag} returned the wrong refusal detail").into());
        }
        if fault == "cross-site-lockdown" && body["code"] != "BZ095" {
            return Err("lockdown refusal is missing code BZ095".into());
        }
    }
    if !metrics
        .lines()
        .any(|l| l == "setjoin_gateway_proxied_to_go_total 0")
    {
        return Err(format!("{fault}/{flag} admission forwarded to Go").into());
    }
    Ok(())
}
