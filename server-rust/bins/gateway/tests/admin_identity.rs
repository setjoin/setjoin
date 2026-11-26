//! F01 slice `users` frozen-Go oracle, replayed without a Go upstream.
mod admin_identity_oracle;
mod common;
macro_rules! case {
    ($name:ident, $action:literal, $kind:literal) => {
        #[tokio::test]
        async fn $name() -> Result<(), common::BoxError> {
            admin_identity_oracle::run($action, $kind, None).await
        }
    };
}
macro_rules! mutant {
    ($name:ident, $action:literal, $kind:literal, $fault:literal) => {
        #[tokio::test]
        async fn $name() -> Result<(), common::BoxError> {
            admin_identity_oracle::run($action, $kind, Some($fault)).await
        }
    };
}

case!(users_success, "users", "success");
case!(users_cross_tenant, "users", "foreign");
case!(users_denied, "users", "denied");
case!(users_invalid_input, "users", "invalid");
case!(users_filtered, "users", "filtered");
case!(users_paged, "users", "paged");
case!(users_scoped, "users", "scoped");
case!(users_status_mutant, "users", "success-status-mutant");
mutant!(
    users_no_tenant_filter_mutant,
    "users",
    "foreign",
    "no-tenant-filter"
);
case!(user_success, "user", "success");
case!(user_cross_tenant, "user", "foreign");
case!(user_invalid_input, "user", "invalid");
case!(user_missing, "user", "missing");
case!(user_status_mutant, "user", "success-status-mutant");
mutant!(
    user_no_tenant_filter_mutant,
    "user",
    "foreign",
    "no-tenant-filter"
);
case!(aliases_success, "aliases", "success");
case!(aliases_cross_tenant, "aliases", "foreign");
case!(aliases_invalid_input, "aliases", "invalid");
case!(aliases_zero, "aliases", "zero");
case!(aliases_status_mutant, "aliases", "success-status-mutant");
mutant!(
    aliases_no_tenant_filter_mutant,
    "aliases",
    "foreign",
    "no-tenant-filter"
);
case!(alias_add_success, "alias-add", "success");
case!(alias_add_cross_tenant, "alias-add", "foreign");
case!(alias_add_invalid_input, "alias-add", "invalid");
case!(alias_add_empty, "alias-add", "empty");
case!(alias_add_bad_email, "alias-add", "bad-email");
case!(alias_add_reserved, "alias-add", "reserved");
case!(alias_add_dup, "alias-add", "dup");
case!(alias_add_repeat, "alias-add", "repeat");
case!(alias_add_folded, "alias-add", "folded");
case!(alias_add_denied, "alias-add", "denied");
case!(
    alias_add_status_mutant,
    "alias-add",
    "success-status-mutant"
);
mutant!(
    alias_add_no_tenant_filter_mutant,
    "alias-add",
    "foreign",
    "no-tenant-filter"
);
case!(alias_remove_success, "alias-remove", "success");
case!(alias_remove_cross_tenant, "alias-remove", "foreign");
case!(alias_remove_invalid_input, "alias-remove", "invalid");
case!(alias_remove_repeat, "alias-remove", "repeat");
case!(
    alias_remove_status_mutant,
    "alias-remove",
    "success-status-mutant"
);
mutant!(
    alias_remove_no_tenant_filter_mutant,
    "alias-remove",
    "foreign",
    "no-tenant-filter"
);
case!(quota_success, "quota", "success");
case!(quota_cross_tenant, "quota", "foreign");
case!(quota_invalid_input, "quota", "invalid");
case!(quota_missing, "quota", "missing");
case!(quota_status_mutant, "quota", "success-status-mutant");
mutant!(
    quota_no_tenant_filter_mutant,
    "quota",
    "foreign",
    "no-tenant-filter"
);
case!(quota_set_success, "quota-set", "success");
case!(quota_set_cross_tenant, "quota-set", "foreign");
case!(quota_set_invalid_input, "quota-set", "invalid");
case!(quota_set_bad_json, "quota-set", "bad-json");
case!(quota_set_partial, "quota-set", "partial");
case!(quota_set_nonpositive, "quota-set", "nonpositive");
case!(quota_set_folded, "quota-set", "folded");
case!(quota_set_repeat, "quota-set", "repeat");
case!(
    quota_set_status_mutant,
    "quota-set",
    "success-status-mutant"
);
mutant!(
    quota_set_no_tenant_filter_mutant,
    "quota-set",
    "foreign",
    "no-tenant-filter"
);
case!(app_passwords_success, "app-passwords", "success");
case!(app_passwords_cross_tenant, "app-passwords", "foreign");
case!(app_passwords_invalid_input, "app-passwords", "invalid");
case!(
    app_passwords_status_mutant,
    "app-passwords",
    "success-status-mutant"
);
mutant!(
    app_passwords_no_tenant_filter_mutant,
    "app-passwords",
    "foreign",
    "no-tenant-filter"
);
case!(app_access_success, "app-access", "success");
case!(app_access_cross_tenant, "app-access", "foreign");
case!(app_access_invalid_input, "app-access", "invalid");
case!(
    app_access_status_mutant,
    "app-access",
    "success-status-mutant"
);
mutant!(
    app_access_no_tenant_filter_mutant,
    "app-access",
    "foreign",
    "no-tenant-filter"
);
case!(app_access_set_success, "app-access-set", "success");
case!(app_access_set_update, "app-access-set", "update");
case!(app_access_set_invalid_input, "app-access-set", "invalid");
case!(app_access_set_cross_tenant, "app-access-set", "foreign");
case!(app_access_set_bad_app, "app-access-set", "bad-app");
case!(app_access_set_bad_body, "app-access-set", "bad-body");
case!(app_access_set_empty, "app-access-set", "empty");
case!(
    app_access_set_missing_user,
    "app-access-set",
    "missing-user"
);
case!(app_access_set_repeat, "app-access-set", "repeat");
case!(
    app_access_set_status_mutant,
    "app-access-set",
    "success-status-mutant"
);
case!(sessions_success, "sessions", "success");
case!(sessions_cross_tenant, "sessions", "foreign");
case!(sessions_invalid_input, "sessions", "invalid");
case!(sessions_missing, "sessions", "missing");
case!(sessions_scoped, "sessions", "scoped");
case!(sessions_status_mutant, "sessions", "success-status-mutant");
mutant!(
    app_access_set_no_audit_mutant,
    "app-access-set",
    "success",
    "no-audit"
);
mutant!(
    quota_set_double_bump_mutant,
    "quota-set",
    "success",
    "double-bump"
);

fn signed_admin_token(user: i64, perms: &[&str]) -> String {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    use p256::ecdsa::{signature::Signer, SigningKey};
    let source = common::recovery_token(user);
    let fields = source.split('.').collect::<Vec<_>>();
    let mut claims: serde_json::Value =
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(fields[1]).unwrap()).unwrap();
    claims["admin"] = serde_json::json!(true);
    claims["perms"] = serde_json::json!(perms);
    let payload = URL_SAFE_NO_PAD.encode(claims.to_string());
    let key = SigningKey::from_slice(&[0x11; 32]).unwrap();
    let signature: p256::ecdsa::Signature = key.sign(format!("{}.{payload}", fields[0]).as_bytes());
    format!(
        "{}.{payload}.{}",
        fields[0],
        URL_SAFE_NO_PAD.encode(signature.to_bytes())
    )
}

async fn cut_authority_proxy(
    dsn: &str,
) -> Result<(String, tokio::task::JoinHandle<()>), common::BoxError> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let cfg: tokio_postgres::Config = dsn.parse()?;
    let host = match cfg.get_hosts().first() {
        Some(tokio_postgres::config::Host::Tcp(h)) => h.clone(),
        _ => return Err("TCP fixture DSN required".into()),
    };
    let port = *cfg.get_ports().first().unwrap_or(&5432);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let mut proxied = format!("host=127.0.0.1 port={}", listener.local_addr()?.port());
    {
        let mut add = |key: &str, value: &str| {
            proxied.push_str(&format!(
                " {key}='{}'",
                value.replace('\\', "\\\\").replace('\'', "\\'")
            ));
        };
        if let Some(v) = cfg.get_user() {
            add("user", v);
        }
        if let Some(v) = cfg.get_password() {
            add("password", std::str::from_utf8(v)?);
        }
        if let Some(v) = cfg.get_dbname() {
            add("dbname", v);
        }
        if let Some(v) = cfg.get_options() {
            add("options", v);
        }
    }
    let task = tokio::spawn(async move {
        const MARKER: &[u8] = b"AS eff_scope";
        loop {
            let Ok((client, _)) = listener.accept().await else {
                break;
            };
            let host = host.clone();
            tokio::spawn(async move {
                let Ok(server) = tokio::net::TcpStream::connect((host.as_str(), port)).await else {
                    return;
                };
                let (mut cr, mut cw) = client.into_split();
                let (mut sr, mut sw) = server.into_split();
                let c2s = async {
                    let mut buf = [0u8; 8192];
                    let mut tail = Vec::with_capacity(MARKER.len());
                    loop {
                        let Ok(n) = cr.read(&mut buf).await else {
                            break;
                        };
                        if n == 0 {
                            break;
                        }
                        let mut window = Vec::with_capacity(tail.len() + n);
                        window.extend_from_slice(&tail);
                        window.extend_from_slice(&buf[..n]);
                        if window.windows(MARKER.len()).any(|w| w == MARKER) {
                            let _ = sw.shutdown().await;
                            break;
                        }
                        let keep = window.len().min(MARKER.len() - 1);
                        tail.clear();
                        tail.extend_from_slice(&window[window.len() - keep..]);
                        if sw.write_all(&buf[..n]).await.is_err() {
                            break;
                        }
                    }
                };
                let s2c = async {
                    let _ = tokio::io::copy(&mut sr, &mut cw).await;
                };
                tokio::select! {
                    _ = c2s => {}
                    _ = s2c => {}
                }
            });
        }
    });
    Ok((proxied, task))
}

#[tokio::test]
async fn authority_lookup_failure_fails_closed_without_forwarding() -> Result<(), common::BoxError>
{
    use hyper::{Request, Response};
    use setjoin_conformance::{fixture, harness::Db};
    use setjoin_gateway::{admin_identity::AdminIdentityRoute, RouteTable};
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };

    let _serial = admin_identity_oracle::SERIAL.lock().await;
    let Some(db) = Db::for_case("admin-identity-authority-fail-closed") else {
        return Ok(());
    };
    let owner = db.connect().await?;
    let a = fixture::account(&owner, "admin1-194").await?;
    let role_id: i64 = owner
        .query_one(
            "INSERT INTO admin_role_groups(name,permissions,domain_scope) VALUES($1,'{users.read}',NULL) RETURNING id",
            &[&format!("admin1-194-{}", a.user)],
        )
        .await?
        .get(0);
    owner
        .execute(
            "INSERT INTO admin_role_assignments(user_id,role_group_id,granted_by) VALUES($1,$2,$1)",
            &[&a.user, &role_id],
        )
        .await?;
    let audit_start: i64 = owner
        .query_one("SELECT COALESCE(max(id),0) FROM admin_audit_log", &[])
        .await?
        .get(0);
    let receipts: Vec<String> = owner
        .query(
            "SELECT operation_id::text FROM rust_operation_receipts WHERE family='F01'",
            &[],
        )
        .await?
        .iter()
        .map(|r| r.get(0))
        .collect();

    let exec_dsn = db.app.as_deref().unwrap_or(&db.dsn);
    let (proxied_dsn, db_proxy) = cut_authority_proxy(exec_dsn).await?;
    let result = async {
        let exec =
            common::patient_exec(&proxied_dsn, 4)?.with_audit_keys("22".repeat(32), String::new());
        let route = AdminIdentityRoute {
            exec,
            worker: None,
            keys: Arc::new(common::recovery_keys()),
            issuer: "mailserver".into(),
        };
        let go_hits = Arc::new(AtomicUsize::new(0));
        let hits = go_hits.clone();
        let upstream = common::fake_upstream(move |_| {
            hits.fetch_add(1, Ordering::SeqCst);
            async {
                Response::builder()
                    .status(500)
                    .body(common::full("go-called"))
                    .unwrap()
            }
        })
        .await;
        let gw = common::gateway(upstream, "", RouteTable::proxy_all().with(route)).await;
        let token = signed_admin_token(a.user, &["users.read"]);
        let req = Request::builder()
            .method("GET")
            .uri("/api/admin/users")
            .header("host", "mail.test")
            .header("origin", "http://mail.test")
            .header("authorization", format!("Bearer {token}"))
            .body(common::full(""))?;
        let resp = common::send(gw, req).await;
        let status = resp.status().as_u16();
        let body = String::from_utf8(common::body_bytes(resp).await.to_vec())?;
        assert_eq!(
            status, 403,
            "expected fail-closed 403, got {status}: {body}"
        );
        let v: serde_json::Value = serde_json::from_str(&body)?;
        assert_eq!(v["detail"], "Forbidden");
        assert_eq!(go_hits.load(Ordering::SeqCst), 0, "must not forward to Go");
        let metrics = common::send(
            gw,
            Request::get("/_gateway/metrics").body(common::full(""))?,
        )
        .await;
        let metrics_body = String::from_utf8(common::body_bytes(metrics).await.to_vec())?;
        assert!(
            metrics_body
                .lines()
                .any(|l| l == "setjoin_gateway_proxied_to_go_by_family_total{family=\"F01\"} 0"),
            "unexpected F01 proxy metric: {metrics_body}"
        );
        Ok::<_, common::BoxError>(())
    }
    .await;

    db_proxy.abort();
    let _ = owner
        .execute(
            "DELETE FROM rust_operation_receipts WHERE family='F01' AND operation_id::text<>ALL($1)",
            &[&receipts],
        )
        .await;
    let _ = owner
        .execute(
            "DELETE FROM admin_role_assignments WHERE user_id=$1",
            &[&a.user],
        )
        .await;
    let _ = owner
        .execute("DELETE FROM admin_role_groups WHERE id=$1", &[&role_id])
        .await;
    let _ = common::remove_blob_account(&owner, &a).await;
    let _ = owner
        .batch_execute(&format!(
            "BEGIN; SET LOCAL session_replication_role=replica; DELETE FROM admin_audit_log WHERE id>{audit_start}; COMMIT;"
        ))
        .await;
    result
}
