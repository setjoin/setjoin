//! F01 slice `idv2-upgrade` frozen-Go oracle, replayed without a Go upstream.
use crate::admin_identity_v2_upgrade_oracle;
use crate::common;
macro_rules! case {
    ($name:ident, $action:literal, $kind:literal) => {
        #[tokio::test]
        async fn $name() -> Result<(), common::BoxError> {
            admin_identity_v2_upgrade_oracle::run($action, $kind).await
        }
    };
}

case!(status_success, "status", "success");
case!(status_etag_match, "status", "etag-match");
case!(status_denied, "status", "denied");
case!(status_only_upgrade, "status", "only-upgrade");
case!(status_only_identity, "status", "only-identity");
case!(status_scoped, "status", "scoped");
case!(
    status_success_status_mutant,
    "status",
    "success-status-mutant"
);

case!(preflight_success, "preflight", "success");
case!(preflight_denied, "preflight", "denied");
case!(preflight_scoped, "preflight", "scoped");
case!(preflight_only_identity, "preflight", "only-identity");
case!(
    preflight_success_status_mutant,
    "preflight",
    "success-status-mutant"
);

case!(retirement_success, "retirement", "success");
case!(retirement_etag_match, "retirement", "etag-match");
case!(retirement_denied, "retirement", "denied");
case!(retirement_scoped, "retirement", "scoped");
case!(
    retirement_success_status_mutant,
    "retirement",
    "success-status-mutant"
);

case!(shadow_success, "shadow", "success");
case!(shadow_oidc, "shadow", "oidc");
case!(shadow_padded, "shadow", "padded");
case!(shadow_etag_match, "shadow", "etag-match");
case!(shadow_missing_source, "shadow", "missing-source");
case!(shadow_bad_key, "shadow", "bad-key");
case!(shadow_no_key, "shadow", "no-key");
case!(shadow_denied, "shadow", "denied");
case!(shadow_scoped, "shadow", "scoped");
case!(shadow_only_upgrade, "shadow", "only-upgrade");
case!(
    shadow_success_status_mutant,
    "shadow",
    "success-status-mutant"
);

case!(doctor_success, "doctor", "success");
case!(doctor_with_source, "doctor", "with-source");
case!(doctor_padded, "doctor", "padded");
case!(doctor_etag_match, "doctor", "etag-match");
case!(doctor_missing_source, "doctor", "missing-source");
case!(doctor_bad_source, "doctor", "bad-source");
case!(doctor_denied, "doctor", "denied");
case!(doctor_scoped, "doctor", "scoped");
case!(
    doctor_success_status_mutant,
    "doctor",
    "success-status-mutant"
);

case!(backfill_plan, "backfill", "plan");
case!(backfill_success, "backfill", "success");
case!(backfill_repeat, "backfill", "repeat");
case!(backfill_blocked, "backfill", "blocked");
case!(backfill_stale, "backfill", "stale");
case!(backfill_header_key_only, "backfill", "header-key-only");
case!(backfill_body_key_only, "backfill", "body-key-only");
case!(backfill_no_key, "backfill", "no-key");
case!(backfill_key_mismatch, "backfill", "key-mismatch");
case!(backfill_bad_key, "backfill", "bad-key");
case!(backfill_bad_checksum, "backfill", "bad-checksum");
case!(backfill_no_checksum, "backfill", "no-checksum");
case!(backfill_bad_action, "backfill", "bad-action");
case!(backfill_bad_json, "backfill", "bad-json");
case!(backfill_unknown_field, "backfill", "unknown-field");
case!(backfill_typed, "backfill", "typed");
case!(backfill_trailing, "backfill", "trailing");
case!(backfill_null_body, "backfill", "null-body");
case!(backfill_oversize, "backfill", "oversize");
case!(backfill_reason_mismatch, "backfill", "reason-mismatch");
case!(backfill_reason_required, "backfill", "reason-required");
case!(backfill_denied, "backfill", "denied");
case!(backfill_scoped, "backfill", "scoped");
case!(backfill_only_upgrade, "backfill", "only-upgrade");
case!(
    backfill_success_status_mutant,
    "backfill",
    "success-status-mutant"
);

case!(canary_success, "canary", "success");
case!(canary_repeat, "canary", "repeat");
case!(canary_stale, "canary", "stale");
case!(canary_bad_generation, "canary", "bad-generation");
case!(canary_text_generation, "canary", "text-generation");
case!(canary_missing_source, "canary", "missing-source");
case!(canary_bad_source_key, "canary", "bad-source-key");
case!(canary_if_match_ok, "canary", "if-match-ok");
case!(canary_if_match_list, "canary", "if-match-list");
case!(canary_if_match_bad, "canary", "if-match-bad");
case!(canary_enable_ldap, "canary", "enable-ldap");
case!(canary_enable_unready, "canary", "enable-unready");
case!(canary_enable_no_users, "canary", "enable-no-users");
case!(canary_too_many_users, "canary", "too-many-users");
case!(canary_bad_user_id, "canary", "bad-user-id");
case!(canary_text_user_id, "canary", "text-user-id");
case!(canary_null_user_id, "canary", "null-user-id");
case!(canary_typed_user_id, "canary", "typed-user-id");
case!(canary_duplicate_users, "canary", "duplicate-users");
case!(canary_typed_enabled, "canary", "typed-enabled");
case!(canary_bad_json, "canary", "bad-json");
case!(canary_unknown_field, "canary", "unknown-field");
case!(canary_typed, "canary", "typed");
case!(canary_trailing, "canary", "trailing");
case!(canary_null_body, "canary", "null-body");
case!(canary_oversize, "canary", "oversize");
case!(canary_reason_mismatch, "canary", "reason-mismatch");
case!(canary_reason_required, "canary", "reason-required");
case!(canary_denied, "canary", "denied");
case!(canary_scoped, "canary", "scoped");
case!(canary_only_upgrade, "canary", "only-upgrade");
case!(canary_only_identity, "canary", "only-identity");
case!(
    canary_success_status_mutant,
    "canary",
    "success-status-mutant"
);

case!(rollback_success, "rollback", "success");
case!(rollback_repeat, "rollback", "repeat");
case!(rollback_bad_read_path, "rollback", "bad-read-path");
case!(rollback_no_read_path, "rollback", "no-read-path");
case!(rollback_bad_json, "rollback", "bad-json");
case!(rollback_unknown_field, "rollback", "unknown-field");
case!(rollback_typed, "rollback", "typed");
case!(rollback_trailing, "rollback", "trailing");
case!(rollback_null_body, "rollback", "null-body");
case!(rollback_oversize, "rollback", "oversize");
case!(rollback_reason_mismatch, "rollback", "reason-mismatch");
case!(rollback_reason_required, "rollback", "reason-required");
case!(rollback_denied, "rollback", "denied");
case!(rollback_scoped, "rollback", "scoped");
case!(rollback_only_upgrade, "rollback", "only-upgrade");
case!(
    rollback_success_status_mutant,
    "rollback",
    "success-status-mutant"
);

case!(diag_create_success, "diag-create", "success");
case!(diag_create_repeat, "diag-create", "repeat");
case!(diag_create_transition, "diag-create", "transition");
case!(diag_create_idem_reuse, "diag-create", "idem-reuse");
case!(
    diag_create_bad_transition_id,
    "diag-create",
    "bad-transition-id"
);
case!(
    diag_create_nil_transition_id,
    "diag-create",
    "nil-transition-id"
);
case!(diag_create_both_scopes, "diag-create", "both-scopes");
case!(diag_create_no_scope, "diag-create", "no-scope");
case!(diag_create_missing_source, "diag-create", "missing-source");
case!(diag_create_bad_source_key, "diag-create", "bad-source-key");
case!(diag_create_zero_since, "diag-create", "zero-since");
case!(diag_create_long_since, "diag-create", "long-since");
case!(diag_create_max_since, "diag-create", "max-since");
case!(diag_create_float_since, "diag-create", "float-since");
case!(diag_create_string_since, "diag-create", "string-since");
case!(
    diag_create_header_key_only,
    "diag-create",
    "header-key-only"
);
case!(diag_create_body_key_only, "diag-create", "body-key-only");
case!(diag_create_no_key, "diag-create", "no-key");
case!(diag_create_key_mismatch, "diag-create", "key-mismatch");
case!(diag_create_bad_key, "diag-create", "bad-key");
case!(diag_create_bad_json, "diag-create", "bad-json");
case!(diag_create_unknown_field, "diag-create", "unknown-field");
case!(diag_create_typed, "diag-create", "typed");
case!(diag_create_trailing, "diag-create", "trailing");
case!(diag_create_null_body, "diag-create", "null-body");
case!(diag_create_oversize, "diag-create", "oversize");
case!(
    diag_create_reason_mismatch,
    "diag-create",
    "reason-mismatch"
);
case!(
    diag_create_reason_required,
    "diag-create",
    "reason-required"
);
case!(diag_create_denied, "diag-create", "denied");
case!(diag_create_scoped, "diag-create", "scoped");
case!(
    diag_create_success_status_mutant,
    "diag-create",
    "success-status-mutant"
);

case!(diag_status_success, "diag-status", "success");
case!(diag_status_running, "diag-status", "running");
case!(diag_status_backfill_job, "diag-status", "backfill-job");
case!(diag_status_kind_denied, "diag-status", "kind-denied");
case!(diag_status_other_actor, "diag-status", "other-actor");
case!(diag_status_missing, "diag-status", "missing");
case!(diag_status_bad_id, "diag-status", "bad-id");
case!(diag_status_nil_id, "diag-status", "nil-id");
case!(diag_status_uppercase, "diag-status", "uppercase");
case!(diag_status_etag_match, "diag-status", "etag-match");
case!(diag_status_denied, "diag-status", "denied");
case!(diag_status_scoped, "diag-status", "scoped");
case!(
    diag_status_success_status_mutant,
    "diag-status",
    "success-status-mutant"
);

case!(diag_download_success, "diag-download", "success");
case!(
    diag_download_large_artifact,
    "diag-download",
    "large-artifact"
);
case!(diag_download_repeat, "diag-download", "repeat");
case!(diag_download_not_ready, "diag-download", "not-ready");
case!(diag_download_expired, "diag-download", "expired");
case!(diag_download_past_expiry, "diag-download", "past-expiry");
case!(diag_download_other_actor, "diag-download", "other-actor");
case!(diag_download_missing, "diag-download", "missing");
case!(diag_download_bad_id, "diag-download", "bad-id");
case!(diag_download_nil_id, "diag-download", "nil-id");
case!(diag_download_denied, "diag-download", "denied");
case!(diag_download_scoped, "diag-download", "scoped");
case!(
    diag_download_success_status_mutant,
    "diag-download",
    "success-status-mutant"
);

case!(diag_delete_success, "diag-delete", "success");
case!(diag_delete_repeat, "diag-delete", "repeat");
case!(diag_delete_missing, "diag-delete", "missing");
case!(diag_delete_other_actor, "diag-delete", "other-actor");
case!(diag_delete_bad_id, "diag-delete", "bad-id");
case!(diag_delete_nil_id, "diag-delete", "nil-id");
case!(diag_delete_bad_json, "diag-delete", "bad-json");
case!(diag_delete_unknown_field, "diag-delete", "unknown-field");
case!(diag_delete_typed, "diag-delete", "typed");
case!(diag_delete_trailing, "diag-delete", "trailing");
case!(diag_delete_null_body, "diag-delete", "null-body");
case!(diag_delete_oversize, "diag-delete", "oversize");
case!(
    diag_delete_reason_mismatch,
    "diag-delete",
    "reason-mismatch"
);
case!(
    diag_delete_reason_required,
    "diag-delete",
    "reason-required"
);
case!(diag_delete_denied, "diag-delete", "denied");
case!(diag_delete_scoped, "diag-delete", "scoped");
case!(
    diag_delete_success_status_mutant,
    "diag-delete",
    "success-status-mutant"
);

/// The digest check must reject a digest that does not describe its report: one flipped digit,
/// and a report edited after hashing. A changed `generatedAt` alone stays valid (excluded by design).
#[tokio::test]
async fn preflight_digest_check_rejects_a_stale_digest() -> Result<(), common::BoxError> {
    let Some(db) = setjoin_conformance::harness::Db::for_case("admin9-digest") else {
        return Ok(());
    };
    let owner = db.connect().await?;
    let body: String = owner
        .query_one(
            "SELECT identity_upgrade_preflight(0,false,false,false,false,false)::text",
            &[],
        )
        .await?
        .get(0);
    admin_identity_v2_upgrade_oracle::digest_is_current(&owner, &body).await?;

    let report: serde_json::Value = serde_json::from_str(&body)?;
    let digest = report["sha256"].as_str().unwrap().to_owned();
    let flipped = format!(
        "{}{}",
        if digest.starts_with('0') { "1" } else { "0" },
        &digest[1..]
    );
    let wrong = body.replace(&digest, &flipped);
    let error = admin_identity_v2_upgrade_oracle::digest_is_current(&owner, &wrong)
        .await
        .expect_err("flipped digest must be rejected");
    assert!(
        error.to_string().contains("stale preflight digest"),
        "{error}"
    );

    let mut edited = report.clone();
    edited["estimates"]["people"] =
        serde_json::json!(report["estimates"]["people"].as_i64().unwrap() + 1);
    let error = admin_identity_v2_upgrade_oracle::digest_is_current(&owner, &edited.to_string())
        .await
        .expect_err("an edited report must be rejected");
    assert!(
        error.to_string().contains("stale preflight digest"),
        "{error}"
    );

    // A self-consistent report from an earlier database state: its own digest matches, but it
    // no longer equals a fresh one.
    let mut older = report.clone();
    older["estimates"]["people"] =
        serde_json::json!(report["estimates"]["people"].as_i64().unwrap() + 1);
    let older = serde_json::to_string(&older)?;
    let older = {
        let digest: String = owner
            .query_one("SELECT encode(digest(convert_to(($1::text::jsonb - 'sha256' - 'generatedAt')::text,'UTF8'),'sha256'),'hex')", &[&older])
            .await?
            .get(0);
        let mut v: serde_json::Value = serde_json::from_str(&older)?;
        v["sha256"] = serde_json::json!(digest);
        v.to_string()
    };
    admin_identity_v2_upgrade_oracle::digest_is_current(&owner, &older).await?;
    let error = admin_identity_v2_upgrade_oracle::report_matches_fresh(&older, &body)
        .expect_err("an out-of-date but self-consistent report must be rejected");
    assert!(
        error.to_string().contains("stale preflight report"),
        "{error}"
    );
    // The endpoint repeating the same wrong answer passes the freshness comparison, but not the
    // database's own count of users.
    admin_identity_v2_upgrade_oracle::report_matches_fresh(&older, &older)?;
    let error = admin_identity_v2_upgrade_oracle::facts_match_database(&owner, &older)
        .await
        .expect_err("a report with a wrong head count must be rejected");
    assert!(
        error.to_string().contains("stale preflight report"),
        "{error}"
    );
    admin_identity_v2_upgrade_oracle::facts_match_database(&owner, &body).await?;
    admin_identity_v2_upgrade_oracle::report_matches_fresh(&body, &body)?;

    let mut regenerated = report;
    regenerated["generatedAt"] = serde_json::json!("2000-01-01T00:00:00Z");
    admin_identity_v2_upgrade_oracle::digest_is_current(&owner, &regenerated.to_string()).await?;
    Ok(())
}

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
        const MARKER: &[u8] = b"rg.permissions";
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
    use setjoin_gateway::{
        admin_identity_v2::SourceSecrets, admin_identity_v2_upgrade::AdminIdentityV2UpgradeRoute,
        RouteTable,
    };
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };

    let _serial = admin_identity_v2_upgrade_oracle::SERIAL.lock().await;
    let Some(db) = Db::for_case("admin-identity-v2-upgrade-authority-fail-closed") else {
        return Ok(());
    };
    let owner = db.connect().await?;
    let a = fixture::account(&owner, "admin9-194").await?;
    let role_id: i64 = owner
        .query_one(
            "INSERT INTO admin_role_groups(name,permissions,domain_scope) VALUES($1,'{system.upgrade,identity.write}',NULL) RETURNING id",
            &[&format!("admin9-194-{}", a.user)],
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
        let worker =
            common::patient_exec(&db.dsn, 4)?.with_audit_keys("22".repeat(32), String::new());
        let route = AdminIdentityV2UpgradeRoute {
            exec,
            worker,
            keys: Arc::new(common::recovery_keys()),
            issuer: "mailserver".into(),
            secrets: SourceSecrets::new(|name| {
                (name == "DB_ENCRYPTION_KEY").then(|| "22".repeat(32))
            }),
            runtime: setjoin_admin_identity::idv2_upgrade::Runtime {
                expected_schema: setjoin_schema::MIGRATIONS.last().map_or(0, |m| m.0),
                worker_dsn: true,
                owner_dsn: true,
                direct_dsn: true,
                authserver: true,
            },
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
        let token = signed_admin_token(a.user, &["system.upgrade", "identity.write"]);
        let req = Request::builder()
            .method("GET")
            .uri("/api/admin/identity/v2/upgrade/status")
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
