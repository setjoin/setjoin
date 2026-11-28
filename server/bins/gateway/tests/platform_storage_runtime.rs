//! Remaining five F08 storage routes (#459), through the HTTP parity seam.
mod common;
mod platform_oracle;
#[tokio::test]
async fn status_success() -> Result<(), common::BoxError> {
    platform_oracle::jobs_storage::run("storage-status", "success").await
}

macro_rules! case {
    ($name:ident, $action:literal, $kind:literal) => {
        #[tokio::test]
        async fn $name() -> Result<(), common::BoxError> {
            platform_oracle::jobs_storage::run($action, $kind).await
        }
    };
}
case!(status_denied, "storage-status", "denied");
case!(status_scoped, "storage-status", "scoped");
case!(status_ignored_query, "storage-status", "ignored-query");
case!(status_mutant, "storage-status", "success-status-mutant");
case!(reconcile_success, "storage-reconcile", "success");

case!(reconcile_denied, "storage-reconcile", "denied");
case!(reconcile_scoped, "storage-reconcile", "scoped");
case!(reconcile_bad_id, "storage-reconcile", "bad-id");
case!(reconcile_missing, "storage-reconcile", "missing");
case!(reconcile_running, "storage-reconcile", "running");
case!(reconcile_bad_details, "storage-reconcile", "bad-details");
case!(reconcile_null_details, "storage-reconcile", "null-details");
case!(reconcile_repeat, "storage-reconcile", "repeat");
case!(
    reconcile_mutant,
    "storage-reconcile",
    "success-status-mutant"
);
case!(scan_success, "storage-dr-start", "success");

case!(migration_success, "storage-migration-start", "success");

case!(migration_transfer, "storage-migration-start", "transfer");

case!(cancel_success, "storage-migration-cancel", "success");

case!(
    cancel_drain_timeout,
    "storage-migration-cancel",
    "drain-timeout"
);

case!(status_multi, "storage-status", "multi");
case!(status_cluster_error, "storage-status", "cluster-error");
case!(status_directory_error, "storage-status", "dir-error");
case!(status_new_topology, "storage-status", "new-topology");
case!(status_http_error_json, "storage-status", "http-error-json");
case!(status_bucket_denied, "storage-status", "bucket-denied");
case!(scan_denied, "storage-dr-start", "denied");
case!(scan_scoped, "storage-dr-start", "scoped");
case!(scan_ignored_query, "storage-dr-start", "ignored-query");
case!(scan_repeat, "storage-dr-start", "repeat");
case!(scan_insert_error, "storage-dr-start", "insert-error");
case!(scan_list_error, "storage-dr-start", "list-error");
case!(scan_one_run, "storage-dr-start", "one-run");
case!(scan_mutant, "storage-dr-start", "success-status-mutant");
case!(migration_denied, "storage-migration-start", "denied");
case!(migration_scoped, "storage-migration-start", "scoped");
case!(
    migration_missing_target,
    "storage-migration-start",
    "no-target"
);
case!(
    migration_same_target,
    "storage-migration-start",
    "same-target"
);
case!(
    migration_unknown_target,
    "storage-migration-start",
    "unknown-target"
);
case!(migration_repeat, "storage-migration-start", "repeat");
case!(migration_skip_verified, "storage-migration-start", "skip");
case!(
    migration_repair_corrupt,
    "storage-migration-start",
    "repair"
);
case!(
    migration_corrupt_source,
    "storage-migration-start",
    "corrupt-source"
);
case!(migration_backup_s3, "storage-migration-start", "backup-s3");
case!(migration_oss, "storage-migration-start", "oss");
case!(migration_one_run, "storage-migration-start", "one-run");
case!(
    migration_mutant,
    "storage-migration-start",
    "transfer-status-mutant"
);
case!(cancel_denied, "storage-migration-cancel", "denied");
case!(cancel_scoped, "storage-migration-cancel", "scoped");
case!(cancel_bad_id, "storage-migration-cancel", "bad-id");
case!(cancel_missing, "storage-migration-cancel", "missing");
case!(cancel_terminal, "storage-migration-cancel", "terminal");
case!(cancel_cutover, "storage-migration-cancel", "cutover");
case!(cancel_orphan, "storage-migration-cancel", "orphan");
case!(cancel_repeat, "storage-migration-cancel", "repeat");
case!(
    cancel_mutant,
    "storage-migration-cancel",
    "success-status-mutant"
);

case!(
    migration_backup_http_io,
    "storage-migration-start",
    "backup-s3-http-io"
);
case!(
    migration_backup_env_region,
    "storage-migration-start",
    "backup-s3-env-region"
);
case!(migration_oss_scope, "storage-migration-start", "oss-scope");
case!(
    migration_closed_admission,
    "storage-migration-start",
    "native-closed"
);

case!(
    migration_invalid_utf8_target,
    "storage-migration-start",
    "invalid-utf8-target"
);

case!(scan_cursor_error, "storage-dr-start", "cursor-error");

/// Existing backup callers must not inherit migration's AWS SDK transport tags.
/// The peer authenticates real requests and rejects any unexpected query string.
#[tokio::test]
async fn backup_defaults_preserve_signed_object_io() -> Result<(), common::BoxError> {
    use http_body_util::BodyExt as _;
    use hyper::{Method, Response};
    use std::sync::{Arc, Mutex};
    let operations = Arc::new(Mutex::new(Vec::new()));
    let seen = operations.clone();
    let peer = common::fake_upstream(move |mut request| {
        let seen = seen.clone();
        async move {
            let bytes = request.body_mut().collect().await.unwrap().to_bytes();
            let accepted = common::s3::observe(&request, &bytes).is_ok()
                && request.uri().path() == "/backup/object";
            seen.lock()
                .unwrap()
                .push((request.method().clone(), accepted));
            if !accepted {
                return Response::builder()
                    .status(400)
                    .body(common::full("unexpected signed request"))
                    .unwrap();
            }
            match *request.method() {
                Method::GET => Response::new(common::full("blob")),
                Method::HEAD => Response::builder()
                    .header("content-length", "4")
                    .body(common::full(""))
                    .unwrap(),
                Method::PUT => {
                    assert_eq!(&bytes[..], b"blob");
                    Response::new(common::full(""))
                }
                Method::DELETE => Response::new(common::full("")),
                _ => panic!("unexpected object operation"),
            }
        }
    })
    .await;
    for provider in ["s3", "backup_s3"] {
        let store = setjoin_backup::store::Store::driver(
            provider,
            &format!("http://{peer}"),
            "us-east-1",
            "backup",
            "test-access",
            "test-secret",
        )?;
        store.put("object", b"blob".to_vec()).await?;
        assert_eq!(store.get("object", 4).await?, b"blob");
        assert_eq!(store.head("object").await?, 4);
        store.delete("object").await?;
        // Sensitivity check: a migration profile at this seam must be refused.
        assert!(store
            .with_aws_operation_query()
            .get("object", 4)
            .await
            .is_err());
    }
    let expected = [
        (Method::PUT, true),
        (Method::GET, true),
        (Method::HEAD, true),
        (Method::DELETE, true),
        (Method::GET, false),
    ]
    .into_iter()
    .cycle()
    .take(10)
    .collect::<Vec<_>>();
    assert_eq!(*operations.lock().unwrap(), expected);
    Ok(())
}
