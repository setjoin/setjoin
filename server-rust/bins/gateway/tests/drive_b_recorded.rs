//! #275: frozen-Go HTTP, committed rows and notifications at spec seams.
mod common;
#[path = "common/drive_b_wire.rs"]
mod drive_wire;
#[path = "common/office_fixture.rs"]
mod fixture;
#[path = "common/drive_b_observation.rs"]
mod observation;
#[path = "common/drive_b_s3.rs"]
mod storage_wire;
use common::BoxError;
/// A CPU-starved shared host can exceed the adapter's default 1 s pool wait / 2 s
/// statement deadline, which forwards the request to Go and masquerades as a parity
/// failure (#421, as #368). Only the deadlines are widened; every assertion is unchanged.
fn patient_exec(dsn: &str, size: usize) -> Result<setjoin_pg::ScopedExecutor, BoxError> {
    let patient = std::time::Duration::from_secs(30);
    Ok(setjoin_pg::ScopedExecutor::from_dsn_with(
        dsn,
        size,
        setjoin_pg::Timeouts {
            pool_wait: patient,
            create: patient,
            statement: patient,
        },
    )
    .map_err(|e| e.0)?)
}

static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
use futures_util::FutureExt;
use hyper::{Request, Response};
use serde_json::{json, Value};
use setjoin_conformance::harness::Db;
use setjoin_gateway::{Config, Gateway, RouteTable, TrustedProxies};

#[tokio::test]
async fn activity_success() -> Result<(), BoxError> {
    run("activity", "success", false).await
}

#[tokio::test]
async fn activity_foreign() -> Result<(), BoxError> {
    run("activity", "foreign", false).await
}
#[tokio::test]
async fn activity_invalid() -> Result<(), BoxError> {
    run("activity", "invalid", false).await
}

#[tokio::test]
async fn search_success() -> Result<(), BoxError> {
    run("search", "success", false).await
}

#[tokio::test]
async fn create_branch_success() -> Result<(), BoxError> {
    run("create_branch", "success", false).await
}

#[tokio::test]
async fn list_versions_success() -> Result<(), BoxError> {
    run("list_versions", "success", false).await
}

#[tokio::test]
async fn list_branches_success() -> Result<(), BoxError> {
    run("list_branches", "success", false).await
}

#[tokio::test]
async fn set_label_success() -> Result<(), BoxError> {
    run("set_label", "success", false).await
}

#[tokio::test]
async fn remove_label_success() -> Result<(), BoxError> {
    run("remove_label", "success", false).await
}

#[tokio::test]
async fn resolve_branch_success() -> Result<(), BoxError> {
    run("resolve_branch", "success", false).await
}

#[tokio::test]
async fn audit_actions_success() -> Result<(), BoxError> {
    run("audit_actions", "success", false).await
}

#[tokio::test]
async fn create_alarm_success() -> Result<(), BoxError> {
    run("create_alarm", "success", false).await
}

#[tokio::test]
async fn delete_alarm_success() -> Result<(), BoxError> {
    run("delete_alarm", "success", false).await
}

#[tokio::test]
async fn patch_branch_success() -> Result<(), BoxError> {
    run("patch_branch", "success", false).await
}

#[tokio::test]
async fn update_alarm_success() -> Result<(), BoxError> {
    run("update_alarm", "success", false).await
}

#[tokio::test]
async fn list_alarms_success() -> Result<(), BoxError> {
    run("list_alarms", "success", false).await
}

#[tokio::test]
async fn verify_audit_success() -> Result<(), BoxError> {
    run("verify_audit", "success", false).await
}

#[tokio::test]
async fn trash_success() -> Result<(), BoxError> {
    run("trash", "success", false).await
}

#[tokio::test]
async fn purge_restore_success() -> Result<(), BoxError> {
    run("purge_restore", "success", false).await
}

#[tokio::test]
async fn office_choices_success() -> Result<(), BoxError> {
    run("office_choices", "success", false).await
}

#[tokio::test]
async fn office_local_open_success() -> Result<(), BoxError> {
    run("office_local_open", "success", false).await
}

#[tokio::test]
async fn office_revoke_success() -> Result<(), BoxError> {
    run("office_revoke", "success", false).await
}

#[tokio::test]
async fn history_success() -> Result<(), BoxError> {
    run("history", "success", false).await
}

#[tokio::test]
async fn audit_success() -> Result<(), BoxError> {
    run("audit", "success", false).await
}

#[tokio::test]
async fn put_version_success() -> Result<(), BoxError> {
    run("put_version", "success", false).await
}

#[tokio::test]
async fn restore_version_success() -> Result<(), BoxError> {
    run("restore_version", "success", false).await
}

#[tokio::test]
async fn office_launch_success() -> Result<(), BoxError> {
    run("office_launch", "success", false).await
}

#[tokio::test]
async fn request_export_success() -> Result<(), BoxError> {
    run("request_export", "success", false).await
}

#[tokio::test]
async fn content_success() -> Result<(), BoxError> {
    run("content", "success", false).await
}

#[tokio::test]
async fn consume_export_success() -> Result<(), BoxError> {
    run("consume_export", "success", false).await
}

#[tokio::test]
async fn activity_rejects_status() -> Result<(), BoxError> {
    let error = run("activity", "success", true)
        .await
        .expect_err("mutant escaped golden")
        .to_string();
    if !error.contains("/response/status:") {
        return Err(error.into());
    }
    println!(
        "{}",
        "MUTANT-REJECTED: GET /drive/spaces/{id}/activity :: changed-status"
    );
    Ok(())
}

#[tokio::test]
async fn audit_foreign() -> Result<(), BoxError> {
    run("audit", "foreign", false).await
}

#[tokio::test]
async fn audit_invalid() -> Result<(), BoxError> {
    run("audit", "invalid", false).await
}

#[tokio::test]
async fn audit_rejects_status() -> Result<(), BoxError> {
    let error = run("audit", "success", true)
        .await
        .expect_err("mutant escaped golden")
        .to_string();
    if !error.contains("/response/status:") {
        return Err(error.into());
    }
    println!("{}", "MUTANT-REJECTED: GET /drive/audit :: changed-status");
    Ok(())
}

#[tokio::test]
async fn audit_actions_foreign() -> Result<(), BoxError> {
    run("audit_actions", "foreign", false).await
}

#[tokio::test]
async fn audit_actions_invalid() -> Result<(), BoxError> {
    run("audit_actions", "invalid", false).await
}

#[tokio::test]
async fn audit_actions_rejects_status() -> Result<(), BoxError> {
    let error = run("audit_actions", "success", true)
        .await
        .expect_err("mutant escaped golden")
        .to_string();
    if !error.contains("/response/status:") {
        return Err(error.into());
    }
    println!(
        "{}",
        "MUTANT-REJECTED: GET /drive/audit-actions :: changed-status"
    );
    Ok(())
}

#[tokio::test]
async fn consume_export_foreign() -> Result<(), BoxError> {
    run("consume_export", "foreign", false).await
}

#[tokio::test]
async fn consume_export_invalid() -> Result<(), BoxError> {
    run("consume_export", "invalid", false).await
}

#[tokio::test]
async fn consume_export_repeat() -> Result<(), BoxError> {
    run("consume_export", "repeat", false).await
}

#[tokio::test]
async fn consume_export_rejects_status() -> Result<(), BoxError> {
    let error = run("consume_export", "success", true)
        .await
        .expect_err("mutant escaped golden")
        .to_string();
    if !error.contains("/response/status:") {
        return Err(error.into());
    }
    println!(
        "{}",
        "MUTANT-REJECTED: GET /drive/export/{token} :: changed-status"
    );
    Ok(())
}

#[tokio::test]
async fn content_foreign() -> Result<(), BoxError> {
    run("content", "foreign", false).await
}

#[tokio::test]
async fn content_invalid() -> Result<(), BoxError> {
    run("content", "invalid", false).await
}

#[tokio::test]
async fn content_repeat() -> Result<(), BoxError> {
    run("content", "repeat", false).await
}

#[tokio::test]
async fn content_rejects_status() -> Result<(), BoxError> {
    let error = run("content", "success", true)
        .await
        .expect_err("mutant escaped golden")
        .to_string();
    if !error.contains("/response/status:") {
        return Err(error.into());
    }
    println!(
        "{}",
        "MUTANT-REJECTED: GET /drive/versions/{id}/content :: changed-status"
    );
    Ok(())
}

#[tokio::test]
async fn create_alarm_foreign() -> Result<(), BoxError> {
    run("create_alarm", "foreign", false).await
}

#[tokio::test]
async fn create_alarm_invalid() -> Result<(), BoxError> {
    run("create_alarm", "invalid", false).await
}

#[tokio::test]
async fn create_alarm_repeat() -> Result<(), BoxError> {
    run("create_alarm", "repeat", false).await
}

#[tokio::test]
async fn create_alarm_rejects_status() -> Result<(), BoxError> {
    let error = run("create_alarm", "success", true)
        .await
        .expect_err("mutant escaped golden")
        .to_string();
    if !error.contains("/response/status:") {
        return Err(error.into());
    }
    println!(
        "{}",
        "MUTANT-REJECTED: POST /drive/audit-alarms :: changed-status"
    );
    Ok(())
}

#[tokio::test]
async fn create_branch_foreign() -> Result<(), BoxError> {
    run("create_branch", "foreign", false).await
}

#[tokio::test]
async fn create_branch_invalid() -> Result<(), BoxError> {
    run("create_branch", "invalid", false).await
}

#[tokio::test]
async fn create_branch_repeat() -> Result<(), BoxError> {
    run("create_branch", "repeat", false).await
}

#[tokio::test]
async fn create_branch_rejects_status() -> Result<(), BoxError> {
    let error = run("create_branch", "success", true)
        .await
        .expect_err("mutant escaped golden")
        .to_string();
    if !error.contains("/response/status:") {
        return Err(error.into());
    }
    println!(
        "{}",
        "MUTANT-REJECTED: POST /drive/files/{id}/branches :: changed-status"
    );
    Ok(())
}

#[tokio::test]
async fn delete_alarm_foreign() -> Result<(), BoxError> {
    run("delete_alarm", "foreign", false).await
}

#[tokio::test]
async fn delete_alarm_invalid() -> Result<(), BoxError> {
    run("delete_alarm", "invalid", false).await
}

#[tokio::test]
async fn delete_alarm_repeat() -> Result<(), BoxError> {
    run("delete_alarm", "repeat", false).await
}

#[tokio::test]
async fn delete_alarm_rejects_status() -> Result<(), BoxError> {
    let error = run("delete_alarm", "success", true)
        .await
        .expect_err("mutant escaped golden")
        .to_string();
    if !error.contains("/response/status:") {
        return Err(error.into());
    }
    println!(
        "{}",
        "MUTANT-REJECTED: DELETE /drive/audit-alarms/{id} :: changed-status"
    );
    Ok(())
}

#[tokio::test]
async fn history_foreign() -> Result<(), BoxError> {
    run("history", "foreign", false).await
}

#[tokio::test]
async fn history_invalid() -> Result<(), BoxError> {
    run("history", "invalid", false).await
}

#[tokio::test]
async fn history_rejects_status() -> Result<(), BoxError> {
    let error = run("history", "success", true)
        .await
        .expect_err("mutant escaped golden")
        .to_string();
    if !error.contains("/response/status:") {
        return Err(error.into());
    }
    println!(
        "{}",
        "MUTANT-REJECTED: GET /drive/files/{id}/history :: changed-status"
    );
    Ok(())
}

#[tokio::test]
async fn list_alarms_foreign() -> Result<(), BoxError> {
    run("list_alarms", "foreign", false).await
}

#[tokio::test]
async fn list_alarms_invalid() -> Result<(), BoxError> {
    run("list_alarms", "invalid", false).await
}

#[tokio::test]
async fn list_alarms_rejects_status() -> Result<(), BoxError> {
    let error = run("list_alarms", "success", true)
        .await
        .expect_err("mutant escaped golden")
        .to_string();
    if !error.contains("/response/status:") {
        return Err(error.into());
    }
    println!(
        "{}",
        "MUTANT-REJECTED: GET /drive/audit-alarms :: changed-status"
    );
    Ok(())
}

#[tokio::test]
async fn list_branches_foreign() -> Result<(), BoxError> {
    run("list_branches", "foreign", false).await
}

#[tokio::test]
async fn list_branches_invalid() -> Result<(), BoxError> {
    run("list_branches", "invalid", false).await
}

#[tokio::test]
async fn list_branches_rejects_status() -> Result<(), BoxError> {
    let error = run("list_branches", "success", true)
        .await
        .expect_err("mutant escaped golden")
        .to_string();
    if !error.contains("/response/status:") {
        return Err(error.into());
    }
    println!(
        "{}",
        "MUTANT-REJECTED: GET /drive/files/{id}/branches :: changed-status"
    );
    Ok(())
}

#[tokio::test]
async fn list_versions_foreign() -> Result<(), BoxError> {
    run("list_versions", "foreign", false).await
}

#[tokio::test]
async fn list_versions_invalid() -> Result<(), BoxError> {
    run("list_versions", "invalid", false).await
}

#[tokio::test]
async fn list_versions_rejects_status() -> Result<(), BoxError> {
    let error = run("list_versions", "success", true)
        .await
        .expect_err("mutant escaped golden")
        .to_string();
    if !error.contains("/response/status:") {
        return Err(error.into());
    }
    println!(
        "{}",
        "MUTANT-REJECTED: GET /drive/files/{id}/versions :: changed-status"
    );
    Ok(())
}

#[tokio::test]
async fn office_choices_foreign() -> Result<(), BoxError> {
    run("office_choices", "foreign", false).await
}

#[tokio::test]
async fn office_choices_invalid() -> Result<(), BoxError> {
    run("office_choices", "invalid", false).await
}

#[tokio::test]
async fn office_choices_rejects_status() -> Result<(), BoxError> {
    let error = run("office_choices", "success", true)
        .await
        .expect_err("mutant escaped golden")
        .to_string();
    if !error.contains("/response/status:") {
        return Err(error.into());
    }
    println!(
        "{}",
        "MUTANT-REJECTED: GET /drive/files/{id}/office/choices :: changed-status"
    );
    Ok(())
}

#[tokio::test]
async fn office_launch_foreign() -> Result<(), BoxError> {
    run("office_launch", "foreign", false).await
}

#[tokio::test]
async fn office_launch_invalid() -> Result<(), BoxError> {
    run("office_launch", "invalid", false).await
}

#[tokio::test]
async fn office_launch_repeat() -> Result<(), BoxError> {
    run("office_launch", "repeat", false).await
}

#[tokio::test]
async fn office_launch_rejects_status() -> Result<(), BoxError> {
    let error = run("office_launch", "success", true)
        .await
        .expect_err("mutant escaped golden")
        .to_string();
    if !error.contains("/response/status:") {
        return Err(error.into());
    }
    println!(
        "{}",
        "MUTANT-REJECTED: POST /drive/files/{id}/office/launches :: changed-status"
    );
    Ok(())
}

#[tokio::test]
async fn office_local_open_foreign() -> Result<(), BoxError> {
    run("office_local_open", "foreign", false).await
}

#[tokio::test]
async fn office_local_open_invalid() -> Result<(), BoxError> {
    run("office_local_open", "invalid", false).await
}

#[tokio::test]
async fn office_local_open_repeat() -> Result<(), BoxError> {
    run("office_local_open", "repeat", false).await
}

#[tokio::test]
async fn office_local_open_rejects_status() -> Result<(), BoxError> {
    let error = run("office_local_open", "success", true)
        .await
        .expect_err("mutant escaped golden")
        .to_string();
    if !error.contains("/response/status:") {
        return Err(error.into());
    }
    println!(
        "{}",
        "MUTANT-REJECTED: POST /drive/files/{id}/office/local-open :: changed-status"
    );
    Ok(())
}

#[tokio::test]
async fn office_revoke_foreign() -> Result<(), BoxError> {
    run("office_revoke", "foreign", false).await
}

#[tokio::test]
async fn office_revoke_invalid() -> Result<(), BoxError> {
    run("office_revoke", "invalid", false).await
}

#[tokio::test]
async fn office_revoke_repeat() -> Result<(), BoxError> {
    run("office_revoke", "repeat", false).await
}

#[tokio::test]
async fn office_revoke_rejects_status() -> Result<(), BoxError> {
    let error = run("office_revoke", "success", true)
        .await
        .expect_err("mutant escaped golden")
        .to_string();
    if !error.contains("/response/status:") {
        return Err(error.into());
    }
    println!(
        "{}",
        "MUTANT-REJECTED: DELETE /drive/files/{id}/office/launches/{launchId} :: changed-status"
    );
    Ok(())
}

#[tokio::test]
async fn patch_branch_foreign() -> Result<(), BoxError> {
    run("patch_branch", "foreign", false).await
}

#[tokio::test]
async fn patch_branch_invalid() -> Result<(), BoxError> {
    run("patch_branch", "invalid", false).await
}

#[tokio::test]
async fn patch_branch_repeat() -> Result<(), BoxError> {
    run("patch_branch", "repeat", false).await
}

#[tokio::test]
async fn patch_branch_rejects_status() -> Result<(), BoxError> {
    let error = run("patch_branch", "success", true)
        .await
        .expect_err("mutant escaped golden")
        .to_string();
    if !error.contains("/response/status:") {
        return Err(error.into());
    }
    println!(
        "{}",
        "MUTANT-REJECTED: PATCH /drive/branches/{id} :: changed-status"
    );
    Ok(())
}

#[tokio::test]
async fn purge_restore_foreign() -> Result<(), BoxError> {
    run("purge_restore", "foreign", false).await
}

#[tokio::test]
async fn purge_restore_invalid() -> Result<(), BoxError> {
    run("purge_restore", "invalid", false).await
}

#[tokio::test]
async fn purge_restore_repeat() -> Result<(), BoxError> {
    run("purge_restore", "repeat", false).await
}

#[tokio::test]
async fn purge_restore_rejects_status() -> Result<(), BoxError> {
    let error = run("purge_restore", "success", true)
        .await
        .expect_err("mutant escaped golden")
        .to_string();
    if !error.contains("/response/status:") {
        return Err(error.into());
    }
    println!(
        "{}",
        "MUTANT-REJECTED: POST /drive/nodes/{id}/purge-restore :: changed-status"
    );
    Ok(())
}

#[tokio::test]
async fn put_version_foreign() -> Result<(), BoxError> {
    run("put_version", "foreign", false).await
}

#[tokio::test]
async fn put_version_invalid() -> Result<(), BoxError> {
    run("put_version", "invalid", false).await
}

#[tokio::test]
async fn put_version_repeat() -> Result<(), BoxError> {
    run("put_version", "repeat", false).await
}

#[tokio::test]
async fn put_version_rejects_status() -> Result<(), BoxError> {
    let error = run("put_version", "success", true)
        .await
        .expect_err("mutant escaped golden")
        .to_string();
    if !error.contains("/response/status:") {
        return Err(error.into());
    }
    println!(
        "{}",
        "MUTANT-REJECTED: POST /drive/files/{id}/versions :: changed-status"
    );
    Ok(())
}

#[tokio::test]
async fn remove_label_foreign() -> Result<(), BoxError> {
    run("remove_label", "foreign", false).await
}

#[tokio::test]
async fn remove_label_invalid() -> Result<(), BoxError> {
    run("remove_label", "invalid", false).await
}

#[tokio::test]
async fn remove_label_repeat() -> Result<(), BoxError> {
    run("remove_label", "repeat", false).await
}

#[tokio::test]
async fn remove_label_rejects_status() -> Result<(), BoxError> {
    let error = run("remove_label", "success", true)
        .await
        .expect_err("mutant escaped golden")
        .to_string();
    if !error.contains("/response/status:") {
        return Err(error.into());
    }
    println!(
        "{}",
        "MUTANT-REJECTED: DELETE /drive/versions/{id}/labels/{label} :: changed-status"
    );
    Ok(())
}

#[tokio::test]
async fn request_export_foreign() -> Result<(), BoxError> {
    run("request_export", "foreign", false).await
}

#[tokio::test]
async fn request_export_invalid() -> Result<(), BoxError> {
    run("request_export", "invalid", false).await
}

#[tokio::test]
async fn request_export_repeat() -> Result<(), BoxError> {
    run("request_export", "repeat", false).await
}

#[tokio::test]
async fn request_export_rejects_status() -> Result<(), BoxError> {
    let error = run("request_export", "success", true)
        .await
        .expect_err("mutant escaped golden")
        .to_string();
    if !error.contains("/response/status:") {
        return Err(error.into());
    }
    println!(
        "{}",
        "MUTANT-REJECTED: POST /drive/export :: changed-status"
    );
    Ok(())
}

#[tokio::test]
async fn resolve_branch_foreign() -> Result<(), BoxError> {
    run("resolve_branch", "foreign", false).await
}

#[tokio::test]
async fn resolve_branch_invalid() -> Result<(), BoxError> {
    run("resolve_branch", "invalid", false).await
}

#[tokio::test]
async fn resolve_branch_repeat() -> Result<(), BoxError> {
    run("resolve_branch", "repeat", false).await
}

#[tokio::test]
async fn resolve_branch_rejects_status() -> Result<(), BoxError> {
    let error = run("resolve_branch", "success", true)
        .await
        .expect_err("mutant escaped golden")
        .to_string();
    if !error.contains("/response/status:") {
        return Err(error.into());
    }
    println!(
        "{}",
        "MUTANT-REJECTED: POST /drive/branches/{id}/resolve :: changed-status"
    );
    Ok(())
}

#[tokio::test]
async fn restore_version_foreign() -> Result<(), BoxError> {
    run("restore_version", "foreign", false).await
}

#[tokio::test]
async fn restore_version_invalid() -> Result<(), BoxError> {
    run("restore_version", "invalid", false).await
}

#[tokio::test]
async fn restore_version_repeat() -> Result<(), BoxError> {
    run("restore_version", "repeat", false).await
}

#[tokio::test]
async fn restore_version_rejects_status() -> Result<(), BoxError> {
    let error = run("restore_version", "success", true)
        .await
        .expect_err("mutant escaped golden")
        .to_string();
    if !error.contains("/response/status:") {
        return Err(error.into());
    }
    println!(
        "{}",
        "MUTANT-REJECTED: POST /drive/files/{id}/versions/{versionId}/restore :: changed-status"
    );
    Ok(())
}

#[tokio::test]
async fn search_foreign() -> Result<(), BoxError> {
    run("search", "foreign", false).await
}

#[tokio::test]
async fn search_invalid() -> Result<(), BoxError> {
    run("search", "invalid", false).await
}

#[tokio::test]
async fn search_rejects_status() -> Result<(), BoxError> {
    let error = run("search", "success", true)
        .await
        .expect_err("mutant escaped golden")
        .to_string();
    if !error.contains("/response/status:") {
        return Err(error.into());
    }
    println!("{}", "MUTANT-REJECTED: GET /drive/search :: changed-status");
    Ok(())
}

#[tokio::test]
async fn set_label_foreign() -> Result<(), BoxError> {
    run("set_label", "foreign", false).await
}

#[tokio::test]
async fn set_label_invalid() -> Result<(), BoxError> {
    run("set_label", "invalid", false).await
}

#[tokio::test]
async fn set_label_repeat() -> Result<(), BoxError> {
    run("set_label", "repeat", false).await
}

#[tokio::test]
async fn set_label_rejects_status() -> Result<(), BoxError> {
    let error = run("set_label", "success", true)
        .await
        .expect_err("mutant escaped golden")
        .to_string();
    if !error.contains("/response/status:") {
        return Err(error.into());
    }
    println!(
        "{}",
        "MUTANT-REJECTED: POST /drive/versions/{id}/labels :: changed-status"
    );
    Ok(())
}

#[tokio::test]
async fn trash_foreign() -> Result<(), BoxError> {
    run("trash", "foreign", false).await
}

#[tokio::test]
async fn trash_invalid() -> Result<(), BoxError> {
    run("trash", "invalid", false).await
}

#[tokio::test]
async fn trash_rejects_status() -> Result<(), BoxError> {
    let error = run("trash", "success", true)
        .await
        .expect_err("mutant escaped golden")
        .to_string();
    if !error.contains("/response/status:") {
        return Err(error.into());
    }
    println!(
        "{}",
        "MUTANT-REJECTED: GET /drive/spaces/{id}/trash :: changed-status"
    );
    Ok(())
}

#[tokio::test]
async fn update_alarm_foreign() -> Result<(), BoxError> {
    run("update_alarm", "foreign", false).await
}

#[tokio::test]
async fn update_alarm_invalid() -> Result<(), BoxError> {
    run("update_alarm", "invalid", false).await
}

#[tokio::test]
async fn update_alarm_repeat() -> Result<(), BoxError> {
    run("update_alarm", "repeat", false).await
}

#[tokio::test]
async fn update_alarm_rejects_status() -> Result<(), BoxError> {
    let error = run("update_alarm", "success", true)
        .await
        .expect_err("mutant escaped golden")
        .to_string();
    if !error.contains("/response/status:") {
        return Err(error.into());
    }
    println!(
        "{}",
        "MUTANT-REJECTED: PATCH /drive/audit-alarms/{id} :: changed-status"
    );
    Ok(())
}

#[tokio::test]
async fn verify_audit_foreign() -> Result<(), BoxError> {
    run("verify_audit", "foreign", false).await
}

#[tokio::test]
async fn verify_audit_invalid() -> Result<(), BoxError> {
    run("verify_audit", "invalid", false).await
}

#[tokio::test]
async fn verify_audit_rejects_status() -> Result<(), BoxError> {
    let error = run("verify_audit", "success", true)
        .await
        .expect_err("mutant escaped golden")
        .to_string();
    if !error.contains("/response/status:") {
        return Err(error.into());
    }
    println!(
        "{}",
        "MUTANT-REJECTED: GET /drive/spaces/{id}/audit/verify :: changed-status"
    );
    Ok(())
}

#[tokio::test]
async fn patch_branch_status() -> Result<(), BoxError> {
    run("patch_branch", "status", false).await
}

#[tokio::test]
async fn patch_branch_both() -> Result<(), BoxError> {
    run("patch_branch", "both", false).await
}

#[tokio::test]
async fn patch_branch_no_fields() -> Result<(), BoxError> {
    run("patch_branch", "no_fields", false).await
}

#[tokio::test]
async fn patch_branch_bad_field() -> Result<(), BoxError> {
    run("patch_branch", "bad_field", false).await
}

#[tokio::test]
async fn update_alarm_enabled() -> Result<(), BoxError> {
    run("update_alarm", "enabled", false).await
}

#[tokio::test]
async fn update_alarm_json_trailer() -> Result<(), BoxError> {
    run("update_alarm", "json_trailer", false).await
}

#[tokio::test]
async fn update_alarm_invalid_value() -> Result<(), BoxError> {
    run("update_alarm", "invalid_value", false).await
}

#[tokio::test]
async fn office_choices_electron() -> Result<(), BoxError> {
    run("office_choices", "electron", false).await
}

#[tokio::test]
async fn office_choices_bad_platform() -> Result<(), BoxError> {
    run("office_choices", "bad_platform", false).await
}

#[tokio::test]
async fn office_revoke_bad_launch() -> Result<(), BoxError> {
    run("office_revoke", "bad_launch", false).await
}

#[tokio::test]
async fn history_bad_limit() -> Result<(), BoxError> {
    run("history", "bad_limit", false).await
}

#[tokio::test]
async fn history_bad_cursor() -> Result<(), BoxError> {
    run("history", "bad_cursor", false).await
}

#[tokio::test]
async fn history_page() -> Result<(), BoxError> {
    run("history", "page", false).await
}

#[tokio::test]
async fn trash_missing_tier() -> Result<(), BoxError> {
    run("trash", "missing_tier", false).await
}

#[tokio::test]
async fn create_branch_encoded_id() -> Result<(), BoxError> {
    run("create_branch", "encoded_id", false).await
}

#[tokio::test]
async fn activity_bad_node() -> Result<(), BoxError> {
    run("activity", "bad_node", false).await
}

#[tokio::test]
async fn activity_bad_before() -> Result<(), BoxError> {
    run("activity", "bad_before", false).await
}

#[tokio::test]
async fn search_bad_max() -> Result<(), BoxError> {
    run("search", "bad_max", false).await
}

#[tokio::test]
async fn search_empty_query() -> Result<(), BoxError> {
    run("search", "empty_query", false).await
}

#[tokio::test]
async fn audit_bad_actor() -> Result<(), BoxError> {
    run("audit", "bad_actor", false).await
}

#[tokio::test]
async fn audit_bad_before() -> Result<(), BoxError> {
    run("audit", "bad_before", false).await
}

#[tokio::test]
async fn audit_bad_from() -> Result<(), BoxError> {
    run("audit", "bad_from", false).await
}

#[tokio::test]
async fn audit_bad_to() -> Result<(), BoxError> {
    run("audit", "bad_to", false).await
}

#[tokio::test]
async fn audit_bad_max() -> Result<(), BoxError> {
    run("audit", "bad_max", false).await
}

#[tokio::test]
async fn history_history_off() -> Result<(), BoxError> {
    run("history", "history_off", false).await
}

#[tokio::test]
async fn office_choices_office_off() -> Result<(), BoxError> {
    run("office_choices", "office_off", false).await
}

#[tokio::test]
async fn office_launch_office_off() -> Result<(), BoxError> {
    run("office_launch", "office_off", false).await
}

#[tokio::test]
async fn office_revoke_office_off() -> Result<(), BoxError> {
    run("office_revoke", "office_off", false).await
}

#[tokio::test]
async fn office_local_open_local_off() -> Result<(), BoxError> {
    run("office_local_open", "local_off", false).await
}

#[tokio::test]
async fn activity_feature_off() -> Result<(), BoxError> {
    run("activity", "feature_off", false).await
}

#[tokio::test]
async fn office_launch_invalid_editor() -> Result<(), BoxError> {
    run("office_launch", "invalid_editor", false).await
}

#[tokio::test]
async fn create_branch_large_trailer() -> Result<(), BoxError> {
    run("create_branch", "large_trailer", false).await
}

#[tokio::test]
async fn create_branch_oversize_value() -> Result<(), BoxError> {
    run("create_branch", "oversize_value", false).await
}

#[tokio::test]
async fn put_version_large_trailer() -> Result<(), BoxError> {
    run("put_version", "large_trailer", false).await
}

#[tokio::test]
async fn put_version_oversize_value() -> Result<(), BoxError> {
    run("put_version", "oversize_value", false).await
}

#[tokio::test]
async fn update_alarm_oversize_body() -> Result<(), BoxError> {
    run("update_alarm", "oversize_body", false).await
}

#[tokio::test]
async fn create_branch_bad_json() -> Result<(), BoxError> {
    run("create_branch", "bad_json", false).await
}

#[tokio::test]
async fn patch_branch_bad_json() -> Result<(), BoxError> {
    run("patch_branch", "bad_json", false).await
}

#[tokio::test]
async fn resolve_branch_bad_json() -> Result<(), BoxError> {
    run("resolve_branch", "bad_json", false).await
}

#[tokio::test]
async fn set_label_bad_json() -> Result<(), BoxError> {
    run("set_label", "bad_json", false).await
}

#[tokio::test]
async fn put_version_bad_json() -> Result<(), BoxError> {
    run("put_version", "bad_json", false).await
}

#[tokio::test]
async fn restore_version_bad_json() -> Result<(), BoxError> {
    run("restore_version", "bad_json", false).await
}

#[tokio::test]
async fn office_launch_bad_json() -> Result<(), BoxError> {
    run("office_launch", "bad_json", false).await
}

#[tokio::test]
async fn office_local_open_bad_json() -> Result<(), BoxError> {
    run("office_local_open", "bad_json", false).await
}

#[tokio::test]
async fn content_range() -> Result<(), BoxError> {
    run("content", "range", false).await
}

#[tokio::test]
async fn content_open_range() -> Result<(), BoxError> {
    run("content", "open_range", false).await
}

#[tokio::test]
async fn content_invalid_range() -> Result<(), BoxError> {
    run("content", "invalid_range", false).await
}

#[tokio::test]
async fn content_multi_range() -> Result<(), BoxError> {
    run("content", "multi_range", false).await
}

#[tokio::test]
async fn content_head() -> Result<(), BoxError> {
    run("content", "head", false).await
}

#[tokio::test]
async fn consume_export_head() -> Result<(), BoxError> {
    run("consume_export", "head", false).await
}

#[tokio::test]
async fn content_protected() -> Result<(), BoxError> {
    run("content", "protected", false).await
}

#[tokio::test]
async fn content_storage_missing() -> Result<(), BoxError> {
    run("content", "storage_missing", false).await
}

#[tokio::test]
async fn content_json_bytes() -> Result<(), BoxError> {
    run("content", "json_bytes", false).await
}

#[tokio::test]
async fn content_audit_repeat() -> Result<(), BoxError> {
    run("content", "audit_repeat", false).await
}

#[tokio::test]
async fn audit_csv() -> Result<(), BoxError> {
    run("audit", "csv", false).await
}

#[tokio::test]
async fn audit_csv_foreign() -> Result<(), BoxError> {
    run("audit", "csv_foreign", false).await
}

#[tokio::test]
async fn create_branch_language() -> Result<(), BoxError> {
    run("create_branch", "language", false).await
}

#[tokio::test]
async fn put_version_worm_success() -> Result<(), BoxError> {
    run("put_version", "worm_success", false).await
}

#[tokio::test]
async fn put_version_worm_failure() -> Result<(), BoxError> {
    run("put_version", "worm_failure", false).await
}

#[tokio::test]
async fn restore_version_worm_success() -> Result<(), BoxError> {
    run("restore_version", "worm_success", false).await
}

#[tokio::test]
async fn restore_version_worm_failure() -> Result<(), BoxError> {
    run("restore_version", "worm_failure", false).await
}

#[tokio::test]
async fn audit_csv_formula() -> Result<(), BoxError> {
    run("audit", "csv_formula", false).await
}

#[tokio::test]
async fn audit_csv_pages() -> Result<(), BoxError> {
    run("audit", "csv_pages", false).await
}

#[tokio::test]
async fn restore_version_whitespace() -> Result<(), BoxError> {
    run("restore_version", "whitespace", false).await
}

#[tokio::test]
async fn activity_fault() -> Result<(), BoxError> {
    run("activity", "fault", false).await
}

#[tokio::test]
async fn search_fault() -> Result<(), BoxError> {
    run("search", "fault", false).await
}

#[tokio::test]
async fn list_versions_fault() -> Result<(), BoxError> {
    run("list_versions", "fault", false).await
}

#[tokio::test]
async fn list_branches_fault() -> Result<(), BoxError> {
    run("list_branches", "fault", false).await
}

#[tokio::test]
async fn audit_actions_fault() -> Result<(), BoxError> {
    run("audit_actions", "fault", false).await
}

#[tokio::test]
async fn list_alarms_fault() -> Result<(), BoxError> {
    run("list_alarms", "fault", false).await
}

#[tokio::test]
async fn verify_audit_fault() -> Result<(), BoxError> {
    run("verify_audit", "fault", false).await
}

#[tokio::test]
async fn history_fault() -> Result<(), BoxError> {
    run("history", "fault", false).await
}

#[tokio::test]
async fn audit_fault() -> Result<(), BoxError> {
    run("audit", "fault", false).await
}

#[tokio::test]
async fn office_choices_fault() -> Result<(), BoxError> {
    run("office_choices", "fault", false).await
}

#[tokio::test]
async fn content_fault() -> Result<(), BoxError> {
    run("content", "fault", false).await
}

#[tokio::test]
async fn consume_export_fault() -> Result<(), BoxError> {
    run("consume_export", "fault", false).await
}

#[tokio::test]
async fn create_branch_audit_fault() -> Result<(), BoxError> {
    run("create_branch", "audit_fault", false).await
}

#[tokio::test]
async fn list_versions_partial_rows() -> Result<(), BoxError> {
    run("list_versions", "partial_rows", false).await
}

#[tokio::test]
async fn office_launch_editor_query() -> Result<(), BoxError> {
    run("office_launch", "editor_query", false).await
}

#[tokio::test]
async fn put_version_quota() -> Result<(), BoxError> {
    run("put_version", "quota", false).await
}

#[tokio::test]
async fn put_version_stale() -> Result<(), BoxError> {
    run("put_version", "stale", false).await
}

#[tokio::test]
async fn put_version_locked() -> Result<(), BoxError> {
    run("put_version", "locked", false).await
}

#[tokio::test]
async fn create_alarm_global() -> Result<(), BoxError> {
    run("create_alarm", "global", false).await
}

#[tokio::test]
async fn resolve_branch_ff() -> Result<(), BoxError> {
    run("resolve_branch", "ff", false).await
}

#[tokio::test]
async fn resolve_branch_adopt() -> Result<(), BoxError> {
    run("resolve_branch", "adopt", false).await
}

#[tokio::test]
async fn resolve_branch_keep_both() -> Result<(), BoxError> {
    run("resolve_branch", "keep_both", false).await
}

#[tokio::test]
async fn put_version_worm_bookkeeping() -> Result<(), BoxError> {
    run("put_version", "worm_bookkeeping", false).await
}

#[tokio::test]
async fn content_framing() -> Result<(), BoxError> {
    run("content", "framing", false).await
}

#[tokio::test]
async fn consume_export_framing() -> Result<(), BoxError> {
    run("consume_export", "framing", false).await
}

#[tokio::test]
async fn consume_export_head_framing() -> Result<(), BoxError> {
    run("consume_export", "head_framing", false).await
}

#[tokio::test]
async fn restore_version_bad_source() -> Result<(), BoxError> {
    run("restore_version", "bad_source", false).await
}

#[tokio::test]
async fn remove_label_invalid_utf8() -> Result<(), BoxError> {
    run("remove_label", "invalid_utf8", false).await
}

#[tokio::test]
async fn content_dirty_type() -> Result<(), BoxError> {
    run("content", "dirty_type", false).await
}

#[tokio::test]
async fn content_revoked() -> Result<(), BoxError> {
    run("content", "revoked", false).await
}

#[tokio::test]
async fn restore_version_oversize_whitespace() -> Result<(), BoxError> {
    run("restore_version", "oversize_whitespace", false).await
}

#[tokio::test]
async fn restore_version_whitespace_cap() -> Result<(), BoxError> {
    run("restore_version", "whitespace_cap", false).await
}

async fn run(route: &str, case: &str, mutant: bool) -> Result<(), BoxError> {
    run_variant(route, case, mutant, None).await
}
async fn run_variant(
    route: &str,
    case: &str,
    mutant: bool,
    mutation: Option<&str>,
) -> Result<(), BoxError> {
    let _serial = SERIAL.lock().await;
    let Some(db) = Db::for_case("drive3-http") else {
        return Ok(());
    };
    let original = db.connect().await?;
    let toggles=original.query("SELECT key,enabled FROM feature_toggles WHERE key IN('feature.drive','feature.drive_history','feature.drive_compliance','feature.office_editing','feature.office_local_open')",&[]).await?;
    let (c, mut s) = fixture::seed(&db).await?;
    c.execute(
        "UPDATE feature_toggles SET enabled=false WHERE key='feature.office_local_open'",
        &[],
    )
    .await?;
    c.execute(
        "UPDATE mailboxes SET used_bytes=20,sending_quota_reset_at=DATE '2026-11-01' WHERE id=$1",
        &[&s.account.mailbox],
    )
    .await?;
    let foreign = if matches!(case, "foreign" | "csv_foreign" | "locked" | "revoked") {
        Some(setjoin_conformance::fixture::account(&c, "drive3-foreign").await?)
    } else {
        None
    };
    let mut private_schema = None;
    let mut commit_wire = None;
    let mut partial_wire = None;
    let mut partial_armed = None;
    let mut race_task = None;
    let result = std::panic::AssertUnwindSafe(async {
    if case.starts_with("worm_"){c.batch_execute("UPDATE feature_toggles SET enabled=true WHERE key='feature.drive_compliance'").await?;s.space=c.query_one("SELECT drive_space_create($1,'Drive3 WORM','gxp',false,30,'governance')",&[&s.account.user]).await?.get(0);s.node=c.query_one("SELECT drive_node_create($1,$2,NULL,'file','governed.docx')",&[&s.account.user,&s.space]).await?.get(0);c.query_one("SELECT drive_chunk_register($1,$2,'84d89877f0d4041efb6bf91a16f0248f2fd573e6af05c19f96bedb9f882f7882',10)",&[&s.account.user,&s.space]).await?;let value:String=c.query_one("SELECT drive_file_put_version($1,$2,repeat('a',64),10,'application/octet-stream',NULL,'[{\"sha256\":\"84d89877f0d4041efb6bf91a16f0248f2fd573e6af05c19f96bedb9f882f7882\",\"size\":10}]'::jsonb,NULL,NULL)::text",&[&s.account.user,&s.node]).await?.get(0);s.version=serde_json::from_str::<Value>(&value)?["versionId"].as_i64().unwrap();c.execute("UPDATE mailboxes SET used_bytes=20 WHERE id=$1",&[&s.account.mailbox]).await?;}

        let _fixture_list_branches:i64=if route=="list_branches"{c.query_one("SELECT drive_branch_create($1,$2,'Fixture branch',$3)",&[&s.account.user,&s.node,&s.version]).await?.get(0)}else{0};
        let _fixture_remove_label:i64=if route=="remove_label"{{c.query_one("SELECT drive_version_label_set($1,$2,'Approved')",&[&s.account.user,&s.version]).await?;0}}else{0};
        let fixture_resolve_branch:i64=if route=="resolve_branch"{c.query_one("SELECT drive_branch_create($1,$2,'Fixture branch',$3)",&[&s.account.user,&s.node,&s.version]).await?.get(0)}else{0};
        let fixture_delete_alarm:i64=if route=="delete_alarm"{c.query_one("SELECT drive_alarm_create($1,$2,'branch.*',5,10)",&[&s.account.user,&s.space]).await?.get(0)}else{0};
        let fixture_patch_branch:i64=if route=="patch_branch"{c.query_one("SELECT drive_branch_create($1,$2,'Fixture branch',$3)",&[&s.account.user,&s.node,&s.version]).await?.get(0)}else{0};
        let fixture_update_alarm:i64=if route=="update_alarm"{c.query_one("SELECT drive_alarm_create($1,$2,'branch.*',5,10)",&[&s.account.user,&s.space]).await?.get(0)}else{0};
        let _fixture_list_alarms:i64=if route=="list_alarms"{c.query_one("SELECT drive_alarm_create($1,$2,'branch.*',5,10)",&[&s.account.user,&s.space]).await?.get(0)}else{0};
        let _fixture_trash:i64=if route=="trash"{{c.query_one("SELECT drive_node_trash($1,$2)",&[&s.account.user,&s.node]).await?;c.query_one("SELECT drive_node_destroy($1,$2)",&[&s.account.user,&s.node]).await?;0}}else{0};
        let _fixture_purge_restore:i64=if route=="purge_restore"{{c.query_one("SELECT drive_node_trash($1,$2)",&[&s.account.user,&s.node]).await?;c.query_one("SELECT drive_node_destroy($1,$2)",&[&s.account.user,&s.node]).await?;0}}else{0};
        let _fixture_office_local_open:i64=if route=="office_local_open"{{c.batch_execute("UPDATE feature_toggles SET enabled=true WHERE key='feature.office_local_open'").await?;0}}else{0};
        if route=="put_version"{c.query_one("SELECT drive_chunk_register($1,$2,'84d89877f0d4041efb6bf91a16f0248f2fd573e6af05c19f96bedb9f882f7882',10)",&[&s.account.user,&s.space]).await?;}
        if route=="consume_export"{use sha2::Digest;let hash=format!("{:x}",sha2::Sha256::digest(b"drive3-fixture-export"));c.query_one("SELECT drive_export_request($1,$2,'download',$3,60)",&[&s.account.user,&s.version,&hash]).await?;}
        let (method,mut path,canonical,mut wire,status_success)=match route{
        "consume_export"=>("GET","/api/drive/export/drive3-fixture-export".into(),"/drive/export/{token}",String::new(),200),
        "content"=>("GET",format!("/api/drive/versions/{}/content",s.version),"/drive/versions/{id}/content",String::new(),200),
"request_export"=>("POST",format!("/api/drive/export"),"/drive/export",json!({"versionId":s.version,"action":"download"}).to_string(),200),
"office_launch"=>("POST",format!("/api/drive/files/{}/office/launches",s.node),"/drive/files/{id}/office/launches",json!({"baseVersionId":s.version,"providerId":"office1","deviceId":"drive3-device"}).to_string(),201),
        "restore_version"=>("POST",format!("/api/drive/files/{}/versions/{}/restore",s.node,s.version),"/drive/files/{id}/versions/{versionId}/restore",String::new(),201),
        "put_version"=>("POST",format!("/api/drive/files/{}/versions",s.node),"/drive/files/{id}/versions",json!({"contentSha256":"b".repeat(64),"size":10,"baseVersionId":s.version,"manifest":[{"sha256":"84d89877f0d4041efb6bf91a16f0248f2fd573e6af05c19f96bedb9f882f7882","size":10}]}).to_string(),201),
"audit"=>("GET",format!("/api/drive/audit?space={}",s.space),"/drive/audit",String::new(),200),
"history"=>("GET",format!("/api/drive/files/{}/history",s.node),"/drive/files/{id}/history",String::new(),200),
"office_revoke"=>("DELETE",format!("/api/drive/files/{}/office/launches/{}",s.node,s.launch["launchId"].as_str().unwrap()),"/drive/files/{id}/office/launches/{launchId}",String::new(),200),
"office_local_open"=>("POST",format!("/api/drive/files/{}/office/local-open",s.node),"/drive/files/{id}/office/local-open",json!({"appId":"libreoffice","deviceId":"drive3-device"}).to_string(),200),
"office_choices"=>("GET",format!("/api/drive/files/{}/office/choices",s.node),"/drive/files/{id}/office/choices",String::new(),200),
"purge_restore"=>("POST",format!("/api/drive/nodes/{}/purge-restore",s.node),"/drive/nodes/{id}/purge-restore",String::new(),204),
"trash"=>("GET",format!("/api/drive/spaces/{}/trash?tier=2",s.space),"/drive/spaces/{id}/trash",String::new(),200),
"verify_audit"=>("GET",format!("/api/drive/spaces/{}/audit/verify",s.space),"/drive/spaces/{id}/audit/verify",String::new(),200),
"list_alarms"=>("GET",format!("/api/drive/audit-alarms"),"/drive/audit-alarms",String::new(),200),
"update_alarm"=>("PATCH",format!("/api/drive/audit-alarms/{}",fixture_update_alarm),"/drive/audit-alarms/{id}",json!({"threshold":7}).to_string(),204),
"patch_branch"=>("PATCH",format!("/api/drive/branches/{}",fixture_patch_branch),"/drive/branches/{id}",json!({"name":"Renamed"}).to_string(),204),
"delete_alarm"=>("DELETE",format!("/api/drive/audit-alarms/{}",fixture_delete_alarm),"/drive/audit-alarms/{id}",String::new(),204),
"create_alarm"=>("POST",format!("/api/drive/audit-alarms"),"/drive/audit-alarms",json!({"spaceId":s.space,"actionPattern":"branch.*"}).to_string(),201),
"audit_actions"=>("GET",format!("/api/drive/audit-actions"),"/drive/audit-actions",String::new(),200),
"resolve_branch"=>("POST",format!("/api/drive/branches/{}/resolve",fixture_resolve_branch),"/drive/branches/{id}/resolve",json!({"verb":"discard"}).to_string(),200),
"remove_label"=>("DELETE",format!("/api/drive/versions/{}/labels/Approved",s.version),"/drive/versions/{id}/labels/{label}",String::new(),204),
"set_label"=>("POST",format!("/api/drive/versions/{}/labels",s.version),"/drive/versions/{id}/labels",json!({"label":"Approved"}).to_string(),204),
"list_branches"=>("GET",format!("/api/drive/files/{}/branches",s.node),"/drive/files/{id}/branches",String::new(),200),
"list_versions"=>("GET",format!("/api/drive/files/{}/versions",s.node),"/drive/files/{id}/versions",String::new(),200),
            "create_branch"=>("POST",format!("/api/drive/files/{}/branches",s.node),"/drive/files/{id}/branches",json!({"name":"Review","fromVersionId":s.version}).to_string(),201),
            "search"=>("GET",format!("/api/drive/search?q=proposal{}",if case=="invalid"{"&space=bad"}else{""}),"/drive/search",String::new(),200),
            "activity"=>("GET",format!("/api/drive/spaces/{}/activity{}",s.space,if case=="invalid"{"?max=bad"}else{""}),"/drive/spaces/{id}/activity",String::new(),200),
            _=>return Err("unregistered oracle route".into())
        };
        let mut extra_headers=Vec::<(&str,String)>::new();
        if case=="invalid"&&!matches!(route,"activity"|"search"){
          if canonical.contains("{id}"){let mut parts:Vec<String>=path.split('/').map(str::to_owned).collect();parts[4]="invalid".into();path=parts.join("/");}
          else if matches!(method,"POST"|"PATCH"){wire="{".into();}
          else if route=="audit"{path="/api/drive/audit?space=bad".into();}
          else if route=="consume_export"{path="/api/drive/export/invalid".into();}
          else{path.push_str("?invalid=bad");}
        }
        if case=="foreign"&&!wire.is_empty(){let mut value:Value=serde_json::from_str(&wire)?;if value.is_object(){value["userId"]=json!(s.account.user);value["mailboxId"]=json!(s.account.mailbox);value["owner_user_id"]=json!(s.account.user);wire=value.to_string();}}
        if route=="patch_branch"&&case=="status"{wire=json!({"status":"review"}).to_string();}
        if route=="patch_branch"&&case=="both"{wire=json!({"name":"Renamed","status":"review"}).to_string();}
        if route=="patch_branch"&&case=="no_fields"{wire=json!({"unknown":true}).to_string();}
        if route=="patch_branch"&&case=="bad_field"{wire=json!({"name":3}).to_string();}
        if route=="update_alarm"&&case=="enabled"{wire=json!({"enabled":false}).to_string();}
        if route=="update_alarm"&&case=="json_trailer"{wire="{\"threshold\":7} {}".into();}
        if route=="update_alarm"&&case=="invalid_value"{wire=json!({"threshold":"abc"}).to_string();}
        if route=="office_choices"&&case=="electron"{path.push_str("?platform=electron");}
        if route=="office_choices"&&case=="bad_platform"{path.push_str("?platform=invalid");}
        if route=="office_revoke"&&case=="bad_launch"{path=path.rsplit_once('/').unwrap().0.to_owned()+"/invalid";}
        if route=="history"&&case=="bad_limit"{path.push_str("?limit=0");}
        if route=="history"&&case=="bad_cursor"{path.push_str("?cursor=invalid");}
        if route=="history"&&case=="page"{path.push_str("?limit=1");}
        if route=="trash"&&case=="missing_tier"{path=path.split('?').next().unwrap().to_owned();}
        if route=="create_branch"&&case=="encoded_id"{let mut parts:Vec<String>=path.split('/').map(str::to_owned).collect();parts[4].push_str("%2Fextra");path=parts.join("/");}
        if route=="activity"&&case=="bad_node"{path.push_str("?node=invalid");}
        if route=="activity"&&case=="bad_before"{path.push_str("?beforeId=invalid");}
        if route=="search"&&case=="bad_max"{path.push_str("&max=invalid");}
        if route=="search"&&case=="empty_query"{path="/api/drive/search?q=".into();}
        if route=="audit"&&case=="bad_actor"{path.push_str("&actor=invalid");}
        if route=="audit"&&case=="bad_before"{path.push_str("&beforeId=invalid");}
        if route=="audit"&&case=="bad_from"{path.push_str("&from=invalid");}
        if route=="audit"&&case=="bad_to"{path.push_str("&to=invalid");}
        if route=="audit"&&case=="bad_max"{path.push_str("&max=invalid");}
        if route=="history"&&case=="history_off"{c.batch_execute("UPDATE feature_toggles SET enabled=false WHERE key='feature.drive_history'").await?;}
        if route=="office_choices"&&case=="office_off"{c.batch_execute("UPDATE feature_toggles SET enabled=false WHERE key IN('feature.office_editing','feature.office_local_open')").await?;}
        if route=="office_launch"&&case=="office_off"{c.batch_execute("UPDATE feature_toggles SET enabled=false WHERE key='feature.office_editing'").await?;}
        if route=="office_revoke"&&case=="office_off"{c.batch_execute("UPDATE feature_toggles SET enabled=false WHERE key='feature.office_editing'").await?;}
        if route=="office_local_open"&&case=="local_off"{c.batch_execute("UPDATE feature_toggles SET enabled=false WHERE key='feature.office_local_open'").await?;}
        if route=="activity"&&case=="feature_off"{c.batch_execute("UPDATE feature_toggles SET enabled=false WHERE key='feature.drive'").await?;}
        if route=="office_launch"&&case=="invalid_editor"{c.batch_execute("UPDATE office_provider_policies SET config=config||'{\"editorUrl\":\"https://editor.test/%zz\"}'::jsonb WHERE provider_id='office1'").await?;}
        if route=="create_branch"&&case=="large_trailer"{wire.push_str(&" ".repeat(32<<10));}
        if route=="create_branch"&&case=="oversize_value"{let mut value:Value=serde_json::from_str(&wire)?;value["unknown"]=json!("x".repeat(17<<10));wire=value.to_string();}
        if route=="put_version"&&case=="large_trailer"{wire.push_str(&" ".repeat(2<<20));}
        if route=="put_version"&&case=="oversize_value"{let mut value:Value=serde_json::from_str(&wire)?;value["unknown"]=json!("x".repeat((1<<20)+1));wire=value.to_string();}
        if route=="update_alarm"&&case=="oversize_body"{wire.push_str(&" ".repeat(17<<10));}
        if route=="create_branch"&&case=="bad_json"{wire="{".into();}
        if route=="patch_branch"&&case=="bad_json"{wire="{".into();}
        if route=="resolve_branch"&&case=="bad_json"{wire="{".into();}
        if route=="set_label"&&case=="bad_json"{wire="{".into();}
        if route=="put_version"&&case=="bad_json"{wire="{".into();}
        if route=="restore_version"&&case=="bad_json"{wire="{".into();}
        if route=="office_launch"&&case=="bad_json"{wire="{".into();}
        if route=="office_local_open"&&case=="bad_json"{wire="{".into();}
        if route=="content"&&case=="range"{extra_headers.push(("range","bytes=2-5".into()));}
        if route=="content"&&case=="open_range"{extra_headers.push(("range","bytes=2-".into()));}
        if route=="content"&&case=="invalid_range"{extra_headers.push(("range","bytes=-3".into()));}
        if route=="content"&&case=="multi_range"{extra_headers.push(("range","bytes=0-1,4-5".into()));}
        if route=="content"&&case=="head"{extra_headers.push(("__method","HEAD".into()));}
        if route=="consume_export"&&case=="head"{extra_headers.push(("__method","HEAD".into()));}
        if route=="content"&&case=="protected"{c.query_one("SELECT drive_space_set_classification($1,$2,'secure')",&[&s.account.user,&s.space]).await?;}
        if route=="content"&&case=="storage_missing"{}
        if route=="content"&&case=="json_bytes"{}
        if route=="content"&&case=="audit_repeat"{c.execute("UPDATE drive_spaces SET export_policy='{\"audit_reads\":true}' WHERE id=$1",&[&s.space]).await?;}
        if route=="audit"&&case=="csv"{path.push_str("&format=csv");}
        if route=="audit"&&case=="csv_foreign"{path.push_str("&format=csv");}
        if route=="create_branch"&&case=="language"{wire="{".into();extra_headers.push(("accept-language","zh-Hans".into()));}
        if route=="put_version"&&case=="worm_failure"{}
        if route=="restore_version"&&case=="worm_success"{}
        if route=="restore_version"&&case=="worm_failure"{}
        if route=="audit"&&case=="csv_formula"{path.push_str("&format=csv");for note in ["=1+1","+SUM(1)","-1","@calc","\tformula","\rformula","'formula","comma,quote\"and\nnewline"]{c.query_one("SELECT drive_access_audit($1,$2,'view','version',$3,NULL,NULL,NULL,$4)",&[&s.account.user,&s.space,&s.version,&note]).await?;}}
        if route=="audit"&&case=="csv_pages"{path.push_str("&format=csv&max=1");c.query("SELECT drive_access_audit($1,$2,'view','version',$3,NULL,NULL,NULL,'page '||i) FROM generate_series(1,1001) i",&[&s.account.user,&s.space,&s.version]).await?;}
        if route=="restore_version"&&case=="whitespace"{wire=" \n\t".into();}
        if route=="list_versions"&&case=="partial_rows"{}
        if route=="office_launch"&&case=="editor_query"{c.execute("UPDATE office_provider_policies SET config=jsonb_set(config,'{editorUrl}',$1::text::jsonb) WHERE provider_id='office1'",&[&json!("https://editor.test/launch?tilde=~&plus=+&empty&=x&a=1&a=2&WOPISrc=old#fragment").to_string()]).await?;}
        if route=="put_version"&&case=="quota"{c.execute("UPDATE drive_spaces SET export_policy='{\"upload_max_bytes\":1}' WHERE id=$1",&[&s.space]).await?;}
        if route=="put_version"&&case=="stale"{c.query_one("SELECT drive_file_put_version($1,$2,repeat('b',64),10,NULL,$3,'[{\"sha256\":\"84d89877f0d4041efb6bf91a16f0248f2fd573e6af05c19f96bedb9f882f7882\",\"size\":10}]'::jsonb,NULL,NULL)",&[&s.account.user,&s.node,&s.version]).await?;}
        if route=="put_version"&&case=="locked"{let other=foreign.as_ref().unwrap();c.execute("INSERT INTO drive_space_members(space_id,user_id,role,granted_by) VALUES($1,$2,'editor',$3)",&[&s.space,&other.user,&s.account.user]).await?;c.query_one("SELECT drive_file_lock($1,$2,'hard')",&[&other.user,&s.node]).await?;}
        if route=="create_alarm"&&case=="global"{wire=json!({"actionPattern":"branch.*"}).to_string();}
        if route=="resolve_branch"&&case=="ff"{wire=json!({"verb":"ff"}).to_string();}
        if route=="resolve_branch"&&case=="adopt"{wire=json!({"verb":"adopt"}).to_string();}
        if route=="resolve_branch"&&case=="keep_both"{wire=json!({"verb":"keep_both"}).to_string();}
        if route=="put_version"&&case=="worm_bookkeeping"{}
        if route=="content"&&case=="framing"{extra_headers.push(("__framing","1".into()));}
        if route=="consume_export"&&case=="framing"{extra_headers.push(("__framing","1".into()));}
        if route=="consume_export"&&case=="head_framing"{extra_headers.push(("__framing","1".into()));extra_headers.push(("__method","HEAD".into()));}
        if route=="restore_version"&&case=="bad_source"{let mut parts:Vec<_>=path.split('/').collect();parts[6]="bad";path=parts.join("/");wire="{".into();}
        if route=="remove_label"&&case=="invalid_utf8"{c.query_one("SELECT drive_version_label_set($1,$2,$3)",&[&s.account.user,&s.version,&"\u{fffd}"]).await?;path=path.rsplit_once('/').unwrap().0.to_owned()+"/%FF";}
        if route=="content"&&case=="dirty_type"{c.execute("UPDATE drive_file_versions SET content_type=$1 WHERE id=$2",&[&"text/plain\r\nX-Drive-Probe: value",&s.version]).await?;}
        if case=="revoked"{let other=foreign.as_ref().unwrap();c.execute("INSERT INTO drive_space_members(space_id,user_id,role,granted_by) VALUES($1,$2,'editor',$3)",&[&s.space,&other.user,&s.account.user]).await?;c.execute("UPDATE drive_spaces SET export_policy='{\"audit_reads\":true}' WHERE id=$1",&[&s.space]).await?;}
        if route=="restore_version"&&case=="oversize_whitespace"{wire=" ".repeat((16<<10)+1);}
        if route=="restore_version"&&case=="whitespace_cap"{wire=" ".repeat(16<<10);}
        // EXTRA REQUESTS
        let io=std::sync::Arc::new(std::sync::Mutex::new(Vec::<Value>::new()));let observed=io.clone();let missing=case=="storage_missing";let content_bytes=if case=="json_bytes"{"{ \"a\": 1 }"}else{"0123456789"};
        let retention_fail=case=="worm_failure";let retention_space=s.space;let endpoint=common::fake_upstream(move|mut r|{let observed=observed.clone();async move{
          if r.uri().query()==Some("location="){return Response::new(common::full("<LocationConstraint>us-east-1</LocationConstraint>"));}
          use http_body_util::BodyExt;let body=r.body_mut().collect().await.unwrap().to_bytes();
          let is_object=r.uri().path().starts_with("/mailblobs/drive/");let range=r.headers().get("range").and_then(|v|v.to_str().ok()).map(str::to_owned);let method=r.method().clone();let path=r.uri().path().to_owned();
          if r.uri().query()==Some("retention="){storage_wire::observe(&r,&body).expect("retention SigV4");let xml=std::str::from_utf8(&body).unwrap();let mode=xml.split("<Mode>").nth(1).unwrap().split("</Mode>").next().unwrap();let until=xml.split("<RetainUntilDate>").nth(1).unwrap().split("</RetainUntilDate>").next().unwrap();let parsed=chrono::DateTime::parse_from_rfc3339(until).unwrap();assert!((parsed.with_timezone(&chrono::Utc)-chrono::Utc::now()-chrono::Duration::days(30)).num_seconds().abs()<60);observed.lock().unwrap().push(json!({"method":method.as_str(),"path":path.replace(&format!("/s{retention_space}/"),"/s<space>/"),"query":"retention=","mode":mode,"until":"<30-days>","signatureValid":true}));return Response::builder().status(if retention_fail{403}else{200}).body(common::full("")).unwrap()}
          if is_object{let signed=storage_wire::observe(&r,&body).is_ok();observed.lock().unwrap().push(json!({"method":method.as_str(),"path":path,"range":range,"signatureValid":signed}));if !signed{return Response::builder().status(403).body(common::full("invalid signature")).unwrap()}}
          if is_object&&missing{return Response::builder().status(404).body(common::full("missing object")).unwrap()}
          if let Some(range)=range{let(lo,hi)=range.strip_prefix("bytes=").unwrap().split_once('-').unwrap();let lo:usize=lo.parse().unwrap();let hi:usize=hi.parse().unwrap();return Response::builder().status(206).header("last-modified","Tue, 01 Sep 2026 00:00:00 GMT").header("etag","\"drive3-content\"").header("content-range",format!("bytes {lo}-{hi}/10")).body(common::full(content_bytes[lo..=hi].to_owned())).unwrap()}
          Response::builder().header("last-modified","Tue, 01 Sep 2026 00:00:00 GMT").header("etag","\"drive3-content\"").body(common::full(content_bytes)).unwrap()
        }}).await;
        let mut request_dsn=db.app.as_deref().unwrap_or(&db.dsn).to_owned();let mut oracle_db=Db{dsn:db.dsn.clone(),direct:db.direct.clone(),app:db.app.clone()};
        if let Some(kind)=mutation.or_else(||matches!(case,"fault"|"audit_fault"|"worm_bookkeeping"|"revoked").then_some(case)){let(schema,dsn)=plant_private(&c,&request_dsn,s.account.user,route,kind).await?;private_schema=Some(schema);request_dsn=dsn.clone();oracle_db.app=Some(dsn);}
        if matches!(case,"commit_before"|"commit_after"){ledger("Plan gofree-drive3 COMMIT proxy on the assigned request DB")?;let cut=if case=="commit_after"{common::commit::CommitCut::AfterCommit}else{common::commit::CommitCut::BeforeCommit};let(dsn,task)=common::commit::commit_cut_proxy(&request_dsn,cut).await;request_dsn=dsn;commit_wire=Some(task);}
        if case=="partial_rows"{ledger("Plan gofree-drive3 partial-row DB proxy")?;let(dsn,armed,task)=drive_wire::partial_rows(&request_dsn).await;request_dsn=dsn.clone();oracle_db.app=Some(dsn);partial_wire=Some(task);partial_armed=Some(armed);}
        let oracle = common::go_oracle::start_named(&oracle_db,endpoint,None,"gofree-drive3").await?;
        if let Some(schema)=private_schema.as_ref(){if matches!(case,"fault"|"audit_fault"|"worm_bookkeeping"|"revoked"){c.batch_execute(&format!("UPDATE {schema}.control SET armed=true")).await?;}}

        if let Some(armed)=partial_armed.as_ref(){armed.store(true,std::sync::atomic::Ordering::SeqCst);}
        let recording = oracle.is_some();
        if std::env::var_os("GOFREE_COVERAGE_PROBE").is_some(){assert!(recording,"covered Go recheck must have a Go oracle");println!("GO-ORACLE: {route} {case} {}",oracle.as_ref().unwrap().address);}
        io.lock().unwrap().clear();
        let adapter = setjoin_gateway::drive::DriveRoute {
            exec:patient_exec(&request_dsn,2)?.with_audit_keys("22".repeat(32),String::new()),
            worker:patient_exec(&db.dsn,2)?.with_audit_keys("22".repeat(32),String::new()),
            store:Some(std::sync::Arc::new(setjoin_gateway::recovery_worker::S3Store::new(&format!("http://{endpoint}"),"mailblobs","test-access","test-secret")?)),
            keys:std::sync::Arc::new(common::recovery_keys()),issuer:"mailserver".into()
        };
        let routes=if recording {RouteTable::proxy_all()} else if mutant{RouteTable::proxy_all().with(ChangedStatus(adapter))}else{RouteTable::proxy_all().with(adapter)};
        let gateway=Gateway::new(Config{upstream:oracle.as_ref().map(|o|format!("http://{}",o.address).parse()).transpose()?,trusted_proxies:TrustedProxies::parse("")?,upstream_header_timeout:setjoin_gateway::proxy::DEFAULT_HEADER_TIMEOUT,edge_limit:None},routes)?;
        let gateway=gateway;
        let listener=tokio::net::TcpListener::bind("127.0.0.1:0").await?;let addr=listener.local_addr()?;
        let task=tokio::spawn(gateway.serve(listener));
        let mut notifications=db.listen("drive").await?;
        let before=observation::snapshot(&c,&s).await?;
        let acting_foreign=matches!(case,"foreign"|"csv_foreign"|"revoked");let credential=fixture::token(if acting_foreign{foreign.as_ref().unwrap().user}else{s.account.user},!acting_foreign);
        if case=="revoked"{let gate=db.connect().await?;let key=i32::try_from(s.account.user)?;let other=foreign.as_ref().unwrap().user;let space=s.space;gate.query_one("SELECT pg_advisory_lock(7711,$1)",&[&key]).await?;ledger("Plan gofree-drive3 metadata revocation barrier, assigned actor/space only")?;race_task=Some(tokio::spawn(async move{let deadline=tokio::time::Instant::now()+std::time::Duration::from_secs(10);loop{let waiting:bool=gate.query_one("SELECT EXISTS(SELECT 1 FROM pg_locks WHERE locktype='advisory' AND classid=7711 AND objid=$1::int::oid AND NOT granted)",&[&key]).await?.get(0);if waiting{break}if tokio::time::Instant::now()>deadline{return Err::<(),BoxError>("metadata barrier was not reached".into())}tokio::time::sleep(std::time::Duration::from_millis(10)).await;}gate.execute("DELETE FROM drive_space_members WHERE space_id=$1 AND user_id=$2",&[&space,&other]).await?;gate.query_one("SELECT pg_advisory_unlock(7711,$1)",&[&key]).await?;Ok::<_,BoxError>(())}));}
        let mut response=capture(addr,method,&path,&credential,&wire,&extra_headers).await?;
        if let Some(task)=race_task.take(){task.await??;ledger("Reaped gofree-drive3 metadata revocation barrier")?;}
        let first=if matches!(case,"repeat"|"audit_repeat"){let first=response;response=capture(addr,method,&path,&credential,&wire,&extra_headers).await?;Some(first)}else{None};
        let pages=if route=="history"&&case=="page"{let cursor=response["body"]["nextCursor"].as_str().ok_or("history first page lost cursor")?.to_owned();let next=capture(addr,method,&format!("{path}&cursor={cursor}"),&credential,&wire,&extra_headers).await?;let mut tampered=cursor.as_bytes().to_vec();let index=cursor.find('.').unwrap()+1;tampered[index]=if tampered[index]==b'A'{b'B'}else{b'A'};let tampered=String::from_utf8(tampered)?;let bad=capture(addr,method,&format!("{path}&cursor={tampered}"),&credential,&wire,&extra_headers).await?;Some(vec![next,bad])}else if route=="content"&&case=="framing"{let mut range_headers=extra_headers.clone();range_headers.push(("range","bytes=2-5".into()));let range=capture(addr,method,&path,&credential,&wire,&range_headers).await?;let mut head_headers=extra_headers.clone();head_headers.push(("__method","HEAD".into()));let head=capture(addr,method,&path,&credential,&wire,&head_headers).await?;Some(vec![range,head])}else{None};
        let status=response["status"].as_u64().unwrap() as u16;
        let mut body=response["body"].take();
        let effects=observation::snapshot(&c,&s).await?;
        if response["headers"]["content-type"]=="text/csv; charset=utf-8"{let header=response["headers"]["content-disposition"].as_str().ok_or("CSV filename absent")?;let prefix=format!("attachment; filename=drive-audit-{}-",s.space);let date=header.strip_prefix(&prefix).and_then(|v|v.strip_suffix(".csv")).ok_or("CSV filename scope")?;chrono::NaiveDate::parse_from_str(date,"%Y%m%d")?;response["headers"]["content-disposition"]=json!("attachment; filename=drive-audit-<space>-<date>.csv");}
        effects.normalize_response(&mut body,path.split('?').next().unwrap().strip_prefix("/api").unwrap(),canonical)?;
        let mut notify=json!(notifications.drain(&c).await?.iter().map(|s|serde_json::from_str::<Value>(s)).collect::<Result<Vec<_>,_>>()?);
        effects.normalize(&mut notify,"","")?;
        let rows=effects.normalized_rows()?;
        response["body"]=body;
        let mut observation=json!({"request":{"method":method,"path":canonical},"response":response,"before":before.normalized_rows()?,"effects":rows,"audit":rows["drive_audit"],"notify":notify});
        if let Some(mut pages)=pages{for page in &mut pages{effects.normalize_response(&mut page["body"],path.strip_prefix("/api").unwrap().split('?').next().unwrap(),canonical)?;}observation["pages"]=json!(pages);}
        if let Some(mut first)=first{effects.normalize_response(&mut first["body"],path.strip_prefix("/api").unwrap().split('?').next().unwrap(),canonical)?;observation["first"]=first;}
        if !recording{let metrics=common::send(addr,Request::builder().uri("/_gateway/metrics").body(common::full(""))?).await;let metrics=String::from_utf8(common::body_bytes(metrics).await.to_vec())?;if !metrics.contains("setjoin_gateway_proxied_to_go_total 0\n")||!metrics.contains("setjoin_gateway_proxied_to_go_by_family_total{family=\"F14\"} 0\n"){return Err("unexpected Go proxy traffic".into())}}
        task.abort();let _=task.await;
        if !mutant&&case=="success"&&status!=status_success {return Err(format!("{route}-{case}: expected status {status_success}, got {status}").into())}
        let golden=std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(format!("../../tests/conformance/drive-b/goldens/{route}-{case}-v5.json"));
        observation["io"]=json!(io.lock().unwrap().clone());
        observation::canonical_states(&mut observation);
        let mutator=method!="GET"||matches!(route,"content"|"consume_export");
        let row_path=golden.with_file_name(format!("{route}-{case}-v5-row-effects.json"));
        if matches!(case,"commit_before"|"commit_after"){
          let cut=tokio::time::timeout(std::time::Duration::from_secs(5),commit_wire.take().unwrap()).await???;let committed=case=="commit_after";if (cut==common::commit::CommitCut::AfterCommit)!=committed||status!=503{return Err("COMMIT loss did not preserve Unknown".into())}
          let operation=observation["response"]["headers"]["x-operation-id"].as_str().ok_or("Unknown lost operation ID")?;if operation.len()!=32||!operation.bytes().all(|b|b.is_ascii_hexdigit()){return Err("operation ID shape".into())}
          let present:bool=c.query_one("SELECT EXISTS(SELECT 1 FROM rust_operation_receipts WHERE operation_id=$1::text::uuid AND family='F14' AND command='drive_branch_create')",&[&operation]).await?.get(0);if present!=committed{return Err("receipt did not resolve actual COMMIT".into())}
          if committed{let mut expected:Value=serde_json::from_slice(&std::fs::read(golden.with_file_name("create_branch-success-v5.json"))?)?;observation::canonical_states(&mut expected["observation"]);for key in ["effects","audit","notify"]{setjoin_conformance::golden::compare(&expected["observation"][key],&observation[key])?;}}else{setjoin_conformance::golden::compare(&observation["before"],&observation["effects"])?;if observation["notify"]!=json!([]){return Err("uncommitted notification".into())}}
          ledger("Reaped gofree-drive3 COMMIT proxy; resolved receipt without replay")?;return Ok(())
        }
        if recording&&std::env::var_os("GOFREE_COVERAGE_PROBE").is_none() {
          let source=std::env::var("GOFREE_GO_SOURCE")?;
          if mutator{setjoin_conformance::golden::record(&row_path,&json!({"format":1,"route":format!("{method} {canonical}"),"case":format!("{route}-{case}-v5-row-effects"),"go_source":source,"effects":[observation["effects"],observation["audit"],observation["notify"]]}))?;}
          setjoin_conformance::golden::record(&golden,&json!({"format":1,"route":format!("{method} {canonical}"),"case":format!("{route}-{case}-v5"),"go_source":source,"normalization":["typed fixture identities","generated RFC3339 timestamps","verified audit checksums"],"observation":observation}))?;
        } else {
          let mut expected:Value=serde_json::from_slice(&std::fs::read(golden)?)?;observation::canonical_states(&mut expected["observation"]);if case=="encoded_id"{observation::normalize_encoded_instance(&mut expected["observation"]["response"]["body"]);}
          setjoin_conformance::golden::compare(&expected["observation"],&observation)?;
          if mutator{let mut rows:Value=serde_json::from_slice(&std::fs::read(row_path)?)?;observation::normalize_generated_names(&mut rows);let mut state=json!({"effects":rows["effects"][0]});observation::canonical_states(&mut state);rows["effects"][0]=state["effects"].take();setjoin_conformance::golden::compare(&rows["effects"],&json!([observation["effects"],observation["audit"],observation["notify"]]))?;}
          println!("GOLDEN-REPLAY: {method} {canonical} :: {route}-{case}-v5");
        }
        let _=mutant;
        Ok::<_,BoxError>(())
    }).catch_unwind().await;
    if let Some(task) = race_task {
        task.abort();
        let _ = task.await;
    }
    if let Some(task) = partial_wire {
        task.abort();
        let _ = task.await;
        ledger("Reaped gofree-drive3 partial-row DB proxy")?;
    }
    if let Some(task) = commit_wire {
        task.abort();
        let _ = task.await;
        ledger("Reaped gofree-drive3 failed COMMIT proxy")?;
    }
    if let Some(schema) = private_schema {
        c.batch_execute(&format!("DROP SCHEMA {schema} CASCADE"))
            .await?;
        ledger(&format!("Removed owned {schema}"))?;
    }
    c.execute(
        "DELETE FROM drive_audit_alarms WHERE space_id=$1 OR created_by=$2",
        &[&s.space, &s.account.user],
    )
    .await?;
    c.execute(
        "DELETE FROM drive_export_grants WHERE space_id=$1",
        &[&s.space],
    )
    .await?;
    if case.starts_with("worm_") {
        c.batch_execute(&format!("BEGIN; SET LOCAL session_replication_role=replica; UPDATE drive_spaces SET classification='regular' WHERE owner_user_id={}; COMMIT;",s.account.user)).await?;
    }
    fixture::cleanup(&c, &s).await?;
    if let Some(a) = foreign {
        setjoin_conformance::fixture::remove(&c, &a).await?;
    }
    for toggle in toggles {
        c.execute(
            "UPDATE feature_toggles SET enabled=$2 WHERE key=$1",
            &[&toggle.get::<_, String>(0), &toggle.get::<_, bool>(1)],
        )
        .await?;
    }
    match result {
        Ok(r) => r,
        Err(p) => std::panic::resume_unwind(p),
    }
}

async fn capture(
    addr: std::net::SocketAddr,
    method: &str,
    path: &str,
    credential: &str,
    wire: &str,
    extra: &[(&str, String)],
) -> Result<Value, BoxError> {
    let wire_method = extra
        .iter()
        .find(|(k, _)| *k == "__method")
        .map_or(method, |(_, v)| v.as_str());
    let mut request = Request::builder()
        .method(wire_method)
        .uri(path)
        .header("authorization", format!("Bearer {credential}"))
        .header("content-type", "application/json")
        .header("x-request-id", "drive3-oracle");
    for (k, v) in extra {
        if !k.starts_with("__") {
            request = request.header(*k, v);
        }
    }
    let mut response = common::send(addr, request.body(common::full(wire.to_owned()))?).await;
    let status = response.status().as_u16();
    let headers: Value = response
        .headers()
        .iter()
        .filter(|(k, _)| {
            !matches!(
                k.as_str(),
                "date" | "content-length" | "transfer-encoding" | "connection"
            ) || (k.as_str() == "content-length"
                && extra.iter().any(|(key, _)| *key == "__framing"))
        })
        .map(|(k, v)| (k.to_string(), json!(v.to_str().unwrap())))
        .collect();
    use http_body_util::BodyExt;
    let mut raw = Vec::new();
    let mut failed = false;
    while let Some(frame) = response.body_mut().frame().await {
        match frame {
            Ok(frame) => {
                if let Some(data) = frame.data_ref() {
                    raw.extend_from_slice(data)
                }
            }
            Err(_) => {
                failed = true;
                break;
            }
        }
    }
    let byte_plane = path.starts_with("/api/drive/export/")
        || (path.starts_with("/api/drive/versions/")
            && path.split('?').next().unwrap().ends_with("/content"));
    let body = if !byte_plane
        || headers
            .get("content-type")
            .is_some_and(|v| v == "application/problem+json")
    {
        serde_json::from_slice::<Value>(&raw).ok()
    } else {
        None
    }
    .unwrap_or_else(|| match String::from_utf8(raw.clone()) {
        Ok(text) => json!(text),
        Err(_) => {
            use base64::Engine;
            json!({"base64":base64::engine::general_purpose::STANDARD.encode(&raw)})
        }
    });
    let mut out = json!({"status":status,"headers":headers,"body":body});
    if failed {
        out["streamError"] = json!(true);
    }
    Ok(out)
}

struct ChangedStatus<K: setjoin_authz::token::KeySource + 'static>(
    setjoin_gateway::drive::DriveRoute<K>,
);
impl<K: setjoin_authz::token::KeySource + 'static> setjoin_gateway::Intercept for ChangedStatus<K> {
    fn matches(&self, r: &Request<setjoin_gateway::Body>) -> bool {
        self.0.matches(r)
    }
    fn admits_member(
        &self,
        h: hyper::HeaderMap,
        s: &'static str,
    ) -> setjoin_gateway::BoxFuture<bool> {
        self.0.admits_member(h, s)
    }
    fn handle(
        &self,
        r: Request<setjoin_gateway::Body>,
        c: setjoin_gateway::RequestContext,
    ) -> setjoin_gateway::BoxFuture<Response<setjoin_gateway::Body>> {
        let result = self.0.handle(r, c);
        Box::pin(async move {
            let mut response = result.await;
            *response.status_mut() = hyper::StatusCode::IM_A_TEAPOT;
            response
        })
    }
}

fn ledger(line: &str) -> Result<(), BoxError> {
    use std::io::Write;
    if let Ok(path) = std::env::var("GOFREE_RESOURCE_LEDGER") {
        writeln!(
            std::fs::OpenOptions::new().append(true).open(path)?,
            "{line}"
        )?;
    }
    Ok(())
}
async fn plant_private(
    c: &tokio_postgres::Client,
    dsn: &str,
    actor: i64,
    route: &str,
    kind: &str,
) -> Result<(String, String), BoxError> {
    let schema = format!("gofree_drive3_boundary_{actor}");
    ledger(&format!("Plan private schema {schema} on the assigned DB"))?;
    c.batch_execute(&format!("CREATE SCHEMA {schema}; GRANT USAGE ON SCHEMA {schema} TO setjoin_app; CREATE TABLE {schema}.control(armed boolean NOT NULL); INSERT INTO {schema}.control VALUES(false); GRANT SELECT ON {schema}.control TO setjoin_app")).await?;
    let result=async{
  let sql=match kind{
   "no-audit"=>format!("CREATE FUNCTION {schema}.drive_access_audit(bigint,bigint,text,text,bigint,jsonb,jsonb,inet,text) RETURNS bigint LANGUAGE sql AS 'SELECT 0::bigint'"),
   "no-notify"|"double-bump"=>{let source:String=c.query_one("SELECT pg_get_functiondef('drive_notify_change(bigint,bigint,text)'::regprocedure)",&[]).await?.get(0);let source=source.replacen("public.drive_notify_change",&format!("{schema}.drive_notify_change"),1);if kind=="no-notify"{source.replace("PERFORM app_notify('drive', json_build_object('spaceId', p_space_id, 'seq', v_seq)::text);","")}else{source.replace("change_seq + 1","change_seq + 2")}},
   "no-tenant-filter"=>{let source:String=c.query_one("SELECT pg_get_functiondef('drive_branch_create(bigint,bigint,text,bigint)'::regprocedure)",&[]).await?.get(0);source.replacen("public.drive_branch_create",&format!("{schema}.drive_branch_create"),1).replacen("LANGUAGE plpgsql","LANGUAGE plpgsql SECURITY DEFINER SET search_path=public",1).replace("PERFORM public.drive_require_node_capability(\n    p_user_id,p_file_node_id,'modify_content');","")},
   "revoked"=>format!("CREATE FUNCTION {schema}.drive_policy_resolve(bigint) RETURNS jsonb LANGUAGE plpgsql AS $$ DECLARE v_out jsonb; BEGIN v_out:=public.drive_policy_resolve($1); IF (SELECT armed FROM {schema}.control) THEN PERFORM pg_advisory_lock(7711,{actor}); PERFORM pg_advisory_unlock(7711,{actor}); END IF; RETURN v_out; END $$"),
   "worm_bookkeeping"=>format!("CREATE FUNCTION {schema}.fail() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER AS $$ BEGIN IF NEW.scope_key IN(SELECT 's'||id FROM public.drive_spaces WHERE owner_user_id={actor}) AND NEW.worm_applied_until IS DISTINCT FROM OLD.worm_applied_until AND (SELECT armed FROM {schema}.control) THEN RAISE EXCEPTION 'drive3 retention bookkeeping fault'; END IF; RETURN NEW; END $$; CREATE TRIGGER gofree_drive3_worm_{actor} BEFORE UPDATE ON public.drive_chunks FOR EACH ROW EXECUTE FUNCTION {schema}.fail()"),
   "audit_fault"=>format!("CREATE FUNCTION {schema}.fail() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER AS $$ BEGIN IF NEW.user_id={actor} AND (SELECT armed FROM {schema}.control) THEN RAISE EXCEPTION 'drive3 audit fault'; END IF; RETURN NEW; END $$; CREATE TRIGGER gofree_drive3_audit_{actor} BEFORE INSERT ON public.drive_audit_log FOR EACH ROW EXECUTE FUNCTION {schema}.fail()"),
   "fault"=>{let table=match route{"list_versions"|"content"|"consume_export"=>Some("drive_file_versions"),"list_branches"=>Some("drive_file_branches"),_=>None};if let Some(table)=table{format!("CREATE FUNCTION {schema}.fail() RETURNS boolean LANGUAGE plpgsql AS $$ BEGIN IF (SELECT armed FROM {schema}.control) THEN RAISE EXCEPTION 'drive3 read fault'; END IF; RETURN true; END $$; CREATE VIEW {schema}.{table} AS SELECT t.* FROM public.{table} t WHERE {schema}.fail(); GRANT SELECT ON {schema}.{table} TO setjoin_app")}else{let name=match route{"activity"=>"drive_activity_feed","search"=>"drive_search_nodes","audit"=>"drive_audit_query","audit_actions"=>"drive_audit_actions","history"=>"drive_file_history_query","office_choices"=>"office_choice_query","list_alarms"|"verify_audit"=>"drive_has_admin_perm",_=>return Err("unknown fault route".into())};let row=c.query_one("SELECT pg_get_function_identity_arguments(p.oid),pg_get_function_result(p.oid),p.pronargs::int FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='public' AND p.proname=$1",&[&name]).await?;let args:String=row.get(0);let result:String=row.get(1);let count:i32=row.get(2);let args_refs=(1..=count).map(|i|format!("${i}")).collect::<Vec<_>>().join(",");format!("CREATE FUNCTION {schema}.{name}({args}) RETURNS {result} LANGUAGE plpgsql AS $$ BEGIN IF (SELECT armed FROM {schema}.control) THEN RAISE EXCEPTION 'drive3 read fault'; END IF; RETURN public.{name}({args_refs}); END $$")}},
   _=>return Err("unknown boundary mutation".into())};
  c.batch_execute(&sql).await?;Ok::<_,BoxError>(())
 }.await;
    if let Err(e) = result {
        c.batch_execute(&format!("DROP SCHEMA {schema} CASCADE"))
            .await?;
        return Err(e);
    }
    let dsn = if dsn.starts_with("postgres://") || dsn.starts_with("postgresql://") {
        format!(
            "{dsn}{}options=-csearch_path%3D{schema}%2Cpublic",
            if dsn.contains('?') { "&" } else { "?" }
        )
    } else {
        format!("{dsn} options='-csearch_path={schema},public'")
    };
    Ok((schema, dsn))
}
#[tokio::test]
async fn branch_commit_before() -> Result<(), BoxError> {
    run("create_branch", "commit_before", false).await
}
#[tokio::test]
async fn branch_commit_after() -> Result<(), BoxError> {
    run("create_branch", "commit_after", false).await
}
async fn rejects_effect(kind: &str) -> Result<(), BoxError> {
    let case = if kind == "no-tenant-filter" {
        "foreign"
    } else {
        "success"
    };
    let e = run_variant("create_branch", case, false, Some(kind))
        .await
        .expect_err("SQL mutant escaped frozen-Go comparison")
        .to_string();
    if !(e.contains("/effects/") || e.contains("/notify/") || e.contains("/audit/")) {
        return Err(e.into());
    }
    println!("Drive B SQL mutant rejected: {kind}");
    Ok(())
}
#[tokio::test]
async fn branch_rejects_no_audit() -> Result<(), BoxError> {
    rejects_effect("no-audit").await
}
#[tokio::test]
async fn branch_rejects_no_notify() -> Result<(), BoxError> {
    rejects_effect("no-notify").await
}
#[tokio::test]
async fn branch_rejects_double_bump() -> Result<(), BoxError> {
    rejects_effect("double-bump").await
}
#[tokio::test]
async fn branch_rejects_no_tenant_filter() -> Result<(), BoxError> {
    rejects_effect("no-tenant-filter").await
}
