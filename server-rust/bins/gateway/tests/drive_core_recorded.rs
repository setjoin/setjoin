//! #274 frozen Go oracle at the front door HTTP seam.
#[path = "common/drive_commit.rs"]
mod commit_wire;
mod common;
#[path = "common/drive_s3.rs"]
mod storage_wire;
use common::BoxError;
use futures_util::FutureExt;
use http_body_util::BodyExt;
use hyper::{Request, Response};
use serde_json::{json, Value};
use setjoin_conformance::{fixture, harness::Db};
use setjoin_gateway::{Config, Gateway, RouteTable, TrustedProxies};
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
#[tokio::test]
async fn list_spaces_success() -> Result<(), BoxError> {
    run("list_spaces", "success", false).await
}

#[tokio::test]
async fn create_space_success() -> Result<(), BoxError> {
    run("create_space", "success", false).await
}

#[tokio::test]
async fn patch_space_success() -> Result<(), BoxError> {
    run("patch_space", "success", false).await
}

#[tokio::test]
async fn list_members_success() -> Result<(), BoxError> {
    run("list_members", "success", false).await
}

#[tokio::test]
async fn grant_member_success() -> Result<(), BoxError> {
    run("grant_member", "success", false).await
}

#[tokio::test]
async fn revoke_member_success() -> Result<(), BoxError> {
    run("revoke_member", "success", false).await
}

#[tokio::test]
async fn grant_member_foreign() -> Result<(), BoxError> {
    run("grant_member", "foreign", false).await
}

#[tokio::test]
async fn tree_success() -> Result<(), BoxError> {
    run("tree", "success", false).await
}

#[tokio::test]
async fn nodes_meta_success() -> Result<(), BoxError> {
    run("nodes_meta", "success", false).await
}

#[tokio::test]
async fn changes_success() -> Result<(), BoxError> {
    run("changes", "success", false).await
}

#[tokio::test]
async fn access_invalidations_success() -> Result<(), BoxError> {
    run("access_invalidations", "success", false).await
}

#[tokio::test]
async fn visibility_snapshot_success() -> Result<(), BoxError> {
    run("visibility_snapshot", "success", false).await
}

#[tokio::test]
async fn create_node_success() -> Result<(), BoxError> {
    run("create_node", "success", false).await
}

#[tokio::test]
async fn patch_node_success() -> Result<(), BoxError> {
    run("patch_node", "success", false).await
}

#[tokio::test]
async fn trash_node_success() -> Result<(), BoxError> {
    run("trash_node", "success", false).await
}

#[tokio::test]
async fn restore_node_success() -> Result<(), BoxError> {
    run("restore_node", "success", false).await
}

#[tokio::test]
async fn destroy_node_success() -> Result<(), BoxError> {
    run("destroy_node", "success", false).await
}

#[tokio::test]
async fn head_chunk_success() -> Result<(), BoxError> {
    run("head_chunk", "success", false).await
}

#[tokio::test]
async fn put_chunk_success() -> Result<(), BoxError> {
    run("put_chunk", "success", false).await
}

#[tokio::test]
async fn preview_success() -> Result<(), BoxError> {
    run("preview", "success", false).await
}

#[tokio::test]
async fn list_spaces_success_state_v2() -> Result<(), BoxError> {
    run("list_spaces", "success-state-v2", false).await
}

#[tokio::test]
async fn list_spaces_foreign_state_v2() -> Result<(), BoxError> {
    run("list_spaces", "foreign-state-v2", false).await
}

#[tokio::test]
async fn list_spaces_invalid_state_v2() -> Result<(), BoxError> {
    run("list_spaces", "invalid-state-v2", false).await
}

#[tokio::test]
async fn create_space_success_state_v2() -> Result<(), BoxError> {
    run("create_space", "success-state-v2", false).await
}

#[tokio::test]
async fn create_space_foreign_state_v2() -> Result<(), BoxError> {
    run("create_space", "foreign-state-v2", false).await
}

#[tokio::test]
async fn create_space_invalid_state_v2() -> Result<(), BoxError> {
    run("create_space", "invalid-state-v2", false).await
}

#[tokio::test]
async fn patch_space_success_state_v2() -> Result<(), BoxError> {
    run("patch_space", "success-state-v2", false).await
}

#[tokio::test]
async fn patch_space_foreign_state_v2() -> Result<(), BoxError> {
    run("patch_space", "foreign-state-v2", false).await
}

#[tokio::test]
async fn patch_space_invalid_state_v2() -> Result<(), BoxError> {
    run("patch_space", "invalid-state-v2", false).await
}

#[tokio::test]
async fn list_members_success_state_v2() -> Result<(), BoxError> {
    run("list_members", "success-state-v2", false).await
}

#[tokio::test]
async fn list_members_foreign_state_v2() -> Result<(), BoxError> {
    run("list_members", "foreign-state-v2", false).await
}

#[tokio::test]
async fn list_members_invalid_state_v2() -> Result<(), BoxError> {
    run("list_members", "invalid-state-v2", false).await
}

#[tokio::test]
async fn grant_member_success_state_v2() -> Result<(), BoxError> {
    run("grant_member", "success-state-v2", false).await
}

#[tokio::test]
async fn grant_member_foreign_state_v2() -> Result<(), BoxError> {
    run("grant_member", "foreign-state-v2", false).await
}

#[tokio::test]
async fn grant_member_invalid_state_v2() -> Result<(), BoxError> {
    run("grant_member", "invalid-state-v2", false).await
}

#[tokio::test]
async fn revoke_member_success_state_v2() -> Result<(), BoxError> {
    run("revoke_member", "success-state-v2", false).await
}

#[tokio::test]
async fn revoke_member_foreign_state_v2() -> Result<(), BoxError> {
    run("revoke_member", "foreign-state-v2", false).await
}

#[tokio::test]
async fn revoke_member_outsider_state_v2() -> Result<(), BoxError> {
    run("revoke_member", "outsider-state-v2", false).await
}

#[tokio::test]
async fn revoke_member_invalid_state_v2() -> Result<(), BoxError> {
    run("revoke_member", "invalid-state-v2", false).await
}

#[tokio::test]
async fn tree_success_state_v2() -> Result<(), BoxError> {
    run("tree", "success-state-v2", false).await
}

#[tokio::test]
async fn tree_foreign_state_v2() -> Result<(), BoxError> {
    run("tree", "foreign-state-v2", false).await
}

#[tokio::test]
async fn tree_invalid_state_v2() -> Result<(), BoxError> {
    run("tree", "invalid-state-v2", false).await
}

#[tokio::test]
async fn nodes_meta_success_state_v2() -> Result<(), BoxError> {
    run("nodes_meta", "success-state-v2", false).await
}

#[tokio::test]
async fn nodes_meta_foreign_state_v2() -> Result<(), BoxError> {
    run("nodes_meta", "foreign-state-v2", false).await
}

#[tokio::test]
async fn nodes_meta_invalid_state_v2() -> Result<(), BoxError> {
    run("nodes_meta", "invalid-state-v2", false).await
}

#[tokio::test]
async fn changes_success_state_v2() -> Result<(), BoxError> {
    run("changes", "success-state-v2", false).await
}

#[tokio::test]
async fn changes_foreign_state_v2() -> Result<(), BoxError> {
    run("changes", "foreign-state-v2", false).await
}

#[tokio::test]
async fn changes_invalid_state_v2() -> Result<(), BoxError> {
    run("changes", "invalid-state-v2", false).await
}

#[tokio::test]
async fn access_invalidations_success_state_v2() -> Result<(), BoxError> {
    run("access_invalidations", "success-state-v2", false).await
}

#[tokio::test]
async fn access_invalidations_foreign_state_v2() -> Result<(), BoxError> {
    run("access_invalidations", "foreign-state-v2", false).await
}

#[tokio::test]
async fn access_invalidations_invalid_state_v2() -> Result<(), BoxError> {
    run("access_invalidations", "invalid-state-v2", false).await
}

#[tokio::test]
async fn visibility_snapshot_success_state_v2() -> Result<(), BoxError> {
    run("visibility_snapshot", "success-state-v2", false).await
}

#[tokio::test]
async fn visibility_snapshot_foreign_state_v2() -> Result<(), BoxError> {
    run("visibility_snapshot", "foreign-state-v2", false).await
}

#[tokio::test]
async fn visibility_snapshot_invalid_state_v2() -> Result<(), BoxError> {
    run("visibility_snapshot", "invalid-state-v2", false).await
}

#[tokio::test]
async fn create_node_success_state_v2() -> Result<(), BoxError> {
    run("create_node", "success-state-v2", false).await
}

#[tokio::test]
async fn create_node_foreign_state_v2() -> Result<(), BoxError> {
    run("create_node", "foreign-state-v2", false).await
}

#[tokio::test]
async fn create_node_invalid_state_v2() -> Result<(), BoxError> {
    run("create_node", "invalid-state-v2", false).await
}

#[tokio::test]
async fn patch_node_success_state_v2() -> Result<(), BoxError> {
    run("patch_node", "success-state-v2", false).await
}

#[tokio::test]
async fn patch_node_foreign_state_v2() -> Result<(), BoxError> {
    run("patch_node", "foreign-state-v2", false).await
}

#[tokio::test]
async fn patch_node_invalid_state_v2() -> Result<(), BoxError> {
    run("patch_node", "invalid-state-v2", false).await
}

#[tokio::test]
async fn trash_node_success_state_v2() -> Result<(), BoxError> {
    run("trash_node", "success-state-v2", false).await
}

#[tokio::test]
async fn trash_node_foreign_state_v2() -> Result<(), BoxError> {
    run("trash_node", "foreign-state-v2", false).await
}

#[tokio::test]
async fn trash_node_invalid_state_v2() -> Result<(), BoxError> {
    run("trash_node", "invalid-state-v2", false).await
}

#[tokio::test]
async fn restore_node_success_state_v2() -> Result<(), BoxError> {
    run("restore_node", "success-state-v2", false).await
}

#[tokio::test]
async fn restore_node_foreign_state_v2() -> Result<(), BoxError> {
    run("restore_node", "foreign-state-v2", false).await
}

#[tokio::test]
async fn restore_node_invalid_state_v2() -> Result<(), BoxError> {
    run("restore_node", "invalid-state-v2", false).await
}

#[tokio::test]
async fn destroy_node_success_state_v2() -> Result<(), BoxError> {
    run("destroy_node", "success-state-v2", false).await
}

#[tokio::test]
async fn destroy_node_foreign_state_v2() -> Result<(), BoxError> {
    run("destroy_node", "foreign-state-v2", false).await
}

#[tokio::test]
async fn destroy_node_invalid_state_v2() -> Result<(), BoxError> {
    run("destroy_node", "invalid-state-v2", false).await
}

#[tokio::test]
async fn head_chunk_success_state_v2() -> Result<(), BoxError> {
    run("head_chunk", "success-state-v2", false).await
}

#[tokio::test]
async fn head_chunk_foreign_state_v2() -> Result<(), BoxError> {
    run("head_chunk", "foreign-state-v2", false).await
}

#[tokio::test]
async fn head_chunk_invalid_state_v2() -> Result<(), BoxError> {
    run("head_chunk", "invalid-state-v2", false).await
}

#[tokio::test]
async fn put_chunk_success_state_v2() -> Result<(), BoxError> {
    run("put_chunk", "success-state-v2", false).await
}

#[tokio::test]
async fn put_chunk_foreign_state_v2() -> Result<(), BoxError> {
    run("put_chunk", "foreign-state-v2", false).await
}

#[tokio::test]
async fn put_chunk_invalid_state_v2() -> Result<(), BoxError> {
    run("put_chunk", "invalid-state-v2", false).await
}

#[tokio::test]
async fn preview_success_state_v2() -> Result<(), BoxError> {
    run("preview", "success-state-v2", false).await
}

#[tokio::test]
async fn preview_foreign_state_v2() -> Result<(), BoxError> {
    run("preview", "foreign-state-v2", false).await
}

#[tokio::test]
async fn preview_invalid_state_v2() -> Result<(), BoxError> {
    run("preview", "invalid-state-v2", false).await
}

#[tokio::test]
async fn patch_space_policy_state() -> Result<(), BoxError> {
    run("patch_space", "policy-state", false).await
}

#[tokio::test]
async fn patch_space_quota_state() -> Result<(), BoxError> {
    run("patch_space", "quota-state", false).await
}

#[tokio::test]
async fn grant_member_folder_state() -> Result<(), BoxError> {
    run("grant_member", "folder-state", false).await
}

#[tokio::test]
async fn list_spaces_status_mutant() -> Result<(), BoxError> {
    let error = run("list_spaces", "success-state-v2", true)
        .await
        .expect_err("live changed-status mutant escaped");
    assert!(
        error.to_string().contains("HTTP 418"),
        "wrong failure: {error}"
    );
    println!(
        "MUTANT-REJECTED: {} :: changed-status",
        route_name("list_spaces")
    );
    Ok(())
}

#[tokio::test]
async fn create_space_status_mutant() -> Result<(), BoxError> {
    let error = run("create_space", "success-state-v2", true)
        .await
        .expect_err("live changed-status mutant escaped");
    assert!(
        error.to_string().contains("HTTP 418"),
        "wrong failure: {error}"
    );
    println!(
        "MUTANT-REJECTED: {} :: changed-status",
        route_name("create_space")
    );
    Ok(())
}

#[tokio::test]
async fn patch_space_status_mutant() -> Result<(), BoxError> {
    let error = run("patch_space", "success-state-v2", true)
        .await
        .expect_err("live changed-status mutant escaped");
    assert!(
        error.to_string().contains("HTTP 418"),
        "wrong failure: {error}"
    );
    println!(
        "MUTANT-REJECTED: {} :: changed-status",
        route_name("patch_space")
    );
    Ok(())
}

#[tokio::test]
async fn list_members_status_mutant() -> Result<(), BoxError> {
    let error = run("list_members", "success-state-v2", true)
        .await
        .expect_err("live changed-status mutant escaped");
    assert!(
        error.to_string().contains("HTTP 418"),
        "wrong failure: {error}"
    );
    println!(
        "MUTANT-REJECTED: {} :: changed-status",
        route_name("list_members")
    );
    Ok(())
}

#[tokio::test]
async fn grant_member_status_mutant() -> Result<(), BoxError> {
    let error = run("grant_member", "success-state-v2", true)
        .await
        .expect_err("live changed-status mutant escaped");
    assert!(
        error.to_string().contains("HTTP 418"),
        "wrong failure: {error}"
    );
    println!(
        "MUTANT-REJECTED: {} :: changed-status",
        route_name("grant_member")
    );
    Ok(())
}

#[tokio::test]
async fn revoke_member_status_mutant() -> Result<(), BoxError> {
    let error = run("revoke_member", "success-state-v2", true)
        .await
        .expect_err("live changed-status mutant escaped");
    assert!(
        error.to_string().contains("HTTP 418"),
        "wrong failure: {error}"
    );
    println!(
        "MUTANT-REJECTED: {} :: changed-status",
        route_name("revoke_member")
    );
    Ok(())
}

#[tokio::test]
async fn tree_status_mutant() -> Result<(), BoxError> {
    let error = run("tree", "success-state-v2", true)
        .await
        .expect_err("live changed-status mutant escaped");
    assert!(
        error.to_string().contains("HTTP 418"),
        "wrong failure: {error}"
    );
    println!("MUTANT-REJECTED: {} :: changed-status", route_name("tree"));
    Ok(())
}

#[tokio::test]
async fn nodes_meta_status_mutant() -> Result<(), BoxError> {
    let error = run("nodes_meta", "success-state-v2", true)
        .await
        .expect_err("live changed-status mutant escaped");
    assert!(
        error.to_string().contains("HTTP 418"),
        "wrong failure: {error}"
    );
    println!(
        "MUTANT-REJECTED: {} :: changed-status",
        route_name("nodes_meta")
    );
    Ok(())
}

#[tokio::test]
async fn changes_status_mutant() -> Result<(), BoxError> {
    let error = run("changes", "success-state-v2", true)
        .await
        .expect_err("live changed-status mutant escaped");
    assert!(
        error.to_string().contains("HTTP 418"),
        "wrong failure: {error}"
    );
    println!(
        "MUTANT-REJECTED: {} :: changed-status",
        route_name("changes")
    );
    Ok(())
}

#[tokio::test]
async fn access_invalidations_status_mutant() -> Result<(), BoxError> {
    let error = run("access_invalidations", "success-state-v2", true)
        .await
        .expect_err("live changed-status mutant escaped");
    assert!(
        error.to_string().contains("HTTP 418"),
        "wrong failure: {error}"
    );
    println!(
        "MUTANT-REJECTED: {} :: changed-status",
        route_name("access_invalidations")
    );
    Ok(())
}

#[tokio::test]
async fn visibility_snapshot_status_mutant() -> Result<(), BoxError> {
    let error = run("visibility_snapshot", "success-state-v2", true)
        .await
        .expect_err("live changed-status mutant escaped");
    assert!(
        error.to_string().contains("HTTP 418"),
        "wrong failure: {error}"
    );
    println!(
        "MUTANT-REJECTED: {} :: changed-status",
        route_name("visibility_snapshot")
    );
    Ok(())
}

#[tokio::test]
async fn create_node_status_mutant() -> Result<(), BoxError> {
    let error = run("create_node", "success-state-v2", true)
        .await
        .expect_err("live changed-status mutant escaped");
    assert!(
        error.to_string().contains("HTTP 418"),
        "wrong failure: {error}"
    );
    println!(
        "MUTANT-REJECTED: {} :: changed-status",
        route_name("create_node")
    );
    Ok(())
}

#[tokio::test]
async fn patch_node_status_mutant() -> Result<(), BoxError> {
    let error = run("patch_node", "success-state-v2", true)
        .await
        .expect_err("live changed-status mutant escaped");
    assert!(
        error.to_string().contains("HTTP 418"),
        "wrong failure: {error}"
    );
    println!(
        "MUTANT-REJECTED: {} :: changed-status",
        route_name("patch_node")
    );
    Ok(())
}

#[tokio::test]
async fn trash_node_status_mutant() -> Result<(), BoxError> {
    let error = run("trash_node", "success-state-v2", true)
        .await
        .expect_err("live changed-status mutant escaped");
    assert!(
        error.to_string().contains("HTTP 418"),
        "wrong failure: {error}"
    );
    println!(
        "MUTANT-REJECTED: {} :: changed-status",
        route_name("trash_node")
    );
    Ok(())
}

#[tokio::test]
async fn restore_node_status_mutant() -> Result<(), BoxError> {
    let error = run("restore_node", "success-state-v2", true)
        .await
        .expect_err("live changed-status mutant escaped");
    assert!(
        error.to_string().contains("HTTP 418"),
        "wrong failure: {error}"
    );
    println!(
        "MUTANT-REJECTED: {} :: changed-status",
        route_name("restore_node")
    );
    Ok(())
}

#[tokio::test]
async fn destroy_node_status_mutant() -> Result<(), BoxError> {
    let error = run("destroy_node", "success-state-v2", true)
        .await
        .expect_err("live changed-status mutant escaped");
    assert!(
        error.to_string().contains("HTTP 418"),
        "wrong failure: {error}"
    );
    println!(
        "MUTANT-REJECTED: {} :: changed-status",
        route_name("destroy_node")
    );
    Ok(())
}

#[tokio::test]
async fn head_chunk_status_mutant() -> Result<(), BoxError> {
    let error = run("head_chunk", "success-state-v2", true)
        .await
        .expect_err("live changed-status mutant escaped");
    assert!(
        error.to_string().contains("HTTP 418"),
        "wrong failure: {error}"
    );
    println!(
        "MUTANT-REJECTED: {} :: changed-status",
        route_name("head_chunk")
    );
    Ok(())
}

#[tokio::test]
async fn put_chunk_status_mutant() -> Result<(), BoxError> {
    let error = run("put_chunk", "success-state-v2", true)
        .await
        .expect_err("live changed-status mutant escaped");
    assert!(
        error.to_string().contains("HTTP 418"),
        "wrong failure: {error}"
    );
    println!(
        "MUTANT-REJECTED: {} :: changed-status",
        route_name("put_chunk")
    );
    Ok(())
}

#[tokio::test]
async fn preview_status_mutant() -> Result<(), BoxError> {
    let error = run("preview", "success-state-v2", true)
        .await
        .expect_err("live changed-status mutant escaped");
    assert!(
        error.to_string().contains("HTTP 418"),
        "wrong failure: {error}"
    );
    println!(
        "MUTANT-REJECTED: {} :: changed-status",
        route_name("preview")
    );
    Ok(())
}

#[tokio::test]
async fn list_spaces_admin_denied_state() -> Result<(), BoxError> {
    run("list_spaces", "admin-denied-state", false).await
}

#[tokio::test]
async fn preview_pending_state() -> Result<(), BoxError> {
    run("preview", "pending-state", false).await
}

#[tokio::test]
async fn list_spaces_admin_state() -> Result<(), BoxError> {
    run("list_spaces", "admin-state", false).await
}

#[tokio::test]
async fn preview_audited_state() -> Result<(), BoxError> {
    run("preview", "audited-state", false).await
}

#[tokio::test]
async fn revoke_member_folder_state() -> Result<(), BoxError> {
    run("revoke_member", "folder-state", false).await
}

#[tokio::test]
async fn preview_range_state() -> Result<(), BoxError> {
    run("preview", "range-state", false).await
}

#[tokio::test]
async fn put_chunk_oversize_state() -> Result<(), BoxError> {
    run("put_chunk", "oversize-state", false).await
}

#[tokio::test]
async fn list_spaces_repeat_state() -> Result<(), BoxError> {
    run("list_spaces", "repeat-state", false).await
}

#[tokio::test]
async fn create_space_repeat_state() -> Result<(), BoxError> {
    run("create_space", "repeat-state", false).await
}

#[tokio::test]
async fn patch_space_repeat_state() -> Result<(), BoxError> {
    run("patch_space", "repeat-state", false).await
}

#[tokio::test]
async fn grant_member_repeat_state() -> Result<(), BoxError> {
    run("grant_member", "repeat-state", false).await
}

#[tokio::test]
async fn revoke_member_repeat_state() -> Result<(), BoxError> {
    run("revoke_member", "repeat-state", false).await
}

#[tokio::test]
async fn create_node_repeat_state() -> Result<(), BoxError> {
    run("create_node", "repeat-state", false).await
}

#[tokio::test]
async fn patch_node_repeat_state() -> Result<(), BoxError> {
    run("patch_node", "repeat-state", false).await
}

#[tokio::test]
async fn trash_node_repeat_state() -> Result<(), BoxError> {
    run("trash_node", "repeat-state", false).await
}

#[tokio::test]
async fn restore_node_repeat_state() -> Result<(), BoxError> {
    run("restore_node", "repeat-state", false).await
}

#[tokio::test]
async fn destroy_node_repeat_state() -> Result<(), BoxError> {
    run("destroy_node", "repeat-state", false).await
}

#[tokio::test]
async fn put_chunk_repeat_state() -> Result<(), BoxError> {
    run("put_chunk", "repeat-state", false).await
}

#[tokio::test]
async fn preview_repeat_state() -> Result<(), BoxError> {
    run("preview", "repeat-state", false).await
}

#[tokio::test]
async fn patch_node_encoded_id_state() -> Result<(), BoxError> {
    run("patch_node", "encoded-id-state", false).await
}

#[tokio::test]
async fn nodes_meta_too_many_state() -> Result<(), BoxError> {
    run("nodes_meta", "too-many-state", false).await
}

#[tokio::test]
async fn list_spaces_commit_before_state() -> Result<(), BoxError> {
    run("list_spaces", "commit-before-state", false).await
}

#[tokio::test]
async fn list_spaces_commit_after_state() -> Result<(), BoxError> {
    run("list_spaces", "commit-after-state", false).await
}

#[tokio::test]
async fn create_space_overflow_state() -> Result<(), BoxError> {
    run("create_space", "overflow-state", false).await
}

#[tokio::test]
async fn create_node_json_trailer_state() -> Result<(), BoxError> {
    run("create_node", "json-trailer-state", false).await
}

#[tokio::test]
async fn create_node_json_oversize_state() -> Result<(), BoxError> {
    run("create_node", "json-oversize-state", false).await
}

#[tokio::test]
async fn create_node_locale_state() -> Result<(), BoxError> {
    run("create_node", "locale-state", false).await
}

#[tokio::test]
async fn grant_member_folder_invalid_state() -> Result<(), BoxError> {
    run("grant_member", "folder-invalid-state", false).await
}

#[tokio::test]
async fn access_invalidations_bad_cursor_state() -> Result<(), BoxError> {
    run("access_invalidations", "bad-cursor-state", false).await
}

#[tokio::test]
async fn visibility_snapshot_stale_epoch_state() -> Result<(), BoxError> {
    run("visibility_snapshot", "stale-epoch-state", false).await
}

#[tokio::test]
async fn preview_bad_range_state() -> Result<(), BoxError> {
    run("preview", "bad-range-state", false).await
}

#[tokio::test]
async fn put_chunk_mismatch_state() -> Result<(), BoxError> {
    run("put_chunk", "mismatch-state", false).await
}

#[tokio::test]
async fn put_chunk_empty_state() -> Result<(), BoxError> {
    run("put_chunk", "empty-state", false).await
}

#[tokio::test]
async fn patch_space_bad_id_state() -> Result<(), BoxError> {
    run("patch_space", "bad-id-state", false).await
}

#[tokio::test]
async fn grant_member_bad_id_state() -> Result<(), BoxError> {
    run("grant_member", "bad-id-state", false).await
}

#[tokio::test]
async fn revoke_member_bad_id_state() -> Result<(), BoxError> {
    run("revoke_member", "bad-id-state", false).await
}

#[tokio::test]
async fn tree_bad_id_state() -> Result<(), BoxError> {
    run("tree", "bad-id-state", false).await
}

#[tokio::test]
async fn changes_missing_space_state() -> Result<(), BoxError> {
    run("changes", "missing-space-state", false).await
}

#[tokio::test]
async fn access_invalidations_missing_space_state() -> Result<(), BoxError> {
    run("access_invalidations", "missing-space-state", false).await
}

#[tokio::test]
async fn visibility_snapshot_missing_space_state() -> Result<(), BoxError> {
    run("visibility_snapshot", "missing-space-state", false).await
}

#[tokio::test]
async fn head_chunk_missing_space_state() -> Result<(), BoxError> {
    run("head_chunk", "missing-space-state", false).await
}

#[tokio::test]
async fn put_chunk_missing_space_state() -> Result<(), BoxError> {
    run("put_chunk", "missing-space-state", false).await
}

#[tokio::test]
async fn head_chunk_bad_binding_state() -> Result<(), BoxError> {
    run("head_chunk", "bad-binding-state", false).await
}

#[tokio::test]
async fn put_chunk_bad_binding_state() -> Result<(), BoxError> {
    run("put_chunk", "bad-binding-state", false).await
}

#[tokio::test]
async fn visibility_snapshot_bad_after_state() -> Result<(), BoxError> {
    run("visibility_snapshot", "bad-after-state", false).await
}

#[tokio::test]
async fn visibility_snapshot_bad_max_state() -> Result<(), BoxError> {
    run("visibility_snapshot", "bad-max-state", false).await
}

#[tokio::test]
async fn patch_node_bad_name_state() -> Result<(), BoxError> {
    run("patch_node", "bad-name-state", false).await
}

#[tokio::test]
async fn patch_node_bad_parent_state() -> Result<(), BoxError> {
    run("patch_node", "bad-parent-state", false).await
}

#[tokio::test]
async fn patch_space_bad_retention_state() -> Result<(), BoxError> {
    run("patch_space", "bad-retention-state", false).await
}

#[tokio::test]
async fn patch_space_bad_worm_state() -> Result<(), BoxError> {
    run("patch_space", "bad-worm-state", false).await
}

#[tokio::test]
async fn patch_space_bad_vault_state() -> Result<(), BoxError> {
    run("patch_space", "bad-vault-state", false).await
}

#[tokio::test]
async fn patch_space_bad_classification_state() -> Result<(), BoxError> {
    run("patch_space", "bad-classification-state", false).await
}

#[tokio::test]
async fn patch_space_empty_patch_state() -> Result<(), BoxError> {
    run("patch_space", "empty-patch-state", false).await
}

#[tokio::test]
async fn create_node_rate_state() -> Result<(), BoxError> {
    run("create_node", "rate-state", false).await
}

#[tokio::test]
async fn patch_node_rate_state() -> Result<(), BoxError> {
    run("patch_node", "rate-state", false).await
}

#[tokio::test]
async fn restore_node_rate_state() -> Result<(), BoxError> {
    run("restore_node", "rate-state", false).await
}

#[tokio::test]
async fn changes_resync_state() -> Result<(), BoxError> {
    run("changes", "resync-state", false).await
}

#[tokio::test]
async fn nodes_meta_query_failure_state() -> Result<(), BoxError> {
    run("nodes_meta", "query-failure-state", false).await
}

#[tokio::test]
async fn list_spaces_query_failure_state() -> Result<(), BoxError> {
    run("list_spaces", "query-failure-state", false).await
}

#[tokio::test]
async fn tree_query_failure_state() -> Result<(), BoxError> {
    run("tree", "query-failure-state", false).await
}

#[tokio::test]
async fn put_chunk_storage_init_denied_state() -> Result<(), BoxError> {
    run("put_chunk", "storage-init-denied-state", false).await
}

#[tokio::test]
async fn put_chunk_storage_copy_denied_state() -> Result<(), BoxError> {
    run("put_chunk", "storage-copy-denied-state", false).await
}

#[tokio::test]
async fn preview_audit_failure_state() -> Result<(), BoxError> {
    run("preview", "audit-failure-state", false).await
}

#[tokio::test]
async fn list_members_query_failure_state() -> Result<(), BoxError> {
    run("list_members", "query-failure-state", false).await
}

#[tokio::test]
async fn head_chunk_query_failure_state() -> Result<(), BoxError> {
    run("head_chunk", "query-failure-state", false).await
}

#[tokio::test]
async fn patch_space_quota_admin_state() -> Result<(), BoxError> {
    run("patch_space", "quota-admin-state", false).await
}

#[tokio::test]
async fn patch_space_bad_quota_state() -> Result<(), BoxError> {
    run("patch_space", "bad-quota-state", false).await
}

#[tokio::test]
async fn patch_node_move_failure_state() -> Result<(), BoxError> {
    run("patch_node", "move-failure-state", false).await
}

#[tokio::test]
async fn put_chunk_bound_state() -> Result<(), BoxError> {
    run("put_chunk", "bound-state", false).await
}

#[tokio::test]
async fn head_chunk_bound_state() -> Result<(), BoxError> {
    run("head_chunk", "bound-state", false).await
}

#[tokio::test]
async fn list_spaces_worker_query_failure_state() -> Result<(), BoxError> {
    run("list_spaces", "worker-query-failure-state", false).await
}

#[tokio::test]
async fn list_spaces_worker_row_failure_state() -> Result<(), BoxError> {
    run("list_spaces", "worker-row-failure-state", false).await
}

#[tokio::test]
async fn list_spaces_permission_failure_state() -> Result<(), BoxError> {
    run("list_spaces", "permission-failure-state", false).await
}

#[tokio::test]
async fn list_spaces_worm_failure_state() -> Result<(), BoxError> {
    run("list_spaces", "worm-failure-state", false).await
}

#[tokio::test]
async fn preview_query_failure_state() -> Result<(), BoxError> {
    run("preview", "query-failure-state", false).await
}

#[tokio::test]
async fn preview_unconfigured_store_forwards_without_audit() -> Result<(), BoxError> {
    run("preview", "missing-store-state", false).await
}

#[tokio::test]
async fn put_chunk_register_failure_state() -> Result<(), BoxError> {
    run("put_chunk", "register-failure-state", false).await
}

#[tokio::test]
async fn preview_request_failure_state() -> Result<(), BoxError> {
    run("preview", "request-failure-state", false).await
}

#[tokio::test]
async fn patch_node_empty_patch_state() -> Result<(), BoxError> {
    run("patch_node", "empty-patch-state", false).await
}

#[tokio::test]
async fn revoke_member_folder_invalid_state() -> Result<(), BoxError> {
    run("revoke_member", "folder-invalid-state", false).await
}

#[tokio::test]
async fn nodes_meta_deleted_node_state() -> Result<(), BoxError> {
    run("nodes_meta", "deleted-node-state", false).await
}

#[tokio::test]
async fn tree_file_lock_state() -> Result<(), BoxError> {
    run("tree", "file-lock-state", false).await
}

#[tokio::test]
async fn preview_revoked_audit_state() -> Result<(), BoxError> {
    run("preview", "revoked-audit-state", false).await
}

#[tokio::test]
async fn patch_node_utf8_id_state() -> Result<(), BoxError> {
    run("patch_node", "utf8-id-state", false).await
}

async fn run(route: &str, case: &str, mutant: bool) -> Result<(), BoxError> {
    let _serial = SERIAL.lock().await;
    let case_name = case;
    let full_effects = (case.ends_with("-state-v2") || case.ends_with("-state"))
        || !matches!(
            route,
            "list_spaces"
                | "create_space"
                | "patch_space"
                | "list_members"
                | "grant_member"
                | "revoke_member"
                | "tree"
                | "nodes_meta"
                | "changes"
                | "access_invalidations"
                | "visibility_snapshot"
        );
    let case = case.strip_suffix("-state-v2").unwrap_or(case);
    let Some(db) = Db::for_case("drive2") else {
        return Ok(());
    };
    let c = db.connect().await?;
    let a = fixture::account(&c, "drive2-owner").await?;
    let b = fixture::account(&c, "drive2-foreign").await?;
    let outsider = if route == "revoke_member" && case == "outsider" {
        Some(fixture::account(&c, "drive2-outsider").await?)
    } else {
        None
    };
    let mut cut_task = None;
    let mut fixture_role = None;
    let acl_flags=c.query("SELECT key,enabled FROM feature_toggles WHERE key IN('feature.drive_node_acl_reads','feature.drive_node_acl_writes')",&[]).await?;
    let toggle: bool = c
        .query_one(
            "SELECT enabled FROM feature_toggles WHERE key='feature.drive'",
            &[],
        )
        .await?
        .get(0);
    let result=std::panic::AssertUnwindSafe(async {
        c.execute("UPDATE feature_toggles SET enabled=true WHERE key='feature.drive'",&[]).await?;
        let space:i64=c.query_one("SELECT drive_space_create($1,'Project','regular')",&[&a.user]).await?.get(0);
        let node:i64=c.query_one("SELECT drive_node_create($1,$2,NULL,'folder','Documents')",&[&a.user,&space]).await?.get(0);
        if matches!(route,"restore_node"|"destroy_node") || case=="deleted-node-state"{c.query_one("SELECT drive_node_trash($1,$2)",&[&a.user,&node]).await?;}
        let chunk_sha=chunk_sha();
        if route=="head_chunk"{c.query_one("SELECT drive_chunk_register($1,$2,$3,$4)",&[&a.user,&space,&chunk_sha,&(CHUNK.len() as i32)]).await?;}
        let version:i64=if route=="preview" || case=="file-lock-state"{
            let file:i64=c.query_one("SELECT drive_node_create($1,$2,NULL,'file','preview.docx')",&[&a.user,&space]).await?.get(0);
            c.query_one("SELECT drive_chunk_register($1,$2,$3,$4)",&[&a.user,&space,&chunk_sha,&(CHUNK.len() as i32)]).await?;
            let manifest=json!([{"sha256":chunk_sha,"size":CHUNK.len()}]).to_string();
            let raw:String=c.query_one("SELECT drive_file_put_version($1,$2,$3,$4,'application/vnd.openxmlformats-officedocument.wordprocessingml.document',NULL,$5::text::jsonb,'drive2','preview')::text",&[&a.user,&file,&chunk_sha,&(CHUNK.len() as i64),&manifest]).await?.get(0);
            let v:Value=serde_json::from_str(&raw)?;let version=v["versionId"].as_i64().ok_or("fixture version")?;
            use sha2::{Digest,Sha256};let hash=format!("{:x}",Sha256::digest(PREVIEW));let manifest=json!([{"sha256":hash,"size":PREVIEW.len()}]).to_string();
            if !matches!(case,"pending-state"|"request-failure-state"){c.query_one("SELECT drive_preview_attach($1,$2,$3::text::jsonb,'ready')",&[&version,&hash,&manifest]).await?;}
            if matches!(case,"audited-state"|"repeat-state"|"audit-failure-state"|"missing-store-state"|"revoked-audit-state"){c.query_one("SELECT drive_space_set_policy($1,$2,'{\"audit_reads\":true}'::jsonb,NULL,NULL,NULL)",&[&a.user,&space]).await?;}
            if case=="file-lock-state"{c.query_one("SELECT drive_file_lock($1,$2,'soft',NULL,$3,'drive2',480)",&[&a.user,&file,&version]).await?;}
            version
        }else{0};
        let destination:i64=if route=="patch_node"{c.query_one("SELECT drive_node_create($1,$2,NULL,'folder','Destination')",&[&a.user,&space]).await?.get(0)}else{0};
        let foreign_space:i64=c.query_one("SELECT drive_space_create($1,'Foreign project','regular')",&[&b.user]).await?.get(0);
        if route=="revoke_member" || case=="revoked-audit-state"{c.query_one("SELECT drive_member_grant($1,$2,$3,'viewer')",&[&a.user,&space,&b.user]).await?;}
        let io=std::sync::Arc::new(std::sync::Mutex::new(Vec::<Value>::new()));
        let endpoint=s3_peer(io.clone(),case).await;

        let mut worker_dsn=db.dsn.clone();
        let mut app_dsn=db.app.clone();
        if case=="revoked-audit-state"{
            let schema=format!("gofree_drive2_admission_{}",a.user);
            c.batch_execute(&format!("CREATE SCHEMA {schema}; GRANT USAGE ON SCHEMA {schema} TO setjoin_app; CREATE FUNCTION {schema}.drive_policy_resolve(p_space bigint) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$ DECLARE v_policy jsonb; BEGIN v_policy=public.drive_policy_resolve(p_space); IF p_space={space} AND EXISTS(SELECT 1 FROM public.drive_space_members WHERE space_id={space} AND user_id={member}) THEN PERFORM public.drive_member_revoke({owner},{space},{member}); END IF; RETURN v_policy; END; $$",space=space,member=b.user,owner=a.user)).await?;
            let base=app_dsn.as_deref().unwrap_or(&db.dsn);app_dsn=Some(format!("{}{}options=-csearch_path%3D{}%2Cpublic",base,if base.contains('?'){"&"}else{"?"},schema));
        }
        if matches!(case,"worker-query-failure-state"|"worker-row-failure-state"){
            let schema=format!("gofree_drive2_worker_{}",a.user);c.batch_execute(&format!("CREATE SCHEMA {schema}")).await?;
            if case=="worker-query-failure-state"{let columns:String=c.query_one("SELECT string_agg(quote_ident(attname),',' ORDER BY attnum) FROM pg_attribute WHERE attrelid='public.drive_spaces'::regclass AND attnum>0 AND NOT attisdropped AND attname<>'used_bytes'",&[]).await?.get(0);c.batch_execute(&format!("CREATE VIEW {schema}.drive_spaces AS SELECT {columns} FROM public.drive_spaces")).await?;}
            else{c.batch_execute(&format!("CREATE FUNCTION {schema}.fail(p_name text) RETURNS boolean LANGUAGE plpgsql AS $$ BEGIN IF p_name='Project' THEN RAISE EXCEPTION 'gofree-drive2-row-fault'; END IF; RETURN true; END; $$; CREATE VIEW {schema}.drive_spaces AS SELECT t.* FROM public.drive_spaces t WHERE {schema}.fail(t.name)")).await?;}
            worker_dsn=format!("{}{}options=-csearch_path%3D{}%2Cpublic",db.dsn,if db.dsn.contains('?'){"&"}else{"?"},schema);
        }
        let oracle_db=Db{dsn:worker_dsn.clone(),direct:db.direct.clone(),app:app_dsn.clone()};
        let oracle=common::go_oracle::start_named(&oracle_db,endpoint,None,"gofree-drive2").await?;
        let recording=oracle.is_some();io.lock().unwrap().clear();
        let mut command_dsn=app_dsn.as_deref().unwrap_or(&db.dsn).to_owned();
        if case.starts_with("commit-"){let cut=if case=="commit-after-state"{commit_wire::CommitCut::AfterCommit}else{commit_wire::CommitCut::BeforeCommit};let(dsn,task)=commit_wire::commit_cut_proxy(&command_dsn,cut).await;command_dsn=dsn;cut_task=Some(task);}
        let baseline=snapshot(&c,a.user,b.user,true).await?;
        let mut adapter=setjoin_gateway::drive::core::CoreRoute {exec:patient_exec(&command_dsn,if case.starts_with("commit-"){1}else{2})?,worker:patient_exec(&worker_dsn,2)?,keys:std::sync::Arc::new(common::recovery_keys()),issuer:"mailserver".into(),store:Some(std::sync::Arc::new(setjoin_gateway::recovery_worker::S3Store::new(&format!("http://{endpoint}"),"mailblobs","test-access","test-secret")?))};
        let forwarded=std::sync::Arc::new(std::sync::Mutex::new(Vec::<Value>::new()));
        let fallback=if case=="missing-store-state"{adapter.store=None;let observed=forwarded.clone();Some(common::fake_upstream(move|mut r|{let observed=observed.clone();async move{let method=r.method().to_string();let uri=r.uri().to_string();let body=r.body_mut().collect().await.unwrap().to_bytes();observed.lock().unwrap().push(json!({"method":method,"uri":uri,"body":String::from_utf8_lossy(&body)}));Response::builder().status(218).body(common::full("{\"forwarded\":true}")).unwrap()}}).await)}else{None};
        let table=if recording {RouteTable::proxy_all()}else{RouteTable::proxy_all().with(StatusMutant {inner:adapter,enabled:mutant})};
        let config=Config{upstream:fallback.map(|a|format!("http://{a}").parse()).transpose()?.or(oracle.as_ref().map(|o|format!("http://{}",o.address).parse()).transpose()?),trusted_proxies:TrustedProxies::parse("")?,upstream_header_timeout:setjoin_gateway::proxy::DEFAULT_HEADER_TIMEOUT,edge_limit:None};
        let gateway=Gateway::new(config,table)?;
        let gateway=if recording{gateway}else{let mut inventory:Value=serde_json::from_str(setjoin_gateway::inventory::BUNDLED)?;for row in inventory["routes"].as_array_mut().unwrap(){if row["family"]=="F14"&&row["slice"]=="sub-router-a"{row["state"]="ON".into();row["upstream"]="local-rust".into();}}gateway.with_inventory(&inventory.to_string())?};
        let listener=tokio::net::TcpListener::bind("127.0.0.1:0").await?;let address=listener.local_addr()?;
        let task=tokio::spawn(gateway.serve(listener));
        let (method,mut path,mut body)=match route {"list_spaces"=>("GET","/api/drive/spaces".to_owned(),String::new()),"create_space"=>("POST","/api/drive/spaces".to_owned(),json!({"name":"Created project"}).to_string()),"patch_space"=>("PATCH",format!("/api/drive/spaces/{space}"),json!({"classification":"secure"}).to_string()),"list_members"=>("GET",format!("/api/drive/spaces/{space}/members"),String::new()),"grant_member"=>("POST",format!("/api/drive/spaces/{space}/members"),json!({"userId":b.user,"role":"viewer"}).to_string()),"revoke_member"=>("DELETE",format!("/api/drive/spaces/{space}/members/{}",b.user),String::new()),"tree"=>("GET",format!("/api/drive/spaces/{space}/tree"),String::new()),"nodes_meta"=>("GET",format!("/api/drive/nodes?ids={node}"),String::new()),"changes"=>("GET",format!("/api/drive/changes?space={space}&since=0"),String::new()),"access_invalidations"=>("GET",format!("/api/drive/access-invalidations?space={space}"),String::new()),"visibility_snapshot"=>("GET",format!("/api/drive/visibility-snapshot?space={space}"),String::new()),"create_node"=>("POST","/api/drive/nodes".into(),json!({"spaceId":space,"kind":"file","name":"Created file.txt","contentType":"text/plain"}).to_string()),"patch_node"=>("PATCH",format!("/api/drive/nodes/{node}"),json!({"newName":"Renamed docs","newParentId":destination}).to_string()),"trash_node"=>("POST",format!("/api/drive/nodes/{node}/trash"),String::new()),"restore_node"=>("POST",format!("/api/drive/nodes/{node}/restore"),String::new()),"destroy_node"=>("DELETE",format!("/api/drive/nodes/{node}"),String::new()),"head_chunk"=>("HEAD",format!("/api/drive/chunks/{chunk_sha}?space={space}"),String::new()),"put_chunk"=>("PUT",format!("/api/drive/chunks/{chunk_sha}?space={space}"),String::from_utf8(CHUNK.to_vec())?),"preview"=>("GET",format!("/api/drive/versions/{version}/preview"),String::new()),_=>unreachable!()};
        let canonical=if route=="preview"{"/drive/versions/{id}/preview"}else if matches!(route,"head_chunk"|"put_chunk"){"/drive/chunks/{sha256}"}else if route=="destroy_node"{"/drive/nodes/{id}"}else if route=="restore_node"{"/drive/nodes/{id}/restore"}else if route=="trash_node"{"/drive/nodes/{id}/trash"}else if route=="patch_node"{"/drive/nodes/{id}"}else if route=="create_node"{"/drive/nodes"}else if route=="visibility_snapshot"{"/drive/visibility-snapshot"}else if route=="access_invalidations"{"/drive/access-invalidations"}else if route=="changes"{"/drive/changes"}else if route=="nodes_meta"{"/drive/nodes"}else if route=="tree"{"/drive/spaces/{id}/tree"}else if route=="revoke_member"{"/drive/spaces/{id}/members/{userId}"}else if matches!(route,"list_members"|"grant_member"){"/drive/spaces/{id}/members"}else if route=="patch_space"{"/drive/spaces/{id}"}else{"/drive/spaces"};
        if case=="foreign"&&route=="create_space"{body=json!({"name":"Created project","ownerUserId":a.user,"userId":a.user,"mailboxId":a.mailbox}).to_string();}
        if case=="invalid"{
            match route{
                "list_spaces"=>path.push_str("?admin=invalid"),
                "create_space"|"patch_space"|"create_node"|"patch_node"|"grant_member"=>body="{".into(),
                "revoke_member"=>path=format!("/api/drive/spaces/{space}/members/invalid"),
                "list_members"=>path="/api/drive/spaces/invalid/members".into(),
                "tree"=>path=format!("/api/drive/spaces/{space}/tree?parent=invalid"),
                "nodes_meta"=>path="/api/drive/nodes?ids=invalid".into(),
                "changes"=>path=format!("/api/drive/changes?space={space}&since=invalid"),
                "access_invalidations"=>path=format!("/api/drive/access-invalidations?space={space}&max=0"),
                "visibility_snapshot"=>path=format!("/api/drive/visibility-snapshot?space={space}&epoch=invalid"),
                "trash_node"=>path="/api/drive/nodes/invalid/trash".into(),
                "restore_node"=>path="/api/drive/nodes/invalid/restore".into(),
                "destroy_node"=>path="/api/drive/nodes/invalid".into(),
                "head_chunk"|"put_chunk"=>path=format!("/api/drive/chunks/invalid?space={space}"),
                "preview"=>path="/api/drive/versions/invalid/preview".into(),
                _=>unreachable!(),
            }
        }
        match case {
            "bad-id-state"=>path=format!("/api{}",canonical.replace("{id}","invalid").replace("{userId}",&b.user.to_string())),
            "missing-space-state"=>path=path.split('?').next().unwrap().to_owned(),
            "bad-binding-state"=>path.push_str("&target=1"),
            "bad-after-state"=>path.push_str("&after=-1"),
            "bad-max-state"=>path.push_str("&max=0"),
            "bad-name-state"=>body=json!({"newName":23}).to_string(),
            "bad-parent-state"=>body=json!({"newParentId":"bad"}).to_string(),
            "bad-retention-state"=>body=json!({"retentionDays":"bad"}).to_string(),
            "bad-worm-state"=>body=json!({"wormMode":23}).to_string(),
            "bad-vault-state"=>body=json!({"vaultQuotaMb":true}).to_string(),
            "bad-classification-state"=>body=json!({"classification":false}).to_string(),
            "empty-patch-state"=>body="{}".into(),
            "resync-state"=>{c.execute("DELETE FROM drive_changes WHERE space_id=$1",&[&space]).await?;},
            "rate-state"=>{c.query("SELECT rate_limit_check('drive:name-mutation:'||$1::bigint::text,120,1,5) FROM generate_series(1,121)",&[&a.user]).await?;},
            "bound-state"=>{c.execute("UPDATE feature_toggles SET enabled=true WHERE key IN('feature.drive_node_acl_reads','feature.drive_node_acl_writes')",&[]).await?;c.execute("UPDATE drive_spaces SET acl_mode='acl' WHERE id=$1 AND owner_user_id=$2",&[&space,&a.user]).await?;let epoch:i64=c.query_one("SELECT epoch FROM drive_acl_generations WHERE space_id=$1",&[&space]).await?.get(0);path.push_str(&format!("&target={node}&aclEpoch={epoch}"));if route=="head_chunk"{c.query_one("SELECT drive_chunk_register_bound($1,$2,$3,$4,$5,$6)",&[&a.user,&space,&node,&epoch,&chunk_sha,&(CHUNK.len() as i32)]).await?;}},
            "quota-admin-state"=>body=json!({"quotaBytes":1000000}).to_string(),
            "bad-quota-state"=>body=json!({"quotaBytes":"bad"}).to_string(),
            "move-failure-state"=>body=json!({"newName":"Must roll back","newParentId":-1}).to_string(),
            "utf8-id-state"=>path="/api/drive/nodes/%F0%90%80".into(),
            "policy-state" => body=json!({"exportPolicy":{"audit_reads":true},"retentionDays":30,"wormMode":"governance","vaultQuotaMb":100}).to_string(),
            "quota-state" => body=json!({"quotaBytes":1000000}).to_string(),
            "folder-state" => path.push_str(&format!("?folder={node}")),
            "admin-denied-state"|"admin-state"|"worker-query-failure-state"|"worker-row-failure-state"|"permission-failure-state"|"worm-failure-state" => path.push_str("?admin=1"),
            "range-state"|"bad-range-state" => {},
            "encoded-id-state"=>path=path.replace(&node.to_string(),&format!("{node}%2Fignored")),
            "too-many-state"=>path=format!("/api/drive/nodes?ids={}",vec![node.to_string();501].join(",")),
            "overflow-state"=>body=json!({"name":"Overflow","retentionDays":2147483648i64}).to_string(),
            "json-trailer-state"=>body.push_str(&" ".repeat(20000)),
            "json-oversize-state"=>body=json!({"spaceId":space,"kind":"file","name":"x".repeat(20000)}).to_string(),
            "locale-state"=>body="{".into(),
            "folder-invalid-state"=>path.push_str("?folder=invalid"),
            "bad-cursor-state"=>path.push_str("&cursor=invalid"),
            "stale-epoch-state"=>path.push_str("&epoch=999"),
            "oversize-state"=>body="x".repeat(4*1024*1024+1),
            "mismatch-state"=>body="wrong hash".into(),
            "empty-state"=>{use sha2::{Digest,Sha256};body.clear();path=format!("/api/drive/chunks/{:x}?space={space}",Sha256::digest([]));},
            _ => {}
        }
        if matches!(case,"admin-state"|"quota-admin-state"|"worker-query-failure-state"|"worker-row-failure-state"|"permission-failure-state"|"worm-failure-state") { let role:i64=c.query_one("INSERT INTO admin_role_groups(name,permissions) VALUES('gofree-drive2-'||$1::bigint::text,ARRAY['drive.view','drive.manage']) RETURNING id",&[&a.user]).await?.get(0);fixture_role=Some(role);c.execute("INSERT INTO admin_role_assignments(user_id,role_group_id,granted_by) VALUES($1,$2,$1)",&[&a.user,&role]).await?; }
        if case=="query-failure-state"{let relation=if route=="list_spaces"{"drive_spaces"}else if route=="list_members"{"drive_space_members"}else if route=="head_chunk"{"drive_chunks"}else if route=="preview"{"drive_file_versions"}else{"drive_nodes"};c.batch_execute(&format!("REVOKE SELECT ON {relation} FROM setjoin_app")).await?;}
        if case=="audit-failure-state"{c.batch_execute(&format!("CREATE FUNCTION gofree_drive2_audit_{0}() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'gofree-drive2-audit-fault'; END; $$; CREATE TRIGGER gofree_drive2_audit_{0} BEFORE INSERT ON drive_audit_log FOR EACH ROW WHEN (NEW.space_id={1} AND NEW.action='preview') EXECUTE FUNCTION gofree_drive2_audit_{0}()",a.user,space)).await?;}
        if matches!(case,"permission-failure-state"|"worm-failure-state"|"request-failure-state"){let name=if case=="permission-failure-state"{"drive_has_admin_perm(bigint,text)"}else if case=="request-failure-state"{"drive_preview_request(bigint,bigint)"}else{"drive_worm_pending(bigint)"};c.batch_execute(&format!("ALTER FUNCTION {name} RENAME TO gofree_drive2_function_{}",a.user)).await?;}
        if case=="register-failure-state"{c.batch_execute(&format!("CREATE FUNCTION gofree_drive2_register_{0}() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'gofree-drive2-register-fault'; END; $$; CREATE TRIGGER gofree_drive2_register_{0} BEFORE INSERT ON drive_upload_claims FOR EACH ROW WHEN (NEW.user_id={0}) EXECUTE FUNCTION gofree_drive2_register_{0}()",a.user)).await?;}
        // Keep both rate-attempt observations in one Go minute bucket.
        if case=="repeat-state" && matches!(route,"create_node"|"patch_node"|"restore_node") {
            let second:i32=c.query_one("SELECT extract(second FROM clock_timestamp())::integer",&[]).await?.get(0);
            if second>=45{tokio::time::sleep(std::time::Duration::from_secs((61-second) as u64)).await;}
        }
        let mut notifications=db.listen("drive").await?;
        let send_request=||common::send(address,Request::builder().method(method).uri(&path).header("host","mail.test").header("origin","http://mail.test").header("authorization",format!("Bearer {}",token(if case=="outsider"{outsider.as_ref().unwrap().user}else if case=="foreign" || case=="revoked-audit-state"{b.user}else{a.user}))).header("content-type","application/json").header("x-request-id","drive2-oracle").header("accept-language",if case=="locale-state"{"zh-CN"}else{"en"}).header("range",if case=="range-state"{"bytes=2-8"}else if case=="bad-range-state"{"bytes=-4"}else{""}).body(common::full(body.clone())).unwrap());
        let mut response=send_request().await;
        let first=if case=="repeat-state"{let status=response.status().as_u16();let hs=headers(response.headers());let bytes=common::body_bytes(response).await;let body=response_body(&bytes,&hs)?;let effects=snapshot(&c,a.user,b.user,true).await?;let notify=notifications.drain(&c).await?.iter().map(|s|serde_json::from_str::<Value>(s)).collect::<Result<Vec<_>,_>>()?;let first=json!({"response":{"status":status,"headers":hs,"body":body},"audit":effects["audit"],"effects":effects,"notify":notify,"io":io.lock().unwrap().clone()});response=send_request().await;Some(first)}else{None};
        let status=response.status().as_u16();let headers=headers(response.headers());let bytes=common::body_bytes(response).await;
        if !recording{let metrics=common::send(address,Request::builder().uri("/_gateway/metrics").body(common::full(""))?).await;let metrics=String::from_utf8(common::body_bytes(metrics).await.to_vec())?;let count=if case=="missing-store-state"{1}else{0};if !metrics.contains(&format!("setjoin_gateway_proxied_to_go_total {count}\n"))||!metrics.contains(&format!("setjoin_gateway_proxied_to_go_by_family_total{{family=\"F14\"}} {count}\n")){return Err(format!("native proxy counters: {metrics}").into())}}
        task.abort();let _=task.await;
        if case=="success"&&status!=if matches!(route,"create_space"|"create_node"|"put_chunk"){201}else if matches!(route,"patch_space"|"revoke_member"|"patch_node"|"trash_node"|"restore_node"|"destroy_node"){204}else{200} {return Err(format!("{route}/{case}: HTTP {status}: {}",String::from_utf8_lossy(&bytes)).into());}
        let mut body:Value=if bytes.is_empty(){Value::Null}else if headers["content-type"]=="application/pdf"{use base64::Engine;json!({"base64":base64::engine::general_purpose::STANDARD.encode(&bytes)})}else{serde_json::from_slice(&bytes)?};
        let actual_path=path.split('?').next().unwrap().strip_prefix("/api").unwrap();
        if case=="encoded-id-state" && body["instance"]==actual_path.replace("%2F","/"){body["instance"]=canonical.replace("{id}","{id}/ignored").into();}
        if body["instance"]==actual_path{
            let instance=if case=="invalid"&&matches!(route,"revoke_member"){canonical.replace("{userId}","invalid")}else if case=="invalid"&&matches!(route,"list_members"|"trash_node"|"restore_node"|"destroy_node"|"preview"){canonical.replace("{id}","invalid")}else{canonical.to_owned()};
            body["instance"]=instance.into();
        }
        let effects=snapshot(&c,a.user,b.user,full_effects).await?;
        let notify=notifications.drain(&c).await?.iter().map(|s|serde_json::from_str::<Value>(s)).collect::<Result<Vec<_>,_>>()?;
        let mut observation=json!({"request":{"method":method,"path":canonical},"response":{"status":status,"headers":headers,"body":body},"audit":effects["audit"],"effects":effects,"notify":notify});
        if let Some(first)=first{observation["first"]=first;}
        if matches!(route,"put_chunk"|"preview"){observation["io"]=json!(io.lock().unwrap().clone());}
        let mut spaces=std::collections::BTreeMap::new();
        let mut created_spaces=0;for row in observation["effects"]["spaces"].as_array().unwrap(){let id=row["id"].as_i64().unwrap();spaces.insert(id,if id==space{"<space>".to_owned()}else if id==foreign_space{"<foreign-space>".into()}else if row["is_personal"]==true{format!("<personal-{}>",if row["owner_user_id"]==a.user{"owner"}else{"foreign"})}else{created_spaces+=1;if created_spaces==1{"<created-space>".into()}else{format!("<created-space-{created_spaces}>")}});}
        if route=="create_space"&&status==201 {let id=observation["response"]["body"]["id"].as_i64().ok_or("created space ID")?;observation["response"]["body"]["id"]=spaces.get(&id).ok_or("created space must exist")?.clone().into();}
        let mut nodes=std::collections::BTreeMap::from([(node,"<node>".to_owned())]);
        for row in observation["effects"]["nodes"].as_array().unwrap(){let id=row["id"].as_i64().unwrap();if id!=node{let label=format!("<node-{}>",nodes.len()+1);nodes.insert(id,label);}}
        if route=="create_node"&&status==201{let id=observation["response"]["body"]["id"].as_i64().ok_or("created node ID")?;observation["response"]["body"]["id"]=nodes.get(&id).ok_or("created node must exist")?.clone().into();}
        if let Some(id)=observation["first"]["response"]["body"]["id"].as_i64(){let labels=if route=="create_space"{&spaces}else{&nodes};observation["first"]["response"]["body"]["id"]=labels.get(&id).ok_or("first created ID")?.clone().into();}
        version_identities(&mut observation);
        normalize(&mut observation,"",&a,&b,&spaces,&nodes);
        invalidation_noise(&mut observation);s3_noise(&mut observation);if observation.get("first").is_some(){s3_noise(&mut observation["first"]);}
        if case=="missing-store-state"{
            assert_eq!(status,218);assert_eq!(*forwarded.lock().unwrap(),vec![json!({"method":method,"uri":path,"body":""})]);
            let mut seeded=json!({"effects":baseline});version_identities(&mut seeded);normalize(&mut seeded,"",&a,&b,&spaces,&nodes);invalidation_noise(&mut seeded);setjoin_conformance::golden::compare(&seeded["effects"],&observation["effects"])?;assert_eq!(observation["notify"],json!([]));assert_eq!(observation["io"],json!([]));return Ok(())
        }
        if case.starts_with("commit-"){
            assert_eq!(status,503,"COMMIT loss must remain Unknown");let committed=case=="commit-after-state";
            let cut=tokio::time::timeout(std::time::Duration::from_secs(5),cut_task.take().unwrap()).await???;assert_eq!(cut==commit_wire::CommitCut::AfterCommit,committed);
            let operation=observation["response"]["headers"]["x-operation-id"].as_str().ok_or("missing operation ID")?;
            let found:bool=c.query_one("SELECT EXISTS(SELECT 1 FROM rust_operation_receipts WHERE operation_id=$1::text::uuid AND family='F14' AND command='drive_list_spaces')",&[&operation]).await?.get(0);assert_eq!(found,committed);
            if committed{let expected:Value=serde_json::from_slice(&std::fs::read(std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/conformance/drive/core/list_spaces-success-state-v2.json"))?)?;for key in ["effects","audit","notify"]{setjoin_conformance::golden::compare(&expected["observation"][key],&observation[key])?;}}
            else{let mut baseline=baseline;normalize(&mut baseline,"",&a,&b,&spaces,&nodes);let mut wrapper=json!({"effects":baseline});invalidation_noise(&mut wrapper);setjoin_conformance::golden::compare(&wrapper["effects"],&observation["effects"])?;assert_eq!(observation["notify"],json!([]));}
            return Ok(())
        }
        let path=std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(format!("../../tests/conformance/drive/core/{route}-{case_name}.json"));
        if recording {setjoin_conformance::golden::record(&path,&json!({"format":1,"route":format!("{method} {canonical}"),"case":format!("{route}-{case_name}"),"go_source":std::env::var("GOFREE_GO_SOURCE")?,"observation":observation}))?;}
        else {let mut expected:Value=serde_json::from_slice(&std::fs::read(&path)?)?;
            if expected["observation"].get("request").is_none(){expected["observation"]["request"]=json!({"method":method,"path":canonical});}
            let admitted=path.parent().unwrap().join("qualified").join(path.file_name().unwrap());
            if admitted.exists(){use sha2::{Digest,Sha256};let admitted:Value=serde_json::from_slice(&std::fs::read(&admitted)?)?;assert_eq!(admitted["source_recording"]["sha256"],format!("{:x}",Sha256::digest(std::fs::read(&path)?)),"immutable Go provenance");setjoin_conformance::golden::compare(&expected["observation"],&admitted["observation"])?;expected=admitted;let rows:Value=serde_json::from_slice(&std::fs::read(path.parent().unwrap().join("qualified").join(format!("{route}-{case_name}-row-effects.json")))?)?;setjoin_conformance::golden::compare(&rows["effects"],&json!([expected["observation"]["effects"],expected["observation"]["audit"],expected["observation"]["notify"],expected["observation"].get("io").cloned().unwrap_or(json!([])),expected["observation"].get("first")]))?;}
            let rules:Value=serde_json::from_str(include_str!("../../../tests/conformance/drive/core/legacy-identities.json"))?;
            if let Some(rules)=rules[format!("{route}-{case_name}")].as_array(){for rule in rules{let value=expected["observation"].pointer_mut(rule["field"].as_str().unwrap()).ok_or("stale identity normalization")?;assert_eq!(*value,rule["from"]);*value=rule["to"].clone();}}
            invalidation_noise(&mut expected["observation"]);s3_noise(&mut expected["observation"]);
            setjoin_conformance::golden::compare(&expected["observation"],&observation)?;println!("GOLDEN-REPLAY: {method} {canonical} :: {}",expected["case"].as_str().unwrap());}

        Ok::<_,BoxError>(())
    }).catch_unwind().await;
    if let Some(task) = cut_task {
        task.abort();
        let _ = task.await;
    }
    if case == "revoked-audit-state" {
        c.batch_execute(&format!(
            "DROP SCHEMA IF EXISTS gofree_drive2_admission_{} CASCADE",
            a.user
        ))
        .await?;
    }
    if matches!(
        case,
        "worker-query-failure-state" | "worker-row-failure-state"
    ) {
        c.batch_execute(&format!(
            "DROP SCHEMA IF EXISTS gofree_drive2_worker_{} CASCADE",
            a.user
        ))
        .await?;
    }
    if matches!(
        case,
        "permission-failure-state" | "worm-failure-state" | "request-failure-state"
    ) {
        let (args, name) = if case == "permission-failure-state" {
            ("bigint,text", "drive_has_admin_perm")
        } else if case == "request-failure-state" {
            ("bigint,bigint", "drive_preview_request")
        } else {
            ("bigint", "drive_worm_pending")
        };
        c.batch_execute(&format!(
            "ALTER FUNCTION gofree_drive2_function_{}({args}) RENAME TO {name}",
            a.user
        ))
        .await?;
    }
    if case == "query-failure-state" {
        let relation = if route == "list_spaces" {
            "drive_spaces"
        } else if route == "list_members" {
            "drive_space_members"
        } else if route == "head_chunk" {
            "drive_chunks"
        } else if route == "preview" {
            "drive_file_versions"
        } else {
            "drive_nodes"
        };
        c.batch_execute(&format!("GRANT SELECT ON {relation} TO setjoin_app"))
            .await?;
    }
    if case == "audit-failure-state" {
        c.batch_execute(&format!("DROP TRIGGER IF EXISTS gofree_drive2_audit_{0} ON drive_audit_log; DROP FUNCTION IF EXISTS gofree_drive2_audit_{0}()",a.user)).await?;
    }
    if case == "register-failure-state" {
        c.batch_execute(&format!("DROP TRIGGER IF EXISTS gofree_drive2_register_{0} ON drive_upload_claims; DROP FUNCTION IF EXISTS gofree_drive2_register_{0}()",a.user)).await?;
    }
    let owned_chunks=c.query("SELECT scope_key,sha256 FROM drive_chunks t WHERE EXISTS(SELECT 1 FROM drive_upload_claims c WHERE c.scope_key=t.scope_key AND c.sha256=t.sha256 AND c.user_id IN($1,$2)) OR EXISTS(SELECT 1 FROM drive_upload_authorizations ua WHERE ua.scope_key=t.scope_key AND ua.sha256=t.sha256 AND ua.user_id IN($1,$2)) OR EXISTS(SELECT 1 FROM drive_version_chunks vc JOIN drive_file_versions v ON v.id=vc.version_id JOIN drive_spaces s ON s.id=v.space_id WHERE vc.scope_key=t.scope_key AND vc.chunk_sha256=t.sha256 AND s.owner_user_id IN($1,$2))",&[&a.user,&b.user]).await?;
    for user in [a.user, b.user] {
        c.execute("DELETE FROM drive_nodes WHERE space_id IN(SELECT id FROM drive_spaces WHERE owner_user_id=$1)",&[&user]).await?;
    }
    c.batch_execute(&format!("BEGIN; SET LOCAL session_replication_role=replica; DELETE FROM drive_audit_log WHERE space_id IN(SELECT id FROM drive_spaces WHERE owner_user_id IN({0},{1})) OR user_id IN({0},{1}); DELETE FROM admin_audit_log WHERE user_id IN({0},{1}); COMMIT;",a.user,b.user)).await?;
    for user in [a.user, b.user] {
        c.execute("DELETE FROM drive_spaces WHERE owner_user_id=$1", &[&user])
            .await?;
    }
    c.execute(
        "DELETE FROM drive_upload_authorizations WHERE user_id IN($1,$2)",
        &[&a.user, &b.user],
    )
    .await?;
    c.execute(
        "DELETE FROM drive_upload_claims WHERE user_id IN($1,$2)",
        &[&a.user, &b.user],
    )
    .await?;
    for row in owned_chunks {
        let scope: String = row.get(0);
        let sha: String = row.get(1);
        c.execute(
            "DELETE FROM drive_chunk_gc_queue WHERE scope_key=$1 AND sha256=$2",
            &[&scope, &sha],
        )
        .await?;
        c.execute("DELETE FROM drive_chunks WHERE scope_key=$1 AND sha256=$2 AND ref_count=0 AND NOT EXISTS(SELECT 1 FROM drive_upload_claims c WHERE c.scope_key=$1 AND c.sha256=$2)",&[&scope,&sha]).await?;
    }
    c.execute("DELETE FROM rate_limit_counters WHERE key IN('drive:name-mutation:'||$1::bigint::text,'drive:name-mutation:'||$2::bigint::text)",&[&a.user,&b.user]).await?;
    c.execute(
        "UPDATE feature_toggles SET enabled=$1 WHERE key='feature.drive'",
        &[&toggle],
    )
    .await?;
    c.execute(
        "DELETE FROM admin_role_assignments WHERE user_id IN($1,$2) OR granted_by IN($1,$2)",
        &[&a.user, &b.user],
    )
    .await?;
    if let Some(role) = fixture_role {
        c.execute("DELETE FROM admin_role_groups WHERE id=$1", &[&role])
            .await?;
    }
    for flag in acl_flags {
        let key: String = flag.get(0);
        let value: bool = flag.get(1);
        c.execute(
            "UPDATE feature_toggles SET enabled=$2 WHERE key=$1",
            &[&key, &value],
        )
        .await?;
    }
    fixture::remove(&c, &a).await?;
    fixture::remove(&c, &b).await?;
    if let Some(outsider) = outsider {
        fixture::remove(&c, &outsider).await?;
    }
    match result {
        Ok(r) => r,
        Err(p) => std::panic::resume_unwind(p),
    }
}
fn token(user: i64) -> String {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B, Engine};
    use p256::ecdsa::{signature::Signer, SigningKey};
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let h = B.encode(json!({"alg":"ES256","kid":"test-es256-1","typ":"JWT"}).to_string());
    let b=B.encode(json!({"uid":user,"email":"drive2@test","typ":"access","jti":"drive2-test","fam":"drive2-test","iss":"mailserver","aud":["mailserver-gateway"],"iat":now-10,"exp":now+600}).to_string());
    let s: p256::ecdsa::Signature = SigningKey::from_slice(&[0x11; 32])
        .unwrap()
        .sign(format!("{h}.{b}").as_bytes());
    format!("{h}.{b}.{}", B.encode(s.to_bytes()))
}
fn headers(h: &hyper::HeaderMap) -> Value {
    let mut v = json!({});
    for (k, s) in h {
        if !matches!(
            k.as_str(),
            "date" | "content-length" | "transfer-encoding" | "connection"
        ) {
            v[k.as_str()] = s.to_str().unwrap().into();
        }
    }
    v
}
async fn snapshot(
    c: &tokio_postgres::Client,
    a: i64,
    b: i64,
    full: bool,
) -> Result<Value, BoxError> {
    let mut v = json!({});
    for(table,query)in [
        ("spaces","SELECT to_jsonb(t)::text FROM drive_spaces t WHERE owner_user_id IN($1,$2) ORDER BY name,id"),
        ("members","SELECT to_jsonb(t)::text FROM drive_space_members t WHERE space_id IN(SELECT id FROM drive_spaces WHERE owner_user_id IN($1,$2)) ORDER BY space_id,role,user_id"),
        ("nodes","SELECT to_jsonb(t)::text FROM drive_nodes t WHERE space_id IN(SELECT id FROM drive_spaces WHERE owner_user_id IN($1,$2)) ORDER BY id"),
        ("changes","SELECT to_jsonb(t)::text FROM drive_changes t WHERE space_id IN(SELECT id FROM drive_spaces WHERE owner_user_id IN($1,$2)) ORDER BY space_id,seq"),
        ("generations","SELECT to_jsonb(t)::text FROM drive_acl_generations t WHERE space_id IN(SELECT id FROM drive_spaces WHERE owner_user_id IN($1,$2)) ORDER BY space_id"),
        ("closure","SELECT to_jsonb(t)::text FROM drive_node_closure t WHERE space_id IN(SELECT id FROM drive_spaces WHERE owner_user_id IN($1,$2)) ORDER BY space_id,ancestor_id,descendant_id"),
        ("files","SELECT to_jsonb(t)::text FROM drive_files t WHERE space_id IN(SELECT id FROM drive_spaces WHERE owner_user_id IN($1,$2)) ORDER BY node_id"),
        ("versions","SELECT to_jsonb(t)::text FROM drive_file_versions t WHERE space_id IN(SELECT id FROM drive_spaces WHERE owner_user_id IN($1,$2)) ORDER BY id"),
        ("grants","SELECT to_jsonb(t)::text FROM drive_acl_grants t WHERE space_id IN(SELECT id FROM drive_spaces WHERE owner_user_id IN($1,$2)) ORDER BY id"),
        ("invalidations","SELECT to_jsonb(t)::text FROM drive_access_invalidations t WHERE space_id IN(SELECT id FROM drive_spaces WHERE owner_user_id IN($1,$2)) ORDER BY created_at,cursor"),
        ("audit","SELECT (to_jsonb(t)-'checksum')::text FROM drive_audit_log t WHERE user_id IN($1,$2) ORDER BY space_id,id")
    ]{v[table]=c.query(query,&[&a,&b]).await?.iter().map(|r|serde_json::from_str::<Value>(&r.get::<_,String>(0))).collect::<Result<Vec<_>,_>>()?.into();}
    if full {
        for table in [
            "drive_acl_breaks",
            "drive_acl_cutover_evidence",
            "drive_acl_shadow_state",
            "drive_acl_shadow_mismatches",
            "drive_folder_admins",
            "drive_file_branches",
            "drive_file_locks",
            "drive_access_request_policies",
            "drive_access_request_details",
            "drive_export_grants",
        ] {
            let query=format!("SELECT to_jsonb(t)::text FROM {table} t WHERE space_id IN(SELECT id FROM drive_spaces WHERE owner_user_id IN($1,$2)) ORDER BY to_jsonb(t)::text");
            v[table] = c
                .query(&query, &[&a, &b])
                .await?
                .iter()
                .map(|r| serde_json::from_str::<Value>(&r.get::<_, String>(0)))
                .collect::<Result<Vec<_>, _>>()?
                .into();
        }
        for(table,query)in[
            ("rate","SELECT to_jsonb(t)::text FROM rate_limit_counters t WHERE key IN('drive:name-mutation:'||$1::bigint::text,'drive:name-mutation:'||$2::bigint::text) ORDER BY key"),
            ("claims","SELECT to_jsonb(t)::text FROM drive_upload_claims t WHERE user_id IN($1,$2) ORDER BY scope_key,sha256,user_id"),
            ("authorizations","SELECT to_jsonb(t)::text FROM drive_upload_authorizations t WHERE user_id IN($1,$2) ORDER BY scope_key,sha256,user_id,target_node_id"),
            ("chunks","SELECT to_jsonb(t)::text FROM drive_chunks t WHERE EXISTS(SELECT 1 FROM drive_upload_claims c WHERE c.scope_key=t.scope_key AND c.sha256=t.sha256 AND c.user_id IN($1,$2)) OR EXISTS(SELECT 1 FROM drive_upload_authorizations ua WHERE ua.scope_key=t.scope_key AND ua.sha256=t.sha256 AND ua.user_id IN($1,$2)) OR EXISTS(SELECT 1 FROM drive_version_chunks vc JOIN drive_file_versions v ON v.id=vc.version_id JOIN drive_spaces s ON s.id=v.space_id WHERE vc.scope_key=t.scope_key AND vc.chunk_sha256=t.sha256 AND s.owner_user_id IN($1,$2)) ORDER BY scope_key,sha256"),
            ("version_chunks","SELECT to_jsonb(t)::text FROM drive_version_chunks t JOIN drive_file_versions v ON v.id=t.version_id JOIN drive_spaces s ON s.id=v.space_id WHERE s.owner_user_id IN($1,$2) ORDER BY t.version_id,t.stream,t.ordinal"),
            ("labels","SELECT to_jsonb(t)::text FROM drive_version_labels t JOIN drive_file_versions v ON v.id=t.version_id JOIN drive_spaces s ON s.id=v.space_id WHERE s.owner_user_id IN($1,$2) ORDER BY t.version_id,t.label"),
            ("watches","SELECT to_jsonb(t)::text FROM drive_watches t JOIN drive_nodes n ON n.id=t.node_id JOIN drive_spaces s ON s.id=n.space_id WHERE s.owner_user_id IN($1,$2) ORDER BY t.node_id,t.user_id"),
            ("core_audit","SELECT (to_jsonb(t)-'checksum')::text FROM admin_audit_log t WHERE user_id IN($1,$2) ORDER BY id")
        ]{v[table]=c.query(query,&[&a,&b]).await?.iter().map(|r|serde_json::from_str::<Value>(&r.get::<_,String>(0))).collect::<Result<Vec<_>,_>>()?.into();}
    }
    let invalid:i64=c.query_one("SELECT count(*) FROM drive_spaces s CROSS JOIN LATERAL verify_drive_audit_chain(s.id) v WHERE s.owner_user_id IN($1,$2) AND NOT v.valid",&[&a,&b]).await?.get(0);
    assert_eq!(
        invalid, 0,
        "Drive audit chain must verify before checksum normalization"
    );
    Ok(v)
}
fn normalize(
    v: &mut Value,
    key: &str,
    a: &fixture::Account,
    b: &fixture::Account,
    spaces: &std::collections::BTreeMap<i64, String>,
    nodes: &std::collections::BTreeMap<i64, String>,
) {
    match v {
        Value::Object(m) => {
            if let Some(id) = m.get("id").and_then(Value::as_i64) {
                let replacement = if m.contains_key("isPersonal") || m.contains_key("is_personal") {
                    spaces.get(&id).cloned()
                } else if m.contains_key("kind") {
                    nodes.get(&id).cloned()
                } else {
                    None
                };
                if let Some(s) = replacement {
                    m.insert("id".into(), s.into());
                }
            }
            if let Some(target) = m.get("target_id").cloned() {
                let id = target
                    .as_i64()
                    .or_else(|| target.as_str().and_then(|s| s.parse().ok()));
                if let Some(id) = id {
                    if m.get("target_type").and_then(Value::as_str) == Some("space") {
                        if let Some(name) = spaces.get(&id) {
                            m.insert("target_id".into(), name.clone().into());
                        }
                    } else if m.get("target_type").and_then(Value::as_str) == Some("member") {
                        if id == a.user {
                            m.insert("target_id".into(), "<owner>".into());
                        } else if id == b.user {
                            m.insert("target_id".into(), "<foreign>".into());
                        }
                    } else if let Some(label) = nodes.get(&id) {
                        m.insert("target_id".into(), label.clone().into());
                    }
                }
            }
            for (k, v) in m {
                normalize(v, k, a, b, spaces, nodes)
            }
        }
        Value::Array(arr) => {
            for v in arr {
                normalize(v, key, a, b, spaces, nodes)
            }
        }
        Value::Number(n) => {
            let id = n.as_i64().unwrap_or(-1);
            let name = if [
                "owner_user_id",
                "user_id",
                "created_by",
                "author_user_id",
                "granted_by",
                "purged_by",
                "revoked_by",
                "holderId",
                "userId",
            ]
            .contains(&key)
            {
                if id == a.user {
                    Some("<owner>".into())
                } else if id == b.user {
                    Some("<foreign>".into())
                } else {
                    None
                }
            } else if ["space_id", "spaceId"].contains(&key) {
                spaces.get(&id).cloned()
            } else if [
                "node_id",
                "file_node_id",
                "fileNodeId",
                "target_node_id",
                "nodeId",
                "parent_id",
                "parentId",
                "ancestor_id",
                "anchor_node_id",
                "anchorNodeId",
                "descendant_id",
            ]
            .contains(&key)
            {
                nodes.get(&id).cloned()
            } else {
                None
            };
            if let Some(name) = name {
                *v = Value::String(name);
            }
        }
        Value::String(s) => {
            if key == "key" && *s == format!("drive:name-mutation:{}", a.user) {
                *s = "<owner-name-rate>".into();
                return;
            }
            if key == "key" && *s == format!("drive:name-mutation:{}", b.user) {
                *s = "<foreign-name-rate>".into();
                return;
            }
            if matches!(key, "nodeId" | "nextAfter") {
                if let Some(label) = s.parse::<i64>().ok().and_then(|id| nodes.get(&id)) {
                    *s = label.clone();
                    return;
                }
            }
            if key == "_checksum" {
                assert_eq!(s.len(), 64);
                assert!(s.bytes().all(|b| b.is_ascii_hexdigit()));
                *s = "<verified-drive-checksum>".into();
            } else if key.ends_with("_at")
                || key == "at"
                || key == "window_start"
                || key == "blocked_until"
                || matches!(
                    key,
                    "grantedAt" | "deletedAt" | "createdAt" | "expiresAt" | "acquiredAt"
                )
            {
                *s = "<time>".into();
            } else if s.contains("@oracle-") {
                *s = if s.starts_with("drive2-owner") {
                    "<owner-email>"
                } else {
                    "<foreign-email>"
                }
                .into();
            }
        }
        _ => {}
    }
}

fn invalidation_noise(v: &mut Value) {
    let rows = v["effects"]["invalidations"].as_array().unwrap();
    let mut tokens = std::collections::BTreeMap::new();
    let mut cursors = std::collections::BTreeMap::new();
    for (i, row) in rows.iter().enumerate() {
        if let Some(token) = row["scan_token"].as_str() {
            if token.starts_with('<') {
                continue;
            }
            assert_eq!(token.len(), 36);
            tokens.insert(token.to_owned(), format!("<scan-token-{}>", i + 1));
        }
        if let Some(cursor) = row["cursor"].as_i64() {
            cursors.insert(cursor, format!("<invalidation-cursor-{}>", i + 1));
        }
    }
    fn walk(
        v: &mut Value,
        key: &str,
        tokens: &std::collections::BTreeMap<String, String>,
        cursors: &std::collections::BTreeMap<i64, String>,
    ) {
        if matches!(key, "scan_token" | "cursor") {
            if let Some(label) = v.as_str().and_then(|s| tokens.get(s)) {
                *v = label.clone().into();
                return;
            }
        }
        if matches!(key, "cursor" | "retained_after_cursor") {
            if let Some(label) = v.as_i64().and_then(|id| cursors.get(&id)) {
                *v = label.clone().into();
                return;
            }
        }
        match v {
            Value::Object(m) => {
                for (k, v) in m {
                    walk(v, k, tokens, cursors)
                }
            }
            Value::Array(a) => {
                for v in a {
                    walk(v, key, tokens, cursors)
                }
            }
            _ => {}
        }
    }
    walk(v, "", &tokens, &cursors);
}

const CHUNK: &[u8] = b"drive2 chunk";
fn chunk_sha() -> String {
    use sha2::{Digest, Sha256};
    format!("{:x}", Sha256::digest(CHUNK))
}

fn normalize_key(key: &str, temps: &mut std::collections::BTreeMap<String, String>) -> String {
    if let Some((prefix, _)) = key.split_once("tmp/upload/") {
        let raw = key.split_once("tmp/upload/").unwrap().1;
        let count = temps.len() + 1;
        let label = temps.entry(raw.into()).or_insert_with(|| {
            if count == 1 {
                "<temporary>".into()
            } else {
                format!("<temporary-{count}>")
            }
        });
        format!("{prefix}tmp/upload/{label}")
    } else {
        key.to_owned()
    }
}
async fn s3_peer(
    io: std::sync::Arc<std::sync::Mutex<Vec<Value>>>,
    case: &str,
) -> std::net::SocketAddr {
    use http_body_util::BodyExt;
    let case = case.to_owned();
    let temps = std::sync::Arc::new(std::sync::Mutex::new(std::collections::BTreeMap::new()));
    common::fake_upstream(move|r|{let io=io.clone();let temps=temps.clone();let case=case.clone();async move{
  if r.uri().query()==Some("location="){return Response::new(common::full("<LocationConstraint>us-east-1</LocationConstraint>"))}
  let method=r.method().clone();let uri=r.uri().path().to_owned();let copy=r.headers().get("x-amz-copy-source").and_then(|v|v.to_str().ok()).unwrap_or("").to_owned();let content=r.headers().get("content-type").and_then(|v|v.to_str().ok()).unwrap_or("").to_owned();
  let(parts,body)=r.into_parts();let bytes=body.collect().await.unwrap().to_bytes();let request=Request::from_parts(parts,());
  if uri.starts_with("/mailblobs/drive/")||uri.starts_with("/mailblobs/tmp/upload/"){
   let signed=storage_wire::observe(&request,&bytes).unwrap_or_else(|e|panic!("{e}; method={} uri={} payload={:?} encoding={:?} bytes={}",request.method(),request.uri(),request.headers().get("x-amz-content-sha256"),request.headers().get("content-encoding"),bytes.len()));
   let mut row=json!({"method":method.as_str(),"query":match request.uri().query().unwrap_or(""){"uploads"=>"uploads=",s=>s},"key":normalize_key(&uri,&mut temps.lock().unwrap()),"copy_source":normalize_key(&copy,&mut temps.lock().unwrap()),"content_type":content,"body":signed["body"],"signature_valid":true});if let Some(range)=request.headers().get("range"){row["range"]=range.to_str().unwrap().into();}io.lock().unwrap().push(row);
  }
  if (case=="storage-init-denied-state"&&method==hyper::Method::POST&&matches!(request.uri().query(),Some("uploads="|"uploads"))) || (case=="storage-copy-denied-state"&&!copy.is_empty()) {return Response::builder().status(403).body(common::full("<Error><Code>AccessDenied</Code><Message>drive2 fixture denial</Message></Error>")).unwrap()}
  if method==hyper::Method::POST&&matches!(request.uri().query(),Some("uploads="|"uploads")){return Response::builder().header("content-type","application/xml").body(common::full(format!("<InitiateMultipartUploadResult><Bucket>mailblobs</Bucket><Key>{}</Key><UploadId>drive2-upload</UploadId></InitiateMultipartUploadResult>",uri.strip_prefix("/mailblobs/").unwrap()))).unwrap()}
  if method==hyper::Method::POST{return Response::builder().header("content-type","application/xml").body(common::full("<CompleteMultipartUploadResult><Location>http://storage.test/temp</Location><Bucket>mailblobs</Bucket><Key>temporary</Key><ETag>drive2</ETag></CompleteMultipartUploadResult>")).unwrap()}
  if method==hyper::Method::PUT{return Response::builder().header("etag","\"drive2\"").body(common::full(if copy.is_empty(){""}else{"<CopyObjectResult><LastModified>2026-11-01T00:00:00.000Z</LastModified><ETag>\"drive2\"</ETag></CopyObjectResult>"})).unwrap()}
  if method==hyper::Method::DELETE{return Response::builder().status(204).body(common::full("")).unwrap()}
  let bounds=request.headers().get("range").and_then(|v|v.to_str().ok()).map(|v|{let (lo,hi)=v.strip_prefix("bytes=").unwrap().split_once('-').unwrap();(lo.parse::<usize>().unwrap(),hi.parse::<usize>().unwrap())});
  let data=if let Some((lo,hi))=bounds{&PREVIEW[lo..=hi]}else{PREVIEW};let mut reply=Response::builder().status(if bounds.is_some(){206}else{200}).header("content-type","application/pdf").header("content-length",data.len().to_string()).header("last-modified","Sun, 01 Nov 2026 00:00:00 GMT").header("etag","\"drive2\"");if let Some((lo,hi))=bounds{reply=reply.header("content-range",format!("bytes {lo}-{hi}/{}",PREVIEW.len()));}reply.body(common::full(if method==hyper::Method::HEAD{Vec::new()}else{data.to_vec()})).unwrap()

 }}).await
}
const PREVIEW: &[u8] = b"%PDF-1.7\nDrive2 preview\n%%EOF\n";

fn s3_noise(v: &mut Value) {
    if let Some(rows) = v["io"].as_array_mut() {
        for row in rows {
            if row["method"] == "POST" && row["query"] == "uploadId=drive2-upload" {
                let body = row["body"]
                    .as_str()
                    .unwrap()
                    .replace(" xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"", "");
                row["body"] = body.into();
                if row["content_type"] == "application/xml" {
                    row["content_type"] = "application/octet-stream".into();
                }
            }
        }
    }
}

fn version_identities(v: &mut Value) {
    let mut ids = std::collections::BTreeMap::new();
    for (i, row) in v["effects"]["versions"]
        .as_array()
        .unwrap()
        .iter()
        .enumerate()
    {
        if let Some(id) = row["id"].as_i64() {
            ids.insert(id, format!("<version-{}>", i + 1));
        }
    }
    fn walk(v: &mut Value, key: &str, ids: &std::collections::BTreeMap<i64, String>) {
        if matches!(
            key,
            "version_id"
                | "versionId"
                | "head_version_id"
                | "headVersionId"
                | "parent_version_id"
                | "conflict_of"
                | "merged_from_version_id"
        ) {
            if let Some(label) = v.as_i64().and_then(|id| ids.get(&id)) {
                *v = label.clone().into();
                return;
            }
        }
        match v {
            Value::Object(m) => {
                if m.contains_key("file_node_id") && m.contains_key("content_sha256") {
                    if let Some(label) = m
                        .get("id")
                        .and_then(Value::as_i64)
                        .and_then(|id| ids.get(&id))
                    {
                        m.insert("id".into(), label.clone().into());
                    }
                }
                if m.get("target_type").and_then(Value::as_str) == Some("version") {
                    if let Some(label) = m
                        .get("target_id")
                        .and_then(Value::as_i64)
                        .and_then(|id| ids.get(&id))
                    {
                        m.insert("target_id".into(), label.clone().into());
                    }
                }
                for (k, v) in m {
                    walk(v, k, ids)
                }
            }
            Value::Array(a) => {
                for v in a {
                    walk(v, key, ids)
                }
            }
            _ => {}
        }
    }
    walk(v, "", &ids);
}

fn route_name(route: &str) -> String {
    let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(format!(
        "../../tests/conformance/drive/core/{route}-success-state-v2.json"
    ));
    let v: Value = serde_json::from_slice(&std::fs::read(p).unwrap()).unwrap();
    v["route"].as_str().unwrap().to_owned()
}
struct StatusMutant<T> {
    inner: T,
    enabled: bool,
}
impl<T: setjoin_gateway::Intercept> setjoin_gateway::Intercept for StatusMutant<T> {
    fn matches(&self, r: &Request<setjoin_gateway::Body>) -> bool {
        self.inner.matches(r)
    }
    fn admits_member(
        &self,
        h: hyper::HeaderMap,
        s: &'static str,
    ) -> setjoin_gateway::BoxFuture<bool> {
        self.inner.admits_member(h, s)
    }
    fn handle(
        &self,
        r: Request<setjoin_gateway::Body>,
        c: setjoin_gateway::RequestContext,
    ) -> setjoin_gateway::BoxFuture<Response<setjoin_gateway::Body>> {
        let result = self.inner.handle(r, c);
        let enabled = self.enabled;
        Box::pin(async move {
            let mut response = result.await;
            if enabled {
                *response.status_mut() = hyper::StatusCode::IM_A_TEAPOT;
            }
            response
        })
    }
}

fn response_body(bytes: &[u8], h: &Value) -> Result<Value, BoxError> {
    if bytes.is_empty() {
        Ok(Value::Null)
    } else if h["content-type"] == "application/pdf" {
        use base64::Engine;
        Ok(json!({"base64":base64::engine::general_purpose::STANDARD.encode(bytes)}))
    } else {
        Ok(serde_json::from_slice(bytes)?)
    }
}
