//! #267: frozen-Go channel HTTP/effect oracle; replay has no Go upstream.
mod common;
use common::BoxError;
use hyper::{Request, Response};
use serde_json::{json, Value};
use setjoin_conformance::harness::Db;
use setjoin_gateway::{Config, Gateway, RouteTable, TrustedProxies};

/// Per-file serial guard (#368). Every case flips the global
/// `feature.chat`, `feature.chat_compliance`, `feature.federation` and
/// `feature.drive` toggles and snapshots shared receipt/audit/outbox rows, so
/// parallel cases saw each other's state. Setup also resets the toggles a
/// previously interrupted run could leave behind. Other test binaries keep parallelism.
static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// The gateway adapter falls back to a Go forward (502 here) when a scoped
/// read hits its 1 s pool wait / 2 s statement default, which happens on a
/// CPU-starved shared host and masquerades as a parity failure. Only the
/// deadlines are widened; every assertion is unchanged.
fn loaded_host_exec(dsn: &str) -> Result<setjoin_pg::ScopedExecutor, BoxError> {
    let patient = std::time::Duration::from_secs(30);
    Ok(setjoin_pg::ScopedExecutor::from_dsn_with(
        dsn,
        1,
        setjoin_pg::Timeouts {
            pool_wait: patient,
            create: patient,
            statement: patient,
        },
    )
    .map_err(|e| e.0)?)
}

async fn reset_shared_toggles(owner: &tokio_postgres::Client) -> Result<(), BoxError> {
    owner
        .execute(
            "UPDATE feature_toggles SET enabled=false WHERE key='feature.federation'",
            &[],
        )
        .await?;
    Ok(())
}

#[tokio::test]
async fn browse_success() -> Result<(), BoxError> {
    run("browse", "success", false).await
}

#[tokio::test]
async fn browse_foreign() -> Result<(), BoxError> {
    run("browse", "foreign", false).await
}

#[tokio::test]
async fn browse_invalid() -> Result<(), BoxError> {
    run("browse", "invalid", false).await
}

#[tokio::test]
async fn browse_public() -> Result<(), BoxError> {
    run("browse", "public", false).await
}

#[tokio::test]
async fn browse_rejects_status() -> Result<(), BoxError> {
    run("browse", "success", true).await
}

#[tokio::test]
async fn conversations_success() -> Result<(), BoxError> {
    run("conversations", "success", false).await
}

#[tokio::test]
async fn conversations_foreign() -> Result<(), BoxError> {
    run("conversations", "foreign", false).await
}

#[tokio::test]
async fn conversations_invalid() -> Result<(), BoxError> {
    run("conversations", "invalid", false).await
}

#[tokio::test]
async fn conversations_rejects_status() -> Result<(), BoxError> {
    run("conversations", "success", true).await
}

#[tokio::test]
async fn roster_success() -> Result<(), BoxError> {
    run("roster", "success", false).await
}

#[tokio::test]
async fn roster_foreign() -> Result<(), BoxError> {
    run("roster", "foreign", false).await
}

#[tokio::test]
async fn roster_invalid() -> Result<(), BoxError> {
    run("roster", "invalid", false).await
}

#[tokio::test]
async fn roster_rejects_status() -> Result<(), BoxError> {
    run("roster", "success", true).await
}

#[tokio::test]
async fn mention_search_success() -> Result<(), BoxError> {
    run("mention_search", "success", false).await
}

#[tokio::test]
async fn mention_search_foreign() -> Result<(), BoxError> {
    run("mention_search", "foreign", false).await
}

#[tokio::test]
async fn mention_search_invalid() -> Result<(), BoxError> {
    run("mention_search", "invalid", false).await
}

#[tokio::test]
async fn mention_search_rejects_status() -> Result<(), BoxError> {
    run("mention_search", "success", true).await
}

#[tokio::test]
async fn pins_success() -> Result<(), BoxError> {
    run("pins", "success", false).await
}

#[tokio::test]
async fn pins_foreign() -> Result<(), BoxError> {
    run("pins", "foreign", false).await
}

#[tokio::test]
async fn pins_invalid() -> Result<(), BoxError> {
    run("pins", "invalid", false).await
}

#[tokio::test]
async fn pins_rejects_status() -> Result<(), BoxError> {
    run("pins", "success", true).await
}

#[tokio::test]
async fn readers_success() -> Result<(), BoxError> {
    run("readers", "success", false).await
}

#[tokio::test]
async fn readers_foreign() -> Result<(), BoxError> {
    run("readers", "foreign", false).await
}

#[tokio::test]
async fn readers_invalid() -> Result<(), BoxError> {
    run("readers", "invalid", false).await
}

#[tokio::test]
async fn readers_rejects_status() -> Result<(), BoxError> {
    run("readers", "success", true).await
}

#[tokio::test]
async fn messages_success() -> Result<(), BoxError> {
    run("messages", "success", false).await
}

#[tokio::test]
async fn messages_foreign() -> Result<(), BoxError> {
    run("messages", "foreign", false).await
}

#[tokio::test]
async fn messages_invalid() -> Result<(), BoxError> {
    run("messages", "invalid", false).await
}

#[tokio::test]
async fn messages_rejects_status() -> Result<(), BoxError> {
    run("messages", "success", true).await
}

#[tokio::test]
async fn since_success() -> Result<(), BoxError> {
    run("since", "success", false).await
}

#[tokio::test]
async fn since_foreign() -> Result<(), BoxError> {
    run("since", "foreign", false).await
}

#[tokio::test]
async fn since_invalid() -> Result<(), BoxError> {
    run("since", "invalid", false).await
}

#[tokio::test]
async fn since_rejects_status() -> Result<(), BoxError> {
    run("since", "success", true).await
}

#[tokio::test]
async fn roster_foreign_language() -> Result<(), BoxError> {
    run("roster", "foreign_language", false).await
}

#[tokio::test]
async fn create_success() -> Result<(), BoxError> {
    run("create", "success", false).await
}

#[tokio::test]
async fn create_foreign() -> Result<(), BoxError> {
    run("create", "foreign", false).await
}

#[tokio::test]
async fn create_invalid() -> Result<(), BoxError> {
    run("create", "invalid", false).await
}

#[tokio::test]
async fn create_repeat() -> Result<(), BoxError> {
    run("create", "repeat", false).await
}

#[tokio::test]
async fn create_rejects_status() -> Result<(), BoxError> {
    run("create", "success", true).await
}

#[tokio::test]
async fn create_invalid_name() -> Result<(), BoxError> {
    run("create", "invalid_name", false).await
}

#[tokio::test]
async fn join_success() -> Result<(), BoxError> {
    run("join", "success", false).await
}

#[tokio::test]
async fn join_foreign() -> Result<(), BoxError> {
    run("join", "foreign", false).await
}

#[tokio::test]
async fn join_invalid() -> Result<(), BoxError> {
    run("join", "invalid", false).await
}

#[tokio::test]
async fn join_repeat() -> Result<(), BoxError> {
    run("join", "repeat", false).await
}

#[tokio::test]
async fn join_rejects_status() -> Result<(), BoxError> {
    run("join", "success", true).await
}

#[tokio::test]
async fn typing_success() -> Result<(), BoxError> {
    run("typing", "success", false).await
}

#[tokio::test]
async fn typing_foreign() -> Result<(), BoxError> {
    run("typing", "foreign", false).await
}

#[tokio::test]
async fn typing_invalid() -> Result<(), BoxError> {
    run("typing", "invalid", false).await
}

#[tokio::test]
async fn typing_repeat() -> Result<(), BoxError> {
    run("typing", "repeat", false).await
}

#[tokio::test]
async fn typing_rejects_status() -> Result<(), BoxError> {
    run("typing", "success", true).await
}

#[tokio::test]
async fn mark_read_success() -> Result<(), BoxError> {
    run("mark_read", "success", false).await
}

#[tokio::test]
async fn mark_read_foreign() -> Result<(), BoxError> {
    run("mark_read", "foreign", false).await
}

#[tokio::test]
async fn mark_read_invalid() -> Result<(), BoxError> {
    run("mark_read", "invalid", false).await
}

#[tokio::test]
async fn mark_read_repeat() -> Result<(), BoxError> {
    run("mark_read", "repeat", false).await
}

#[tokio::test]
async fn mark_read_rejects_status() -> Result<(), BoxError> {
    run("mark_read", "success", true).await
}

#[tokio::test]
async fn notif_success() -> Result<(), BoxError> {
    run("notif", "success", false).await
}

#[tokio::test]
async fn notif_foreign() -> Result<(), BoxError> {
    run("notif", "foreign", false).await
}

#[tokio::test]
async fn notif_invalid() -> Result<(), BoxError> {
    run("notif", "invalid", false).await
}

#[tokio::test]
async fn notif_repeat() -> Result<(), BoxError> {
    run("notif", "repeat", false).await
}

#[tokio::test]
async fn notif_rejects_status() -> Result<(), BoxError> {
    run("notif", "success", true).await
}

#[tokio::test]
async fn add_member_success() -> Result<(), BoxError> {
    run("add_member", "success", false).await
}

#[tokio::test]
async fn add_member_foreign() -> Result<(), BoxError> {
    run("add_member", "foreign", false).await
}

#[tokio::test]
async fn add_member_invalid() -> Result<(), BoxError> {
    run("add_member", "invalid", false).await
}

#[tokio::test]
async fn add_member_repeat() -> Result<(), BoxError> {
    run("add_member", "repeat", false).await
}

#[tokio::test]
async fn add_member_rejects_status() -> Result<(), BoxError> {
    run("add_member", "success", true).await
}

#[tokio::test]
async fn update_success() -> Result<(), BoxError> {
    run("update", "success", false).await
}

#[tokio::test]
async fn update_foreign() -> Result<(), BoxError> {
    run("update", "foreign", false).await
}

#[tokio::test]
async fn update_invalid() -> Result<(), BoxError> {
    run("update", "invalid", false).await
}

#[tokio::test]
async fn update_repeat() -> Result<(), BoxError> {
    run("update", "repeat", false).await
}

#[tokio::test]
async fn update_rejects_status() -> Result<(), BoxError> {
    run("update", "success", true).await
}

#[tokio::test]
async fn remove_member_success() -> Result<(), BoxError> {
    run("remove_member", "success", false).await
}

#[tokio::test]
async fn remove_member_foreign() -> Result<(), BoxError> {
    run("remove_member", "foreign", false).await
}

#[tokio::test]
async fn remove_member_invalid() -> Result<(), BoxError> {
    run("remove_member", "invalid", false).await
}

#[tokio::test]
async fn remove_member_repeat() -> Result<(), BoxError> {
    run("remove_member", "repeat", false).await
}

#[tokio::test]
async fn remove_member_rejects_status() -> Result<(), BoxError> {
    run("remove_member", "success", true).await
}

#[tokio::test]
async fn dm_success() -> Result<(), BoxError> {
    run("dm", "success", false).await
}

#[tokio::test]
async fn dm_foreign() -> Result<(), BoxError> {
    run("dm", "foreign", false).await
}

#[tokio::test]
async fn dm_invalid() -> Result<(), BoxError> {
    run("dm", "invalid", false).await
}

#[tokio::test]
async fn dm_repeat() -> Result<(), BoxError> {
    run("dm", "repeat", false).await
}

#[tokio::test]
async fn dm_rejects_status() -> Result<(), BoxError> {
    run("dm", "success", true).await
}

#[tokio::test]
async fn space_success() -> Result<(), BoxError> {
    run("space", "success", false).await
}

#[tokio::test]
async fn space_foreign() -> Result<(), BoxError> {
    run("space", "foreign", false).await
}

#[tokio::test]
async fn space_invalid() -> Result<(), BoxError> {
    run("space", "invalid", false).await
}

#[tokio::test]
async fn space_repeat() -> Result<(), BoxError> {
    run("space", "repeat", false).await
}

#[tokio::test]
async fn space_rejects_status() -> Result<(), BoxError> {
    run("space", "success", true).await
}

#[tokio::test]
async fn preview_success() -> Result<(), BoxError> {
    run("preview", "success", false).await
}

#[tokio::test]
async fn preview_foreign() -> Result<(), BoxError> {
    run("preview", "foreign", false).await
}

#[tokio::test]
async fn preview_invalid() -> Result<(), BoxError> {
    run("preview", "invalid", false).await
}

#[tokio::test]
async fn preview_rejects_status() -> Result<(), BoxError> {
    run("preview", "success", true).await
}

#[tokio::test]
async fn send_success() -> Result<(), BoxError> {
    run("send", "success", false).await
}

#[tokio::test]
async fn send_foreign() -> Result<(), BoxError> {
    run("send", "foreign", false).await
}

#[tokio::test]
async fn send_invalid() -> Result<(), BoxError> {
    run("send", "invalid", false).await
}

#[tokio::test]
async fn send_repeat() -> Result<(), BoxError> {
    run("send", "repeat", false).await
}

#[tokio::test]
async fn send_rejects_status() -> Result<(), BoxError> {
    run("send", "success", true).await
}

#[tokio::test]
async fn poll_success() -> Result<(), BoxError> {
    run("poll", "success", false).await
}

#[tokio::test]
async fn poll_foreign() -> Result<(), BoxError> {
    run("poll", "foreign", false).await
}

#[tokio::test]
async fn poll_invalid() -> Result<(), BoxError> {
    run("poll", "invalid", false).await
}

#[tokio::test]
async fn poll_repeat() -> Result<(), BoxError> {
    run("poll", "repeat", false).await
}

#[tokio::test]
async fn poll_rejects_status() -> Result<(), BoxError> {
    run("poll", "success", true).await
}

#[tokio::test]
async fn schedule_success() -> Result<(), BoxError> {
    run("schedule", "success", false).await
}

#[tokio::test]
async fn schedule_foreign() -> Result<(), BoxError> {
    run("schedule", "foreign", false).await
}

#[tokio::test]
async fn schedule_invalid() -> Result<(), BoxError> {
    run("schedule", "invalid", false).await
}

#[tokio::test]
async fn schedule_repeat() -> Result<(), BoxError> {
    run("schedule", "repeat", false).await
}

#[tokio::test]
async fn schedule_rejects_status() -> Result<(), BoxError> {
    run("schedule", "success", true).await
}

#[tokio::test]
async fn federated_dm_success() -> Result<(), BoxError> {
    run("federated_dm", "success", false).await
}

#[tokio::test]
async fn federated_dm_foreign() -> Result<(), BoxError> {
    run("federated_dm", "foreign", false).await
}

#[tokio::test]
async fn federated_dm_invalid() -> Result<(), BoxError> {
    run("federated_dm", "invalid", false).await
}

#[tokio::test]
async fn federated_dm_repeat() -> Result<(), BoxError> {
    run("federated_dm", "repeat", false).await
}

#[tokio::test]
async fn federated_dm_rejects_status() -> Result<(), BoxError> {
    run("federated_dm", "success", true).await
}

#[tokio::test]
async fn federation_bind_success() -> Result<(), BoxError> {
    run("federation_bind", "success", false).await
}

#[tokio::test]
async fn federation_bind_foreign() -> Result<(), BoxError> {
    run("federation_bind", "foreign", false).await
}

#[tokio::test]
async fn federation_bind_invalid() -> Result<(), BoxError> {
    run("federation_bind", "invalid", false).await
}

#[tokio::test]
async fn federation_bind_repeat() -> Result<(), BoxError> {
    run("federation_bind", "repeat", false).await
}

#[tokio::test]
async fn federation_bind_rejects_status() -> Result<(), BoxError> {
    run("federation_bind", "success", true).await
}

#[tokio::test]
async fn federation_roster_success() -> Result<(), BoxError> {
    run("federation_roster", "success", false).await
}

#[tokio::test]
async fn federation_roster_foreign() -> Result<(), BoxError> {
    run("federation_roster", "foreign", false).await
}

#[tokio::test]
async fn federation_roster_invalid() -> Result<(), BoxError> {
    run("federation_roster", "invalid", false).await
}

#[tokio::test]
async fn federation_roster_rejects_status() -> Result<(), BoxError> {
    run("federation_roster", "success", true).await
}

#[tokio::test]
async fn federation_invite_success() -> Result<(), BoxError> {
    run("federation_invite", "success", false).await
}

#[tokio::test]
async fn federation_invite_foreign() -> Result<(), BoxError> {
    run("federation_invite", "foreign", false).await
}

#[tokio::test]
async fn federation_invite_invalid() -> Result<(), BoxError> {
    run("federation_invite", "invalid", false).await
}

#[tokio::test]
async fn federation_invite_repeat() -> Result<(), BoxError> {
    run("federation_invite", "repeat", false).await
}

#[tokio::test]
async fn federation_invite_rejects_status() -> Result<(), BoxError> {
    run("federation_invite", "success", true).await
}

#[tokio::test]
async fn federation_remove_success() -> Result<(), BoxError> {
    run("federation_remove", "success", false).await
}

#[tokio::test]
async fn federation_remove_foreign() -> Result<(), BoxError> {
    run("federation_remove", "foreign", false).await
}

#[tokio::test]
async fn federation_remove_invalid() -> Result<(), BoxError> {
    run("federation_remove", "invalid", false).await
}

#[tokio::test]
async fn federation_remove_repeat() -> Result<(), BoxError> {
    run("federation_remove", "repeat", false).await
}

#[tokio::test]
async fn federation_remove_rejects_status() -> Result<(), BoxError> {
    run("federation_remove", "success", true).await
}

#[tokio::test]
async fn typing_rejects_missing_notify() -> Result<(), BoxError> {
    let error = run_inner("typing", "success", false, true)
        .await
        .expect_err("missing notification must fail the HTTP oracle");
    assert!(error.to_string().contains("/notify"), "{error}");
    println!("MUTANT-REJECTED: POST /chat/channels/{{id}}/typing :: no-notify");
    Ok(())
}

#[tokio::test]
async fn send_commit_before() -> Result<(), BoxError> {
    run("send", "commit-before", false).await
}
#[tokio::test]
async fn send_commit_after() -> Result<(), BoxError> {
    run("send", "commit-after", false).await
}

#[tokio::test]
async fn send_bad_json() -> Result<(), BoxError> {
    run("send", "bad_json", false).await
}

#[tokio::test]
async fn send_body_cap() -> Result<(), BoxError> {
    run("send", "body_cap", false).await
}

#[tokio::test]
async fn create_bad_json() -> Result<(), BoxError> {
    run("create", "bad_json", false).await
}

#[tokio::test]
async fn dm_bad_json() -> Result<(), BoxError> {
    run("dm", "bad_json", false).await
}

#[tokio::test]
async fn preview_bad_json() -> Result<(), BoxError> {
    run("preview", "bad_json", false).await
}

#[tokio::test]
async fn notif_bad_json() -> Result<(), BoxError> {
    run("notif", "bad_json", false).await
}

#[tokio::test]
async fn mark_read_bad_json() -> Result<(), BoxError> {
    run("mark_read", "bad_json", false).await
}

#[tokio::test]
async fn add_member_bad_json() -> Result<(), BoxError> {
    run("add_member", "bad_json", false).await
}

#[tokio::test]
async fn update_bad_json() -> Result<(), BoxError> {
    run("update", "bad_json", false).await
}

#[tokio::test]
async fn poll_bad_json() -> Result<(), BoxError> {
    run("poll", "bad_json", false).await
}

#[tokio::test]
async fn schedule_bad_json() -> Result<(), BoxError> {
    run("schedule", "bad_json", false).await
}

#[tokio::test]
async fn federated_dm_bad_json() -> Result<(), BoxError> {
    run("federated_dm", "bad_json", false).await
}

#[tokio::test]
async fn federation_invite_bad_json() -> Result<(), BoxError> {
    run("federation_invite", "bad_json", false).await
}

#[tokio::test]
async fn federation_remove_bad_json() -> Result<(), BoxError> {
    run("federation_remove", "bad_json", false).await
}

#[tokio::test]
async fn federated_dm_disabled() -> Result<(), BoxError> {
    run("federated_dm", "disabled", false).await
}

#[tokio::test]
async fn federation_bind_disabled() -> Result<(), BoxError> {
    run("federation_bind", "disabled", false).await
}

#[tokio::test]
async fn federation_roster_disabled() -> Result<(), BoxError> {
    run("federation_roster", "disabled", false).await
}

#[tokio::test]
async fn federation_invite_disabled() -> Result<(), BoxError> {
    run("federation_invite", "disabled", false).await
}

#[tokio::test]
async fn federation_remove_disabled() -> Result<(), BoxError> {
    run("federation_remove", "disabled", false).await
}

#[tokio::test]
async fn federation_bind_no_domain() -> Result<(), BoxError> {
    run("federation_bind", "no_domain", false).await
}

#[tokio::test]
async fn browse_chat_disabled() -> Result<(), BoxError> {
    run("browse", "chat_disabled", false).await
}

#[tokio::test]
async fn space_drive_disabled() -> Result<(), BoxError> {
    run("space", "drive_disabled", false).await
}

#[tokio::test]
async fn send_drive_disabled() -> Result<(), BoxError> {
    run("send", "drive_disabled", false).await
}

#[tokio::test]
async fn preview_empty_email() -> Result<(), BoxError> {
    run("preview", "empty_email", false).await
}

#[tokio::test]
async fn preview_preview_unknown() -> Result<(), BoxError> {
    run("preview", "preview_unknown", false).await
}

#[tokio::test]
async fn federated_dm_empty_remote() -> Result<(), BoxError> {
    run("federated_dm", "empty_remote", false).await
}

#[tokio::test]
async fn dm_empty_dm() -> Result<(), BoxError> {
    run("dm", "empty_dm", false).await
}

#[tokio::test]
async fn remove_member_invalid_user() -> Result<(), BoxError> {
    run("remove_member", "invalid_user", false).await
}

#[tokio::test]
async fn messages_bad_before() -> Result<(), BoxError> {
    run("messages", "bad_before", false).await
}

#[tokio::test]
async fn messages_bad_limit() -> Result<(), BoxError> {
    run("messages", "bad_limit", false).await
}

#[tokio::test]
async fn messages_bad_around() -> Result<(), BoxError> {
    run("messages", "bad_around", false).await
}

#[tokio::test]
async fn since_bad_seq() -> Result<(), BoxError> {
    run("since", "bad_seq", false).await
}

#[tokio::test]
async fn send_invalid_attachments() -> Result<(), BoxError> {
    run("send", "invalid_attachments", false).await
}

#[tokio::test]
async fn send_invalid_msg_type() -> Result<(), BoxError> {
    run("send", "invalid_msg_type", false).await
}

#[tokio::test]
async fn poll_invalid_closes() -> Result<(), BoxError> {
    run("poll", "invalid_closes", false).await
}

#[tokio::test]
async fn schedule_invalid_fire() -> Result<(), BoxError> {
    run("schedule", "invalid_fire", false).await
}

#[tokio::test]
async fn send_empty_body() -> Result<(), BoxError> {
    run("send", "empty_body", false).await
}

#[tokio::test]
async fn poll_bad_options() -> Result<(), BoxError> {
    run("poll", "bad_options", false).await
}

#[tokio::test]
async fn schedule_missing_fire() -> Result<(), BoxError> {
    run("schedule", "missing_fire", false).await
}

#[tokio::test]
async fn send_attachment_shape() -> Result<(), BoxError> {
    run("send", "attachment_shape", false).await
}

#[tokio::test]
async fn typing_federation_native() -> Result<(), BoxError> {
    run("typing", "federation_native", false).await
}
#[tokio::test]
async fn send_url_native() -> Result<(), BoxError> {
    run("send", "url_native", false).await
}

#[tokio::test]
async fn send_url_cached() -> Result<(), BoxError> {
    run("send", "url_cached", false).await
}

#[tokio::test]
async fn send_url_claim() -> Result<(), BoxError> {
    run("send", "url_claim", false).await
}

#[tokio::test]
async fn send_url_foreign() -> Result<(), BoxError> {
    run("send", "foreign_url", false).await
}
#[tokio::test]
async fn send_url_invalid_type() -> Result<(), BoxError> {
    run("send", "url_invalid_type", false).await
}

#[tokio::test]
async fn send_url_malformed_path() -> Result<(), BoxError> {
    run("send", "url_malformed", false).await
}
#[tokio::test]
async fn send_url_raw_query() -> Result<(), BoxError> {
    run("send", "url_raw_query", false).await
}

#[tokio::test]
async fn send_url_repeat() -> Result<(), BoxError> {
    run("send", "url_repeat", false).await
}
#[tokio::test]
async fn send_url_budget_is_per_sender() -> Result<(), BoxError> {
    run("send", "url_budget", false).await
}

#[tokio::test]
async fn conversations_query_fault() -> Result<(), BoxError> {
    run("conversations", "query_fault", false).await
}

#[tokio::test]
async fn send_raw_payload() -> Result<(), BoxError> {
    run("send", "raw_payload", false).await
}

#[tokio::test]
async fn send_raw_attachment() -> Result<(), BoxError> {
    run("send", "raw_attachment", false).await
}
#[tokio::test]
async fn send_go_json() -> Result<(), BoxError> {
    run("send", "go_json", false).await
}
#[tokio::test]
async fn preview_trailing() -> Result<(), BoxError> {
    run("preview", "trailing", false).await
}

fn token(user: i64) -> String {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    use p256::ecdsa::{signature::Signer, SigningKey};
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let header =
        URL_SAFE_NO_PAD.encode(json!({"alg":"ES256","kid":"test-es256-1","typ":"JWT"}).to_string());
    let claims=URL_SAFE_NO_PAD.encode(json!({"uid":user,"email":"chat-oracle@test","admin":true,"perms":["chat.compliance_manage"],"typ":"access","jti":"chat2-test","fam":"chat2-test","iss":"mailserver","aud":["mailserver-gateway"],"iat":now-10,"exp":now+600}).to_string());
    let key = SigningKey::from_slice(&[0x11; 32]).unwrap();
    let sig: p256::ecdsa::Signature = key.sign(format!("{header}.{claims}").as_bytes());
    format!(
        "{header}.{claims}.{}",
        URL_SAFE_NO_PAD.encode(sig.to_bytes())
    )
}

struct Principal {
    user: i64,
    mailbox: i64,
    domain: i64,
}
async fn principal_pair(
    owner: &tokio_postgres::Client,
) -> Result<(Principal, Principal), BoxError> {
    owner.batch_execute("BEGIN").await?;
    let result = async {
        let account = principal_in_transaction(owner, "chat2-actor").await?;
        let foreign = principal_in_transaction(owner, "chat2-foreign").await?;
        owner.batch_execute("COMMIT").await?;
        Ok::<_, tokio_postgres::Error>((account, foreign))
    }
    .await;
    match result {
        Ok(pair) => Ok(pair),
        Err(error) => {
            let _ = owner.batch_execute("ROLLBACK").await;
            Err(format!("Chat principal-pair setup: {error:?}").into())
        }
    }
}
async fn principal_in_transaction(
    owner: &tokio_postgres::Client,
    label: &str,
) -> Result<Principal, tokio_postgres::Error> {
    let unique: String = owner
        .query_one("SELECT replace(gen_random_uuid()::text,'-','')", &[])
        .await?
        .get(0);
    let domain_name = format!("oracle-{unique}.test");
    let email = format!("{label}@{domain_name}");
    let domain: i64 = owner
        .query_one(
            "INSERT INTO domains(name,is_local) VALUES($1,true) RETURNING id",
            &[&domain_name],
        )
        .await?
        .get(0);
    let user:i64=owner.query_one("INSERT INTO users(username,domain_id,email,display_name,password_hash) VALUES($1,$2,$1,$3,'x') RETURNING id",&[&email,&domain,&label]).await?.get(0);
    let mut mailbox: i64 = owner
        .query_one("SELECT nextval('mailboxes_id_seq')", &[])
        .await?
        .get(0);
    if mailbox == user {
        mailbox = owner
            .query_one("SELECT nextval('mailboxes_id_seq')", &[])
            .await?
            .get(0);
    }
    owner.execute("INSERT INTO mailboxes(id,user_id,domain_id,email,display_name,type,is_primary) VALUES($1,$2,$3,$4,$5,'personal',true)",&[&mailbox,&user,&domain,&email,&label]).await?;
    Ok(Principal {
        user,
        mailbox,
        domain,
    })
}
async fn remove_principal(owner: &tokio_postgres::Client, p: &Principal) -> Result<(), BoxError> {
    owner.batch_execute(&format!("BEGIN; SET LOCAL session_replication_role=replica; DELETE FROM mailbox_audit_log WHERE mailbox_id={}; COMMIT;",p.mailbox)).await?;
    owner.batch_execute(&format!("BEGIN; DELETE FROM mailboxes WHERE id={} AND user_id={}; DELETE FROM users WHERE id={} AND domain_id={}; COMMIT;",p.mailbox,p.user,p.user,p.domain)).await?;
    owner
        .execute("DELETE FROM domains WHERE id=$1", &[&p.domain])
        .await?;
    Ok(())
}

async fn wait_url_preview(
    owner: &tokio_postgres::Client,
    channel: i64,
    count: i64,
) -> Result<bool, BoxError> {
    for _ in 0..100 {
        let found:i64=owner.query_one("SELECT count(*) FROM chat_messages WHERE channel_id=$1 AND payload->'preview'->>'appliedBy'='chat_message_unfurl_apply'",&[&channel]).await?.get(0);
        if found >= count {
            return Ok(true);
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    Ok(false)
}
async fn run(route: &str, case: &str, mutant: bool) -> Result<(), BoxError> {
    run_inner(route, case, mutant, false).await
}
async fn run_inner(route: &str, case: &str, mutant: bool, no_notify: bool) -> Result<(), BoxError> {
    let canonical = match route {
        "browse" => "/chat/channels/browse",
        "conversations" => "/chat/conversations",
        "roster" => "/chat/channels/{id}/members",
        "mention_search" => "/chat/channels/{id}/members/search",
        "pins" => "/chat/channels/{id}/pins",
        "readers" => "/chat/channels/{id}/readers",
        "messages" => "/chat/channels/{id}/messages",
        "since" => "/chat/channels/{id}/messages/since",
        "create" => "/chat/channels",
        "join" => "/chat/channels/{id}/join",
        "typing" => "/chat/channels/{id}/typing",
        "mark_read" => "/chat/channels/{id}/read",
        "notif" => "/chat/channels/{id}/notif",
        "add_member" => "/chat/channels/{id}/members",
        "update" => "/chat/channels/{id}",
        "remove_member" => "/chat/channels/{id}/members/{userId}",
        "dm" => "/chat/dm",
        "space" => "/chat/channels/{id}/space",
        "preview" => "/chat/channels/{id}/members/guest-preview",
        "send" => "/chat/channels/{id}/messages",
        "poll" => "/chat/channels/{id}/polls",
        "schedule" => "/chat/channels/{id}/messages/schedule",
        "federated_dm" => "/chat/dm/federated",
        "federation_bind" => "/chat/channels/{id}/federation",
        "federation_roster" => "/chat/channels/{id}/federation",
        "federation_invite" => "/chat/channels/{id}/federation/invite",
        "federation_remove" => "/chat/channels/{id}/federation/remove",
        _ => return Err("unknown route".into()),
    };
    let writing = matches!(
        route,
        "create"
            | "join"
            | "typing"
            | "mark_read"
            | "notif"
            | "add_member"
            | "update"
            | "remove_member"
            | "dm"
            | "space"
            | "preview"
            | "send"
            | "poll"
            | "schedule"
            | "federated_dm"
            | "federation_bind"
            | "federation_invite"
            | "federation_remove"
    );
    let method = if route == "remove_member" {
        "DELETE"
    } else if route == "update" {
        "PATCH"
    } else if route == "add_member" {
        "POST"
    } else if route == "notif" {
        "PUT"
    } else if route == "mark_read" {
        "POST"
    } else if writing {
        "POST"
    } else {
        "GET"
    };
    let _serial = SERIAL.lock().await;
    let db = Db::for_case("chat2").ok_or("database required")?;
    let owner = db.connect().await?;
    reset_shared_toggles(&owner).await?;
    let (account, foreign) = principal_pair(&owner).await?;
    let request_body = if route == "federation_remove" {
        r#"{"memberDomain":"gofree-chat2-peer.test","actorId":0,"mailboxId":0}"#.into()
    } else if route == "federation_invite" {
        r#"{"memberDomain":"gofree-chat2-peer.test","contactAddr":"remote@gofree-chat2-peer.test","actorId":0,"mailboxId":0}"#.into()
    } else if route == "federation_bind" {
        String::new()
    } else if route == "federated_dm" {
        if case == "invalid" {
            "{".into()
        } else {
            r#"{"remoteAddr":"remote@gofree-chat2-peer.test","actorId":0,"mailboxId":0}"#.into()
        }
    } else if route == "schedule" {
        r#"{"body":"scheduled oracle","fireAt":"2099-01-01T00:00:00Z","mentions":[],"actorId":0,"mailboxId":0}"#.into()
    } else if route == "poll" {
        r#"{"question":"oracle poll","options":["yes","no"],"multi":false,"actorId":0,"mailboxId":0}"#.into()
    } else if matches!(route, "send" | "poll") {
        r#"{"body":"oracle hello","mentions":[],"actorId":0,"mailboxId":0}"#.into()
    } else if route == "preview" {
        r#"{"email":"not-found@gofree-chat2.test"}"#.into()
    } else if route == "space" {
        String::new()
    } else if route == "dm" {
        if case == "invalid" {
            "{".into()
        } else {
            format!(
                r#"{{"userIds":[{}],"actorId":0,"mailboxId":0}}"#,
                if case.starts_with("foreign") {
                    account.user
                } else {
                    foreign.user
                }
            )
        }
    } else if route == "remove_member" {
        String::new()
    } else if route == "update" {
        r#"{"name":"chat2-renamed","topic":"updated topic","archived":false,"postPermission":"admins","broadcastPermission":"all","actorId":0,"mailboxId":0}"#.into()
    } else if route == "add_member" {
        r#"{"userId":__FOREIGN__,"actorId":0,"mailboxId":0}"#
            .replace("__FOREIGN__", &foreign.user.to_string())
    } else if route == "notif" {
        r#"{"level":"mentions","actorId":0,"mailboxId":0}"#.to_owned()
    } else if route == "mark_read" {
        r#"{"seq":35,"actorId":0,"mailboxId":0}"#.to_owned()
    } else if route == "join" {
        String::new()
    } else if writing {
        if case == "invalid" {
            "{".to_owned()
        } else if case == "invalid_name" {
            r#"{"name":" "}"#.to_owned()
        } else {
            r#"{"name":"chat2-created","topic":"oracle topic","visibility":"private","actorId":0,"mailboxId":0}"#.to_owned()
        }
    } else {
        String::new()
    };

    let request_body = if route == "send" && case.starts_with("commit-") {
        r#"{"body":"https://example.test/path"}"#.into()
    } else if case == "body_cap" {
        format!(r#"{{"body":"{}"}}"#, "x".repeat(1 << 20))
    } else if case == "bad_json" {
        "{".into()
    } else {
        request_body
    };
    let request_body=match case{
        "raw_attachment"=>r#"{"body":"oracle","attachments":[{"name":"\ud800","sha256":"SHA","size":0,"manifest":[]}]}"#.replace("SHA",&"a".repeat(64)),
        "go_json"=>r#"{"BODY":"\ud800","body":null,"MeNtIoNs":[null],"MSGTYPE":"question","PAYLOAD":{"raw":"<&>","nested":[{"quote":"},\""}]},"unknown":1e1000}"#.into(),
        "trailing"=>r#"{"email":"unknown@test"} {}"#.into(),
        "raw_payload"=>r#"{"body":"oracle","payload":{"value":"\ud800"}}"#.into(),
        "url_raw_query"=>r#"{"body":"https://chat4-unfurl.invalid/article?q=%zz","actorId":0}"#.into(),
        "url_malformed"=>r#"{"body":"https://chat4-unfurl.invalid/%zz","actorId":0}"#.into(),
        "url_invalid_type"=>r#"{"body":"https://example.test/path","msgType":"poll","actorId":0}"#.into(),
        "url_claim"=>r#"{"body":"https://chat4-unfurl.invalid/article","actorId":0}"#.into(),
        "url_native"|"url_cached"|"foreign_url"|"url_repeat"|"url_budget"=>r#"{"body":"https://example.test/path","actorId":0}"#.into(),
        "empty_body"=>r#"{"body":""}"#.into(),"bad_options"=>r#"{"question":"oracle poll","options":[]}"#.into(),"missing_fire"=>r#"{"body":"scheduled oracle"}"#.into(),"invalid_fire"=>r#"{"body":"scheduled oracle","fireAt":"bad"}"#.into(),
        "empty_remote"|"empty_email"|"empty_dm"=>"{}".into(),"preview_unknown"=>r#"{"email":"unknown@test","unexpected":1}"#.into(),
        "invalid_attachments"=>r#"{"body":"oracle","attachments":{}}"#.into(),"attachment_shape"|"drive_disabled"=>if route=="send"{r#"{"body":"oracle","attachments":[{}]}"#.into()}else{request_body},
        "invalid_msg_type"=>r#"{"body":"oracle","msgType":"poll"}"#.into(),"invalid_closes"=>r#"{"question":"oracle poll","options":["yes","no"],"closesAt":"bad"}"#.into(),_=>request_body};
    let channel:i64=owner.query_one("INSERT INTO chat_channels(kind,name,created_by,visibility) VALUES ('channel','chat2-oracle',$1,'private') RETURNING id",&[&account.user]).await?.get(0);
    owner
        .execute(
            "INSERT INTO chat_channel_members(channel_id,user_id,role) VALUES ($1,$2,'owner')",
            &[&channel, &account.user],
        )
        .await?;
    let unfurl_previous = if matches!(
        case,
        "url_cached"
            | "url_claim"
            | "foreign_url"
            | "url_invalid_type"
            | "url_malformed"
            | "url_raw_query"
            | "url_repeat"
            | "url_budget"
    ) || case.starts_with("commit-")
    {
        let old: Option<bool> = owner
            .query_opt(
                "SELECT enabled FROM feature_toggles WHERE key='chat.unfurl'",
                &[],
            )
            .await?
            .map(|r| r.get(0));
        owner.execute("INSERT INTO feature_toggles(key,enabled) VALUES('chat.unfurl',true) ON CONFLICT(key) DO UPDATE SET enabled=true",&[]).await?;
        use sha2::{Digest, Sha256};
        let link = match case {
            "url_claim" => "https://chat4-unfurl.invalid/article",
            "url_malformed" => "https://chat4-unfurl.invalid/%zz",
            "url_raw_query" => "https://chat4-unfurl.invalid/article?q=%zz",
            _ => "https://example.test/path",
        };
        let hash = format!("{:x}", Sha256::digest(link.as_bytes()));
        if matches!(
            case,
            "url_cached" | "foreign_url" | "url_invalid_type" | "url_repeat" | "url_budget"
        ) || case.starts_with("commit-")
        {
            owner.execute("INSERT INTO chat_link_previews(url_hash,url,title,description,status) VALUES($1,'https://example.test/path','Cached URL title','Cached URL description','ok')",&[&hash]).await?;
        }
        Some((old, hash))
    } else {
        None
    };
    if case == "url_budget" {
        owner
            .execute(
                "INSERT INTO chat_channel_members(channel_id,user_id,role) VALUES($1,$2,'member')",
                &[&channel, &foreign.user],
            )
            .await?;
    }
    let prior: Option<bool> = owner
        .query_opt(
            "SELECT enabled FROM feature_toggles WHERE key='feature.chat'",
            &[],
        )
        .await?
        .map(|r| r.get(0));
    owner.execute("INSERT INTO feature_toggles(key,enabled) VALUES('feature.chat',true) ON CONFLICT(key) DO UPDATE SET enabled=true",&[]).await?;
    if case == "chat_disabled" {
        owner
            .execute(
                "UPDATE feature_toggles SET enabled=false WHERE key='feature.chat'",
                &[],
            )
            .await?;
    }
    let drive_prior = if case == "drive_disabled" {
        let old = owner
            .query_one(
                "SELECT enabled FROM feature_toggles WHERE key='feature.drive'",
                &[],
            )
            .await?
            .get::<_, bool>(0);
        owner
            .execute(
                "UPDATE feature_toggles SET enabled=false WHERE key='feature.drive'",
                &[],
            )
            .await?;
        Some(old)
    } else {
        None
    };
    if case == "public" {
        owner
            .execute(
                "UPDATE chat_channels SET visibility='public' WHERE id=$1 AND created_by=$2",
                &[&channel, &account.user],
            )
            .await?;
    }
    let compliance_prior = if writing {
        let old: Option<bool> = owner
            .query_opt(
                "SELECT enabled FROM feature_toggles WHERE key='feature.chat_compliance'",
                &[],
            )
            .await?
            .map(|r| r.get(0));
        owner.execute("INSERT INTO feature_toggles(key,enabled) VALUES('feature.chat_compliance',true) ON CONFLICT(key) DO UPDATE SET enabled=true",&[]).await?;
        Some(old)
    } else {
        None
    };
    if route == "join" && !case.starts_with("foreign") {
        owner
            .execute(
                "UPDATE chat_channels SET visibility='public' WHERE id=$1 AND created_by=$2",
                &[&channel, &account.user],
            )
            .await?;
    }
    if route == "remove_member" {
        owner
            .execute(
                "INSERT INTO chat_channel_members(channel_id,user_id,role) VALUES($1,$2,'member')",
                &[&channel, &foreign.user],
            )
            .await?;
    }
    let federation_prior = if route == "federated_dm"
        || route.starts_with("federation_")
        || (route == "typing" && case == "federation_native")
    {
        let old = owner
            .query_one(
                "SELECT enabled FROM feature_toggles WHERE key='feature.federation'",
                &[],
            )
            .await?
            .get::<_, bool>(0);
        owner
            .execute(
                "UPDATE feature_toggles SET enabled=$1 WHERE key='feature.federation'",
                &[&(case != "disabled")],
            )
            .await?;
        owner.execute("INSERT INTO federation_allowlist(peer_domain,peer_anchor,scope,enabled) VALUES('gofree-chat2-peer.test','oracle anchor','room',true)",&[]).await?;
        Some(old)
    } else {
        None
    };
    if matches!(
        route,
        "federation_roster" | "federation_invite" | "federation_remove"
    ) {
        owner.execute("INSERT INTO federation_rooms(room_id,hub_domain,channel_id) VALUES('00000000-0000-4000-8000-000000000001@gofree-chat2.test','gofree-chat2.test',$1)",&[&channel]).await?;
        owner.execute("UPDATE chat_channels SET federated_room_id='00000000-0000-4000-8000-000000000001@gofree-chat2.test' WHERE id=$1 AND created_by=$2",&[&channel,&account.user]).await?;
        if matches!(route, "federation_roster" | "federation_remove") {
            owner.execute("INSERT INTO federation_room_members(room_id,member_domain) VALUES('00000000-0000-4000-8000-000000000001@gofree-chat2.test','gofree-chat2-peer.test')",&[]).await?;
        }
    }
    let receipt_before = owner
        .query(
            "SELECT operation_id::text FROM rust_operation_receipts WHERE family='F12'",
            &[],
        )
        .await?
        .into_iter()
        .map(|r| r.get::<_, String>(0))
        .collect::<Vec<_>>();
    let mut request_path = if canonical.contains("{id}") {
        format!(
            "/api{}",
            canonical.replace(
                "{id}",
                &if case == "invalid" {
                    "bad".into()
                } else {
                    channel.to_string()
                }
            )
        )
    } else {
        format!(
            "{}{}",
            if case == "invalid" && !writing {
                "/%61pi"
            } else {
                "/api"
            },
            canonical
        )
    };
    if route == "remove_member" {
        request_path = request_path.replace(
            "{userId}",
            &if case.starts_with("foreign") {
                account.user.to_string()
            } else {
                foreign.user.to_string()
            },
        );
    }
    let mut app_dsn = db.app.clone().unwrap_or_else(|| db.dsn.clone());
    let mut cut_task = if case.starts_with("commit-") {
        if std::env::var_os("GOFREE_RECORD_GO_BINARY").is_some() {
            return Err("COMMIT cuts never record".into());
        }
        record_resource(
            "Planned gofree-chat2 PostgreSQL COMMIT-cut listener, assigned app DSN only",
        )?;
        let (dsn, task) = common::commit::commit_cut_proxy(
            &app_dsn,
            if case.ends_with("after") {
                common::commit::CommitCut::AfterCommit
            } else {
                common::commit::CommitCut::BeforeCommit
            },
        )
        .await;
        app_dsn = dsn;
        Some(task)
    } else {
        None
    };
    let schema = if no_notify {
        let (dsn, schema) = plant_no_notify(&owner, &app_dsn).await?;
        app_dsn = dsn;
        Some(schema)
    } else if case == "query_fault" {
        let schema = format!("gofree_chat2_query_{}", account.user);
        record_resource(&format!(
            "Planned query fault schema {schema}, assigned DB only"
        ))?;
        owner.batch_execute(&format!("CREATE SCHEMA {schema}; GRANT USAGE ON SCHEMA {schema} TO PUBLIC; CREATE FUNCTION {schema}.chat_conversation_list(bigint) RETURNS jsonb LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'chat2 query fault'; END $$;")).await?;
        app_dsn = format!("{app_dsn}?options=-csearch_path%3D{schema}%2Cpublic");
        Some(schema)
    } else {
        None
    };
    if case == "invalid_user" {
        request_path = request_path.replace(&format!("/members/{}", foreign.user), "/members/bad");
    }
    if let Some(query) = match case {
        "bad_before" => Some("beforeSeq"),
        "bad_limit" => Some("limit"),
        "bad_around" => Some("aroundSeq"),
        "bad_seq" => Some("seq"),
        _ => None,
    } {
        request_path.push_str(&format!("?{query}=bad"));
    }
    let result=async {
        let fake=common::fake_upstream(|_|async{Response::new(common::full("unused"))}).await;
        let oracle_db=Db{dsn:db.dsn.clone(),direct:db.direct.clone(),app:Some(app_dsn.clone())};
        let oracle=common::go_oracle::start_named_with_federation_domain(&oracle_db,fake,"gofree-chat2",if case=="no_domain"{""}else{"gofree-chat2.test"}).await?;
        let recording=oracle.is_some();
        let adapter=setjoin_gateway::chat_channels::ChannelRoute{ unfurl:if matches!(case,"url_cached"|"url_claim"|"foreign_url"|"url_invalid_type"|"url_malformed"|"url_raw_query"|"url_repeat"|"url_budget") || case.starts_with("commit-") {Some(std::sync::Arc::new(setjoin_gateway::chat_unfurl::Unfurl::production(loaded_host_exec(&app_dsn)?,std::sync::Arc::new(setjoin_gateway::recovery_worker::S3Store::new(&format!("http://{fake}"),"mailblobs","test-access","test-secret")?))))}else{None},federation_typing:None,federation_local_domain:if case=="no_domain"{String::new()}else{"gofree-chat2.test".into()},exec:loaded_host_exec(&app_dsn)?.with_audit_keys("22".repeat(32),String::new()),keys:std::sync::Arc::new(common::recovery_keys()),issuer:"mailserver".into()};
        let gateway=Gateway::new(Config{upstream:oracle.as_ref().map(|o|format!("http://{}",o.address).parse()).transpose()?,trusted_proxies:TrustedProxies::parse("")?,upstream_header_timeout:setjoin_gateway::proxy::DEFAULT_HEADER_TIMEOUT,edge_limit:None},if recording{RouteTable::proxy_all()}else if mutant{RouteTable::proxy_all().with(ChangedStatus(adapter))}else{RouteTable::proxy_all().with(adapter)})?;
        let inventory:Value=serde_json::from_str(include_str!("../route-inventory.json"))?;
        let gateway=if recording{gateway}else{gateway.with_inventory(&inventory.to_string())?};
        let listen=tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let address=listen.local_addr()?;
        let server=tokio::spawn(gateway.serve(listen));
        let mut listener=db.listen(&format!("chat:{}",account.user)).await?;
        let mut before=snapshot(&owner,account.user,foreign.user).await?;if route.starts_with("federation_"){before["federation"]=federation_snapshot(&owner,account.user,foreign.user).await?;}if route=="schedule"{before["scheduled_actions"]=scheduled_snapshot(&owner,account.user,foreign.user).await?;}
        if matches!(route,"send"|"poll"){before["message_details"]=message_snapshot(&owner,account.user,foreign.user).await?;}
        if route=="space"{before["drive"]=space_snapshot(&owner,account.user,foreign.user).await?;}
        let mut drive_listener=if route=="space"{Some(db.listen("drive").await?)}else{None};
        let audit_start:i64=owner.query_one("SELECT coalesce(max(id),0) FROM admin_audit_log",&[]).await?.get(0);
        let mut other_listener=db.listen(&format!("chat:{}",foreign.user)).await?;
        if case=="url_budget" {
            let start=std::time::Instant::now();
            for _ in 0..30 {
                let response=common::send(address,Request::post(&request_path).header("host","mail.test").header("origin","http://mail.test").header("content-type","application/json").header("authorization",format!("Bearer {}",token(account.user))).body(common::full(r#"{"body":"budget primer"}"#))?).await;
                assert_eq!(response.status(),201);common::body_bytes(response).await;
            }
            assert!(start.elapsed()<std::time::Duration::from_secs(45),"priming must fit inside Go's minute window");
        }
        let first=if matches!(case,"repeat"|"url_repeat"){
            let response=common::send(address,Request::builder().method(method).uri(&request_path).header("host","mail.test").header("origin","http://mail.test").header("content-type","application/json").header("authorization",format!("Bearer {}",token(account.user))).header("x-request-id","chat2-oracle").body(common::full(request_body.clone()))?).await;
            let status=response.status().as_u16();let mut headers=serde_json::Map::new();for(k,v)in response.headers(){if !matches!(k.as_str(),"date"|"content-length"){headers.insert(k.as_str().into(),v.to_str()?.into());}}let bytes=common::body_bytes(response).await;
            if case=="url_repeat" && !wait_url_preview(&owner,channel,1).await? {return Err("first repeated URL did not enrich".into())}
            Some(json!({"status":status,"headers":headers,"body":if bytes.is_empty(){Value::Null}else{serde_json::from_slice::<Value>(&bytes).map_err(|e|format!("first repeat response {status} is not JSON ({e}): {}",String::from_utf8_lossy(&bytes)))?}}))
        }else{None};
        let response=common::send(address,Request::builder().method(method).uri(&request_path).header("host","mail.test").header("authorization",format!("Bearer {}",token(if case.starts_with("foreign"){foreign.user}else{account.user}))).header("origin","http://mail.test").header("content-type","application/json").header("accept-language",if case=="foreign_language"{"zh-CN, en;q=0.8"}else{"en"}).header("x-request-id","chat2-oracle").body(common::full(request_body.clone()))?).await;
        let status=response.status().as_u16();
        if !recording && status==502{return Err("native Chat route must answer without Go (got 502)".into());}
        let mut headers=serde_json::Map::new();for(k,v)in response.headers(){if !matches!(k.as_str(),"date"|"content-length"){headers.insert(k.as_str().into(),v.to_str()?.into());}}
        let bytes=common::body_bytes(response).await;
        let second_actor=if case=="url_budget" {
            let response=common::send(address,Request::post(&request_path).header("host","mail.test").header("origin","http://mail.test").header("content-type","application/json").header("x-request-id","chat2-oracle").header("authorization",format!("Bearer {}",token(foreign.user))).body(common::full(request_body.clone()))?).await;
            let status=response.status().as_u16();assert_eq!(status,201);
            Some(json!({"status":status,"body":serde_json::from_slice::<Value>(&common::body_bytes(response).await)?}))
        }else{None};
        if !recording {
            let response=common::send(address,Request::builder().uri("/_gateway/metrics").body(common::full(""))?).await;
            let metrics=String::from_utf8(common::body_bytes(response).await.to_vec())?;
            if !metrics.lines().any(|l|l==format!("setjoin_gateway_proxied_to_go_total {}",0))||!metrics.lines().any(|l|l==format!("setjoin_gateway_proxied_to_go_by_family_total{{family=\"F12\"}} {}",0)){return Err(format!("unexpected Chat proxy accounting: {metrics}").into());}
        }
        server.abort();let _=server.await;
        if case.starts_with("commit-"){
            assert_eq!(status,503,"an unknown COMMIT must never report success");let operation=headers.get("x-operation-id").and_then(Value::as_str).ok_or("missing lookup ID")?;assert!(operation.len()==32&&operation.bytes().all(|b|b.is_ascii_hexdigit()));
            let mut id=[0;16];for(i,byte)in id.iter_mut().enumerate(){*byte=u8::from_str_radix(&operation[i*2..i*2+2],16)?;}
            let cut=tokio::time::timeout(std::time::Duration::from_secs(10),cut_task.take().ok_or("missing COMMIT cut")?).await???;let committed=cut==common::commit::CommitCut::AfterCommit;
            let auth=setjoin_pg::MailboxAuthContext::from_authenticated_session(setjoin_contracts::ids::ActorId::new(account.user).unwrap(),setjoin_contracts::ids::MailboxId::new(account.mailbox).unwrap(),setjoin_contracts::ids::Generation(1));
            let exec=setjoin_pg::ScopedExecutor::from_dsn(db.app.as_deref().unwrap_or(&db.dsn),1).map_err(|e|e.0)?;
            let found=setjoin_pg::lookup_command(&exec,&auth,setjoin_contracts::ids::OperationId(id),setjoin_pg::ReceiptCommand{family:"F12",command:"chat_message_send"}).await.map_err(|e|format!("lookup SQLSTATE {:?}",e.sqlstate))?;assert_eq!(found==setjoin_pg::OperationLookup::Committed,committed);
            let row=owner.query_one("SELECT c.change_seq,(SELECT count(*) FROM chat_messages WHERE channel_id=c.id),(SELECT count(*) FROM chat_audit_log WHERE channel_id=c.id) FROM chat_channels c WHERE c.id=$1 AND c.created_by=$2",&[&channel,&account.user]).await?;let expected=if committed{1}else{0};assert_eq!(row.get::<_,i64>(0),expected);assert_eq!(row.get::<_,i64>(1),expected);assert_eq!(row.get::<_,i64>(2),0,"frozen-Go send records no Chat chain act");assert_eq!(listener.drain(&owner).await?.len(),expected as usize);
            let enriched:i64=owner.query_one("SELECT count(*) FROM chat_messages WHERE channel_id=$1 AND payload IS NOT NULL",&[&channel]).await?.get(0);assert_eq!(enriched,0,"an unknown send must not start detached preview application");
            record_resource("Reaped gofree-chat2 COMMIT-cut proxy; scoped lookup resolved without replay")?;return Ok(());
        }
        let body=if bytes.is_empty(){Value::Null}else{serde_json::from_slice::<Value>(&bytes).unwrap_or_else(|_|json!(String::from_utf8_lossy(&bytes)))};
        if matches!(case,"url_cached"|"url_repeat"|"url_budget") {
            let applied=wait_url_preview(&owner,channel,if case=="url_repeat" {2}else{1}).await?;
            if recording && !applied {return Err("Go cached URL send did not apply preview".into());}
        }
        if matches!(case,"url_claim"|"url_malformed"|"url_raw_query") {
            for _ in 0..if case=="url_malformed" {100}else{300} {
                let done:bool=owner.query_one("SELECT EXISTS(SELECT 1 FROM chat_link_previews WHERE url_hash=$1 AND status='error')",&[&unfurl_previous.as_ref().unwrap().1]).await?.get(0);
                if done {break} tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            }
        }
        let notifications=listener.drain(&owner).await?.into_iter().map(|p|serde_json::from_str::<Value>(&p)).collect::<Result<Vec<_>,_>>()?;
        let mut after=snapshot(&owner,account.user,foreign.user).await?;if route.starts_with("federation_"){after["federation"]=federation_snapshot(&owner,account.user,foreign.user).await?;}if route=="schedule"{after["scheduled_actions"]=scheduled_snapshot(&owner,account.user,foreign.user).await?;}if matches!(route,"send"|"poll"){after["message_details"]=message_snapshot(&owner,account.user,foreign.user).await?;}if route=="space"{after["drive"]=space_snapshot(&owner,account.user,foreign.user).await?;}
        let mut observed=json!({"request":{"method":method,"path":canonical,"body":if case=="body_cap"{json!({"oversizedBytes":request_body.len()})}else if writing{serde_json::from_str::<Value>(&request_body).unwrap_or(json!(request_body))}else{json!("")}},"response":{"status":status,"headers":headers,"body":body},"effects":{"before":before,"after":after},"audit":[],"notify":notifications});
        if matches!(case,"url_claim"|"url_malformed"|"url_raw_query") {
            let cache:Option<String>=owner.query_one("SELECT (SELECT jsonb_build_object('status',status,'title',title,'description',description,'image',image_blob_sha256)::text FROM chat_link_previews WHERE url_hash=$1)",&[&unfurl_previous.as_ref().unwrap().1]).await?.get(0);
            let cache=cache.map(|v|serde_json::from_str::<Value>(&v)).transpose()?;
            if recording && matches!(case,"url_claim"|"url_raw_query") && cache.as_ref().is_none_or(|v|v["status"]!="error") {return Err("Go did not persist URL claim/fetch error".into())}
            if recording && case=="url_malformed" && cache.is_some() {return Err("Go unexpectedly claimed malformed URL".into())}
            observed["effects"]["unfurl"]=json!({"before":null,"after":cache});
        }
        if let Some(second)=second_actor {observed["secondActorResponse"]=second; observed["primingSends"]=30.into();}
        if let Some(first)=first{observed["firstResponse"]=first;}
        if writing{
            let extra=other_listener.drain(&owner).await?.into_iter().map(|v|serde_json::from_str::<Value>(&v)).collect::<Result<Vec<_>,_>>()?;
            let mut events=Vec::new();for v in observed["notify"].as_array().unwrap(){events.push(json!({"recipient":"actor","payload":v}));}for v in extra{events.push(json!({"recipient":"foreign","payload":v}));}if let Some(listener)=drive_listener.as_mut(){for v in listener.drain(&owner).await?{events.push(json!({"recipient":"drive","payload":serde_json::from_str::<Value>(&v)?}));}}observed["notify"]=events.into();
            let raw:String=owner.query_one("SELECT coalesce(jsonb_agg(jsonb_build_object('userId',user_id,'action',action,'targetType',target_type,'targetId',target_id,'before',before_state,'after',after_state-'_checksum'-'_prev_checksum','notes',notes,'ip',host(ip)) ORDER BY id),'[]'::jsonb)::text FROM admin_audit_log WHERE id>$3 AND user_id IN($1,$2)",&[&account.user,&foreign.user,&audit_start]).await?.get(0);observed["audit"]=serde_json::from_str(&raw)?;
            let valid:bool=owner.query_one("SELECT coalesce(bool_and(v.valid),true) FROM chat_channels c CROSS JOIN LATERAL verify_chat_audit_chain(c.id) v WHERE c.created_by IN($1,$2)",&[&account.user,&foreign.user]).await?.get(0);if !valid{return Err("Chat audit chain failed independent verification".into());}observed["effects"]["chainValid"]=valid.into();
            if route=="space"{let valid:bool=owner.query_one("SELECT coalesce(bool_and(v.valid),true) FROM drive_spaces s CROSS JOIN LATERAL verify_drive_audit_chain(s.id) v WHERE s.chat_channel_id IN(SELECT id FROM chat_channels WHERE created_by IN($1,$2))",&[&account.user,&foreign.user]).await?.get(0);if !valid{return Err("Drive audit chain failed independent verification".into());}observed["effects"]["driveChainValid"]=valid.into();normalize_spaces(&mut observed);}
            if matches!(route,"send"|"poll"){normalize_message_ids(&mut observed);}
            if route=="schedule"{normalize_actions(&mut observed);}
            normalize_new_channels(&mut observed,channel);
        }
        if route.starts_with("federation_"){normalize_federation(&mut observed);}
        normalize(&mut observed,&[(account.user,"<actor>".into()),(foreign.user,"<foreign>".into()),(channel,"<channel>".into())]);
        if !recording && matches!(case,"url_cached"|"url_claim"|"url_raw_query"|"url_repeat"|"url_budget") {
            let receipts:Vec<String>=owner.query("SELECT command FROM rust_operation_receipts WHERE family='F12' AND NOT(operation_id::text=ANY($1)) ORDER BY command",&[&receipt_before]).await?.iter().map(|r|r.get(0)).collect();
            let expected=match case {"url_cached"=>vec!["chat_message_send","chat_message_unfurl_apply"],"url_repeat"=>vec!["chat_message_send","chat_message_send","chat_message_unfurl_apply","chat_message_unfurl_apply"],"url_budget"=>{let mut v=vec!["chat_message_send";32];v.push("chat_message_unfurl_apply");v},_=>vec!["chat_link_preview_cache_write","chat_link_preview_claim","chat_message_send"]};
            assert_eq!(receipts,expected,"each committed Go boundary has its own receipt");
        }
        let golden_case=if case=="federation_native"{"success"}else{case};
        let path=std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(format!("../../tests/conformance/chat/goldens/channels-{route}-{golden_case}.json"));
        if recording{let expected=if writing{if case=="body_cap"{413}else if matches!(case,"invalid"|"bad_json"){400}else if route=="federation_remove"{if case.starts_with("foreign")||case=="repeat"{403}else{204}}else if route=="federation_invite"{if case.starts_with("foreign"){403}else{204}}else if route=="federation_bind"{if case.starts_with("foreign"){403}else if case=="repeat"{422}else{200}}else if route=="federated_dm"{500}else if route=="dm"{200}else if matches!(route,"space"|"preview")&&!case.starts_with("foreign"){200}else if case=="invalid_name"{422}else if case.starts_with("foreign")&&route!="create"{if route=="join"{404}else{403}}else if matches!(route,"remove_member"|"update"|"add_member"|"notif"|"mark_read"|"typing"|"join"){204}else{201}}else if case=="invalid"{if canonical.contains("{id}"){400}else{404}}else if case.starts_with("foreign")&&canonical.contains("{id}"){403}else{200};let expected=match case{"disabled"|"chat_disabled"|"drive_disabled"|"no_domain"=>404,"empty_body"|"bad_options"|"missing_fire"|"empty_dm"=>422,"empty_remote"|"empty_email"|"preview_unknown"|"invalid_attachments"|"attachment_shape"|"invalid_msg_type"|"url_invalid_type"|"invalid_user"|"invalid_fire"|"bad_before"|"bad_limit"|"bad_around"|"bad_seq"=>400,"invalid_closes"|"query_fault"|"raw_payload"|"raw_attachment"=>500,"trailing"=>400,_=>expected};if status!=expected{return Err(format!("unexpected Go status {status}, expected {expected}: {observed:#}").into());}if writing{setjoin_conformance::golden::record(&path.with_file_name(format!("channels-{route}-{case}-row-effects.json")),&json!({"format":1,"route":format!("{method} {canonical}"),"case":format!("{route}-{case}-row-effects"),"go_source":std::env::var("GOFREE_GO_SOURCE")?,"effects":[observed["effects"].clone(),observed["audit"].clone(),observed["notify"].clone()]}))?;}setjoin_conformance::golden::record(&path,&json!({"format":1,"route":format!("{method} {canonical}"),"case":format!("{route}-{case}"),"go_source":std::env::var("GOFREE_GO_SOURCE")?,"observation":observed}))?;}else{
            let golden:Value=serde_json::from_slice(&std::fs::read(&path)?)?;
            let mut expected=golden["observation"].clone();
            // This immutable recording predates the end-of-path fixture-ID rule.
            if route=="update"&&case=="foreign"{if let Some(value)=expected.pointer_mut("/response/body/instance"){let raw=value.as_str().ok_or("invalid recorded instance")?;if raw.strip_prefix("/chat/channels/").is_some_and(|s|s.parse::<i64>().is_ok_and(|n|n>0)){*value="/chat/channels/{id}".into();}}}
            if route=="space"{normalize_space_clock(&mut expected);if case=="success"{for phase in ["before","after"]{if let Some(rows)=expected.pointer_mut(&format!("/effects/{phase}/drive/drive_spaces")).and_then(Value::as_array_mut){for row in rows{if row["chat_channel_id"].as_i64().is_some_and(|id|id>0){row["chat_channel_id"]="<channel>".into();}}}}}}
            let comparison=setjoin_conformance::golden::compare(&expected,&observed);
            if mutant {if comparison.is_ok(){return Err("planted mutant survived the oracle".into());}println!("MUTANT-REJECTED: {method} {canonical} :: changed-status");}else{comparison?;println!("GOLDEN-REPLAY: {method} {canonical} :: {route}-{case}");}
        }
        Ok::<_,BoxError>(())
    }.await;
    if let Some((old, hash)) = unfurl_previous {
        owner
            .execute("DELETE FROM chat_link_previews WHERE url_hash=$1", &[&hash])
            .await?;
        if let Some(old) = old {
            owner
                .execute(
                    "UPDATE feature_toggles SET enabled=$1 WHERE key='chat.unfurl'",
                    &[&old],
                )
                .await?;
        } else {
            owner
                .execute("DELETE FROM feature_toggles WHERE key='chat.unfurl'", &[])
                .await?;
        }
    }
    if let Some(task) = cut_task {
        task.abort();
        let _ = task.await;
    }
    if let Some(schema) = schema {
        owner
            .batch_execute(&format!("DROP SCHEMA {schema} CASCADE"))
            .await?;
    }
    if route == "schedule" {
        owner.execute("DELETE FROM scheduled_actions WHERE action_kind='chat_send' AND payload->>'userId' IN($1::bigint::text,$2::bigint::text)",&[&account.user,&foreign.user]).await?;
    }
    if writing {
        owner.batch_execute(&format!("BEGIN; SET LOCAL session_replication_role=replica; DELETE FROM drive_audit_log WHERE space_id IN(SELECT id FROM drive_spaces WHERE chat_channel_id IN(SELECT id FROM chat_channels WHERE created_by IN({},{}))); DELETE FROM admin_audit_log WHERE user_id IN({},{}); DELETE FROM chat_audit_log WHERE channel_id IN(SELECT id FROM chat_channels WHERE created_by IN({},{})); COMMIT;",account.user,foreign.user,account.user,foreign.user,account.user,foreign.user)).await?;
        owner.execute("DELETE FROM rust_operation_receipts WHERE family='F12' AND NOT(operation_id::text=ANY($1))",&[&receipt_before]).await?;
    }
    owner.execute("DELETE FROM drive_spaces WHERE chat_channel_id IN(SELECT id FROM chat_channels WHERE created_by IN($1,$2))",&[&account.user,&foreign.user]).await?;
    if route.starts_with("federation_") {
        owner.execute("DELETE FROM federation_room_members WHERE room_id IN(SELECT federated_room_id FROM chat_channels WHERE created_by IN($1,$2))",&[&account.user,&foreign.user]).await?;
        owner.execute("DELETE FROM federation_rooms WHERE channel_id IN(SELECT id FROM chat_channels WHERE created_by IN($1,$2))",&[&account.user,&foreign.user]).await?;
    }
    owner
        .execute(
            "DELETE FROM chat_channels WHERE created_by IN($1,$2)",
            &[&account.user, &foreign.user],
        )
        .await?;
    if let Some(old) = federation_prior {
        owner
            .execute(
                "DELETE FROM federation_outbox WHERE peer_domain='gofree-chat2-peer.test'",
                &[],
            )
            .await?;
        owner
            .execute(
                "DELETE FROM federation_peers WHERE peer_domain='gofree-chat2-peer.test'",
                &[],
            )
            .await?;
        owner
            .execute(
                "DELETE FROM federation_allowlist WHERE peer_domain='gofree-chat2-peer.test'",
                &[],
            )
            .await?;
        owner
            .execute(
                "UPDATE feature_toggles SET enabled=$1 WHERE key='feature.federation'",
                &[&old],
            )
            .await?;
    }
    if let Some(old) = drive_prior {
        owner
            .execute(
                "UPDATE feature_toggles SET enabled=$1 WHERE key='feature.drive'",
                &[&old],
            )
            .await?;
    }
    if let Some(old) = compliance_prior {
        if let Some(old) = old {
            owner
                .execute(
                    "UPDATE feature_toggles SET enabled=$1 WHERE key='feature.chat_compliance'",
                    &[&old],
                )
                .await?;
        } else {
            owner
                .execute(
                    "DELETE FROM feature_toggles WHERE key='feature.chat_compliance'",
                    &[],
                )
                .await?;
        }
    }
    if let Some(prior) = prior {
        owner
            .execute(
                "UPDATE feature_toggles SET enabled=$1 WHERE key='feature.chat'",
                &[&prior],
            )
            .await?;
    } else {
        owner
            .execute("DELETE FROM feature_toggles WHERE key='feature.chat'", &[])
            .await?;
    }
    remove_principal(&owner, &account).await?;
    remove_principal(&owner, &foreign).await?;
    result
}

async fn snapshot(c: &tokio_postgres::Client, actor: i64, foreign: i64) -> Result<Value, BoxError> {
    let mut out = serde_json::Map::new();
    for (table, predicate, order) in [
        ("chat_channels", "created_by IN($1,$2)", "id"),
        (
            "chat_channel_members",
            "channel_id IN(SELECT id FROM chat_channels WHERE created_by IN($1,$2))",
            "channel_id,user_id",
        ),
        (
            "chat_messages",
            "channel_id IN(SELECT id FROM chat_channels WHERE created_by IN($1,$2))",
            "id",
        ),
        (
            "chat_audit_log",
            "channel_id IN(SELECT id FROM chat_channels WHERE created_by IN($1,$2))",
            "id",
        ),
        ("chat_send_counters", "user_id IN($1,$2)", "user_id"),
        ("chat_push_intents", "sender_user_id IN($1,$2)", "id"),
        ("chat_polls", "created_by IN($1,$2)", "id"),
        (
            "scheduled_actions",
            "action_kind='chat_send' AND payload->>'userId' IN($1::bigint::text,$2::bigint::text)",
            "fire_at,id",
        ),
    ] {
        let sql=format!("SELECT COALESCE(jsonb_agg(to_jsonb(t) ORDER BY {order}),'[]'::jsonb)::text FROM (SELECT * FROM {table} WHERE {predicate})t");
        let raw: String = c.query_one(&sql, &[&actor, &foreign]).await?.get(0);
        if table != "scheduled_actions" {
            out.insert(table.into(), serde_json::from_str(&raw)?);
        }
    }
    Ok(Value::Object(out))
}
// Identity currencies remain separate: channel IDs can equal user IDs, and a
// seq/count is never an identity. Normalize only fields with an ID contract.
fn normalize(value: &mut Value, ids: &[(i64, String)]) {
    fn walk(value: &mut Value, ids: &[(i64, String)], key: &str, table: &str) {
        match value {
            Value::Object(o) => {
                let target = o
                    .get("targetType")
                    .or_else(|| o.get("target_type"))
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_owned();
                for (k, v) in o {
                    if matches!(
                        k.as_str(),
                        "created_at"
                            | "joined_at"
                            | "occurred_at"
                            | "createdAt"
                            | "joinedAt"
                            | "window_start"
                            | "updated_at"
                            | "next_attempt_at"
                    ) && !v.is_null()
                    {
                        assert!(
                            v.as_str()
                                .is_some_and(|s| chrono::DateTime::parse_from_rfc3339(s).is_ok()),
                            "invalid generated timestamp: {v}"
                        );
                        *v = "<timestamp>".into();
                    } else if k == "federated_local_key" && !v.is_null() {
                        let raw = v.as_str().unwrap();
                        assert!(raw.len() == 64 && raw.bytes().all(|b| b.is_ascii_hexdigit()));
                        *v = "<local-key>".into();
                    } else {
                        walk(
                            v,
                            ids,
                            if (k == "targetId" || k == "target_id") && target == "member" {
                                "userId"
                            } else if (k == "targetId" || k == "target_id")
                                && target == "chat_channel"
                            {
                                "channelId"
                            } else {
                                k
                            },
                            if k.starts_with("chat_") || k.starts_with("drive_") {
                                k
                            } else {
                                table
                            },
                        )
                    }
                }
            }
            Value::Array(a) => {
                for v in a {
                    walk(v, ids, key, table)
                }
            }
            Value::String(s) if key == "member_key" => {
                let labels = s
                    .split(':')
                    .map(|part| {
                        part.parse::<i64>().ok().and_then(|id| {
                            ids[..2]
                                .iter()
                                .find(|(uid, _)| *uid == id)
                                .map(|(_, label)| label.clone())
                        })
                    })
                    .collect::<Option<Vec<_>>>();
                if let Some(labels) = labels {
                    *s = labels.join(":");
                }
            }
            Value::String(s) if key == "instance" => {
                *s = s.replace(&format!("/channels/{}/", ids[2].0), "/channels/{id}/");
                if *s == format!("/chat/channels/{}", ids[2].0) {
                    *s = "/chat/channels/{id}".into();
                }
                for (user, _) in &ids[..2] {
                    if s.ends_with(&format!("/members/{user}")) {
                        *s = s.trim_end_matches(&user.to_string()).to_owned() + "{userId}";
                    }
                }
            }
            Value::Number(n) => {
                let channel = matches!(
                    key,
                    "channel_id" | "channelId" | "chatChannelId" | "chat_channel_id"
                ) || (key == "id" && table == "chat_channels");
                let user = matches!(
                    key,
                    "user_id"
                        | "userId"
                        | "created_by"
                        | "author_id"
                        | "authorId"
                        | "mentioned_user_id"
                        | "mentions"
                        | "sender_user_id"
                        | "owner_user_id"
                        | "memberIds"
                        | "userIds"
                );
                if channel || user {
                    let candidates = if channel { &ids[2..3] } else { &ids[..2] };
                    if let Some((_, label)) = n
                        .as_i64()
                        .and_then(|n| candidates.iter().find(|(id, _)| *id == n))
                    {
                        *value = label.clone().into();
                    }
                }
            }
            _ => {}
        }
    }
    walk(value, ids, "", "")
}

struct ChangedStatus<K: setjoin_authz::token::KeySource + 'static>(
    setjoin_gateway::chat_channels::ChannelRoute<K>,
);
impl<K: setjoin_authz::token::KeySource + 'static> setjoin_gateway::Intercept for ChangedStatus<K> {
    fn matches(&self, r: &Request<setjoin_gateway::Body>) -> bool {
        setjoin_gateway::Intercept::matches(&self.0, r)
    }
    fn admits_member(
        &self,
        h: hyper::HeaderMap,
        s: &'static str,
    ) -> setjoin_gateway::BoxFuture<bool> {
        setjoin_gateway::Intercept::admits_member(&self.0, h, s)
    }
    fn handle(
        &self,
        r: Request<setjoin_gateway::Body>,
        c: setjoin_gateway::RequestContext,
    ) -> setjoin_gateway::BoxFuture<Response<setjoin_gateway::Body>> {
        let future = setjoin_gateway::Intercept::handle(&self.0, r, c);
        Box::pin(async move {
            let mut response = future.await;
            *response.status_mut() = hyper::StatusCode::NOT_IMPLEMENTED;
            response
        })
    }
}

fn normalize_new_channels(value: &mut Value, fixture: i64) {
    let mut ids = std::collections::BTreeMap::new();
    if let Some(rows) = value
        .pointer("/effects/after/chat_channels")
        .and_then(Value::as_array)
    {
        for row in rows {
            let id = row["id"].as_i64().unwrap();
            if id != fixture {
                ids.insert(id, format!("<created-channel-{}>", ids.len() + 1));
            }
        }
    }
    fn walk(v: &mut Value, key: &str, table: &str, ids: &std::collections::BTreeMap<i64, String>) {
        match v {
            Value::Object(o) => {
                let target = o
                    .get("targetType")
                    .or_else(|| o.get("target_type"))
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_owned();
                for (k, v) in o {
                    if matches!(table, "chat_audit_log" | "drive_audit_log")
                        && key == "after_state"
                        && (k == "_checksum" || k == "_prev_checksum")
                    {
                        *v = "<verified-checksum>".into();
                    } else {
                        walk(
                            v,
                            if (k == "targetId" || k == "target_id") && target == "chat_channel" {
                                "channelId"
                            } else {
                                k
                            },
                            if k.starts_with("chat_") || k.starts_with("drive_") {
                                k
                            } else {
                                table
                            },
                            ids,
                        )
                    }
                }
            }
            Value::Array(a) => {
                for v in a {
                    walk(v, key, table, ids)
                }
            }
            Value::Number(n)
                if matches!(key, "channelId" | "channel_id")
                    || (key == "id" && table == "chat_channels") =>
            {
                if let Some(label) = n.as_i64().and_then(|n| ids.get(&n)) {
                    *v = label.clone().into();
                }
            }
            _ => {}
        }
    }
    walk(value, "", "", &ids)
}

async fn space_snapshot(
    c: &tokio_postgres::Client,
    actor: i64,
    foreign: i64,
) -> Result<Value, BoxError> {
    let mut out = serde_json::Map::new();
    for(table,predicate,order)in[
("drive_spaces","chat_channel_id IN(SELECT id FROM chat_channels WHERE created_by IN($1,$2))","id"),
("drive_changes","space_id IN(SELECT id FROM drive_spaces WHERE chat_channel_id IN(SELECT id FROM chat_channels WHERE created_by IN($1,$2)))","space_id,seq"),
("drive_audit_log","space_id IN(SELECT id FROM drive_spaces WHERE chat_channel_id IN(SELECT id FROM chat_channels WHERE created_by IN($1,$2)))","space_id,id"),
("drive_acl_generations","space_id IN(SELECT id FROM drive_spaces WHERE chat_channel_id IN(SELECT id FROM chat_channels WHERE created_by IN($1,$2)))","space_id"),
("drive_space_members","space_id IN(SELECT id FROM drive_spaces WHERE chat_channel_id IN(SELECT id FROM chat_channels WHERE created_by IN($1,$2)))","space_id,user_id")]{let sql=format!("SELECT coalesce(jsonb_agg(to_jsonb(t) ORDER BY {order}),'[]'::jsonb)::text FROM (SELECT * FROM {table} WHERE {predicate})t");let raw:String=c.query_one(&sql,&[&actor,&foreign]).await?.get(0);out.insert(table.into(),serde_json::from_str(&raw)?);}
    Ok(out.into())
}
fn normalize_spaces(value: &mut Value) {
    let ids = value
        .pointer("/effects/after/drive/drive_spaces")
        .and_then(Value::as_array)
        .unwrap()
        .iter()
        .enumerate()
        .map(|(i, r)| (r["id"].as_i64().unwrap(), format!("<space-{}>", i + 1)))
        .collect::<std::collections::BTreeMap<_, _>>();
    fn walk(v: &mut Value, key: &str, table: &str, ids: &std::collections::BTreeMap<i64, String>) {
        match v {
            Value::Object(o) => {
                let target = o
                    .get("target_type")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_owned();
                for (k, v) in o {
                    if k == "at" && table == "drive_changes" {
                        if !v.is_null() {
                            assert!(v
                                .as_str()
                                .is_some_and(|s| chrono::DateTime::parse_from_rfc3339(s).is_ok()));
                            *v = "<timestamp>".into();
                        }
                    } else {
                        walk(
                            v,
                            if k == "target_id" && target == "space" {
                                "spaceId"
                            } else {
                                k
                            },
                            if k.starts_with("drive_") { k } else { table },
                            ids,
                        )
                    }
                }
            }
            Value::Array(a) => {
                for v in a {
                    walk(v, key, table, ids)
                }
            }
            Value::Number(n)
                if matches!(key, "space_id" | "spaceId")
                    || (key == "id" && table == "drive_spaces") =>
            {
                if let Some(label) = n.as_i64().and_then(|n| ids.get(&n)) {
                    *v = label.clone().into();
                }
            }
            _ => {}
        }
    }
    walk(value, "", "", &ids)
}

fn normalize_space_clock(v: &mut Value) {
    match v {
        Value::Object(o) => {
            for (k, v) in o {
                if k == "updated_at" && !v.is_null() {
                    let raw = v.as_str().expect("timestamp");
                    if raw != "<timestamp>" {
                        assert!(chrono::DateTime::parse_from_rfc3339(raw).is_ok());
                        *v = "<timestamp>".into();
                    }
                } else {
                    normalize_space_clock(v)
                }
            }
        }
        Value::Array(a) => {
            for v in a {
                normalize_space_clock(v)
            }
        }
        _ => {}
    }
}

async fn message_snapshot(
    c: &tokio_postgres::Client,
    actor: i64,
    foreign: i64,
) -> Result<Value, BoxError> {
    let mut out = serde_json::Map::new();
    for(table,predicate,order)in[
("chat_mentions","message_id IN(SELECT id FROM chat_messages WHERE channel_id IN(SELECT id FROM chat_channels WHERE created_by IN($1,$2)))","message_id,mentioned_user_id"),
("chat_message_attachments","channel_id IN(SELECT id FROM chat_channels WHERE created_by IN($1,$2))","id"),
("chat_poll_options","poll_id IN(SELECT id FROM chat_polls WHERE created_by IN($1,$2))","poll_id,ordinal"),
("chat_poll_votes","poll_id IN(SELECT id FROM chat_polls WHERE created_by IN($1,$2))","poll_id,option_id,user_id")]{let sql=format!("SELECT coalesce(jsonb_agg(to_jsonb(t) ORDER BY {order}),'[]'::jsonb)::text FROM (SELECT * FROM {table} WHERE {predicate})t");let raw:String=c.query_one(&sql,&[&actor,&foreign]).await?.get(0);out.insert(table.into(),serde_json::from_str(&raw)?);}
    Ok(out.into())
}
fn normalize_message_ids(value: &mut Value) {
    let mut maps =
        std::collections::BTreeMap::<String, std::collections::BTreeMap<i64, String>>::new();
    for (table, label) in [
        ("chat_messages", "message"),
        ("chat_polls", "poll"),
        ("chat_push_intents", "push-intent"),
        ("chat_poll_options", "option"),
    ] {
        let rows = value
            .pointer(&if table == "chat_poll_options" {
                format!("/effects/after/message_details/{table}")
            } else {
                format!("/effects/after/{table}")
            })
            .and_then(Value::as_array)
            .unwrap();
        maps.insert(
            table.into(),
            rows.iter()
                .enumerate()
                .map(|(i, r)| (r["id"].as_i64().unwrap(), format!("<{label}-{}>", i + 1)))
                .collect(),
        );
    }
    fn walk(
        v: &mut Value,
        key: &str,
        table: &str,
        maps: &std::collections::BTreeMap<String, std::collections::BTreeMap<i64, String>>,
    ) {
        match v {
            Value::Object(o) => {
                let target = o
                    .get("target_type")
                    .or_else(|| o.get("targetType"))
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_owned();
                for (k, v) in o {
                    walk(
                        v,
                        if matches!(k.as_str(), "target_id" | "targetId")
                            && matches!(target.as_str(), "message" | "chat_message")
                        {
                            "messageId"
                        } else {
                            k
                        },
                        if k.starts_with("chat_") { k } else { table },
                        maps,
                    )
                }
            }
            Value::Array(a) => {
                for v in a {
                    walk(v, key, table, maps)
                }
            }
            Value::Number(n) => {
                let kind = if matches!(
                    key,
                    "message_id"
                        | "messageId"
                        | "parent_message_id"
                        | "parentMessageId"
                        | "parentId"
                ) {
                    Some("chat_messages")
                } else if matches!(key, "poll_id" | "pollId") {
                    Some("chat_polls")
                } else if matches!(key, "option_id" | "optionId") {
                    Some("chat_poll_options")
                } else if key == "id" && maps.contains_key(table) {
                    Some(table)
                } else {
                    None
                };
                if let Some(label) =
                    kind.and_then(|kind| n.as_i64().and_then(|id| maps[kind].get(&id)))
                {
                    *v = label.clone().into();
                }
            }
            _ => {}
        }
    }
    walk(value, "", "", &maps)
}

async fn scheduled_snapshot(
    c: &tokio_postgres::Client,
    actor: i64,
    foreign: i64,
) -> Result<Value, BoxError> {
    let raw:String=c.query_one("SELECT coalesce(jsonb_agg(to_jsonb(t) ORDER BY created_at,id),'[]'::jsonb)::text FROM scheduled_actions t WHERE action_kind='chat_send' AND payload->>'userId' IN($1::bigint::text,$2::bigint::text)",&[&actor,&foreign]).await?.get(0);
    Ok(serde_json::from_str(&raw)?)
}
fn normalize_actions(value: &mut Value) {
    let ids = value
        .pointer("/effects/after/scheduled_actions")
        .and_then(Value::as_array)
        .unwrap()
        .iter()
        .enumerate()
        .map(|(i, row)| {
            (
                row["id"].as_str().unwrap().to_owned(),
                format!("<action-{}>", i + 1),
            )
        })
        .collect::<std::collections::BTreeMap<_, _>>();
    fn walk(v: &mut Value, ids: &std::collections::BTreeMap<String, String>) {
        match v {
            Value::Object(o) => {
                for v in o.values_mut() {
                    walk(v, ids)
                }
            }
            Value::Array(a) => {
                for v in a {
                    walk(v, ids)
                }
            }
            Value::String(s) => {
                if let Some(label) = ids.get(s) {
                    *s = label.clone();
                }
            }
            _ => {}
        }
    }
    walk(value, &ids)
}

async fn federation_snapshot(
    c: &tokio_postgres::Client,
    actor: i64,
    foreign: i64,
) -> Result<Value, BoxError> {
    let mut out = serde_json::Map::new();
    for (table, predicate, order) in [
        (
            "federation_rooms",
            "channel_id IN(SELECT id FROM chat_channels WHERE created_by IN($1,$2))",
            "room_id",
        ),
        (
            "federation_room_members",
            "room_id IN(SELECT federated_room_id FROM chat_channels WHERE created_by IN($1,$2))",
            "room_id,member_domain",
        ),
        (
            "federation_peers",
            "peer_domain='gofree-chat2-peer.test' AND $1::bigint>0 AND $2::bigint>0",
            "peer_domain",
        ),
        (
            "federation_outbox",
            "peer_domain='gofree-chat2-peer.test' AND $1::bigint>0 AND $2::bigint>0",
            "peer_seq",
        ),
    ] {
        let raw:String=c.query_one(&format!("SELECT coalesce(jsonb_agg(to_jsonb(t) ORDER BY {order}),'[]'::jsonb)::text FROM {table} t WHERE {predicate}"),&[&actor,&foreign]).await?.get(0);
        out.insert(table.into(), serde_json::from_str(&raw)?);
    }
    Ok(out.into())
}
fn normalize_federation(v: &mut Value) {
    match v {
        Value::Object(o) => {
            for (k, v) in o {
                if k == "stanza_id" {
                    let text = v.as_str().unwrap();
                    let (prefix, suffix) = text.rsplit_once(':').unwrap();
                    assert!(
                        suffix.len() == 36
                            && suffix
                                .bytes()
                                .filter(|b| *b != b'-')
                                .all(|b| b.is_ascii_hexdigit())
                    );
                    *v = format!("{prefix}:<stanza>").into();
                } else if matches!(
                    k.as_str(),
                    "invited_at" | "invitedAt" | "left_at" | "parked_at" | "parkedAt" | "resumedAt"
                ) && !v.is_null()
                {
                    assert!(v
                        .as_str()
                        .is_some_and(|s| chrono::DateTime::parse_from_rfc3339(s).is_ok()));
                    *v = "<timestamp>".into();
                } else {
                    normalize_federation(v)
                }
            }
        }
        Value::Array(a) => {
            for v in a {
                normalize_federation(v)
            }
        }
        Value::String(s) => {
            if let Some((uuid, _)) = s.split_once('@') {
                if uuid.len() == 36
                    && uuid.bytes().enumerate().all(|(i, b)| {
                        if [8, 13, 18, 23].contains(&i) {
                            b == b'-'
                        } else {
                            b.is_ascii_hexdigit()
                        }
                    })
                    && s.ends_with("@gofree-chat2.test")
                {
                    *s = "<room>@gofree-chat2.test".into();
                }
            }
        }
        _ => {}
    }
}

async fn plant_no_notify(
    owner: &tokio_postgres::Client,
    base: &str,
) -> Result<(String, String), BoxError> {
    if std::env::var_os("GOFREE_RECORD_GO_BINARY").is_some() {
        return Err("mutants never run in recording mode".into());
    }
    let id: String = owner
        .query_one("SELECT replace(gen_random_uuid()::text,'-','')", &[])
        .await?
        .get(0);
    assert!(id.len() == 32 && id.bytes().all(|b| b.is_ascii_hexdigit()));
    let schema = format!("gofree_chat2_notify_{id}");
    let original: String = owner
        .query_one(
            "SELECT pg_get_functiondef('public.chat_typing_signal(bigint,bigint)'::regprocedure)",
            &[],
        )
        .await?
        .get(0);
    let signature = "CREATE OR REPLACE FUNCTION public.chat_typing_signal(";
    let marker = "PERFORM notify_chat_state(p_channel_id, 'typing');";
    if original.matches(signature).count() != 1
        || original.matches(marker).count() != 1
        || base.contains("options=")
    {
        return Err("notification mutant seam moved".into());
    }
    let definition = original
        .replacen(
            signature,
            &format!("CREATE OR REPLACE FUNCTION {schema}.chat_typing_signal("),
            1,
        )
        .replacen(marker, "NULL;", 1);
    record_resource(&format!(
        "Planned no-notify mutant schema {schema}; assigned fixture DB only"
    ))?;
    owner.batch_execute(&format!("BEGIN; CREATE SCHEMA {schema}; GRANT USAGE ON SCHEMA {schema} TO PUBLIC; {definition}; COMMIT;")).await?;
    let dsn = if base.starts_with("postgres://") || base.starts_with("postgresql://") {
        format!(
            "{base}{}options=-csearch_path%3D{schema}%2Cpublic",
            if base.contains('?') { '&' } else { '?' }
        )
    } else {
        format!("{base} options='-csearch_path={schema},public'")
    };
    Ok((dsn, schema))
}
fn record_resource(line: &str) -> Result<(), BoxError> {
    use std::io::Write;
    if let Ok(path) = std::env::var("GOFREE_RESOURCE_LEDGER") {
        writeln!(
            std::fs::OpenOptions::new().append(true).open(path)?,
            "{line}"
        )?;
    }
    Ok(())
}

#[tokio::test]
async fn all_channel_routes_roll_back_intact() -> Result<(), BoxError> {
    use http_body_util::BodyExt;
    if std::env::var_os("GOFREE_RECORD_GO_BINARY").is_some() {
        return Err("rollback invariants never record".into());
    }
    let _serial = SERIAL.lock().await;
    let db = Db::for_case("chat2-rollback").ok_or("database required")?;
    let owner = db.connect().await?;
    reset_shared_toggles(&owner).await?;
    let (account, foreign) = principal_pair(&owner).await?;
    let result=async{
  let endpoint=common::fake_upstream(|request|async move{let method=request.method().to_string();let uri=request.uri().to_string();let trace=request.headers().get("x-chat2-trace").unwrap().to_str().unwrap().to_owned();let bytes=request.into_body().collect().await.unwrap().to_bytes();Response::builder().status(418).header("x-chat2-go","yes").body(common::full(json!({"method":method,"uri":uri,"body":String::from_utf8_lossy(&bytes),"trace":trace}).to_string())).unwrap()}).await;
  for global in [false,true]{
   let mut inventory:Value=serde_json::from_str(include_str!("../route-inventory.json"))?;let routes=inventory["routes"].as_array().unwrap().iter().filter(|r|r["family"]=="F12"&&r["slice"]=="sub-router-a").cloned().collect::<Vec<_>>();assert_eq!(routes.len(),27);
   for row in inventory["routes"].as_array_mut().unwrap(){if row["family"]=="F12"&&row["slice"]=="sub-router-a"{row["state"]="OFF".into();row["upstream"]="go-mail".into();}}
   let adapter=setjoin_gateway::chat_channels::ChannelRoute{ unfurl:None,federation_typing:None,exec:loaded_host_exec(db.app.as_deref().unwrap_or(&db.dsn))?,keys:std::sync::Arc::new(common::recovery_keys()),issuer:"mailserver".into(),federation_local_domain:"gofree-chat2.test".into()};
   let gateway=Gateway::new(Config{upstream:Some(format!("http://{endpoint}").parse()?),trusted_proxies:TrustedProxies::parse("")?,upstream_header_timeout:setjoin_gateway::proxy::DEFAULT_HEADER_TIMEOUT,edge_limit:None},RouteTable::proxy_all().with(adapter))?.with_inventory(&inventory.to_string())?.with_enabled(!global);
   let listener=tokio::net::TcpListener::bind("127.0.0.1:0").await?;let address=listener.local_addr()?;let task=tokio::spawn(gateway.serve(listener));
   let check=async{
    for route in &routes{
     let method=route["method"].as_str().unwrap();let path=format!("/api{}?rollback=on&x=%2F",route["path"].as_str().unwrap().replace("{id}","991").replace("{userId}","992"));let body=r#"{"opaque":"unchanged","actorId":0}"#;
     let response=common::send(address,Request::builder().method(method).uri(&path).header("host","mail.test").header("origin","http://mail.test").header("authorization",format!("Bearer {}",token(account.user))).header("content-type","application/json").header("x-chat2-trace","preserved").body(common::full(body))?).await;
     assert_eq!(response.status(),418,"rollback {method} {path}");assert_eq!(response.headers()["x-chat2-go"],"yes");let value:Value=serde_json::from_slice(&common::body_bytes(response).await)?;assert_eq!(value,json!({"method":method,"uri":path,"body":body,"trace":"preserved"}));
    }
    if !global{let response=common::send(address,Request::builder().uri("/_gateway/metrics").body(common::full(""))?).await;let metrics=String::from_utf8(common::body_bytes(response).await.to_vec())?;assert!(metrics.lines().any(|line|line=="setjoin_gateway_proxied_to_go_total 27"),"{metrics}");assert!(metrics.lines().any(|line|line=="setjoin_gateway_proxied_to_go_by_family_total{family=\"F12\"} 27"),"{metrics}");}
    Ok::<_,BoxError>(())
   }.await;task.abort();let _=task.await;check?;
  }
  Ok::<_,BoxError>(())
 }.await;
    remove_principal(&owner, &account).await?;
    remove_principal(&owner, &foreign).await?;
    result
}
