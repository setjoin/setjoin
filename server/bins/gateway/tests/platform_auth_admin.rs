//! F21 `gateway * /auth/admin/` (#365) native deny-by-default oracle tests.
use crate::platform_oracle;

async fn check(label: &str) {
    platform_oracle::auth_admin::run(label, false)
        .await
        .unwrap();
}

#[tokio::test]
async fn auth_admin_success_returns_go_404() {
    check("success").await;
}

#[tokio::test]
async fn auth_admin_head_returns_empty_404_with_length() {
    check("head").await;
}

#[tokio::test]
async fn auth_admin_post_returns_go_404() {
    check("post").await;
}

#[tokio::test]
async fn auth_admin_denied_ignores_forged_claim_and_writes_console_denied() {
    check("denied").await;
}

#[tokio::test]
async fn auth_admin_unauthenticated_returns_401_challenge() {
    check("unauthenticated").await;
}

#[tokio::test]
async fn auth_admin_bad_signature_returns_401_challenge() {
    check("bad-sig").await;
}

#[tokio::test]
async fn auth_admin_expired_returns_401_challenge() {
    check("expired").await;
}

#[tokio::test]
async fn auth_admin_alg_none_returns_401_challenge() {
    check("alg-none").await;
}

#[tokio::test]
async fn auth_admin_basic_auth_returns_401_challenge_without_go() {
    check("basic-auth").await;
}

#[tokio::test]
async fn auth_admin_guest_claim_is_rejected_without_go() {
    check("guest").await;
}

#[tokio::test]
async fn auth_admin_csrf_is_rejected_before_auth_and_audit() {
    check("csrf").await;
}

#[tokio::test]
async fn auth_admin_rate_limit_spends_auth_budget_without_go() {
    check("rate-limit").await;
}

#[tokio::test]
async fn auth_admin_bare_redirects_307_before_auth() {
    check("bare").await;
}

#[tokio::test]
async fn auth_admin_bare_preserves_query_on_307() {
    check("bare-query").await;
}

#[tokio::test]
async fn auth_admin_bare_post_redirects_307() {
    check("bare-post").await;
}

#[tokio::test]
async fn auth_admin_bare_api_redirects_307_to_canonical_root() {
    check("bare-api").await;
}

#[tokio::test]
async fn auth_admin_api_alias_returns_go_404() {
    check("api-alias").await;
}

#[tokio::test]
async fn auth_admin_api_alias_denied_strips_api_in_console_denied() {
    check("api-alias-denied").await;
}

#[tokio::test]
async fn auth_admin_percent_escaped_segment_matches_subtree() {
    check("escaped").await;
}

#[tokio::test]
async fn auth_admin_get_impersonate_falls_through_to_subtree_404() {
    check("get-impersonate").await;
}

#[tokio::test]
async fn auth_admin_get_impersonate_denied_writes_console_denied() {
    check("get-impersonate-denied").await;
}

#[tokio::test]
async fn auth_admin_get_impersonate_unauth_returns_401_challenge() {
    check("get-impersonate-unauth").await;
}

#[tokio::test]
async fn auth_admin_post_api_impersonate_routes_to_rust_auth_and_active_guest_404s() {
    platform_oracle::auth_admin::verify_routing_and_guest()
        .await
        .unwrap();
}

#[tokio::test]
async fn auth_admin_status_mutant_is_rejected() {
    platform_oracle::auth_admin::run("success", true)
        .await
        .unwrap();
}
