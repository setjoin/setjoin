//! SAML SP public HTTP seam. The frozen middleware's path mismatch is parity.
mod common;
include!("saml_oracle/harness.rs");
#[path = "saml_oracle/flows.rs"]
mod flows;
#[path = "saml_oracle/link_begin.rs"]
mod link_begin;
#[path = "saml_oracle/links.rs"]
mod links;
#[path = "saml_oracle/unlink.rs"]
mod unlink;
#[tokio::test]
async fn disabled_saml_routes_are_native_not_found() {
    let db = Db::for_case("IDFED3-saml").expect("assigned disposable DB required");
    let auth = AuthServer::new(setjoin_pg::ScopedExecutor::from_dsn(&db.dsn, 2).unwrap());
    for (method, path) in [
        ("GET", "/auth/saml/missing/login"),
        ("GET", "/auth/saml/missing/metadata"),
        ("POST", "/auth/saml/missing/acs"),
    ] {
        let response = auth
            .handle(
                Request::builder()
                    .method(method)
                    .uri(path)
                    .body(body(""))
                    .unwrap(),
            )
            .await;
        assert_eq!(response.status(), 404, "{method} {path}");
        assert_eq!(
            response.into_body().collect().await.unwrap().to_bytes(),
            "404 page not found\n"
        );
    }
}

#[tokio::test]
async fn login_redirect_success() {
    flows::login("success", false).await.unwrap();
}

#[tokio::test]
async fn login_post_success() {
    flows::login("post", false).await.unwrap();
}

#[tokio::test]
async fn login_encoded_idp() {
    flows::login("encoded", false).await.unwrap();
}

#[tokio::test]
async fn login_existing_sp_session() {
    flows::login("session", false).await.unwrap();
}

#[tokio::test]
async fn acs_success() {
    flows::public("acs", "success", false).await.unwrap();
}

#[tokio::test]
async fn mux_success() {
    flows::public("mux", "success", false).await.unwrap();
}

macro_rules! floor_public {
    ($name:ident,$group:literal,$kind:literal) => {
        #[tokio::test]
        async fn $name() {
            flows::public($group, $kind, false).await.unwrap();
        }
    };
}
macro_rules! floor_login {
    ($name:ident,$kind:literal) => {
        #[tokio::test]
        async fn $name() {
            flows::login($kind, false).await.unwrap();
        }
    };
}
floor_login!(floor_login_cross_tenant, "cross-tenant");
floor_login!(floor_login_invalid_input, "invalid-input");
floor_login!(floor_login_invalid_session, "invalid-session");
floor_login!(floor_login_foreign_session, "foreign-session");
floor_public!(floor_metadata_success, "metadata", "success");
floor_public!(floor_metadata_cross_tenant, "metadata", "cross-tenant");
floor_public!(floor_metadata_invalid_input, "metadata", "invalid-input");
floor_public!(floor_acs_cross_tenant, "acs", "cross-tenant");
floor_public!(floor_acs_invalid_input, "acs", "invalid-input");
floor_public!(floor_acs_repeat, "acs", "repeat");
floor_public!(floor_acs_wrapping, "acs", "wrapping");
floor_public!(floor_alias_success, "alias", "success");
floor_public!(floor_alias_cross_tenant, "alias", "cross-tenant");
floor_public!(floor_alias_invalid_input, "alias", "invalid-input");
floor_public!(floor_mux_cross_tenant, "mux", "cross-tenant");
floor_public!(floor_mux_invalid_input, "mux", "invalid-input");

#[tokio::test]
async fn login_status_mutant() {
    flows::login("success", true).await.unwrap();
}
#[tokio::test]
async fn metadata_status_mutant() {
    flows::public("metadata", "success", true).await.unwrap();
}
#[tokio::test]
async fn acs_status_mutant() {
    flows::public("acs", "success", true).await.unwrap();
}
#[tokio::test]
async fn alias_status_mutant() {
    flows::public("alias", "success", true).await.unwrap();
}
#[tokio::test]
async fn mux_status_mutant() {
    flows::public("mux", "success", true).await.unwrap();
}

#[tokio::test]
async fn list_success() {
    links::list("success", false).await.unwrap();
}

#[tokio::test]
async fn list_infinite_timestamp_fails_closed() {
    links::list("infinity", false).await.unwrap();
}
#[tokio::test]
async fn list_floor_cross_tenant() {
    links::list("cross-tenant", false).await.unwrap();
}
#[tokio::test]
async fn list_floor_invalid_input() {
    links::list("invalid-input", false).await.unwrap();
}
#[tokio::test]
async fn list_status_mutant() {
    links::list("success", true).await.unwrap();
}

#[tokio::test]
async fn link_success() {
    link_begin::run("success").await.unwrap();
}

macro_rules! link_floor {
    ($name:ident,$kind:literal) => {
        #[tokio::test]
        async fn $name() {
            link_begin::run($kind).await.unwrap();
        }
    };
}
link_floor!(link_floor_cross_tenant, "cross-tenant");
link_floor!(link_floor_invalid_input, "invalid-input");
link_floor!(link_floor_repeat, "repeat");
link_floor!(link_floor_no_session, "no-session");
link_floor!(link_floor_aal1, "aal1");
link_floor!(link_floor_stale, "stale");
link_floor!(link_floor_bearer_only, "bearer-only");
link_floor!(link_floor_inactive_session, "inactive-session");
link_floor!(link_floor_cross_session, "cross-session");
link_floor!(link_floor_csrf, "csrf");
link_floor!(link_floor_sp_session, "sp-session");
#[tokio::test]
async fn link_status_mutant() {
    link_begin::variant("success", true).await.unwrap();
}

#[tokio::test]
async fn unlink_success() {
    unlink::run("success", false).await.unwrap();
}

macro_rules! unlink_floor {
    ($name:ident,$kind:literal) => {
        #[tokio::test]
        async fn $name() {
            unlink::run($kind, false).await.unwrap();
        }
    };
}
unlink_floor!(unlink_floor_cross_tenant, "cross-tenant");
unlink_floor!(unlink_floor_invalid_input, "invalid-input");
unlink_floor!(unlink_floor_repeat, "repeat");
unlink_floor!(unlink_floor_no_session, "no-session");
unlink_floor!(unlink_floor_aal1, "aal1");
unlink_floor!(unlink_floor_csrf, "csrf");
unlink_floor!(unlink_floor_malformed, "malformed");
unlink_floor!(unlink_floor_empty_reason, "empty-reason");
unlink_floor!(unlink_floor_oversized, "oversized");
unlink_floor!(unlink_floor_trailing_large, "trailing-large");
#[tokio::test]
async fn unlink_status_mutant() {
    unlink::run("success", true).await.unwrap();
}

#[path = "saml_oracle/ssrf.rs"]
mod ssrf;
#[tokio::test]
async fn metadata_ssrf_private_literal_and_dns() {
    ssrf::run().await;
}

unlink_floor!(unlink_floor_invalid_owner, "invalid-owner");
