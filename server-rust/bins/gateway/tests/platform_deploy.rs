//! #455 process-local deployment wizard HTTP parity.
mod common;
mod platform_oracle;
#[tokio::test]
async fn status_matches_frozen_go() -> Result<(), common::BoxError> {
    for case in ["success", "scoped", "invalid", "empty", "denied"] {
        eprintln!("ORACLE-CASE deploy-status {case}");
        platform_oracle::updates::run("deploy-status", case, None).await?;
    }
    Ok(())
}
#[tokio::test]
async fn status_mutant_is_rejected() -> Result<(), common::BoxError> {
    platform_oracle::updates::run("deploy-status", "success-status-mutant", None).await
}

#[tokio::test]
async fn start_matches_frozen_go() -> Result<(), common::BoxError> {
    for case in ["success", "scoped", "invalid", "bad-key", "denied"] {
        eprintln!("ORACLE-CASE deploy-start {case}");
        platform_oracle::updates::run("deploy-start", case, None).await?;
    }
    Ok(())
}
#[tokio::test]
async fn start_status_mutant_is_rejected() -> Result<(), common::BoxError> {
    platform_oracle::updates::run("deploy-start", "success-status-mutant", None).await
}

#[tokio::test]
async fn cancel_matches_frozen_go() -> Result<(), common::BoxError> {
    for case in ["success", "scoped", "invalid", "empty", "fence", "denied"] {
        eprintln!("ORACLE-CASE deploy-cancel {case}");
        platform_oracle::updates::run("deploy-cancel", case, None).await?;
    }
    Ok(())
}
#[tokio::test]
async fn cancel_status_mutant_is_rejected() -> Result<(), common::BoxError> {
    platform_oracle::updates::run("deploy-cancel", "success-status-mutant", None).await
}

#[tokio::test]
async fn duplicate_nodes_reuse_existing_fields() -> Result<(), common::BoxError> {
    platform_oracle::updates::run("deploy-start", "duplicate-nodes", None).await
}

#[tokio::test]
async fn remote_signal_error_matches_go() -> Result<(), common::BoxError> {
    platform_oracle::updates::run("deploy-start", "signal", None).await
}

#[tokio::test]
async fn pinned_host_certificate_matches_go() -> Result<(), common::BoxError> {
    platform_oracle::updates::run("deploy-start", "host-cert", None).await
}

#[tokio::test]
async fn invalid_utf8_output_matches_go() -> Result<(), common::BoxError> {
    platform_oracle::updates::run("deploy-start", "invalid-utf8", None).await
}

#[tokio::test]
async fn byte_truncation_matches_go() -> Result<(), common::BoxError> {
    platform_oracle::updates::run("deploy-start", "truncated-utf8", None).await
}

#[tokio::test]
async fn rsa_authenticated_deployment_matches_go() -> Result<(), common::BoxError> {
    platform_oracle::updates::run("deploy-start", "rsa", None).await
}

#[tokio::test]
async fn echoed_credentials_are_redacted_like_go() -> Result<(), common::BoxError> {
    platform_oracle::updates::run("deploy-start", "redact", None).await
}

// #542: the scoped cases replay against the reviewed security expectations
// (platform/divergences.json); mutants upgrade-scoped-grant-{deploy-start,deploy-cancel,deploy-status}.
#[tokio::test]
async fn start_scoped() -> Result<(), common::BoxError> {
    platform_oracle::updates::run("deploy-start", "scoped", None).await
}
#[tokio::test]
async fn cancel_scoped() -> Result<(), common::BoxError> {
    platform_oracle::updates::run("deploy-cancel", "scoped", None).await
}
#[tokio::test]
async fn status_scoped() -> Result<(), common::BoxError> {
    platform_oracle::updates::run("deploy-status", "scoped", None).await
}
