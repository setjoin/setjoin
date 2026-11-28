//! #455 recovery admin HTTP seam, immutable frozen-Go responses and effects.
mod common;
mod platform_oracle;
#[tokio::test]
async fn list_success() -> Result<(), common::BoxError> {
    platform_oracle::updates::run("recovery-list", "success", None).await
}
#[tokio::test]
async fn list_invalid_limit() -> Result<(), common::BoxError> {
    platform_oracle::updates::run("recovery-list", "invalid", None).await
}
#[tokio::test]
async fn list_scoped_admin_is_denied() -> Result<(), common::BoxError> {
    platform_oracle::updates::run("recovery-list", "scoped", None).await
}
#[tokio::test]
async fn list_filters_status_and_cursor_before_limiting() -> Result<(), common::BoxError> {
    platform_oracle::updates::run("recovery-list", "filtered", None).await
}
#[tokio::test]
async fn list_status_mutant_is_rejected() -> Result<(), common::BoxError> {
    platform_oracle::updates::run("recovery-list", "success-status-mutant", None).await
}
#[tokio::test]
async fn signals_matches_frozen_go() -> Result<(), common::BoxError> {
    for case in ["success", "scoped", "invalid"] {
        platform_oracle::updates::run("recovery-signals", case, None).await?;
    }
    Ok(())
}
#[tokio::test]
async fn signals_status_mutant_is_rejected() -> Result<(), common::BoxError> {
    platform_oracle::updates::run("recovery-signals", "success-status-mutant", None).await
}
#[tokio::test]
async fn artifacts_matches_frozen_go() -> Result<(), common::BoxError> {
    for case in ["success", "scoped", "invalid", "invalid-limit", "missing"] {
        platform_oracle::updates::run("recovery-artifacts", case, None).await?;
    }
    Ok(())
}
#[tokio::test]
async fn artifacts_status_mutant_is_rejected() -> Result<(), common::BoxError> {
    platform_oracle::updates::run("recovery-artifacts", "success-status-mutant", None).await
}
#[tokio::test]
async fn artifacts_uuid_aliases_match_frozen_go() -> Result<(), common::BoxError> {
    for case in ["compact", "urn", "wrapped", "nil"] {
        platform_oracle::updates::run("recovery-artifacts", case, None).await?;
    }
    Ok(())
}
#[tokio::test]
async fn approve_matches_frozen_go() -> Result<(), common::BoxError> {
    for case in [
        "success",
        "scoped",
        "invalid",
        "repeat",
        "bad-id",
        "unknown-field",
        "bad-reason",
        "denied",
        "self",
    ] {
        platform_oracle::updates::run("recovery-approve", case, None).await?;
    }
    Ok(())
}
#[tokio::test]
async fn approve_status_mutant_is_rejected() -> Result<(), common::BoxError> {
    platform_oracle::updates::run("recovery-approve", "success-status-mutant", None).await
}
#[tokio::test]
async fn close_matches_frozen_go() -> Result<(), common::BoxError> {
    for case in ["success", "scoped", "invalid", "repeat", "bad-id", "denied"] {
        platform_oracle::updates::run("recovery-close", case, None).await?;
    }
    Ok(())
}
#[tokio::test]
async fn close_status_mutant_is_rejected() -> Result<(), common::BoxError> {
    platform_oracle::updates::run("recovery-close", "success-status-mutant", None).await
}
#[tokio::test]
async fn open_matches_frozen_go() -> Result<(), common::BoxError> {
    for case in [
        "success",
        "scoped",
        "invalid",
        "repeat",
        "denied",
        "no-step-up",
        "bad-scope",
        "bad-mailbox",
        "bad-expiry",
        "bad-evidence",
        "wrong-evidence",
        "compact-incident",
        "approval",
        "short-expiry",
    ] {
        eprintln!("ORACLE-CASE recovery-open {case}");
        platform_oracle::updates::run("recovery-open", case, None).await?;
    }
    Ok(())
}
#[tokio::test]
async fn open_status_mutant_is_rejected() -> Result<(), common::BoxError> {
    platform_oracle::updates::run("recovery-open", "success-status-mutant", None).await
}

#[tokio::test]
async fn accept_matches_frozen_go() -> Result<(), common::BoxError> {
    for case in [
        "success",
        "scoped",
        "invalid",
        "repeat",
        "bad-id",
        "bad-resolution",
        "infected",
        "unapproved",
        "fork-without-consent",
        "fork-consented",
        "denied",
    ] {
        eprintln!("ORACLE-CASE recovery-accept {case}");
        platform_oracle::updates::run("recovery-accept", case, None).await?;
    }
    Ok(())
}
#[tokio::test]
async fn accept_status_mutant_is_rejected() -> Result<(), common::BoxError> {
    platform_oracle::updates::run("recovery-accept", "success-status-mutant", None).await
}

#[tokio::test]
async fn list_edges_match_frozen_go() -> Result<(), common::BoxError> {
    for case in ["large", "bad-cursor", "bad-status", "disabled"] {
        eprintln!("ORACLE-CASE recovery-list {case}");
        platform_oracle::updates::run("recovery-list", case, None).await?;
    }
    Ok(())
}

#[tokio::test]
async fn list_uses_cached_feature_snapshot() -> Result<(), common::BoxError> {
    platform_oracle::updates::run("recovery-list", "cached", None).await
}

#[tokio::test]
async fn open_no_notify_is_rejected() -> Result<(), common::BoxError> {
    platform_oracle::updates::run("recovery-open", "success", Some("no-notify")).await
}
#[tokio::test]
async fn close_no_notify_is_rejected() -> Result<(), common::BoxError> {
    platform_oracle::updates::run("recovery-close", "success", Some("no-notify")).await
}
#[tokio::test]
async fn accept_no_notify_is_rejected() -> Result<(), common::BoxError> {
    platform_oracle::updates::run("recovery-accept", "success", Some("no-notify")).await
}

#[tokio::test]
async fn committed_response_loss_is_unknown() -> Result<(), common::BoxError> {
    platform_oracle::updates::run("recovery-open", "success", Some("commit-after")).await
}

#[tokio::test]
async fn remaining_commit_cuts_are_unknown() -> Result<(), common::BoxError> {
    for action in ["recovery-open", "recovery-approve", "recovery-close", "recovery-accept"] {
        for fault in ["commit-before", "commit-after"] {
            if action == "recovery-open" && fault == "commit-after" { continue; }
            platform_oracle::updates::run(action, "success", Some(fault)).await?;
        }
    }
    Ok(())
}

#[tokio::test]
async fn failed_recovery_statement_rolls_back_all_effects() -> Result<(), common::BoxError> {
    for action in ["recovery-open", "recovery-approve", "recovery-close", "recovery-accept"] {
        platform_oracle::updates::run(action, "success", Some("statement-failure")).await?;
    }
    Ok(())
}
