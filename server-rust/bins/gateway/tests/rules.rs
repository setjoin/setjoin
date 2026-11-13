mod common;
mod rules_oracle;
#[tokio::test]
async fn personal_list_success() -> Result<(), common::BoxError> {
    rules_oracle::run("personal-list", "success", None).await
}

#[tokio::test]
async fn personal_create_success() -> Result<(), common::BoxError> {
    rules_oracle::run("personal-create", "success", None).await
}

#[tokio::test]
async fn personal_update_success() -> Result<(), common::BoxError> {
    rules_oracle::run("personal-update", "success", None).await
}

#[tokio::test]
async fn personal_delete_success() -> Result<(), common::BoxError> {
    rules_oracle::run("personal-delete", "success", None).await
}

#[tokio::test]
async fn retro_apply_success() -> Result<(), common::BoxError> {
    rules_oracle::run("retro-apply", "success", None).await
}

#[tokio::test]
async fn retro_status_success() -> Result<(), common::BoxError> {
    rules_oracle::run("retro-status", "success", None).await
}

#[tokio::test]
async fn admin_list_success() -> Result<(), common::BoxError> {
    rules_oracle::run("admin-list", "success", None).await
}

#[tokio::test]
async fn admin_get_success() -> Result<(), common::BoxError> {
    rules_oracle::run("admin-get", "success", None).await
}

#[tokio::test]
async fn admin_create_success() -> Result<(), common::BoxError> {
    rules_oracle::run("admin-create", "success", None).await
}

#[tokio::test]
async fn admin_update_success() -> Result<(), common::BoxError> {
    rules_oracle::run("admin-update", "success", None).await
}

#[tokio::test]
async fn admin_delete_success() -> Result<(), common::BoxError> {
    rules_oracle::run("admin-delete", "success", None).await
}

#[tokio::test]
async fn admin_test_success() -> Result<(), common::BoxError> {
    rules_oracle::run("admin-test", "success", None).await
}

#[tokio::test]
async fn template_list_success() -> Result<(), common::BoxError> {
    rules_oracle::run("template-list", "success", None).await
}

#[tokio::test]
async fn template_get_success() -> Result<(), common::BoxError> {
    rules_oracle::run("template-get", "success", None).await
}

#[tokio::test]
async fn template_resolve_success() -> Result<(), common::BoxError> {
    rules_oracle::run("template-resolve", "success", None).await
}

/// Ordinary CI exercises a real replay; recording a selected batch is explicit.
#[tokio::test]
async fn recording_driver_or_replay_smoke() -> Result<(), common::BoxError> {
    match std::env::var("GOFREE_RULES1_CASES") {
        Ok(cases) => rules_oracle::record_selected(&cases).await,
        Err(_) => rules_oracle::run("personal-list", "success", None).await,
    }
}

#[tokio::test]
async fn template_create_success() -> Result<(), common::BoxError> {
    rules_oracle::run("template-create", "success", None).await
}

#[tokio::test]
async fn template_update_success() -> Result<(), common::BoxError> {
    rules_oracle::run("template-update", "success", None).await
}

#[tokio::test]
async fn template_delete_success() -> Result<(), common::BoxError> {
    rules_oracle::run("template-delete", "success", None).await
}

#[tokio::test]
async fn template_visibility_get_success() -> Result<(), common::BoxError> {
    rules_oracle::run("template-visibility-get", "success", None).await
}

#[tokio::test]
async fn template_visibility_set_success() -> Result<(), common::BoxError> {
    rules_oracle::run("template-visibility-set", "success", None).await
}

#[tokio::test]
async fn template_personal_list_success() -> Result<(), common::BoxError> {
    rules_oracle::run("template-personal-list", "success", None).await
}

#[tokio::test]
async fn admin_create_from_template() -> Result<(), common::BoxError> {
    rules_oracle::run("admin-create", "from-template", None).await
}

macro_rules! case {
    ($name:ident,$action:literal,$label:literal) => {
        #[tokio::test]
        async fn $name() -> Result<(), common::BoxError> {
            rules_oracle::run($action, $label, None).await
        }
    };
}
macro_rules! mutant {
    ($name:ident,$action:literal,$fault:literal) => {
        #[tokio::test]
        async fn $name() -> Result<(), common::BoxError> {
            rules_oracle::run($action, "success", Some($fault)).await
        }
    };
}
include!("rules_oracle/cases.rs");
mutant!(family_no_audit, "admin-create", "no-audit");
mutant!(family_double_bump, "admin-create", "double-bump");
mutant!(family_no_tenant_filter, "personal-list", "no-tenant-filter");

mutant!(
    commit_personal_create_before,
    "personal-create",
    "commit-before"
);
mutant!(
    commit_personal_create_after,
    "personal-create",
    "commit-after"
);
mutant!(commit_admin_create_before, "admin-create", "commit-before");
mutant!(commit_admin_create_after, "admin-create", "commit-after");
mutant!(commit_retro_apply_before, "retro-apply", "commit-before");
mutant!(commit_retro_apply_after, "retro-apply", "commit-after");
mutant!(
    commit_template_create_before,
    "template-create",
    "commit-before"
);
mutant!(
    commit_template_create_after,
    "template-create",
    "commit-after"
);
mutant!(
    commit_template_visibility_set_before,
    "template-visibility-set",
    "commit-before"
);
mutant!(
    commit_template_visibility_set_after,
    "template-visibility-set",
    "commit-after"
);
