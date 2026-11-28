//! Frozen-Go Exchange replacement HTTP oracle (#294).
mod common;
mod exchange_oracle;
#[tokio::test]
async fn registry_success() -> Result<(), common::BoxError> {
    exchange_oracle::run("registry", "seeded").await
}
#[tokio::test]
async fn projects_success() -> Result<(), common::BoxError> {
    exchange_oracle::run("projects", "success").await
}

macro_rules! case {
    ($name:ident,$action:literal,$kind:literal) => {
        #[tokio::test]
        async fn $name() -> Result<(), common::BoxError> {
            exchange_oracle::run($action, $kind).await
        }
    };
}
case!(registry_foreign, "registry", "foreign");
case!(registry_invalid, "registry", "invalid");
case!(registry_denied, "registry", "denied");
case!(registry_status_mutant, "registry", "status-mutant");
case!(projects_foreign, "projects", "foreign");
case!(projects_invalid, "projects", "invalid");
case!(projects_denied, "projects", "denied");
case!(projects_status_mutant, "projects", "status-mutant");
case!(runs_success, "runs", "success");
case!(runs_foreign, "runs", "foreign");
case!(runs_invalid, "runs", "invalid");
case!(runs_denied, "runs", "denied");
case!(runs_status_mutant, "runs", "status-mutant");

case!(create_project_success, "create-project", "success");
case!(create_project_foreign, "create-project", "foreign");
case!(create_project_invalid, "create-project", "invalid");
case!(create_project_denied, "create-project", "denied");
case!(create_project_repeat, "create-project", "repeat");
case!(create_project_weak_aal, "create-project", "weak-aal");
case!(create_project_stale_aal, "create-project", "stale-aal");
case!(
    create_project_status_mutant,
    "create-project",
    "status-mutant"
);
case!(create_run_success, "create-run", "success");
case!(create_run_foreign, "create-run", "foreign");
case!(create_run_invalid, "create-run", "invalid");
case!(create_run_denied, "create-run", "denied");
case!(create_run_repeat, "create-run", "repeat");
case!(create_run_weak_aal, "create-run", "weak-aal");
case!(create_run_stale_aal, "create-run", "stale-aal");
case!(create_run_status_mutant, "create-run", "status-mutant");
case!(transition_success, "transition", "success");
case!(transition_foreign, "transition", "foreign");
case!(transition_invalid, "transition", "invalid");
case!(transition_denied, "transition", "denied");
case!(transition_repeat, "transition", "repeat");
case!(transition_weak_aal, "transition", "weak-aal");
case!(transition_stale_aal, "transition", "stale-aal");
case!(transition_status_mutant, "transition", "status-mutant");
case!(attestation_success, "attestation", "success");
case!(attestation_foreign, "attestation", "foreign");
case!(attestation_invalid, "attestation", "invalid");
case!(attestation_denied, "attestation", "denied");
case!(attestation_repeat, "attestation", "repeat");
case!(attestation_weak_aal, "attestation", "weak-aal");
case!(attestation_stale_aal, "attestation", "stale-aal");
case!(attestation_status_mutant, "attestation", "status-mutant");
case!(decision_success, "decision", "success");
case!(decision_foreign, "decision", "foreign");
case!(decision_invalid, "decision", "invalid");
case!(decision_denied, "decision", "denied");
case!(decision_repeat, "decision", "repeat");
case!(decision_weak_aal, "decision", "weak-aal");
case!(decision_stale_aal, "decision", "stale-aal");
case!(decision_status_mutant, "decision", "status-mutant");
case!(resolve_success, "resolve", "success");
case!(resolve_foreign, "resolve", "foreign");
case!(resolve_invalid, "resolve", "invalid");
case!(resolve_denied, "resolve", "denied");
case!(resolve_repeat, "resolve", "repeat");
case!(resolve_weak_aal, "resolve", "weak-aal");
case!(resolve_stale_aal, "resolve", "stale-aal");
case!(resolve_status_mutant, "resolve", "status-mutant");
case!(delete_success, "delete", "success");
case!(delete_foreign, "delete", "foreign");
case!(delete_invalid, "delete", "invalid");
case!(delete_denied, "delete", "denied");
case!(delete_repeat, "delete", "repeat");
case!(delete_weak_aal, "delete", "weak-aal");
case!(delete_stale_aal, "delete", "stale-aal");
case!(delete_status_mutant, "delete", "status-mutant");
case!(audit_success, "audit", "success");
case!(audit_foreign, "audit", "foreign");
case!(audit_invalid, "audit", "invalid");
case!(audit_denied, "audit", "denied");
case!(audit_weak_aal, "audit", "weak-aal");
case!(audit_stale_aal, "audit", "stale-aal");
case!(audit_status_mutant, "audit", "status-mutant");
case!(
    create_project_reason_required,
    "create-project",
    "reason-required"
);
case!(
    create_project_unknown_field,
    "create-project",
    "unknown-field"
);
case!(create_run_unknown_field, "create-run", "unknown-field");
case!(transition_unknown_field, "transition", "unknown-field");
case!(attestation_unknown_field, "attestation", "unknown-field");
case!(decision_unknown_field, "decision", "unknown-field");
case!(resolve_unknown_field, "resolve", "unknown-field");
case!(delete_unknown_field, "delete", "unknown-field");
case!(create_project_group_scope, "create-project", "group-scope");
case!(
    transition_generation_clash,
    "transition",
    "generation-clash"
);
case!(
    create_project_locale_invalid,
    "create-project",
    "locale-invalid"
);

case!(bundle_success, "bundle", "success");
case!(bundle_foreign, "bundle", "foreign");
case!(bundle_invalid, "bundle", "invalid");
case!(bundle_denied, "bundle", "denied");
case!(bundle_repeat, "bundle", "repeat");
case!(bundle_weak_aal, "bundle", "weak-aal");
case!(bundle_stale_aal, "bundle", "stale-aal");
case!(bundle_empty, "bundle", "empty");
case!(bundle_bad_generation, "bundle", "bad-generation");
case!(bundle_bad_sha, "bundle", "bad-sha");
case!(bundle_stale_generation, "bundle", "stale-generation");
case!(bundle_bad_state, "bundle", "bad-state");
case!(bundle_put_denied, "bundle", "put-denied");
case!(bundle_smx, "bundle", "smx");
case!(bundle_hybrid, "bundle", "hybrid");
case!(bundle_status_mutant, "bundle", "status-mutant");

case!(publish_success, "publish", "success");
case!(publish_foreign, "publish", "foreign");
case!(publish_invalid, "publish", "invalid");
case!(publish_denied, "publish", "denied");
case!(publish_repeat, "publish", "repeat");
case!(publish_weak_aal, "publish", "weak-aal");
case!(publish_stale_aal, "publish", "stale-aal");
case!(publish_unknown_field, "publish", "unknown-field");
case!(publish_bad_state, "publish", "bad-state");
case!(publish_missing_snapshot, "publish", "missing-snapshot");
case!(publish_stale_cell, "publish", "stale-cell");
case!(publish_unassessed, "publish", "unassessed");
case!(publish_put_denied, "publish", "put-denied");
case!(publish_smx, "publish", "smx");
case!(publish_hybrid, "publish", "hybrid");
case!(publish_status_mutant, "publish", "status-mutant");
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn worker_project() -> Result<(), common::BoxError> {
    exchange_oracle::worker::run("project").await
}
case!(registry_head, "registry", "head");
case!(projects_head, "projects", "head");
case!(runs_head, "runs", "head");
case!(audit_head, "audit", "head");
case!(
    create_project_malformed_body,
    "create-project",
    "malformed-body"
);
case!(create_project_empty_body, "create-project", "empty-body");
case!(create_project_type_error, "create-project", "type-error");
case!(create_project_extra_body, "create-project", "extra-body");

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn worker_artifact() -> Result<(), common::BoxError> {
    exchange_oracle::worker::run("artifact").await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn worker_run() -> Result<(), common::BoxError> {
    exchange_oracle::worker::run("run").await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn worker_empty() -> Result<(), common::BoxError> {
    exchange_oracle::worker::run("empty").await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn worker_feature_off() -> Result<(), common::BoxError> {
    exchange_oracle::worker::run("feature-off").await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn worker_fail_delete() -> Result<(), common::BoxError> {
    exchange_oracle::worker::run("fail-delete").await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn worker_state_mutant() -> Result<(), common::BoxError> {
    exchange_oracle::worker::run("state-mutant").await
}

case!(create_project_top_array,"create-project","top-array");
case!(create_project_top_scalar,"create-project","top-scalar");
case!(create_run_wrong_version,"create-run","wrong-version");
