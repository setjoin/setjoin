//! F06 slice `tls`: frozen-Go oracle replayed without a Go upstream.
mod common;
mod mailsec_oracle;
macro_rules! case {
    ($name:ident, $action:literal, $kind:literal) => {
        #[tokio::test]
        async fn $name() -> Result<(), common::BoxError> {
            mailsec_oracle::run("tls", $action, $kind, None).await
        }
    };
}
macro_rules! fault {
    ($name:ident, $action:literal, $kind:literal, $fault:literal) => {
        #[tokio::test]
        async fn $name() -> Result<(), common::BoxError> {
            mailsec_oracle::run("tls", $action, $kind, Some($fault)).await
        }
    };
}

case!(status_success, "status", "success");
case!(status_denied, "status", "denied");
case!(status_scoped, "status", "scoped");
case!(status_enabled_nocert, "status", "enabled-nocert");
case!(status_enabled_cert, "status", "enabled-cert");
case!(status_cert_garbage, "status", "cert-garbage");
case!(status_cert_wrong_block, "status", "cert-wrong-block");
case!(status_cert_after_junk, "status", "cert-after-junk");
case!(status_no_cache_dir, "status", "no-cache-dir");
case!(status_challenge_only, "status", "challenge-only");
case!(status_typed_values, "status", "typed-values");
case!(status_ignored_query, "status", "ignored-query");
case!(status_status_mutant, "status", "success-status-mutant");

case!(config_get_success, "config-get", "success");
case!(config_get_empty, "config-get", "empty");
case!(config_get_denied, "config-get", "denied");
case!(config_get_scoped, "config-get", "scoped");
case!(config_get_ignored_query, "config-get", "ignored-query");
case!(
    config_get_status_mutant,
    "config-get",
    "success-status-mutant"
);

case!(config_put_success, "config-put", "success");
case!(config_put_overwrite, "config-put", "overwrite");
case!(config_put_secret, "config-put", "secret");
case!(
    config_put_sentinel_preserve,
    "config-put",
    "sentinel-preserve"
);
case!(config_put_sentinel_mixed, "config-put", "sentinel-mixed");
case!(config_put_sentinel_absent, "config-put", "sentinel-absent");
case!(config_put_non_tls_only, "config-put", "non-tls-only");
case!(config_put_null_body, "config-put", "null-body");
case!(config_put_empty_object, "config-put", "empty-object");
case!(config_put_invalid_json, "config-put", "invalid-json");
case!(config_put_array_body, "config-put", "array-body");
case!(config_put_string_body, "config-put", "string-body");
case!(config_put_number_body, "config-put", "number-body");
case!(config_put_invalid_number, "config-put", "invalid-number");
case!(config_put_trailing, "config-put", "trailing");
case!(config_put_duplicate_keys, "config-put", "duplicate-keys");
case!(config_put_escape, "config-put", "escape");
case!(config_put_denied, "config-put", "denied");
case!(config_put_scoped, "config-put", "scoped");
case!(config_put_repeat, "config-put", "repeat");
case!(
    config_put_status_mutant,
    "config-put",
    "success-status-mutant"
);

case!(import_cert_success, "import-cert", "success");
case!(import_cert_existing, "import-cert", "existing");
case!(import_cert_missing_cert, "import-cert", "missing-cert");
case!(import_cert_missing_key, "import-cert", "missing-key");
case!(import_cert_not_multipart, "import-cert", "not-multipart");
case!(import_cert_no_boundary, "import-cert", "no-boundary");
case!(import_cert_no_filename, "import-cert", "no-filename");
case!(import_cert_swapped, "import-cert", "swapped");
case!(import_cert_duplicate_cert, "import-cert", "duplicate-cert");
case!(import_cert_too_large, "import-cert", "too-large");
case!(import_cert_empty_files, "import-cert", "empty-files");
case!(import_cert_dir_blocked, "import-cert", "dir-blocked");
case!(import_cert_key_blocked, "import-cert", "key-blocked");
case!(import_cert_denied, "import-cert", "denied");
case!(import_cert_scoped, "import-cert", "scoped");
case!(import_cert_repeat, "import-cert", "repeat");
case!(
    import_cert_status_mutant,
    "import-cert",
    "success-status-mutant"
);

case!(policy_get_success, "policy-get", "success");
case!(policy_get_set, "policy-get", "set");
case!(policy_get_bad_types, "policy-get", "bad-types");
case!(policy_get_null_values, "policy-get", "null-values");
case!(policy_get_empty_mode, "policy-get", "empty-mode");
case!(policy_get_html, "policy-get", "html");
case!(policy_get_partial, "policy-get", "partial");
case!(policy_get_denied, "policy-get", "denied");
case!(policy_get_scoped, "policy-get", "scoped");
case!(policy_get_ignored_query, "policy-get", "ignored-query");
case!(
    policy_get_status_mutant,
    "policy-get",
    "success-status-mutant"
);

case!(policy_put_success, "policy-put", "success");
case!(policy_put_overwrite, "policy-put", "overwrite");
case!(policy_put_opportunistic, "policy-put", "opportunistic");
case!(policy_put_html_escape, "policy-put", "html-escape");
case!(policy_put_invalid_json, "policy-put", "invalid-json");
case!(policy_put_trailing, "policy-put", "trailing");
case!(policy_put_array_body, "policy-put", "array-body");
case!(policy_put_missing_enforce, "policy-put", "missing-enforce");
case!(policy_put_null_enforce, "policy-put", "null-enforce");
case!(policy_put_missing_skip, "policy-put", "missing-skip");
case!(policy_put_missing_mode, "policy-put", "missing-mode");
case!(policy_put_bad_mode, "policy-put", "bad-mode");
case!(policy_put_bad_mode_quote, "policy-put", "bad-mode-quote");
case!(
    policy_put_enforce_wrong_type,
    "policy-put",
    "enforce-wrong-type"
);
case!(policy_put_mode_number, "policy-put", "mode-number");
case!(policy_put_key_case, "policy-put", "key-case");
case!(policy_put_null_elements, "policy-put", "null-elements");
case!(policy_put_null_mode, "policy-put", "null-mode");
case!(policy_put_denied, "policy-put", "denied");
case!(policy_put_scoped, "policy-put", "scoped");
case!(policy_put_repeat, "policy-put", "repeat");
case!(
    policy_put_status_mutant,
    "policy-put",
    "success-status-mutant"
);

// Family mutants: each plants a real database fault the unchanged expectation must reject.
fault!(
    config_put_no_audit_fault,
    "config-put",
    "success",
    "no-audit"
);
fault!(
    import_cert_no_audit_fault,
    "import-cert",
    "success",
    "no-audit"
);
fault!(
    policy_put_no_notify_fault,
    "policy-put",
    "success",
    "no-policy-notify"
);

#[tokio::test]
async fn status_strict_certificate_cases() -> Result<(), common::BoxError> {
    let mut errors = Vec::new();
    for c in mailsec_oracle::certificates::cases() {
        if let Err(error) = mailsec_oracle::run("tls", "status", &format!("cert-strict-{}", c.name), None).await {
            errors.push(format!("{}: {error}", c.name));
        }
    }
    if !errors.is_empty() { return Err(errors.join("\n").into()); }
    Ok(())
}

// Separately selectable when recording newly added boundary fixtures.
#[tokio::test]
async fn status_oid_boundary() -> Result<(), common::BoxError> {
    for name in ["oversized-oid-extension", "valid-long-oid", "valid-p224", "invalid-p224"] {
        mailsec_oracle::run("tls", "status", &format!("cert-strict-{name}"), None).await?;
    }
    Ok(())
}

#[tokio::test]
async fn status_policy_oid() -> Result<(), common::BoxError> {
    for name in ["valid-wide-policy", "nonminimal-policy-oid"] {
        mailsec_oracle::run("tls", "status", &format!("cert-strict-{name}"), None).await?;
    }
    Ok(())
}
