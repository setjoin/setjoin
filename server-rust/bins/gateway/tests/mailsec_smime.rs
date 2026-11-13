//! F06 slice `smime`: frozen-Go oracle replayed without a Go upstream.
mod common;
mod mailsec_oracle;
macro_rules! case {
    ($name:ident, $action:literal, $kind:literal) => {
        #[tokio::test]
        async fn $name() -> Result<(), common::BoxError> {
            mailsec_oracle::run("smime", $action, $kind, None).await
        }
    };
}
macro_rules! fault {
    ($name:ident, $action:literal, $kind:literal, $fault:literal) => {
        #[tokio::test]
        async fn $name() -> Result<(), common::BoxError> {
            mailsec_oracle::run("smime", $action, $kind, Some($fault)).await
        }
    };
}

case!(list_success, "list", "success");
case!(list_empty, "list", "empty");
case!(list_denied, "list", "denied");
case!(list_scoped, "list", "scoped");
case!(list_null_bounds, "list", "null-bounds");
case!(list_html, "list", "html");
case!(list_ignored_query, "list", "ignored-query");
case!(list_status_mutant, "list", "success-status-mutant");

case!(import_success, "import", "success");
case!(import_success_no_label, "import", "success-no-label");
case!(import_success_label_trim, "import", "success-label-trim");
case!(import_blank_label, "import", "blank-label");
case!(import_label_in_query, "import", "label-in-query");
case!(import_label_first_wins, "import", "label-first-wins");
case!(import_label_html, "import", "label-html");
case!(import_cn_last, "import", "cn-last");
case!(import_no_cn, "import", "no-cn");
case!(import_future, "import", "future");
case!(import_bundle, "import", "bundle");
case!(import_bundle_expired_last, "import", "bundle-expired-last");
case!(import_expired, "import", "expired");
case!(import_expired_first, "import", "expired-first");
case!(import_existing, "import", "existing");
case!(import_scoped_existing, "import", "scoped-existing");
case!(import_not_multipart, "import", "not-multipart");
case!(import_no_boundary, "import", "no-boundary");
case!(import_empty_body, "import", "empty-body");
case!(import_missing_cert, "import", "missing-cert");
case!(import_cert_not_file, "import", "cert-not-file");
case!(import_empty_file_name, "import", "empty-file-name");
case!(import_empty_cert, "import", "empty-cert");
case!(import_garbage, "import", "garbage");
case!(import_key_block, "import", "key-block");
case!(import_trailing_junk, "import", "trailing-junk");
case!(import_trailing_space, "import", "trailing-space");
case!(import_leading_junk, "import", "leading-junk");
case!(import_crlf, "import", "crlf");
case!(import_no_final_newline, "import", "no-final-newline");
case!(import_pem_headers, "import", "pem-headers");
case!(import_bad_base64, "import", "bad-base64");
case!(import_trailing_der, "import", "trailing-der");
case!(import_other_block_type, "import", "other-block-type");
case!(import_too_large, "import", "too-large");
case!(import_bad_query, "import", "bad-query");
case!(import_semicolon_query, "import", "semicolon-query");
case!(import_denied, "import", "denied");
case!(import_scoped, "import", "scoped");
case!(import_repeat, "import", "repeat");
case!(import_status_mutant, "import", "success-status-mutant");

case!(delete_success, "delete", "success");
case!(
    delete_global_deletes_scoped,
    "delete",
    "global-deletes-scoped"
);
case!(delete_other_domain, "delete", "other-domain");
case!(delete_scoped_own, "delete", "scoped-own");
case!(delete_scoped_global_row, "delete", "scoped-global-row");
case!(delete_scoped_foreign, "delete", "scoped-foreign");
case!(delete_not_found, "delete", "not-found");
case!(delete_bad_id, "delete", "bad-id");
case!(delete_overflow_id, "delete", "overflow-id");
case!(delete_negative_id, "delete", "negative-id");
case!(delete_plus_id, "delete", "plus-id");
case!(delete_denied, "delete", "denied");
case!(delete_repeat, "delete", "repeat");
case!(delete_status_mutant, "delete", "success-status-mutant");

case!(cert_status_success, "cert-status", "success");
case!(cert_status_foreign, "cert-status", "foreign");
case!(cert_status_ignored_query, "cert-status", "ignored-query");
case!(
    cert_status_status_mutant,
    "cert-status",
    "success-status-mutant"
);

// Family mutants: each plants a real database fault the unchanged expectation must reject.
fault!(
    import_no_notify_fault,
    "import",
    "success",
    "no-smime-notify"
);
fault!(
    delete_no_notify_fault,
    "delete",
    "success",
    "no-smime-notify"
);
fault!(
    delete_no_scope_fault,
    "delete",
    "scoped-foreign",
    "no-delete-scope"
);

case!(import_duplicate_extension, "import", "duplicate-extension");

mod drain_oracle;
mod divfix;
#[tokio::test]
async fn cert_status_presented_valid() -> Result<(), common::BoxError> {
    divfix::status("valid").await
}

#[tokio::test]
async fn cert_status_expiry_states() -> Result<(), common::BoxError> {
    for case in ["expired", "expiring", "expires-today", "valid-31days", "future", "none"] {
        divfix::status(case).await?;
    }
    Ok(())
}

#[tokio::test]
async fn cert_status_from_the_actual_tls_peer() -> Result<(), common::BoxError> {
    divfix::tls_peer_status(false).await
}

#[tokio::test]
async fn import_strict_certificate_cases() -> Result<(), common::BoxError> {
    let mut errors = Vec::new();
    for c in mailsec_oracle::certificates::cases() {
        if let Err(error) = mailsec_oracle::run("smime", "import", &format!("strict-{}", c.name), None).await {
            errors.push(format!("{}: {error}", c.name));
        }
    }
    if !errors.is_empty() { return Err(errors.join("\n").into()); }
    Ok(())
}

#[tokio::test]
async fn cert_status_uses_configured_client_ca() -> Result<(), common::BoxError> {
    divfix::tls_peer_status(true).await
}

// Separately selectable when recording newly added boundary fixtures.
#[tokio::test]
async fn import_oid_boundary() -> Result<(), common::BoxError> {
    for name in ["oversized-oid-extension", "valid-long-oid", "valid-p224", "invalid-p224"] {
        mailsec_oracle::run("smime", "import", &format!("strict-{name}"), None).await?;
    }
    Ok(())
}

#[tokio::test]
async fn import_policy_oid() -> Result<(), common::BoxError> {
    for name in ["valid-wide-policy", "nonminimal-policy-oid"] {
        mailsec_oracle::run("smime", "import", &format!("strict-{name}"), None).await?;
    }
    Ok(())
}

#[tokio::test]
async fn cert_status_without_client_roots_remains_optional() -> Result<(), common::BoxError> {
    divfix::tls_without_client_roots().await
}
