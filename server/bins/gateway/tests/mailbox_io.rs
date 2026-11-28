//! F05 slice `mailboxes`, import and export, frozen-Go oracle replayed without a Go upstream.
mod common;
mod mailbox_io_oracle;
macro_rules! case {
    ($name:ident, $action:literal, $kind:literal) => {
        #[tokio::test]
        async fn $name() -> Result<(), common::BoxError> {
            mailbox_io_oracle::run($action, $kind).await
        }
    };
}
case!(import_success_eml, "import", "success-eml");
case!(import_success_mbox, "import", "success-mbox");
case!(import_success_zip, "import", "success-zip");
case!(import_repeat, "import", "repeat");
case!(import_cross_tenant, "import", "cross-tenant");
case!(import_invalid_id, "import", "invalid-id");
case!(import_zero_id, "import", "zero-id");
case!(import_missing, "import", "missing");
case!(import_denied, "import", "denied");
case!(import_wrong_perm, "import", "wrong-perm");
case!(import_shared, "import", "shared");
case!(import_global, "import", "global");
case!(import_bad_query, "import", "bad-query");
case!(import_folder_query, "import", "folder-query");
case!(import_folder, "import", "folder");
case!(import_folder_form, "import", "folder-form");
case!(import_folder_missing, "import", "folder-missing");
case!(import_folder_zero, "import", "folder-zero");
case!(import_zip_corrupt, "import", "zip-corrupt");
case!(import_zip_bad_entry, "import", "zip-bad-entry");
case!(import_zip_empty, "import", "zip-empty");
case!(import_zip_odd_name, "import", "zip-odd-name");
case!(import_charsets, "import", "charsets");
case!(import_headers, "import", "headers");
case!(import_headers_odd, "import", "headers-odd");
case!(import_lf_eml, "import", "lf-eml");
case!(import_nul_body, "import", "nul-body");
case!(import_invalid_utf8, "import", "invalid-utf8");
case!(import_empty_eml, "import", "empty-eml");
case!(import_mbox_empty, "import", "mbox-empty");
case!(import_mbox_no_separator, "import", "mbox-no-separator");
case!(import_mbox_short_from, "import", "mbox-short-from");
case!(import_unsupported, "import", "unsupported");
case!(import_trailing_slash_name, "import", "trailing-slash-name");
case!(import_no_file, "import", "no-file");
case!(import_file_without_name, "import", "file-without-name");
case!(import_bad_multipart, "import", "bad-multipart");
case!(import_status_mutant, "import", "success-eml-status-mutant");
case!(export_success_eml, "export", "success-eml");
case!(export_success_zip, "export", "success-zip");
case!(export_success_mbox, "export", "success-mbox");
case!(export_unknown_format, "export", "unknown-format");
case!(export_folder, "export", "folder");
case!(export_mbox_folder, "export", "mbox-folder");
case!(export_folder_missing, "export", "folder-missing");
case!(export_empty_mbox, "export", "empty-mbox");
case!(export_empty_zip, "export", "empty-zip");
case!(export_missing_object, "export", "missing-object");
case!(export_missing_object_mbox, "export", "missing-object-mbox");
case!(export_long_id, "export", "long-id");
case!(export_large, "export", "large");
case!(export_shared, "export", "shared");
case!(export_global, "export", "global");
case!(export_cross_tenant, "export", "cross-tenant");
case!(export_invalid_id, "export", "invalid-id");
case!(export_zero_id, "export", "zero-id");
case!(export_missing, "export", "missing");
case!(export_denied, "export", "denied");
case!(export_wrong_perm, "export", "wrong-perm");
case!(export_status_mutant, "export", "success-zip-status-mutant");
