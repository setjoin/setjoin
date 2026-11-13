//! F17 slice `contacts` frozen-Go oracle, replayed without a Go upstream.
mod common;
mod contacts_oracle;

macro_rules! case {
    ($name:ident, $route:literal, $label:literal) => {
        #[tokio::test]
        async fn $name() -> Result<(), common::BoxError> {
            contacts_oracle::run($route, $label, false).await
        }
    };
}
macro_rules! mutant {
    ($name:ident, $route:literal) => {
        #[tokio::test]
        async fn $name() -> Result<(), common::BoxError> {
            contacts_oracle::run($route, "success", true).await
        }
    };
}

case!(preview_success, "csv-preview", "success");
case!(preview_cross_tenant, "csv-preview", "cross-tenant");
case!(preview_invalid_input, "csv-preview", "invalid-input");
case!(preview_missing_file, "csv-preview", "missing-file");
case!(preview_empty, "csv-preview", "empty");
case!(preview_bad_header, "csv-preview", "bad-header");
case!(preview_bad_row, "csv-preview", "bad-row");
case!(preview_header_only, "csv-preview", "header-only");
case!(preview_bad_query, "csv-preview", "bad-query");
case!(preview_wrong_method, "csv-preview", "wrong-method");

case!(import_csv_success, "csv-import", "success");
case!(import_csv_repeat, "csv-import", "repeat");
case!(import_csv_cross_tenant, "csv-import", "cross-tenant");
case!(import_csv_invalid_input, "csv-import", "invalid-input");
case!(import_csv_missing_file, "csv-import", "missing-file");
case!(import_csv_bad_book, "csv-import", "bad-book");
case!(import_csv_no_book, "csv-import", "no-book");
case!(import_csv_unknown_book, "csv-import", "unknown-book");
case!(import_csv_bad_dialect, "csv-import", "bad-dialect");
case!(import_csv_bad_mapping, "csv-import", "bad-mapping");
case!(import_csv_mapping, "csv-import", "mapping");
case!(import_csv_skip, "csv-import", "skip");
case!(import_csv_overwrite, "csv-import", "overwrite");
case!(import_csv_setjoin_dialect, "csv-import", "setjoin-dialect");
case!(import_csv_parse_error, "csv-import", "parse-error");
case!(import_csv_empty, "csv-import", "empty");
case!(import_csv_blank_email, "csv-import", "blank-email");
case!(import_csv_no_email_column, "csv-import", "no-email-column");
case!(import_csv_query_wins, "csv-import", "query-wins");
case!(import_csv_nul_cell, "csv-import", "nul-cell");

case!(import_vcf_success, "vcf-import", "success");
case!(import_vcf_repeat, "vcf-import", "repeat");
case!(import_vcf_cross_tenant, "vcf-import", "cross-tenant");
case!(import_vcf_invalid_input, "vcf-import", "invalid-input");
case!(import_vcf_missing_uid, "vcf-import", "missing-uid");
case!(import_vcf_rename, "vcf-import", "rename");
case!(import_vcf_overwrite, "vcf-import", "overwrite");
case!(import_vcf_skip, "vcf-import", "skip");
case!(import_vcf_dates, "vcf-import", "dates");
case!(import_vcf_bad_date, "vcf-import", "bad-date");

case!(export_csv_success, "csv-export", "success");
case!(export_csv_cross_tenant, "csv-export", "cross-tenant");
case!(export_csv_invalid_input, "csv-export", "invalid-input");
case!(export_csv_empty_book, "csv-export", "empty-book");
case!(export_csv_bad_json, "csv-export", "bad-json");
case!(export_csv_wrong_method, "csv-export", "wrong-method");

case!(export_vcf_success, "vcf-export", "success");
case!(export_vcf_cross_tenant, "vcf-export", "cross-tenant");
case!(export_vcf_invalid_input, "vcf-export", "invalid-input");
case!(export_vcf_contact, "vcf-export", "contact");
case!(export_vcf_contact_foreign, "vcf-export", "contact-foreign");
case!(export_vcf_contact_missing, "vcf-export", "contact-missing");
case!(export_vcf_bad_contact, "vcf-export", "bad-contact");
case!(export_vcf_bad_json, "vcf-export", "bad-json");
case!(export_vcf_long_line, "vcf-export", "long-line");

mutant!(preview_status_mutant, "csv-preview");
mutant!(import_csv_status_mutant, "csv-import");
mutant!(import_vcf_status_mutant, "vcf-import");
mutant!(export_csv_status_mutant, "csv-export");
mutant!(export_vcf_status_mutant, "vcf-export");
