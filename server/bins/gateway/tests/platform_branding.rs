//! F08 slice `terms-remaining`, group `branding`: the brand name and logo, replayed without a
//! Go upstream and against a fake object store.
mod common;
mod platform_oracle;
macro_rules! case {
    ($name:ident, $action:literal, $kind:literal) => {
        #[tokio::test]
        async fn $name() -> Result<(), common::BoxError> {
            platform_oracle::terms::run($action, $kind, None).await
        }
    };
}

case!(get_success, "branding-get", "success");
case!(get_denied, "branding-get", "denied");
case!(get_scoped, "branding-get", "scoped");
case!(get_defaults, "branding-get", "defaults");
case!(get_name_only, "branding-get", "name-only");
case!(get_number_name, "branding-get", "number-name");
case!(get_null_name, "branding-get", "null-name");
case!(get_object_name, "branding-get", "object-name");
case!(get_ignored_query, "branding-get", "ignored-query");

case!(set_success, "branding-set", "success");
case!(set_denied, "branding-set", "denied");
case!(set_scoped, "branding-set", "scoped");
case!(set_repeat, "branding-set", "repeat");
case!(set_name_bare, "branding-set", "name-bare");
case!(set_name_number, "branding-set", "name-number");
case!(set_name_null, "branding-set", "name-null");
case!(set_name_empty, "branding-set", "name-empty");
case!(set_name_twice, "branding-set", "name-twice");
case!(set_name_in_query, "branding-set", "name-in-query");
case!(set_name_query_only, "branding-set", "name-query-only");
case!(set_name_unicode, "branding-set", "name-unicode");
case!(set_name_escaped, "branding-set", "name-escaped");
case!(set_name_overwrites, "branding-set", "name-overwrites");
case!(set_logo, "branding-set", "logo");
case!(set_logo_default_type, "branding-set", "logo-default-type");
case!(set_logo_and_name, "branding-set", "logo-and-name");
case!(set_logo_empty, "branding-set", "logo-empty");
case!(set_logo_twice, "branding-set", "logo-twice");
case!(set_logo_no_filename, "branding-set", "logo-no-filename");
case!(
    set_logo_empty_filename,
    "branding-set",
    "logo-empty-filename"
);
case!(set_other_file, "branding-set", "other-file");
case!(set_unnamed_part, "branding-set", "unnamed-part");
case!(set_empty_form, "branding-set", "empty-form");
case!(set_no_body, "branding-set", "no-body");
case!(set_bad_boundary_body, "branding-set", "bad-boundary-body");
case!(set_wrong_content_type, "branding-set", "wrong-content-type");
case!(set_urlencoded, "branding-set", "urlencoded");
case!(set_no_boundary, "branding-set", "no-boundary");
case!(set_truncated, "branding-set", "truncated");
case!(set_bad_query_escape, "branding-set", "bad-query-escape");
case!(set_semicolon_query, "branding-set", "semicolon-query");
case!(set_oversize, "branding-set", "oversize");
case!(set_just_under, "branding-set", "just-under");

case!(get_status_mutant, "branding-get", "success-status-mutant");
case!(set_status_mutant, "branding-set", "success-status-mutant");
