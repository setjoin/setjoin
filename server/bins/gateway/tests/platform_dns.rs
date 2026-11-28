//! F08 slice `terms-remaining`, group `dns`: record generation and DNS verification against a
//! fake zone server, replayed without a Go upstream.
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

case!(records_success, "dns-records", "success");
case!(records_denied, "dns-records", "denied");
case!(records_scoped_other, "dns-records", "scoped-other");
case!(records_scoped_own, "dns-records", "scoped-own");
case!(records_no_selector, "dns-records", "no-selector");
case!(records_multi_selector, "dns-records", "multi-selector");
case!(records_missing_domain, "dns-records", "missing-domain");
case!(records_empty_domain, "dns-records", "empty-domain");
case!(records_blank_domain, "dns-records", "blank-domain");
case!(records_padded_domain, "dns-records", "padded-domain");
case!(records_uppercase_domain, "dns-records", "uppercase-domain");
case!(records_escaped_domain, "dns-records", "escaped-domain");
case!(records_repeated_domain, "dns-records", "repeated-domain");
case!(records_gateway_host, "dns-records", "gateway-host");
case!(
    records_gateway_host_empty,
    "dns-records",
    "gateway-host-empty"
);
case!(
    records_gateway_host_plain,
    "dns-records",
    "gateway-host-plain"
);

case!(verify_success, "dns-verify", "success");
case!(verify_denied, "dns-verify", "denied");
case!(verify_scoped_other, "dns-verify", "scoped-other");
case!(verify_scoped_own, "dns-verify", "scoped-own");
case!(verify_no_selector, "dns-verify", "no-selector");
case!(verify_multi_selector, "dns-verify", "multi-selector");
case!(verify_missing_domain, "dns-verify", "missing-domain");
case!(verify_empty_domain, "dns-verify", "empty-domain");
case!(verify_blank_domain, "dns-verify", "blank-domain");
case!(verify_padded_domain, "dns-verify", "padded-domain");
case!(verify_uppercase_domain, "dns-verify", "uppercase-domain");
case!(verify_escaped_domain, "dns-verify", "escaped-domain");
case!(verify_repeated_domain, "dns-verify", "repeated-domain");
case!(verify_gateway_host, "dns-verify", "gateway-host");
case!(
    verify_gateway_host_empty,
    "dns-verify",
    "gateway-host-empty"
);
case!(
    verify_gateway_host_plain,
    "dns-verify",
    "gateway-host-plain"
);
case!(verify_mx_only, "dns-verify", "mx-only");
case!(verify_nxdomain, "dns-verify", "nxdomain");
case!(verify_nodata, "dns-verify", "nodata");
case!(verify_servfail, "dns-verify", "servfail");
case!(verify_weak_records, "dns-verify", "weak-records");
case!(verify_mx_order, "dns-verify", "mx-order");
case!(verify_dkim_missing, "dns-verify", "dkim-missing");
case!(verify_invalid_name, "dns-verify", "invalid-name");
case!(verify_underscore_name, "dns-verify", "underscore-name");
case!(verify_numeric_name, "dns-verify", "numeric-name");
case!(verify_long_label, "dns-verify", "long-label");

case!(
    records_status_mutant,
    "dns-records",
    "success-status-mutant"
);
case!(verify_status_mutant, "dns-verify", "success-status-mutant");
