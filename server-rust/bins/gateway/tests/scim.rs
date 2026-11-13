//! F02 SCIM (#375) frozen-Go oracle, replayed without a Go upstream.
mod common;
mod scim_oracle;
macro_rules! case {
    ($name:ident, $action:literal, $kind:literal) => {
        #[tokio::test]
        async fn $name() -> Result<(), common::BoxError> {
            scim_oracle::run($action, $kind).await
        }
    };
}
include!("scim_oracle/cases.rs");
