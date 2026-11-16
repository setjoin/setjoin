//! Throwaway pre-check canary (#428 proof). Never merge.
#[test]
fn precheck_canary_fails() {
    assert_eq!(1, 2, "pre-check integration canary");
}
