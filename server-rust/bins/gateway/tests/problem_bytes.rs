//! #364: the byte-level problem+json check rejects what Go never writes and
//! accepts what it does (the 413 title pin is in the lib unit tests too).
mod common;
use common::problem_bytes::assert_go_problem_bytes;

#[test]
fn go_shaped_problem_passes() {
    assert_go_problem_bytes(
        b"{\"type\":\"about:blank\",\"title\":\"Request Entity Too Large\",\"status\":413,\"detail\":\"d\",\"instance\":\"/x\"}\n",
    );
    assert_go_problem_bytes(
        b"{\"type\":\"https://setjoin.com/problems/reducer/bz192\",\"title\":\"Conflict\",\"status\":409,\"detail\":\"d\",\"instance\":\"/x\",\"remediation\":\"r\",\"code\":\"BZ192\",\"retryable\":false,\"holderId\":3}\n",
    );
}

#[test]
#[should_panic(expected = "out of Go order")]
fn alphabetical_keys_fail() {
    assert_go_problem_bytes(
        b"{\"code\":\"BZ1\",\"detail\":\"d\",\"instance\":\"/x\",\"status\":409,\"title\":\"Conflict\",\"type\":\"t\"}\n",
    );
}

#[test]
#[should_panic(expected = "out of Go order")]
fn code_before_remediation_fails() {
    assert_go_problem_bytes(
        b"{\"type\":\"t\",\"title\":\"Conflict\",\"status\":409,\"detail\":\"d\",\"instance\":\"/x\",\"code\":\"BZ1\",\"remediation\":\"r\"}\n",
    );
}

#[test]
#[should_panic(expected = "http.StatusText(413)")]
fn hyper_413_title_fails() {
    assert_go_problem_bytes(
        b"{\"type\":\"about:blank\",\"title\":\"Payload Too Large\",\"status\":413,\"detail\":\"d\",\"instance\":\"\"}\n",
    );
}

#[test]
#[should_panic(expected = "newline")]
fn missing_newline_fails() {
    assert_go_problem_bytes(
        b"{\"type\":\"about:blank\",\"title\":\"Bad Request\",\"status\":400,\"detail\":\"d\",\"instance\":\"\"}",
    );
}
