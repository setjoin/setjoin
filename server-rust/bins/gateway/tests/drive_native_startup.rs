//! Deployment key floor must be checked before the native signer serves.
use crate::common::boot::CommandBootExt;
mod common;
#[test]
fn weak_native_signing_secret_is_rejected_before_listening() {
    use std::os::unix::process::CommandExt;
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_setjoin-gateway"))
        .arg0("gofree-idlogin3-weak-drive-key")
        .env_clear()
        .env("GATEWAY_LISTEN", "127.0.0.1:0")
        .env("DB_DSN", std::env::var("DB_DSN").unwrap())
        .env(
            "AUTHSERVER_JWKS_URL",
            "http://127.0.0.1:1/.well-known/jwks.json",
        )
        .env("JWT_SECRET", "weak")
        .output_boot()
        .unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(
        stderr.contains("JWT_SECRET must be at least 32 characters"),
        "{stderr}"
    );
}
