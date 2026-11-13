//! Deployment configuration is a public seam; child processes isolate env state.
use std::os::unix::process::CommandExt;
use std::process::Command;
fn child(test: &str) -> Command {
    let mut command = Command::new(std::env::current_exe().unwrap());
    command
        .arg0(format!("{}-config-probe", std::env::var("GOFREE_RESOURCE_PREFIX").unwrap_or_else(|_| "gofree-idlogin1".into())))
        .args(["--exact", test, "--nocapture"])
        .env_remove("SETJOIN_CONFIG")
        .env("CRYPTO_ALGORITHM_PROFILE", "standard")
        .env("JWT_SECRET", "idlogin1-fixture-secret-at-least-32-bytes")
        .env("DB_DSN", std::env::var("TEST_DB_DSN").unwrap())
        .env("LISTEN_ADDR", "127.0.0.1:0")
        .env("IDLOGIN1_CONFIG_PROBE", "1");
    command
}
#[test]
fn go_boolean_spellings_preserve_enabled_security_controls() {
    if std::env::var_os("IDLOGIN1_CONFIG_PROBE").is_some() {
        let cfg = setjoin_auth::Config::from_env().unwrap();
        assert_eq!(cfg.threat_controls, [true; 5]);
        assert!(
            !cfg.cookie_secure,
            "Go does not read COOKIE_SECURE; TLS configuration supplies the default"
        );
        assert!(cfg.trust_proxy);
        return;
    }
    let out = child("go_boolean_spellings_preserve_enabled_security_controls")
        .env("THREAT_FEED_ENABLED", "TRUE")
        .env("GEO_BLOCK_ENABLED", "1")
        .env("SPRAY_DETECT_ENABLED", "True")
        .env("CAPTCHA_ENABLED", "t")
        .env("TARPIT_ENABLED", "T")
        .env("COOKIE_SECURE", "True")
        .env("AUTH_TRUST_PROXY", "1")
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}
#[test]
fn smx_profile_keeps_go_s_sixteen_byte_secret_floor() {
    if std::env::var_os("IDLOGIN1_CONFIG_PROBE").is_some() {
        let cfg = setjoin_auth::Config::from_env().unwrap();
        assert!(cfg.sm2_pem.is_some());
        std::env::remove_var("SM2_PRIVATE_KEY_FILE");
        assert!(setjoin_auth::Config::from_env().is_err());
        return;
    }
    let fixture: serde_json::Value = serde_json::from_str(include_str!(
        "../../../tests/conformance/identity-login/keys.json"
    ))
    .unwrap();
    let path =
        std::env::temp_dir().join(format!("gofree-idlogin1-config-{}.pem", std::process::id()));
    std::fs::write(&path, fixture["sm2_pem"].as_str().unwrap()).unwrap();
    let out = child("smx_profile_keeps_go_s_sixteen_byte_secret_floor")
        .env("CRYPTO_ALGORITHM_PROFILE", "smx")
        .env("JWT_SECRET", "at-least-16-chars")
        .env("SM2_PRIVATE_KEY_FILE", &path)
        .output();
    std::fs::remove_file(path).unwrap();
    let out = out.unwrap();
    assert!(
        out.status.success(),
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn webauthn_relying_party_environment_overrides_yaml() {
    if std::env::var_os("IDLOGIN1_CONFIG_PROBE").is_some() {
        let cfg=setjoin_auth::Config::from_env().unwrap();
        assert_eq!(cfg.webauthn_rp_id,"env.example.test");
        assert_eq!(cfg.webauthn_rp_name,"Environment RP");
        assert_eq!(cfg.webauthn_rp_origin,"https://env.example.test");
        return;
    }
    let path=std::env::temp_dir().join(format!("gofree-idmfa2-config-{}.yaml",std::process::id()));
    std::fs::write(&path,"webauthn:\n  rp_id: yaml.example.test\n  rp_name: YAML RP\n  rp_origin: https://yaml.example.test\n").unwrap();
    let out=child("webauthn_relying_party_environment_overrides_yaml").env("SETJOIN_CONFIG",&path)
        .env("WEBAUTHN_RP_ID","env.example.test").env("WEBAUTHN_RP_NAME","Environment RP")
        .env("WEBAUTHN_RP_ORIGIN","https://env.example.test").output();
    std::fs::remove_file(path).unwrap();let out=out.unwrap();
    assert!(out.status.success(),"{}{}",String::from_utf8_lossy(&out.stdout),String::from_utf8_lossy(&out.stderr));
}

#[test]
fn auth_url_without_port_keeps_go_auth_listener_port_for_process_swap(){
 if std::env::var_os("IDLOGIN1_CONFIG_PROBE").is_some(){
  assert_eq!(setjoin_auth::Config::from_env().unwrap().listen,"127.0.0.1:8443");return;
 }
 for url in ["http://127.0.0.1","https://127.0.0.1"]{
  let out=child("auth_url_without_port_keeps_go_auth_listener_port_for_process_swap").env_remove("LISTEN_ADDR").env("AUTHSERVER_URL",url).output().unwrap();
  assert!(out.status.success(),"{url}: {}{}",String::from_utf8_lossy(&out.stdout),String::from_utf8_lossy(&out.stderr));
 }
}

#[test]
fn rp_boot_and_mapping_settings_are_independent_of_op() {
    if std::env::var_os("IDLOGIN1_CONFIG_PROBE").is_some() {
        let cfg=setjoin_auth::Config::from_env().unwrap();
        assert!(cfg.oidc_rp_enabled);
        assert!(!cfg.oidc_enabled);
        assert!(cfg.jit_enabled);
        assert!(cfg.sso_allow_super_admin_mapping);
        return;
    }
    let out=child("rp_boot_and_mapping_settings_are_independent_of_op")
        .env("OIDC_ENABLED","TRUE").env("OIDC_PROVIDER_ENABLED","false")
        .env("JIT_ENABLED","1").env("SSO_ALLOW_SUPER_ADMIN_MAPPING","t").output().unwrap();
    assert!(out.status.success(),"{}{}",String::from_utf8_lossy(&out.stdout),String::from_utf8_lossy(&out.stderr));
}
