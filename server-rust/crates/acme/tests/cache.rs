//! Cache and account-key containers match frozen Go byte-for-byte in layout.
use setjoin_acme::{cache::DirCache, Config, Http01Store, Manager};
use std::os::unix::fs::PermissionsExt;

fn dir(name: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!("gofree-plat7-cache-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    d
}

#[test]
fn blobs_live_at_the_sha256_of_the_domain_with_go_permissions() {
    let d = dir("layout");
    let cache = DirCache::new(&d);
    cache.put("example.com", b"blob").unwrap();
    // sha256("example.com")
    assert_eq!(
        cache.path("example.com").file_name().unwrap(),
        "a379a6f6eeafb9a55e378c118034e2751e682fab9f2d30ab13d2125586ce1947"
    );
    assert_eq!(std::fs::read(cache.path("example.com")).unwrap(), b"blob");
    assert_eq!(
        std::fs::metadata(cache.path("example.com"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    assert_eq!(
        std::fs::metadata(&d).unwrap().permissions().mode() & 0o777,
        0o700
    );
    assert_eq!(
        std::fs::read_dir(&d).unwrap().count(),
        1,
        "no temp file is left behind"
    );
}

#[test]
fn the_account_key_is_created_once_as_sec1_pem_and_reused() {
    let d = dir("account");
    let config = Config {
        domains: vec!["a.example".into()],
        email: "ops@example.test".into(),
        cache_dir: d.clone(),
        key_file: None,
        ca_dir_url: None,
        ca_root: None,
        backoff: None,
    };
    Manager::new(config.clone(), Http01Store::default()).unwrap();
    let path = d.join("account.key");
    let first = std::fs::read_to_string(&path).unwrap();
    assert!(
        first.starts_with("-----BEGIN EC PRIVATE KEY-----\n")
            && first.ends_with("-----END EC PRIVATE KEY-----\n")
    );
    assert!(!first.contains('\r'));
    assert_eq!(
        std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o600
    );
    Manager::new(config, Http01Store::default()).unwrap();
    assert_eq!(std::fs::read_to_string(&path).unwrap(), first);
}

#[test]
fn construction_failures_match_go() {
    let base = Config {
        domains: vec!["a.example".into()],
        email: "ops@example.test".into(),
        cache_dir: dir("errors"),
        key_file: None,
        ca_dir_url: None,
        ca_root: None,
        backoff: None,
    };
    let err = |f: &dyn Fn(&mut Config)| {
        let mut c = base.clone();
        f(&mut c);
        Manager::new(c, Http01Store::default()).err().unwrap()
    };
    assert_eq!(
        err(&|c| c.domains.clear()),
        "acme/dns01: at least one domain is required"
    );
    assert_eq!(err(&|c| c.email.clear()), "acme/dns01: email is required");
    assert_eq!(
        err(&|c| c.cache_dir = "".into()),
        "acme/dns01: cache dir is required"
    );
    assert_eq!(
        err(&|c| c.domains = vec!["*.example".into()]),
        "acme/dns01: wildcard domain \"*.example\" requires the dns-01 challenge (configured: http-01)"
    );
}

#[test]
fn the_token_store_answers_only_pending_challenge_paths() {
    let store = Http01Store::default();
    store.present("tok", "tok.thumb");
    assert_eq!(
        store.answer("/.well-known/acme-challenge/tok").as_deref(),
        Some("tok.thumb")
    );
    assert_eq!(store.answer("/.well-known/acme-challenge/other"), None);
    assert_eq!(store.answer("/index.html"), None);
    store.clean_up("tok");
    assert_eq!(store.answer("/.well-known/acme-challenge/tok"), None);
}
