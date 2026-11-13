//! Scenario table for the #380 LDAP oracle: one entry per recorded case.
use setjoin_conformance::ldap_fake::Entry;

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Reach {
    Up,
    Down,
    BadPassword,
}

#[derive(Clone)]
pub struct Scenario {
    pub method: &'static str,
    /// Path below `/api`, query included.
    pub path: &'static str,
    pub body: &'static str,
    pub revoked: bool,
    /// `None` seeds no `ldap_sync_*` rows at all.
    pub configured: bool,
    pub enabled: &'static str,
    pub subject: &'static str,
    pub filter: &'static str,
    pub auto_depts: bool,
    pub sweep_hours: Option<&'static str>,
    pub cursor: Option<&'static str>,
    pub last_sweep: Option<&'static str>,
    pub reach: Reach,
    pub tls: &'static str,
    pub dir: Dir,
    pub seed: Seed,
    pub activate_source: bool,
    pub fail_search: bool,
    pub expect: u16,
    /// Worker-mode replay: run the Rust worker loop once instead of the request.
    pub worker_tick: bool,
    /// Send the request once before the observed one (mutator repeat floor).
    pub repeat: bool,
    /// Extra `system_config` rows seeded verbatim (key, JSON text, encrypted).
    pub extra: &'static [(&'static str, &'static str, bool)],
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Dir {
    Empty,
    Mixed,
    Page,
    Normalized,
    NormalizedDuplicate,
    NormalizedBlocked,
    Incremental,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Seed {
    None,
    Mixed,
    Sweep,
    Preview,
    Conflicts,
    LogError,
}

pub fn base() -> Scenario {
    Scenario {
        method: "GET",
        path: "/admin/ldap/health",
        body: "",
        revoked: false,
        configured: true,
        enabled: "true",
        subject: "",
        filter: "",
        auto_depts: false,
        sweep_hours: None,
        cursor: None,
        last_sweep: None,
        reach: Reach::Up,
        tls: "true",
        dir: Dir::Mixed,
        seed: Seed::None,
        activate_source: false,
        fail_search: false,
        expect: 200,
        worker_tick: false,
        repeat: false,
        extra: &[],
    }
}

/// (route, case) -> scenario; the golden is `ldap-<route>-<case>.json`.
pub fn scenario(route: &str, case: &str) -> Scenario {
    let b = base();
    match (route, case) {
        ("test", "success") => Scenario {
            method: "POST",
            path: "/admin/ldap/test-connection",
            ..b
        },
        ("test", "foreign") => Scenario {
            method: "POST",
            path: "/admin/ldap/test-connection",
            revoked: true,
            expect: 403,
            ..b
        },
        ("test", "invalid") => Scenario {
            method: "POST",
            path: "/admin/ldap/test-connection",
            configured: false,
            expect: 503,
            ..b
        },
        ("test", "bad-password") => Scenario {
            method: "POST",
            path: "/admin/ldap/test-connection",
            reach: Reach::BadPassword,
            expect: 500,
            ..b
        },
        ("test", "unreachable") => Scenario {
            method: "POST",
            path: "/admin/ldap/test-connection",
            reach: Reach::Down,
            expect: 500,
            ..b
        },
        ("test", "search-failure") => Scenario {
            method: "POST",
            path: "/admin/ldap/test-connection",
            fail_search: true,
            expect: 500,
            ..b
        },
        ("test", "starttls") => Scenario {
            method: "POST",
            path: "/admin/ldap/test-connection",
            tls: "false",
            ..b
        },
        ("preview", "success") => Scenario {
            path: "/admin/ldap/preview",
            seed: Seed::Preview,
            ..b
        },
        ("preview", "limit") => Scenario {
            path: "/admin/ldap/preview?limit=2",
            seed: Seed::Preview,
            ..b
        },
        ("preview", "foreign") => Scenario {
            path: "/admin/ldap/preview",
            revoked: true,
            expect: 403,
            ..b
        },
        ("preview", "invalid") => Scenario {
            path: "/admin/ldap/preview?limit=abc",
            ..b
        },
        ("preview", "unconfigured") => Scenario {
            path: "/admin/ldap/preview",
            configured: false,
            expect: 503,
            ..b
        },
        ("preview", "empty") => Scenario {
            path: "/admin/ldap/preview",
            dir: Dir::Empty,
            ..b
        },
        ("preview", "bad-password") => Scenario {
            path: "/admin/ldap/preview",
            reach: Reach::BadPassword,
            expect: 500,
            ..b
        },
        ("sync", "success") => Scenario {
            method: "POST",
            path: "/admin/ldap/sync",
            seed: Seed::Mixed,
            auto_depts: true,
            ..b
        },
        ("sync", "foreign") => Scenario {
            method: "POST",
            path: "/admin/ldap/sync",
            revoked: true,
            expect: 403,
            ..b
        },
        ("sync", "invalid") => Scenario {
            method: "POST",
            path: "/admin/ldap/sync",
            enabled: "false",
            expect: 503,
            ..b
        },
        ("sync", "repeat") => Scenario {
            method: "POST",
            path: "/admin/ldap/sync",
            seed: Seed::Mixed,
            auto_depts: true,
            repeat: true,
            ..b
        },
        ("sync", "unconfigured") => Scenario {
            method: "POST",
            path: "/admin/ldap/sync",
            configured: false,
            expect: 503,
            ..b
        },
        ("sync", "search-failure") => Scenario {
            method: "POST",
            path: "/admin/ldap/sync",
            fail_search: true,
            expect: 500,
            ..b
        },
        ("sync", "bad-password") => Scenario {
            method: "POST",
            path: "/admin/ldap/sync",
            reach: Reach::BadPassword,
            expect: 500,
            ..b
        },
        ("sync", "no-dept") => Scenario {
            method: "POST",
            path: "/admin/ldap/sync",
            seed: Seed::Mixed,
            ..b
        },
        ("sync", "incremental") => Scenario {
            method: "POST",
            path: "/admin/ldap/sync",
            seed: Seed::Mixed,
            dir: Dir::Incremental,
            cursor: Some("20260101000003Z"),
            sweep_hours: Some("0"),
            ..b
        },
        ("sync", "sweep-due") => Scenario {
            method: "POST",
            path: "/admin/ldap/sync",
            seed: Seed::Sweep,
            dir: Dir::Incremental,
            cursor: Some("20260101000003Z"),
            last_sweep: Some("2020-01-01T00:00:00Z"),
            ..b
        },
        ("sync", "sweep-fresh") => Scenario {
            method: "POST",
            path: "/admin/ldap/sync",
            seed: Seed::Sweep,
            dir: Dir::Incremental,
            cursor: Some("20260101000003Z"),
            last_sweep: Some("2999-01-01T00:00:00Z"),
            ..b
        },
        ("sync", "filtered") => Scenario {
            method: "POST",
            path: "/admin/ldap/sync",
            seed: Seed::Mixed,
            filter: "(&(objectClass=person)(!(cn=nobody)))",
            ..b
        },
        ("sync", "paged") => Scenario {
            method: "POST",
            path: "/admin/ldap/sync",
            dir: Dir::Page,
            ..b
        },
        ("sync", "normalized") => Scenario {
            method: "POST",
            path: "/admin/ldap/sync",
            dir: Dir::Normalized,
            subject: "entryUUID",
            activate_source: true,
            ..b
        },
        ("sync", "normalized-duplicate") => Scenario {
            method: "POST",
            path: "/admin/ldap/sync",
            dir: Dir::NormalizedDuplicate,
            subject: "entryUUID",
            activate_source: true,
            expect: 500,
            ..b
        },
        ("sync", "normalized-blocked") => Scenario {
            method: "POST",
            path: "/admin/ldap/sync",
            dir: Dir::NormalizedBlocked,
            subject: "entryUUID",
            activate_source: true,
            expect: 500,
            ..b
        },
        ("health", "success") => Scenario {
            seed: Seed::Conflicts,
            ..b
        },
        ("health", "foreign") => Scenario {
            revoked: true,
            expect: 403,
            ..b
        },
        ("health", "invalid") => Scenario {
            path: "/admin/ldap/health?x=%zz",
            configured: false,
            ..b
        },
        ("health", "error") => Scenario {
            seed: Seed::LogError,
            ..b
        },
        ("config", "put-success") => Scenario {
            method: "PUT",
            path: "/admin/ldap/config",
            body: r#"{"ldap_sync_host":"127.0.0.1","ldap_sync_port":"{port}","ldap_sync_tls":"true","ldap_sync_bind_dn":"cn=svc,dc=example,dc=test","ldap_sync_password_enc":"pw","ldap_sync_base_dn":"dc=example,dc=test","ldap_sync_enabled":"false","ldap_sync_user_filter":"(objectClass=inetOrgPerson)"}"#,
            configured: false,
            expect: 204,
            ..b
        },
        ("config", "put-repeat") => Scenario {
            method: "PUT",
            path: "/admin/ldap/config",
            body: r#"{"ldap_sync_host":"127.0.0.1","ldap_sync_port":"{port}","ldap_sync_password_enc":"pw","ldap_sync_enabled":"false"}"#,
            configured: false,
            expect: 204,
            repeat: true,
            ..b
        },
        ("config", "put-foreign") => Scenario {
            method: "PUT",
            path: "/admin/ldap/config",
            body: r#"{"ldap_sync_host":"x"}"#,
            revoked: true,
            expect: 403,
            ..b
        },
        ("config", "put-invalid") => Scenario {
            method: "PUT",
            path: "/admin/ldap/config",
            body: r#"{"ldap_sync_host": 5}"#,
            expect: 400,
            ..b
        },
        ("config", "put-bad-json") => Scenario {
            method: "PUT",
            path: "/admin/ldap/config",
            body: "{\"ldap_sync_host\":",
            expect: 400,
            ..b
        },
        ("config", "put-foreign-key") => Scenario {
            method: "PUT",
            path: "/admin/ldap/config",
            body: r#"{"ad_sync_host":"x"}"#,
            expect: 400,
            ..b
        },
        ("config", "put-bad-filter") => Scenario {
            method: "PUT",
            path: "/admin/ldap/config",
            body: r#"{"ldap_sync_user_filter":"(a=\\zz)","ldap_sync_enabled":"false"}"#,
            enabled: "false",
            expect: 500,
            ..b
        },
        ("config", "put-bad-bool") => Scenario {
            method: "PUT",
            path: "/admin/ldap/config",
            body: r#"{"ldap_sync_enabled":"maybe"}"#,
            expect: 500,
            ..b
        },
        ("config", "put-preserve") => Scenario {
            method: "PUT",
            path: "/admin/ldap/config",
            body: r#"{"ldap_sync_password_enc":"[ENCRYPTED]","ldap_sync_base_dn":"dc=example,dc=test","ldap_sync_enabled":"false"}"#,
            enabled: "false",
            expect: 204,
            ..b
        },
        ("config", "put-absent-secret") => Scenario {
            method: "PUT",
            path: "/admin/ldap/config",
            body: r#"{"ldap_sync_password_enc":"[ENCRYPTED]"}"#,
            configured: false,
            expect: 500,
            ..b
        },
        ("config", "put-null") => Scenario {
            method: "PUT",
            path: "/admin/ldap/config",
            body: "null",
            expect: 204,
            enabled: "false",
            ..b
        },
        ("config", "put-trailing") => Scenario {
            method: "PUT",
            path: "/admin/ldap/config",
            body: r#"{"ldap_sync_interval_min":"30","ldap_sync_enabled":"false"} trailing"#,
            enabled: "false",
            expect: 204,
            ..b
        },
        _ => panic!("unknown LDAP oracle scenario {route}/{case}"),
    }
}

pub const DIRECTORY: &str = "dc=example,dc=test";

pub fn dn(uid: &str) -> String {
    format!("uid={uid},ou=people,{DIRECTORY}")
}

/// Directory contents for a scenario; `dom` is the fixture mail domain.
pub fn entries(kind: Dir, dom: &str) -> Vec<Entry> {
    let person = |uid: &str, mail: &str, extra: &[(&str, &str)]| {
        let mut attrs: Vec<(&str, &str)> = vec![("objectClass", "person"), ("cn", uid)];
        if !mail.is_empty() {
            attrs.push(("mail", mail));
        }
        attrs.extend_from_slice(extra);
        Entry::new(&dn(uid), &attrs)
    };
    match kind {
        Dir::Empty => vec![],
        Dir::Mixed => {
            let bob_dn = dn("bob");
            vec![
                person(
                    "alice",
                    &format!("Alice@{dom}"),
                    &[
                        ("displayName", "Alice A"),
                        ("givenName", "Alice"),
                        ("sn", "A"),
                        ("title", "Engineer"),
                        ("telephoneNumber", "+1 555 0001"),
                        ("department", "Engineering"),
                        ("userPrincipalName", &format!("alice@{dom}")),
                        ("manager", &bob_dn),
                        ("modifyTimestamp", "20260101000001Z"),
                    ],
                ),
                person(
                    "bob",
                    &format!("bob@{dom}"),
                    &[
                        ("displayName", "Bob Renamed"),
                        ("givenName", "Bob"),
                        ("sn", "B"),
                        ("title", "Director"),
                        ("telephoneNumber", "+1 555 0002"),
                        ("department", "Engineering"),
                        ("userPrincipalName", "bob.new@CORP.EXAMPLE"),
                        ("modifyTimestamp", "20260101000002Z"),
                    ],
                ),
                person(
                    "carol",
                    &format!("carol@{dom}"),
                    &[
                        ("displayName", "Carol Directory"),
                        ("modifyTimestamp", "20260101000003Z"),
                    ],
                ),
                person(
                    "dave",
                    &format!("dave@{dom}"),
                    &[
                        ("displayName", "Dave"),
                        ("nsAccountLock", "TRUE"),
                        ("modifyTimestamp", "20260101000004Z"),
                    ],
                ),
                person(
                    "erin",
                    "",
                    &[
                        ("displayName", "Erin NoMail"),
                        ("modifyTimestamp", "20260101000005Z"),
                    ],
                ),
                person(
                    "frank",
                    &format!("fra\u{1}nk@{dom}"),
                    &[
                        ("displayName", "Frank Control"),
                        ("modifyTimestamp", "20260101000006Z"),
                    ],
                ),
                person(
                    "gina",
                    &format!("postmaster@{dom}"),
                    &[
                        ("displayName", "Gina Reserved"),
                        ("modifyTimestamp", "20260101000007Z"),
                    ],
                ),
                person(
                    "hank",
                    &format!("hank@{dom}"),
                    &[
                        ("displayName", "Hank Locked"),
                        ("pwdAccountLockedTime", "20260101000000Z"),
                        ("modifyTimestamp", "20260101000008Z"),
                    ],
                ),
                person(
                    "ivan",
                    &format!("ivan@{dom}"),
                    &[
                        ("displayName", "Ivan UAC"),
                        ("userAccountControl", "514"),
                        ("modifyTimestamp", "20260101000009Z"),
                    ],
                ),
            ]
        }
        Dir::Incremental => vec![
            person(
                "bob",
                &format!("bob@{dom}"),
                &[
                    ("displayName", "Bob Renamed"),
                    ("modifyTimestamp", "20260101000004Z"),
                ],
            ),
            person(
                "zed",
                &format!("zed@{dom}"),
                &[
                    ("displayName", "Zed Newer"),
                    ("modifyTimestamp", "20260101000009Z"),
                ],
            ),
        ],
        Dir::Page => (0..7)
            .map(|i| {
                person(
                    &format!("p{i:02}"),
                    &format!("p{i:02}@{dom}"),
                    &[
                        ("displayName", &format!("Page {i}")),
                        ("modifyTimestamp", &format!("202601010000{:02}Z", 10 + i)),
                    ],
                )
            })
            .collect(),
        Dir::Normalized => vec![
            person(
                "n1",
                &format!("n1@{dom}"),
                &[
                    ("entryUUID", "uuid-n1"),
                    ("displayName", "Norm One"),
                    ("givenName", "N"),
                    ("sn", "One"),
                    ("title", "Boss"),
                    ("modifyTimestamp", "20260101000011Z"),
                ],
            ),
            person(
                "n2",
                &format!("n2@{dom}"),
                &[
                    ("entryUUID", "uuid-n2"),
                    ("displayName", "Norm Two"),
                    ("manager", &dn("n1")),
                    ("department", "Ops"),
                    ("modifyTimestamp", "20260101000012Z"),
                ],
            ),
            person(
                "n3",
                "",
                &[
                    ("entryUUID", "uuid-n3"),
                    ("displayName", "No Mail"),
                    ("modifyTimestamp", "20260101000013Z"),
                ],
            ),
            person(
                "n4",
                &format!("n4@{dom}"),
                &[
                    ("displayName", "No Subject"),
                    ("modifyTimestamp", "20260101000014Z"),
                ],
            ),
            person(
                "n5",
                &format!("n5@{dom}"),
                &[
                    ("entryUUID", " padded "),
                    ("displayName", "Bad Subject"),
                    ("modifyTimestamp", "20260101000015Z"),
                ],
            ),
        ],
        Dir::NormalizedDuplicate => vec![
            person(
                "d1",
                &format!("d1@{dom}"),
                &[
                    ("entryUUID", "same"),
                    ("modifyTimestamp", "20260101000021Z"),
                ],
            ),
            person(
                "d2",
                &format!("d2@{dom}"),
                &[
                    ("entryUUID", "same"),
                    ("modifyTimestamp", "20260101000022Z"),
                ],
            ),
        ],
        Dir::NormalizedBlocked => vec![person(
            "b1",
            &format!("b1@{dom}"),
            &[
                ("entryUUID", "uuid-b1"),
                ("nsAccountLock", "TRUE"),
                ("modifyTimestamp", "20260101000031Z"),
            ],
        )],
    }
}

pub const CASES: &[(&str, &str)] = &[
    ("test", "success"),
    ("test", "foreign"),
    ("test", "invalid"),
    ("test", "bad-password"),
    ("test", "unreachable"),
    ("test", "search-failure"),
    ("test", "starttls"),
    ("preview", "success"),
    ("preview", "limit"),
    ("preview", "foreign"),
    ("preview", "invalid"),
    ("preview", "empty"),
    ("preview", "bad-password"),
    ("preview", "unconfigured"),
    ("sync", "success"),
    ("sync", "foreign"),
    ("sync", "invalid"),
    ("sync", "unconfigured"),
    ("sync", "search-failure"),
    ("sync", "bad-password"),
    ("sync", "no-dept"),
    ("sync", "incremental"),
    ("sync", "sweep-due"),
    ("sync", "sweep-fresh"),
    ("sync", "filtered"),
    ("sync", "paged"),
    ("sync", "normalized"),
    ("sync", "normalized-duplicate"),
    ("sync", "normalized-blocked"),
    ("sync", "repeat"),
    ("health", "success"),
    ("health", "foreign"),
    ("health", "invalid"),
    ("health", "error"),
    ("config", "put-success"),
    ("config", "put-foreign"),
    ("config", "put-invalid"),
    ("config", "put-bad-json"),
    ("config", "put-foreign-key"),
    ("config", "put-bad-filter"),
    ("config", "put-bad-bool"),
    ("config", "put-preserve"),
    ("config", "put-absent-secret"),
    ("config", "put-repeat"),
    ("config", "put-null"),
    ("config", "put-trailing"),
];
