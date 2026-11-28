//! Scenario table for the #381 AD oracle: one entry per recorded case.
use setjoin_conformance::ldap_fake::Entry;

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Reach {
    Up,
    Down,
    BadPassword,
}

/// How the worker finds a domain controller.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Discovery {
    /// `ad_sync_ldap_host=127.0.0.1` (port 636, no DNS).
    Host,
    /// No host: SRV `_ldap._tcp.<domain>` answers `localhost`.
    Srv,
    /// No host: the SRV name does not exist.
    SrvMissing,
}

#[derive(Clone)]
pub struct Scenario {
    pub method: &'static str,
    /// Path below `/api`, query included.
    pub path: &'static str,
    pub body: &'static str,
    pub revoked: bool,
    /// Seeds no `ad_sync_*` rows at all when false.
    pub configured: bool,
    /// `AD_SYNC_ENABLED` for Go and the Rust runtime.
    pub enabled: bool,
    pub discovery: Discovery,
    pub reach: Reach,
    pub dir: Dir,
    pub seed: Seed,
    pub activate_source: bool,
    pub fail_search: bool,
    /// Committed cursor JSON seeded on the `legacy:ad` source row.
    pub cursor: Option<&'static str>,
    pub expect: u16,
    /// Send the request once before the observed one (mutator repeat floor).
    pub repeat: bool,
    /// `ad_sync_domain` value (empty seeds the row with an empty string).
    pub domain: &'static str,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Dir {
    Mixed,
    Clean,
    /// Only new, well-formed, enabled accounts: nothing for the reducer to block.
    Fresh,
    Incremental,
    Quarantine,
    Duplicate,
    BadUac,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Seed {
    None,
    /// Existing accounts for the directory entries, each with an active `legacy:ad` link.
    Linked,
    Conflicts,
    LogError,
}

pub const DOMAIN: &str = "ad.example.test";
pub const BASE: &str = "DC=ad,DC=example,DC=test";

pub fn base() -> Scenario {
    Scenario {
        method: "GET",
        path: "/admin/ad/health",
        body: "",
        revoked: false,
        configured: true,
        enabled: true,
        discovery: Discovery::Host,
        reach: Reach::Up,
        dir: Dir::Mixed,
        seed: Seed::None,
        activate_source: false,
        fail_search: false,
        cursor: None,
        expect: 200,
        repeat: false,
        domain: DOMAIN,
    }
}

fn post(path: &'static str) -> Scenario {
    Scenario {
        method: "POST",
        path,
        ..base()
    }
}

fn put(body: &'static str) -> Scenario {
    Scenario {
        method: "PUT",
        path: "/admin/ad/config",
        body,
        ..base()
    }
}

const TEST: &str = "/admin/ad/test-connection";
const SYNC: &str = "/admin/ad/sync";

/// (route, case) -> scenario; the golden is `ad-<route>-<case>.json`.
pub fn scenario(route: &str, case: &str) -> Scenario {
    let b = base();
    match (route, case) {
        ("test", "success") => post(TEST),
        ("test", "foreign") => Scenario {
            revoked: true,
            expect: 403,
            ..post(TEST)
        },
        ("test", "invalid") => Scenario {
            configured: false,
            expect: 503,
            ..post(TEST)
        },
        ("test", "bad-password") => Scenario {
            reach: Reach::BadPassword,
            expect: 500,
            ..post(TEST)
        },
        ("test", "unreachable") => Scenario {
            reach: Reach::Down,
            expect: 500,
            ..post(TEST)
        },
        ("test", "search-failure") => Scenario {
            fail_search: true,
            expect: 500,
            ..post(TEST)
        },
        ("test", "srv") => Scenario {
            discovery: Discovery::Srv,
            ..post(TEST)
        },
        ("test", "srv-missing") => Scenario {
            discovery: Discovery::SrvMissing,
            expect: 503,
            ..post(TEST)
        },
        ("test", "disabled") => Scenario {
            enabled: false,
            expect: 503,
            ..post(TEST)
        },
        ("test", "bad-uac") => Scenario {
            dir: Dir::BadUac,
            expect: 500,
            ..post(TEST)
        },
        ("sync", "success") => Scenario {
            dir: Dir::Clean,
            seed: Seed::Linked,
            activate_source: true,
            ..post(SYNC)
        },
        ("sync", "blocked") => Scenario {
            activate_source: true,
            expect: 500,
            ..post(SYNC)
        },
        ("sync", "foreign") => Scenario {
            revoked: true,
            expect: 403,
            ..post(SYNC)
        },
        ("sync", "invalid") => Scenario {
            configured: false,
            expect: 503,
            ..post(SYNC)
        },
        ("sync", "repeat") => Scenario {
            dir: Dir::Clean,
            seed: Seed::Linked,
            activate_source: true,
            repeat: true,
            ..post(SYNC)
        },
        ("sync", "search-failure") => Scenario {
            fail_search: true,
            activate_source: true,
            expect: 500,
            ..post(SYNC)
        },
        ("sync", "bad-password") => Scenario {
            reach: Reach::BadPassword,
            activate_source: true,
            expect: 500,
            ..post(SYNC)
        },
        ("sync", "unreachable") => Scenario {
            reach: Reach::Down,
            activate_source: true,
            expect: 500,
            ..post(SYNC)
        },
        ("sync", "incremental") => Scenario {
            seed: Seed::Linked,
            dir: Dir::Incremental,
            activate_source: true,
            cursor: Some(r#"{"usn":"1005"}"#),
            ..post(SYNC)
        },
        ("sync", "quarantine") => Scenario {
            dir: Dir::Quarantine,
            activate_source: true,
            ..post(SYNC)
        },
        ("sync", "duplicate") => Scenario {
            dir: Dir::Duplicate,
            activate_source: true,
            expect: 500,
            ..post(SYNC)
        },
        ("sync", "source-paused") => post(SYNC),
        ("sync", "bad-uac") => Scenario {
            dir: Dir::BadUac,
            activate_source: true,
            expect: 500,
            ..post(SYNC)
        },
        ("sync", "bad-cursor") => Scenario {
            activate_source: true,
            cursor: Some(r#"{"usn":"abc"}"#),
            expect: 500,
            ..post(SYNC)
        },
        ("sync", "srv") => Scenario {
            discovery: Discovery::Srv,
            dir: Dir::Fresh,
            activate_source: true,
            ..post(SYNC)
        },
        ("sync", "disabled") => Scenario {
            enabled: false,
            expect: 503,
            ..post(SYNC)
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
            path: "/admin/ad/health?x=%zz",
            configured: false,
            ..b
        },
        ("health", "error") => Scenario {
            seed: Seed::LogError,
            ..b
        },
        ("health", "disabled") => Scenario {
            enabled: false,
            seed: Seed::Conflicts,
            ..b
        },
        ("config", "put-success") => Scenario {
            expect: 204,
            ..put(
                r#"{"ad_sync_domain":"ad.example.test","ad_sync_ldap_host":"127.0.0.1","ad_sync_bind_dn":"CN=svc,DC=ad,DC=example,DC=test","ad_sync_password_enc":"pw","ad_sync_interval_min":"30"}"#,
            )
        },
        ("config", "put-repeat") => Scenario {
            repeat: true,
            configured: false,
            expect: 204,
            ..put(
                r#"{"ad_sync_domain":"ad.example.test","ad_sync_ldap_host":"127.0.0.1","ad_sync_password_enc":"pw"}"#,
            )
        },
        ("config", "put-foreign") => Scenario {
            revoked: true,
            expect: 403,
            ..put(r#"{"ad_sync_domain":"x"}"#)
        },
        ("config", "put-invalid") => Scenario {
            expect: 400,
            ..put(r#"{"ad_sync_domain": 5}"#)
        },
        ("config", "put-bad-json") => Scenario {
            expect: 400,
            ..put("{\"ad_sync_domain\":")
        },
        ("config", "put-foreign-key") => Scenario {
            expect: 400,
            ..put(r#"{"ldap_sync_host":"x"}"#)
        },
        ("config", "put-preserve") => Scenario {
            expect: 204,
            ..put(
                r#"{"ad_sync_password_enc":"[ENCRYPTED]","ad_sync_bind_dn":"CN=svc,DC=ad,DC=example,DC=test"}"#,
            )
        },
        ("config", "put-absent-secret") => Scenario {
            configured: false,
            expect: 500,
            ..put(r#"{"ad_sync_password_enc":"[ENCRYPTED]"}"#)
        },
        ("config", "put-null") => Scenario {
            expect: 204,
            ..put("null")
        },
        ("config", "put-trailing") => Scenario {
            expect: 204,
            ..put(r#"{"ad_sync_interval_min":"30"} trailing"#)
        },
        ("config", "put-no-domain") => Scenario {
            configured: false,
            expect: 204,
            ..put(r#"{"ad_sync_bind_dn":"CN=svc,DC=ad,DC=example,DC=test"}"#)
        },
        ("config", "put-srv") => Scenario {
            configured: false,
            discovery: Discovery::Srv,
            expect: 204,
            ..put(r#"{"ad_sync_domain":"ad.example.test","ad_sync_password_enc":"pw"}"#)
        },
        ("config", "put-srv-failure") => Scenario {
            configured: false,
            discovery: Discovery::SrvMissing,
            expect: 500,
            ..put(r#"{"ad_sync_domain":"ad.example.test","ad_sync_password_enc":"pw"}"#)
        },
        ("config", "put-disabled") => Scenario {
            configured: false,
            enabled: false,
            expect: 204,
            ..put(
                r#"{"ad_sync_domain":"ad.example.test","ad_sync_ldap_host":"127.0.0.1","ad_sync_password_enc":"pw"}"#,
            )
        },
        _ => panic!("unknown AD oracle scenario {route}/{case}"),
    }
}

pub fn dn(cn: &str) -> String {
    format!("CN={cn},OU=People,{BASE}")
}

/// A deterministic 16-byte `objectGUID` for entry `n`.
pub fn guid(n: u8) -> [u8; 16] {
    [
        0x10 + n,
        0x20,
        0x30,
        0x40,
        0x50,
        0x60,
        0x70,
        0x80,
        0x90,
        0xa0,
        0xb0,
        0xc0,
        0xd0,
        0xe0,
        0xf0,
        n,
    ]
}

/// Directory contents for a scenario; `dom` is the fixture mail domain.
pub fn entries(kind: Dir, dom: &str) -> Vec<Entry> {
    let person = |cn: &str, n: u8, mail: &str, usn: u32, extra: &[(&str, &str)]| {
        let mut attrs: Vec<(&str, String)> = vec![
            ("objectClass", "user".into()),
            ("objectCategory", "person".into()),
            ("sAMAccountName", cn.to_owned()),
            ("uSNChanged", usn.to_string()),
        ];
        if !mail.is_empty() {
            attrs.push(("mail", mail.to_owned()));
        }
        for (k, v) in extra {
            attrs.push((k, (*v).to_owned()));
        }
        let pairs: Vec<(&str, &str)> = attrs.iter().map(|(k, v)| (*k, v.as_str())).collect();
        let entry = Entry::new(&dn(cn), &pairs);
        if n == 0 {
            entry
        } else {
            entry.with_bin("objectGUID", &guid(n))
        }
    };
    match kind {
        Dir::Mixed => {
            let bob_dn = dn("bob");
            let boss_dn = dn("boss");
            vec![
                person(
                    "alice",
                    1,
                    &format!("Alice@{dom}"),
                    1001,
                    &[
                        ("displayName", "Alice A"),
                        ("givenName", "Alice"),
                        ("sn", "A"),
                        ("title", "Engineer"),
                        ("telephoneNumber", "+1 555 0001"),
                        ("department", "Engineering"),
                        ("userPrincipalName", &format!("alice@{dom}")),
                        ("manager", &bob_dn),
                        ("proxyAddresses", &format!("smtp:alice.alt@{dom}")),
                        ("proxyAddresses", "X500:/o=corp"),
                    ],
                ),
                person(
                    "bob",
                    2,
                    &format!("bob@{dom}"),
                    1002,
                    &[
                        ("displayName", "Bob Renamed"),
                        ("givenName", "Bob"),
                        ("sn", "B"),
                        ("title", "Director"),
                        ("userPrincipalName", "bob.new@CORP.EXAMPLE"),
                    ],
                ),
                person(
                    "carol",
                    3,
                    &format!("carol@{dom}"),
                    1003,
                    &[("displayName", "Carol Directory"), ("manager", &boss_dn)],
                ),
                person(
                    "dave",
                    4,
                    &format!("dave@{dom}"),
                    1004,
                    &[("displayName", "Dave"), ("userAccountControl", "514")],
                ),
                person("erin", 5, "", 1005, &[("displayName", "Erin NoMail")]),
                person(
                    "frank",
                    6,
                    &format!("fra\u{1}nk@{dom}"),
                    1006,
                    &[("displayName", "Frank Control")],
                ),
                person(
                    "gina",
                    7,
                    &format!("postmaster@{dom}"),
                    1007,
                    &[("displayName", "Gina Reserved")],
                ),
                person(
                    "hank",
                    8,
                    &format!("hank@{dom}"),
                    1008,
                    &[
                        ("displayName", "Hank Disabled"),
                        ("userAccountControl", "66050"),
                    ],
                ),
                person(
                    "ivan",
                    0,
                    &format!("ivan@{dom}"),
                    1009,
                    &[("displayName", "Ivan NoGuid")],
                ),
                person(
                    "judy",
                    9,
                    &format!("judy@{dom}"),
                    1010,
                    &[("displayName", "Judy"), ("userAccountControl", "512")],
                ),
                Entry::new(
                    &dn("kate"),
                    &[
                        ("objectClass", "user"),
                        ("objectCategory", "person"),
                        ("mail", &format!("kate@{dom}")),
                        ("uSNChanged", "notanumber"),
                        ("displayName", "Kate BadUsn"),
                    ],
                )
                .with_bin("objectGUID", &guid(10)),
                // Outside the page's user filter, but reachable by the manager lookup.
                Entry::new(
                    &boss_dn,
                    &[
                        ("objectClass", "user"),
                        ("objectCategory", "group"),
                        ("uSNChanged", "5"),
                    ],
                )
                .with_bin("objectGUID", &guid(11)),
            ]
        }
        Dir::Fresh => {
            let all = entries(Dir::Mixed, dom);
            let keep = ["alice", "bob", "carol", "judy", "boss"];
            all.into_iter()
                .filter(|e| keep.iter().any(|k| e.dn.starts_with(&format!("CN={k},"))))
                .collect()
        }
        Dir::Clean => {
            let all = entries(Dir::Mixed, dom);
            let keep = [
                "alice", "bob", "carol", "dave", "erin", "hank", "ivan", "judy", "kate", "boss",
            ];
            all.into_iter()
                .filter(|e| keep.iter().any(|k| e.dn.starts_with(&format!("CN={k},"))))
                .collect()
        }
        Dir::Incremental => vec![
            person(
                "bob",
                2,
                &format!("bob@{dom}"),
                1006,
                &[("displayName", "Bob Renamed")],
            ),
            person(
                "zed",
                12,
                &format!("zed@{dom}"),
                1009,
                &[("displayName", "Zed Newer")],
            ),
            person(
                "old",
                13,
                &format!("old@{dom}"),
                1001,
                &[("displayName", "Old Stays Out")],
            ),
        ],
        Dir::Quarantine => vec![
            person(
                "q1",
                14,
                &format!("q1@{dom}"),
                1021,
                &[("displayName", "Fine")],
            ),
            person("q2", 15, "", 1022, &[("displayName", "No Mail")]),
            person(
                "q3",
                0,
                &format!("q3@{dom}"),
                1023,
                &[("displayName", "No Guid")],
            ),
            person(
                "q4",
                16,
                "not-an-address",
                1024,
                &[("displayName", "Bad Mail")],
            ),
        ],
        Dir::Duplicate => vec![
            person("d1", 18, &format!("d1@{dom}"), 1031, &[]),
            person("d2", 18, &format!("d2@{dom}"), 1032, &[]),
        ],
        Dir::BadUac => vec![person(
            "u1",
            19,
            &format!("u1@{dom}"),
            1041,
            &[("userAccountControl", "notanumber")],
        )],
    }
}
