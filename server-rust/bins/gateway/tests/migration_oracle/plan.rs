//! Fixtures and the request each (action, label) case sends.
use crate::common::BoxError;
use setjoin_conformance::fixture::{self, Account};
use tokio_postgres::Client;

pub const MISSING: i64 = 999_999_999;
/// The raw `DB_ENCRYPTION_KEY` both the frozen Go process and the replay use.
pub fn root() -> String {
    "22".repeat(32)
}

pub struct Fx {
    pub a: Account,
    pub b: Account,
    pub j1: i64,
    pub j2: i64,
    pub j3: i64,
    pub role: i64,
    pub a_domain: String,
    pub b_domain: String,
    /// `system_config` rows the case replaced, put back on removal.
    pub saved: Vec<(String, serde_json::Value, bool)>,
}

pub struct Plan {
    pub method: &'static str,
    pub pattern: &'static str,
    pub path: String,
    pub query: String,
    pub body: String,
    pub recorded_body: String,
    /// Send the request once before the observed one.
    pub repeat: bool,
    pub head: bool,
}

pub const KEYS: [&str; 3] = ["imap.defaults", "ews.global", "m365.app"];

/// Whether the case is a read (`requireMailPerm`) rather than a pipeline write.
pub fn is_read(action: &str) -> bool {
    matches!(action, "jobs" | "job-get" | "source-get")
}

/// Governed permissions and whether the admin is scoped to its own domain.
pub fn access(action: &str, label: &str) -> (Vec<&'static str>, bool) {
    let read = is_read(action);
    let perms = match label {
        "denied" => vec!["users.read"],
        "wrong-perm" => {
            if read {
                vec!["users.create"]
            } else {
                vec!["domains.read"]
            }
        }
        _ if read => vec!["domains.read"],
        _ => vec!["mail.pipeline"],
    };
    (perms, label == "foreign")
}

const IMAP_ROW: &str = r#"{"host":"imap.example.com","port":993,"tls_mode":"tls"}"#;
pub const EWS_PLAIN: &str = r#"{"serverURL":"https://ews.example.com/EWS/Exchange.asmx","username":"svc","password":"hunter2","authMode":"impersonation","insecureSkipVerify":false,"privateHosts":["exch.corp"],"privateCIDRs":["10.0.0.0/8"]}"#;
pub const M365_PLAIN: &str = r#"{"client_id":"app-123","client_secret":"s3cret","tenant_id":"tenant-1","cloud":"global","source_email":"src@example.com"}"#;

fn wrapped(plain: &str) -> String {
    use setjoin_mailboxes::migration as m;
    let key = m::derive_key(&root(), "system").expect("key");
    m::wrapper(&m::seal(plain.as_bytes(), &key).expect("seal"))
}

impl Fx {
    pub async fn build(c: &Client, label: &str, action: &str) -> Result<Fx, BoxError> {
        let a = fixture::account(c, "mbox2-admin").await?;
        let b = fixture::account(c, "mbox2-other").await?;
        let name = |d: i64| async move {
            Ok::<String, BoxError>(
                c.query_one("SELECT name FROM domains WHERE id=$1", &[&d])
                    .await?
                    .get(0),
            )
        };
        let (a_domain, b_domain) = (name(a.domain).await?, name(b.domain).await?);
        let mut ids = vec![];
        for (user, status, hours, progress, errors, started) in [
            (
                a.user,
                "completed",
                3,
                r#"{"imported": 3, "phase": "done"}"#,
                "[]",
                true,
            ),
            (
                b.user,
                "failed",
                2,
                r#"{"phase":"fetching","n":1.50,"tags":["<a>","b&c"]}"#,
                r#"["boom <x> & y", "second"]"#,
                true,
            ),
            (b.user, "cancelled", 1, "{}", "[]", false),
        ] {
            let id: i64 = c
                .query_one(
                    "INSERT INTO migration_jobs (user_id,source_type,status,progress,error_log,created_at,started_at,completed_at,target_mailbox_id) \
                     VALUES ($1,'imap',$2,$3::text::jsonb,$4::text::jsonb,now()-($5||' hours')::interval, \
                     CASE WHEN $6 THEN now()-($5||' hours')::interval+interval '1 minute' END, \
                     CASE WHEN $2<>'cancelled' THEN now()-($5||' hours')::interval+interval '2 minutes' END,$7) RETURNING id",
                    &[&user, &status, &progress, &errors, &hours.to_string(), &started, &if user == a.user { Some(a.mailbox) } else { Some(b.mailbox) }],
                )
                .await?
                .get(0);
            ids.push(id);
        }
        let (perms, scoped) = access(action, label);
        let perms: Vec<String> = perms.iter().map(|p| p.to_string()).collect();
        let scope: Option<i64> = scoped.then_some(a.domain);
        let role: i64 = c
            .query_one(
                "INSERT INTO admin_role_groups(name,permissions,domain_scope) VALUES ($1,$2,$3) RETURNING id",
                &[&format!("mbox2-role-{}", a.user), &perms, &scope],
            )
            .await?
            .get(0);
        c.execute(
            "INSERT INTO admin_role_assignments(user_id,role_group_id,granted_by) VALUES($1,$2,$1)",
            &[&a.user, &role],
        )
        .await?;
        let mut saved = vec![];
        for row in c
            .query(
                "SELECT key, value::text, encrypted FROM system_config WHERE key=ANY($1)",
                &[&KEYS.map(String::from).to_vec()],
            )
            .await?
        {
            saved.push((
                row.get::<_, String>(0),
                serde_json::from_str(&row.get::<_, String>(1))?,
                row.get::<_, bool>(2),
            ));
        }
        c.execute(
            "DELETE FROM system_config WHERE key=ANY($1)",
            &[&KEYS.map(String::from).to_vec()],
        )
        .await?;
        Ok(Fx {
            a,
            b,
            j1: ids[0],
            j2: ids[1],
            j3: ids[2],
            role,
            a_domain,
            b_domain,
            saved,
        })
    }

    async fn put(c: &Client, key: &str, value: &str, encrypted: bool) -> Result<(), BoxError> {
        c.execute(
            "INSERT INTO system_config(key,value,encrypted) VALUES ($1,$2::text::jsonb,$3) ON CONFLICT (key) DO UPDATE SET value=EXCLUDED.value, encrypted=EXCLUDED.encrypted",
            &[&key, &value, &encrypted],
        )
        .await?;
        Ok(())
    }

    /// The stored configuration a case starts from.
    pub async fn seed(&self, c: &Client, action: &str, label: &str) -> Result<(), BoxError> {
        let sealed_ews = wrapped(EWS_PLAIN);
        let sealed_m365 = wrapped(M365_PLAIN);
        match (action, label) {
            ("source-get", "success" | "foreign" | "denied" | "wrong-perm") => {
                Self::put(c, "imap.defaults", IMAP_ROW, false).await?
            }
            ("source-get", "ews") => Self::put(c, "ews.global", &sealed_ews, true).await?,
            ("source-get", "m365") => Self::put(c, "m365.app", &sealed_m365, true).await?,
            ("source-get", "ews-plain") => Self::put(c, "ews.global", &sealed_ews, false).await?,
            ("source-get", "ews-garbage") => {
                Self::put(
                    c,
                    "ews.global",
                    r#"{"_enc":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}"#,
                    true,
                )
                .await?
            }
            ("source-get", "ews-wrapper") => {
                Self::put(c, "ews.global", r#""not an object""#, true).await?
            }
            ("source-get", "ews-array") => Self::put(c, "ews.global", r#"[1,2]"#, true).await?,
            ("source-get", "ews-base64") => {
                Self::put(c, "ews.global", r#"{"_enc":"!!!"}"#, true).await?
            }
            ("source-get", "ews-null") => Self::put(c, "ews.global", "null", true).await?,
            ("source-get", "ews-fields") => {
                Self::put(c, "ews.global", &wrapped(r#"{"serverURL":5}"#), true).await?
            }
            ("source-get", "m365-fields") => {
                Self::put(c, "m365.app", &wrapped(r#"{"client_id":["x"]}"#), true).await?
            }
            ("source-get", "m365-folded") => {
                Self::put(
                    c,
                    "m365.app",
                    &wrapped(r#"{"CLIENT_ID":"folded","tenant_id":null}"#),
                    true,
                )
                .await?
            }
            ("source-get", "imap-sealed") => {
                Self::put(c, "imap.defaults", r#"{"_enc":"c2VhbGVk"}"#, true).await?
            }
            ("source-delete", "success" | "repeat" | "foreign" | "denied" | "wrong-perm") => {
                Self::put(c, "imap.defaults", IMAP_ROW, false).await?
            }
            ("source-delete", "ews") => Self::put(c, "ews.global", &sealed_ews, true).await?,
            ("source-delete", "m365") => Self::put(c, "m365.app", &sealed_m365, true).await?,
            ("source-delete", "others-stay") => {
                Self::put(c, "imap.defaults", IMAP_ROW, false).await?;
                Self::put(c, "ews.global", &sealed_ews, true).await?;
            }
            ("put-imap", "overwrite") => {
                Self::put(
                    c,
                    "imap.defaults",
                    r#"{"host":"old.example.com","port":143,"tls_mode":"none"}"#,
                    false,
                )
                .await?
            }
            ("put-imap", "overwrite-sealed") => {
                Self::put(c, "imap.defaults", r#"{"_enc":"c2VhbGVk"}"#, true).await?
            }
            ("put-ews", "overwrite") => {
                Self::put(
                    c,
                    "ews.global",
                    &wrapped(r#"{"serverURL":"https://old.example.com","username":"old"}"#),
                    true,
                )
                .await?
            }
            ("put-ews", "overwrite-plain") => Self::put(c, "ews.global", IMAP_ROW, false).await?,
            ("put-m365", "overwrite") => Self::put(c, "m365.app", &sealed_m365, true).await?,
            ("m365-connect", "no-config" | "invalid") => {}
            ("m365-connect", "plain") => Self::put(c, "m365.app", &sealed_m365, false).await?,
            ("m365-connect", "bad-wrapper") => Self::put(c, "m365.app", r#""x""#, true).await?,
            ("m365-connect", "bad-base64") => {
                Self::put(c, "m365.app", r#"{"_enc":"!!!"}"#, true).await?
            }
            ("m365-connect", "bad-cipher") => {
                Self::put(
                    c,
                    "m365.app",
                    r#"{"_enc":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}"#,
                    true,
                )
                .await?
            }
            ("m365-connect", "bad-fields") => {
                Self::put(c, "m365.app", &wrapped(r#"{"client_id":5}"#), true).await?
            }
            ("m365-connect", "escape-client-id") => {
                Self::put(
                    c,
                    "m365.app",
                    &wrapped(r#"{"client_id":"id with&space<é","client_secret":"x"}"#),
                    true,
                )
                .await?
            }
            ("m365-connect", "stale") => {
                Self::put(c, "m365.app", &sealed_m365, true).await?;
                c.execute("INSERT INTO m365_consent_states(state_token,actor_user_id,cloud,expires_at,issued_at) VALUES ('stale-token-1',$1,'global',now()-interval '1 minute',now()-interval '20 minutes')", &[&self.a.user]).await?;
                c.execute("INSERT INTO m365_consent_states(state_token,actor_user_id,cloud,expires_at,issued_at) VALUES ('other-token-1',$1,'global',now()-interval '1 minute',now()-interval '20 minutes')", &[&self.b.user]).await?;
            }
            ("m365-connect", _) => Self::put(c, "m365.app", &sealed_m365, true).await?,
            _ => {}
        }
        Ok(())
    }

    pub async fn remove(&self, c: &Client) -> Result<(), BoxError> {
        c.execute(
            "DELETE FROM system_config WHERE key=ANY($1)",
            &[&KEYS.map(String::from).to_vec()],
        )
        .await?;
        for (key, value, encrypted) in &self.saved {
            c.execute(
                "INSERT INTO system_config(key,value,encrypted) VALUES ($1,$2::text::jsonb,$3)",
                &[key, &value.to_string(), encrypted],
            )
            .await?;
        }
        let users = vec![self.a.user, self.b.user];
        c.execute(
            "DELETE FROM m365_consent_states WHERE actor_user_id=ANY($1)",
            &[&users],
        )
        .await?;
        c.execute(
            "DELETE FROM migration_jobs WHERE user_id=ANY($1)",
            &[&users],
        )
        .await?;
        c.execute(
            "DELETE FROM admin_role_assignments WHERE role_group_id=$1",
            &[&self.role],
        )
        .await?;
        c.execute("DELETE FROM admin_role_groups WHERE id=$1", &[&self.role])
            .await?;
        fixture::remove(c, &self.a).await?;
        fixture::remove(c, &self.b).await?;
        Ok(())
    }

    /// Ids a case may mention, keyed by the JSON key that carries them.
    pub fn ids(&self) -> Vec<(&'static str, i64, String)> {
        let mut out: Vec<(&'static str, i64, String)> = vec![];
        for key in [
            "user_id",
            "actor_id",
            "actor_user_id",
            "updated_by",
            "created_by",
        ] {
            out.push((key, self.a.user, "<admin>".into()));
            out.push((key, self.b.user, "<other>".into()));
        }
        for (id, name) in [
            (self.j1, "<job-completed>"),
            (self.j2, "<job-failed>"),
            (self.j3, "<job-cancelled>"),
        ] {
            out.push(("id", id, name.into()));
            out.push(("job_id", id, name.into()));
        }
        for (id, name) in [
            (self.a.mailbox, "<mailbox-a>"),
            (self.b.mailbox, "<mailbox-b>"),
        ] {
            out.push(("mailbox", id, name.into()));
        }
        out
    }

    /// Domain names carry a per-run suffix.
    pub fn names(&self, text: &str) -> String {
        text.replace(&self.a_domain, "host-a.test")
            .replace(&self.b_domain, "host-b.test")
    }
}

fn base(method: &'static str, pattern: &'static str, path: String) -> Plan {
    Plan {
        method,
        pattern,
        path,
        query: String::new(),
        body: String::new(),
        recorded_body: String::new(),
        repeat: false,
        head: false,
    }
}
fn with_body(method: &'static str, pattern: &'static str, path: &str, body: &str) -> Plan {
    Plan {
        body: body.to_owned(),
        recorded_body: body.to_owned(),
        ..base(method, pattern, path.to_owned())
    }
}

const JOBS: &str = "/admin/migration/jobs";
const JOB: &str = "/admin/migration/jobs/{id}";
const SOURCE: &str = "/admin/migration/source/{type}";
const IMAP: &str = "/admin/migration/source/imap";
const EWS: &str = "/admin/migration/source/ews";
const M365: &str = "/admin/migration/source/m365";
const CONNECT: &str = "/admin/migration/m365/connect";

const IMAP_OK: &str = r#"{"host":"imap.example.com","port":993,"tls_mode":"tls"}"#;
const EWS_OK: &str = r#"{"serverURL":"https://ews.example.com/EWS/Exchange.asmx","username":"svc","password":"hunter2","authMode":"impersonation"}"#;
const M365_OK: &str = r#"{"client_id":"app-123","client_secret":"s3cret"}"#;

/// The request of an (action, label) case. Paths use real ids; `{id}` tokens in the
/// recorded form name the fixture (`<job-completed>` ...).
pub fn plan(action: &str, label: &str, fx: &Fx) -> Plan {
    let job_path = |id: &str| format!("/admin/migration/jobs/{id}");
    let src = |t: &str| format!("/admin/migration/source/{t}");
    let guarded = matches!(label, "foreign" | "denied" | "wrong-perm");
    match action {
        "jobs" => {
            let mut p = base("GET", JOBS, JOBS.to_owned());
            p.query = match label {
                "status" => "?status=failed".into(),
                "user" => format!("?user_id={}", fx.b.user),
                "both" => format!("?status=cancelled&user_id={}", fx.b.user),
                "empty" => "?status=nosuch".into(),
                "invalid" => "?user_id=abc".into(),
                "spaced" => "?user_id=%20%20".into(),
                "plus" => format!("?user_id=%2B{}", fx.a.user),
                "head" => String::new(),
                _ => String::new(),
            };
            p.head = label == "head";
            p
        }
        "job-get" => {
            let id = match label {
                "failed" => fx.j2.to_string(),
                "cancelled" => fx.j3.to_string(),
                "invalid" => "abc".into(),
                "plus" => format!("+{}", fx.j1),
                "huge" => "99999999999999999999".into(),
                "missing" => MISSING.to_string(),
                "zero" => "0".into(),
                "negative" => "-1".into(),
                _ => fx.j1.to_string(),
            };
            let mut p = base("GET", JOB, format!("/admin/migration/jobs/{id}"));
            p.head = label == "head";
            p
        }
        "job-delete" => {
            let id = match label {
                "invalid" => "abc".into(),
                "missing" => MISSING.to_string(),
                "other" => fx.j2.to_string(),
                _ => fx.j1.to_string(),
            };
            let mut p = base("DELETE", JOB, job_path(&id));
            p.repeat = label == "repeat";
            p
        }
        "source-get" => {
            let t = match label {
                "ews" | "ews-plain" | "ews-garbage" | "ews-wrapper" | "ews-array"
                | "ews-base64" | "ews-null" | "ews-fields" | "ews-missing" => "ews",
                "m365" | "m365-fields" | "m365-folded" | "m365-missing" => "m365",
                "invalid" => "pop3",
                _ => "imap",
            };
            base("GET", SOURCE, src(t))
        }
        "source-delete" => {
            let t = match label {
                "ews" | "missing" => "ews",
                "m365" => "m365",
                "invalid" => "pop3",
                _ => "imap",
            };
            let mut p = base("DELETE", SOURCE, src(t));
            p.repeat = label == "repeat";
            p
        }
        "put-imap" => {
            let body = match label {
                "defaults" => r#"{"host":"imap.example.com"}"#,
                "ssl" => r#"{"host":"imap.example.com","port":995,"tls_mode":"ssl"}"#,
                "starttls" => r#"{"host":"imap.example.com","port":143,"tls_mode":"starttls"}"#,
                "none" => r#"{"host":"imap.example.com","port":143,"tls_mode":"none"}"#,
                "policy" => {
                    r#"{"host":"imap.corp","port":993,"tls_mode":"tls","private_hosts":["IMAP.corp."],"private_cidrs":["10.0.0.0/8"," fd00::/8"]}"#
                }
                "escape" => r#"{"host":"a&b<c>.example.com","port":993,"tls_mode":"tls"}"#,
                "no-host" | "invalid" => r#"{"port":993}"#,
                "bad-tls" => r#"{"host":"imap.example.com","tls_mode":"ssl3\""}"#,
                "policy-half" => r#"{"host":"imap.example.com","private_hosts":["imap.corp"]}"#,
                "policy-cidr-half" => {
                    r#"{"host":"imap.example.com","private_cidrs":["10.0.0.0/8"]}"#
                }
                "policy-bad-host" => {
                    r#"{"host":"imap.example.com","private_hosts":["10.0.0.1"],"private_cidrs":["10.0.0.0/8"]}"#
                }
                "policy-slash-host" => {
                    r#"{"host":"imap.example.com","private_hosts":["a/b"],"private_cidrs":["10.0.0.0/8"]}"#
                }
                "policy-bad-cidr" => {
                    r#"{"host":"imap.example.com","private_hosts":["h"],"private_cidrs":["nonsense"]}"#
                }
                "policy-public-cidr" => {
                    r#"{"host":"imap.example.com","private_hosts":["h"],"private_cidrs":["8.8.8.0/24"]}"#
                }
                "policy-wide-cidr" => {
                    r#"{"host":"imap.example.com","private_hosts":["h"],"private_cidrs":["10.0.0.0/7"]}"#
                }
                "policy-empty" => {
                    r#"{"host":"imap.example.com","private_hosts":[],"private_cidrs":[]}"#
                }
                "policy-null-element" => {
                    r#"{"host":"imap.example.com","private_hosts":[null],"private_cidrs":["10.0.0.0/8"]}"#
                }
                "bad-json" => "{not json",
                "typed" => r#"{"host":"imap.example.com","port":"993"}"#,
                "float-port" => r#"{"host":"imap.example.com","port":993.5}"#,
                "null-fields" => r#"{"host":"imap.example.com","port":null,"tls_mode":null}"#,
                "case-keys" => r#"{"HOST":"imap.example.com","Port":10993,"TLS_MODE":"starttls"}"#,
                "unknown-keys" => r#"{"host":"imap.example.com","extra":{"a":1}}"#,
                "trailing" => r#"{"host":"imap.example.com"} garbage"#,
                "empty-body" => "",
                "array" => "[]",
                "null-body" => "null",
                _ => IMAP_OK,
            };
            let mut p = with_body("PUT", IMAP, IMAP, body);
            p.repeat = label == "repeat";
            p
        }
        "put-ews" => {
            let body = match label {
                "defaults" => {
                    r#"{"serverURL":"https://ews.example.com/EWS/Exchange.asmx","username":"svc","password":"p"}"#
                }
                "policy" => {
                    r#"{"serverURL":"https://exch.local/EWS/Exchange.asmx","username":"svc","password":"p","authMode":"per_user","privateHosts":["Exch.Local"],"privateCIDRs":["192.168.0.0/16"],"insecureSkipVerify":true}"#
                }
                "no-url" | "invalid" => r#"{"username":"svc"}"#,
                "no-user" => r#"{"serverURL":"https://ews.example.com"}"#,
                "http" => r#"{"serverURL":"http://ews.example.com","username":"svc"}"#,
                "no-scheme" => r#"{"serverURL":"ews.example.com/EWS","username":"svc"}"#,
                "ip" => r#"{"serverURL":"https://10.1.2.3/EWS","username":"svc"}"#,
                "public-ip" => r#"{"serverURL":"https://8.8.8.8/EWS","username":"svc"}"#,
                "loopback" => r#"{"serverURL":"https://127.0.0.1/EWS","username":"svc"}"#,
                "ipv6" => r#"{"serverURL":"https://[::1]:443/EWS","username":"svc"}"#,
                "local" => r#"{"serverURL":"https://exch.local/EWS","username":"svc"}"#,
                "userinfo" => r#"{"serverURL":"https://u:p@ews.example.com/EWS","username":"svc"}"#,
                "bad-port" => r#"{"serverURL":"https://ews.example.com:99x/EWS","username":"svc"}"#,
                "space-host" => r#"{"serverURL":"https://ews example.com/EWS","username":"svc"}"#,
                "upper-scheme" => r#"{"serverURL":"HTTPS://EWS.Example.com/EWS","username":"svc"}"#,
                "escaped-host" => {
                    r#"{"serverURL":"https://ews%2eexample.com/EWS","username":"svc"}"#
                }
                "bad-escape" => {
                    r#"{"serverURL":"https://ews%zz.example.com/EWS","username":"svc"}"#
                }
                "control" => r#"{"serverURL":"https://ews.example.com/\u0001","username":"svc"}"#,
                "empty-host" => r#"{"serverURL":"https:///EWS","username":"svc"}"#,
                "policy-half" => {
                    r#"{"serverURL":"https://ews.example.com","username":"svc","privateHosts":["h"]}"#
                }
                "policy-bad-cidr" => {
                    r#"{"serverURL":"https://ews.example.com","username":"svc","privateHosts":["h"],"privateCIDRs":["1.2.3.4/33"]}"#
                }
                "escape" => {
                    r#"{"serverURL":"https://ews.example.com/a?b=<c>&d","username":"u<s>&r","password":"p "}"#
                }
                "bad-json" => "{",
                "typed" => r#"{"serverURL":5,"username":"svc"}"#,
                "typed-bool" => {
                    r#"{"serverURL":"https://ews.example.com","username":"svc","insecureSkipVerify":"yes"}"#
                }
                "null-fields" => {
                    r#"{"serverURL":"https://ews.example.com","username":"svc","authMode":null,"privateHosts":null}"#
                }
                "case-keys" => {
                    r#"{"SERVERURL":"https://ews.example.com","UserName":"svc","AUTHMODE":"impersonation"}"#
                }
                "empty-body" => "",
                _ => EWS_OK,
            };
            let mut p = with_body("PUT", EWS, EWS, body);
            p.repeat = label == "repeat";
            p
        }
        "put-m365" => {
            let body = match label {
                "minimal" => r#"{"client_id":"a","client_secret":"b"}"#,
                "extras" => {
                    r#"{"client_id":"a","client_secret":"b","tenant_id":"t-1","cloud":"china","source_email":"s@example.com","source_user_id":"u-1"}"#
                }
                "no-client" | "invalid" => r#"{"client_secret":"b"}"#,
                "no-secret" => r#"{"client_id":"a"}"#,
                "escape" => r#"{"client_id":"a<b>&c","client_secret":" "}"#,
                "bad-json" => "[1,",
                "typed" => r#"{"client_id":1,"client_secret":"b"}"#,
                "null-fields" => r#"{"client_id":"a","client_secret":"b","tenant_id":null}"#,
                "case-keys" => r#"{"CLIENT_ID":"a","Client_Secret":"b"}"#,
                "unknown-keys" => r#"{"client_id":"a","client_secret":"b","x":[1,2]}"#,
                _ => M365_OK,
            };
            let mut p = with_body("PUT", M365, M365, body);
            p.repeat = label == "repeat";
            p
        }
        "m365-connect" => {
            let mut p = base("GET", CONNECT, CONNECT.to_owned());
            p.query = match label {
                "china" => "?cloud=china".into(),
                "global" => "?cloud=global".into(),
                "invalid" => "?cloud=mars".into(),
                "empty-cloud" => "?cloud=".into(),
                _ => String::new(),
            };
            p.head = label == "head";
            let _ = guarded;
            p
        }
        other => panic!("unknown action {other}"),
    }
}
