//! Fixtures and the request of each (action, label) case of the runner routes (#431).
use crate::common::BoxError;
use setjoin_conformance::fixture::{self, Account};
use tokio_postgres::Client;

pub const MISSING: i64 = 999_999_999;
/// The host's public address, where the admin connection test may dial (override with
/// `GOFREE_PUBLIC_IP`; only record mode binds it).
pub const PUBLIC: &str = "152.42.219.185";
pub const HOST: &str = "gofree-mbox6-imap.test";
pub const USER: &str = "alice";
pub const PASSWORD: &str = "pw";

/// The raw `DB_ENCRYPTION_KEY` both the frozen Go process and the replay use.
pub fn root() -> String {
    "22".repeat(32)
}

/// What a case does before the observed request, and how long it waits after it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Setup {
    None,
    /// Start a job over the (stalled) source first: it is running during the request.
    Running,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Settle {
    /// Wait until no job of the case is pending/fetching/importing.
    Terminal,
    /// Wait a fixed time (a parked job never settles).
    Fixed(u64),
}

pub struct Plan {
    pub method: &'static str,
    pub pattern: &'static str,
    pub path: String,
    pub body: String,
    pub repeat: bool,
    pub setup: Setup,
    pub settle: Settle,
    /// The profile `imap.defaults` the case runs under.
    pub profile: bool,
    /// Hold the source's fetches until the case releases them.
    pub stall: bool,
    /// The source accepts this password.
    pub password: &'static str,
    /// The source listens on the host's public address: the admin connection test dials
    /// with no private-network policy.
    pub public: bool,
}

pub struct Fx {
    pub a: Account,
    pub b: Account,
    pub b_email: String,
    /// completed (a), failed (b, no config), cancelled (b, no config)
    pub j1: i64,
    pub j2: i64,
    pub j3: i64,
    /// pending (a) with a valid config; paused (b) with a valid config.
    pub pending: i64,
    pub paused: i64,
    pub sealed: Vec<u8>,
    pub role: i64,
    pub a_domain: String,
    pub b_domain: String,
    pub saved: Vec<(String, serde_json::Value, bool)>,
}

pub const KEYS: [&str; 3] = ["imap.defaults", "ews.global", "m365.app"];

pub fn access(label: &str) -> (Vec<&'static str>, bool) {
    let label = label
        .strip_prefix("ews-")
        .or_else(|| label.strip_prefix("m365-"))
        .unwrap_or(label);
    let perms = match label {
        "denied" => vec!["users.read"],
        "wrong-perm" => vec!["domains.read"],
        _ => vec!["mail.pipeline"],
    };
    (perms, label == "foreign")
}

/// A pending job config for an IMAP source (`use_global_auth` with the profile).
pub fn job_config(port: u16) -> String {
    serde_json::json!({
        "use_global_auth": true, "source_type": "imap", "self_service": false,
        "imap": {"host": HOST, "port": port, "tls_mode": "none",
                 "credentials": {"username": USER, "password": PASSWORD}},
    })
    .to_string()
}

pub fn profile(port: u16) -> String {
    serde_json::json!({
        "host": HOST, "port": port, "tls_mode": "none",
        "private_hosts": [HOST], "private_cidrs": ["172.17.0.0/16"],
    })
    .to_string()
}

impl Fx {
    pub async fn build(c: &Client, label: &str, port: u16) -> Result<Fx, BoxError> {
        use setjoin_mailboxes::migration as m;
        let a = fixture::account(c, "mbox6-admin").await?;
        let b = fixture::account(c, "mbox6-target").await?;
        let name = |d: i64| async move {
            Ok::<String, BoxError>(
                c.query_one("SELECT name FROM domains WHERE id=$1", &[&d])
                    .await?
                    .get(0),
            )
        };
        let (a_domain, b_domain) = (name(a.domain).await?, name(b.domain).await?);
        let b_email: String = c
            .query_one("SELECT email FROM users WHERE id=$1", &[&b.user])
            .await?
            .get(0);
        let key = m::derive_key(&root(), "migration").expect("key");
        let sealed = m::seal(job_config(port).as_bytes(), &key).expect("seal");
        let mut ids = vec![];
        for (user, mailbox, status, hours, config) in [
            (a.user, a.mailbox, "completed", 5, None::<Vec<u8>>),
            (b.user, b.mailbox, "failed", 4, None),
            (b.user, b.mailbox, "cancelled", 3, None),
        ] {
            // At most one active job per user: the second active row of a user waits.
            let id: i64 = c
                .query_one(
                    "INSERT INTO migration_jobs (user_id,source_type,status,progress,error_log,created_at,target_mailbox_id,source_config_enc,started_at) \
                     VALUES ($1,'imap',$2,'{}','[]',now()-($3||' hours')::interval,$4,$5,CASE WHEN $2<>'pending' THEN now() END) RETURNING id",
                    &[&user, &status, &hours.to_string(), &mailbox, &config],
                )
                .await?
                .get(0);
            ids.push(id);
        }
        let (perms, scoped) = access(label);
        let perms: Vec<String> = perms.iter().map(|p| p.to_string()).collect();
        let scope: Option<i64> = scoped.then_some(a.domain);
        let role: i64 = c
            .query_one(
                "INSERT INTO admin_role_groups(name,permissions,domain_scope) VALUES ($1,$2,$3) RETURNING id",
                &[&format!("mbox6-role-{}", a.user), &perms, &scope],
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
            b_email,
            j1: ids[0],
            j2: ids[1],
            j3: ids[2],
            pending: 0,
            paused: 0,
            sealed,
            role,
            a_domain,
            b_domain,
            saved,
        })
    }

    /// The active job a case needs (one per user, the target's): created after the frozen
    /// Go process started, whose startup recovery fails every paused job in the database.
    pub async fn add_active(&mut self, c: &Client, status: &str) -> Result<(), BoxError> {
        let id: i64 = c
            .query_one(
                "INSERT INTO migration_jobs (user_id,source_type,status,progress,error_log,created_at,target_mailbox_id,source_config_enc,started_at) \
                 VALUES ($1,'imap',$2,'{}','[]',now()-interval '1 hour',$3,$4,CASE WHEN $2<>'pending' THEN now() END) RETURNING id",
                &[&self.b.user, &status, &self.b.mailbox, &self.sealed],
            )
            .await?
            .get(0);
        if status == "pending" {
            self.pending = id;
        } else {
            self.paused = id;
        }
        Ok(())
    }

    pub async fn put_profile(&self, c: &Client, port: u16) -> Result<(), BoxError> {
        c.execute(
            "INSERT INTO system_config(key,value,encrypted) VALUES ('imap.defaults',$1::text::jsonb,false) \
             ON CONFLICT (key) DO UPDATE SET value=EXCLUDED.value, encrypted=false",
            &[&profile(port)],
        )
        .await?;
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
        // Imported messages and the tags created for them belong to the fixture mailboxes.
        c.execute(
            "DELETE FROM message_tags WHERE message_id IN (SELECT id FROM messages WHERE mailbox_id=ANY($1))",
            &[&vec![self.a.mailbox, self.b.mailbox]],
        )
        .await?;
        // Calendar/address-book journal triggers need the mailbox to still exist.
        c.execute(
            "DELETE FROM calendars WHERE mailbox_id=ANY($1)",
            &[&vec![self.a.mailbox, self.b.mailbox]],
        )
        .await?;
        c.execute(
            "DELETE FROM addressbooks WHERE mailbox_id=ANY($1)",
            &[&vec![self.a.mailbox, self.b.mailbox]],
        )
        .await?;
        fixture::remove(c, &self.a).await?;
        fixture::remove(c, &self.b).await?;
        Ok(())
    }

    pub fn ids(&self) -> Vec<(&'static str, i64, String)> {
        let mut out: Vec<(&'static str, i64, String)> = vec![];
        for key in ["user_id", "actor_id", "actor_user_id"] {
            out.push((key, self.a.user, "<admin>".into()));
            out.push((key, self.b.user, "<target>".into()));
        }
        for (id, name) in self.jobs() {
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

    pub fn jobs(&self) -> [(i64, &'static str); 5] {
        [
            (self.j1, "<job-completed>"),
            (self.j2, "<job-failed>"),
            (self.j3, "<job-cancelled>"),
            (self.pending, "<job-pending>"),
            (self.paused, "<job-paused>"),
        ]
    }

    /// Domain names and the source's port carry per-run values.
    pub fn names(&self, text: &str, port: u16) -> String {
        text.replace(&self.a_domain, "host-a.test")
            .replace(&self.b_domain, "host-b.test")
            .replace(&self.b_email, "target@host-b.test")
            .replace(&format!("\"port\":{port}"), "\"port\":\"<port>\"")
            .replace(&format!(":{port}"), ":<port>")
            .replace(PUBLIC, "<public-ip>")
            .replace(&format!("\"imap_port\":{port}"), "\"imap_port\":\"<port>\"")
    }
}

fn base(pattern: &'static str, path: String, body: &str) -> Plan {
    Plan {
        method: "POST",
        pattern,
        path,
        body: body.to_owned(),
        repeat: false,
        setup: Setup::None,
        settle: Settle::Terminal,
        profile: true,
        stall: false,
        password: PASSWORD,
        public: false,
    }
}

const START: &str = "/admin/migration/start";
const TEST: &str = "/admin/migration/test-connection";
const CANCEL: &str = "/admin/migration/jobs/{id}/cancel";
const RETRY: &str = "/admin/migration/jobs/{id}/retry";
const PAUSE: &str = "/admin/migration/jobs/{id}/pause";
const RESUME: &str = "/admin/migration/jobs/{id}/resume";

/// `{PORT}`, `{TARGET}`, `{HOST}` in a body are replaced when the request is built.
fn imap_start(targets: &str) -> String {
    format!(
        r#"{{"source_type":"imap","imap_host":"{HOST}","imap_port":{{PORT}},"imap_ssl":false,"targets":{targets}}}"#
    )
}
const ONE_TARGET: &str = r#"[{"source_email":"alice","target_email":"{TARGET}","password":"pw"}]"#;

/// The request of an (action, label) case. `{ID:<name>}` in a path names a fixture job.
pub fn plan(action: &str, label: &str) -> Plan {
    let guarded = matches!(label, "foreign" | "denied" | "wrong-perm");
    match action {
        "start" => {
            let mut p = base(START, START.into(), &imap_start(ONE_TARGET));
            match label {
                "success" | "foreign" | "denied" | "wrong-perm" => {}
                "repeat" => p.repeat = true,
                "bare" => p.profile = false,
                "bad-login" => p.password = "other",
                "multi" => {
                    p.body = imap_start(
                        r#"[{"source_email":"alice","target_email":"{TARGET}","password":"pw"},{"source_email":"alice","target_email":"{TARGET}","password":"pw"}]"#,
                    )
                }
                "tls" => {
                    p.body = format!(
                        r#"{{"source_type":"imap","imap_host":"{HOST}","imap_port":{{PORT}},"imap_ssl":true,"targets":{ONE_TARGET}}}"#
                    )
                }
                "no-port" => {
                    p.body = format!(
                        r#"{{"source_type":"imap","imap_host":"{HOST}","imap_ssl":false,"targets":{ONE_TARGET}}}"#
                    )
                }
                "unknown-target" => {
                    p.body = imap_start(
                        r#"[{"source_email":"alice","target_email":"nobody@nowhere.test","password":"pw"}]"#,
                    )
                }
                "no-host" => p.body = format!(r#"{{"source_type":"imap","targets":{ONE_TARGET}}}"#),
                "bad-type" => {
                    p.body = format!(r#"{{"source_type":"pop3","targets":{ONE_TARGET}}}"#)
                }
                "no-type" => p.body = format!(r#"{{"targets":{ONE_TARGET}}}"#),
                "no-targets" => p.body = imap_start("[]"),
                "null-targets" => p.body = imap_start("null"),
                "empty-source" => {
                    p.body = imap_start(r#"[{"source_email":"","target_email":"{TARGET}"}]"#)
                }
                "empty-target" => {
                    p.body = imap_start(r#"[{"source_email":"alice","target_email":""}]"#)
                }
                "ews-no-url" => {
                    p.body = format!(r#"{{"source_type":"ews","targets":{ONE_TARGET}}}"#)
                }
                "ews-http" => {
                    p.body = format!(
                        r#"{{"source_type":"ews","ews_url":"http://ews.example.com/EWS","targets":{ONE_TARGET}}}"#
                    )
                }
                "ews-ip" => {
                    p.body = format!(
                        r#"{{"source_type":"ews","ews_url":"https://10.0.0.1/EWS","targets":{ONE_TARGET}}}"#
                    )
                }
                "m365-no-config" => {
                    p.body = format!(r#"{{"source_type":"m365","targets":{ONE_TARGET}}}"#)
                }
                "case-keys" => {
                    p.body = format!(
                        r#"{{"SOURCE_TYPE":"imap","Imap_Host":"{HOST}","IMAP_PORT":{{PORT}},"imap_ssl":false,"unknown":1,"targets":[{{"SOURCE_EMAIL":"alice","Target_Email":"{{TARGET}}","password":"pw"}}]}}"#
                    )
                }
                "bad-json" => p.body = "{".into(),
                "typed" => p.body = r#"{"source_type":5}"#.into(),
                "port-float" => {
                    p.body = format!(
                        r#"{{"source_type":"imap","imap_host":"{HOST}","imap_port":993.5,"targets":{ONE_TARGET}}}"#
                    )
                }
                "empty-body" => p.body = String::new(),
                "array-body" => p.body = "[]".into(),
                other => panic!("no start/{other}"),
            }
            if guarded {
                p.settle = Settle::Fixed(300);
            }
            p
        }
        "test-connection" => {
            let body = |inner: &str| format!("{{{inner}}}");
            let imap = |extra: &str| {
                body(&format!(
                    r#""source_type":"imap","host":"{{PUBLIC}}","port":{{PORT}},"ssl":false{extra}"#
                ))
            };
            let mut p = base(TEST, TEST.into(), &imap(""));
            p.public = true;
            p.profile = false;
            p.settle = Settle::Fixed(100);
            match label {
                "success" | "foreign" | "denied" | "wrong-perm" => {}
                "repeat" => p.repeat = true,
                "login" => p.body = imap(r#","username":"alice","password":"pw""#),
                "bad-login" => p.body = imap(r#","username":"alice","password":"nope""#),
                "list-only-user" => p.body = imap(r#","username":"alice""#),
                "refused" => {
                    p.body = body(r#""source_type":"imap","host":"{PUBLIC}","port":1,"ssl":false"#)
                }
                "private" => {
                    p.body =
                        body(r#""source_type":"imap","host":"10.1.2.3","port":{PORT},"ssl":false"#)
                }
                "loopback" => {
                    p.body =
                        body(r#""source_type":"imap","host":"127.0.0.1","port":{PORT},"ssl":false"#)
                }
                "metadata" => {
                    p.body = body(
                        r#""source_type":"imap","host":"169.254.169.254","port":{PORT},"ssl":false"#,
                    )
                }
                "no-host" => p.body = body(r#""source_type":"imap""#),
                "bad-type" => p.body = body(r#""source_type":"pop3""#),
                "no-type" => p.body = "{}".into(),
                "ews-no-url" => p.body = body(r#""source_type":"ews""#),
                "ews-http" => {
                    p.body = body(r#""source_type":"ews","url":"http://ews.example.com/EWS""#)
                }
                "ews-ip" => p.body = body(r#""source_type":"ews","url":"https://10.0.0.1/EWS""#),
                "m365-no-config" => p.body = body(r#""source_type":"m365""#),
                "case-keys" => {
                    p.body = body(
                        r#""SOURCE_TYPE":"imap","Host":"{PUBLIC}","PORT":{PORT},"ssl":false,"extra":true"#,
                    )
                }
                "bad-json" => p.body = "{".into(),
                "typed" => p.body = r#"{"source_type":5}"#.into(),
                "empty-body" => p.body = String::new(),
                "array-body" => p.body = "[]".into(),
                other => panic!("no test-connection/{other}"),
            }
            p
        }
        "cancel" | "retry" | "pause" | "resume" => {
            let (pattern, _ok) = match action {
                "cancel" => (CANCEL, "running"),
                "retry" => (RETRY, "failed"),
                "pause" => (PAUSE, "running"),
                _ => (RESUME, "paused"),
            };
            let id = |name: &str| pattern.replace("{id}", name);
            let mut p = base(pattern, id("{ID:failed}"), "");
            p.settle = Settle::Fixed(1500);
            match label {
                "running" => {
                    p.setup = Setup::Running;
                    p.stall = true;
                    p.path = id("{ID:started}");
                    p.settle = if action == "pause" {
                        Settle::Fixed(1500)
                    } else {
                        Settle::Terminal
                    };
                }
                "failed" | "paused" | "pending" | "completed" | "cancelled" => {
                    p.path = id(&format!("{{ID:{label}}}"));
                    p.settle = Settle::Terminal;
                    if label == "failed" || label == "completed" || label == "cancelled" {
                        p.settle = Settle::Fixed(1000);
                    }
                }
                "missing" => p.path = id("999999999"),
                "invalid" => p.path = id("abc"),
                "plus" => p.path = id("%2B1"),
                "huge" => p.path = id("99999999999999999999"),
                "zero" => p.path = id("0"),
                "negative" => p.path = id("-1"),
                "repeat" => {
                    p.repeat = true;
                    p.path = id(if action == "resume" {
                        "{ID:paused}"
                    } else {
                        "{ID:failed}"
                    });
                    p.settle = Settle::Fixed(1000);
                }
                "foreign" | "denied" | "wrong-perm" => {
                    p.path = id("{ID:failed}");
                    p.settle = Settle::Fixed(300);
                }
                other => panic!("no {action}/{other}"),
            }
            p
        }
        other => panic!("no action {other}"),
    }
}

/// Resolve the `{ID:name}`, `{PORT}` and `{TARGET}` tokens of a path or body.
pub fn fill(text: &str, fx: &Fx, started: Option<i64>, port: u16) -> String {
    let mut out = text
        .replace("{PUBLIC}", PUBLIC)
        .replace("{PORT}", &port.to_string())
        .replace("{TARGET}", &fx.b_email);
    for (name, id) in [
        ("failed", fx.j2),
        ("completed", fx.j1),
        ("cancelled", fx.j3),
        ("pending", fx.pending),
        ("paused", fx.paused),
        ("started", started.unwrap_or(0)),
    ] {
        out = out.replace(&format!("{{ID:{name}}}"), &id.to_string());
    }
    out
}

pub(super) fn provider_plan(action: &str, label: &str) -> Plan {
    if action == "callback" {
        let pattern = "/admin/migration/m365/callback";
        let mut p = base(
            pattern,
            format!("{pattern}?state=fixture-state&admin_consent=True&tenant=candidate"),
            "",
        );
        p.method = "GET";
        p.profile = false;
        match label {
            "success" | "repeat" | "foreign" | "denied" | "wrong-perm" | "expired"
            | "fabricated" | "other-actor" | "verify-failure" | "no-config" | "bad-config" => {}
            "no-cookie" => {}
            "mismatch" => p.path = p.path.replace("state=fixture-state", "state=other"),
            "no-state" => p.path = p.path.replace("state=fixture-state&", ""),
            "denied-consent" => {
                p.path = p.path.replace("admin_consent=True", "admin_consent=False")
            }
            "no-tenant" => p.path = p.path.replace("&tenant=candidate", ""),
            "description" => {
                p.path = p.path.replace(
                    "admin_consent=True",
                    "admin_consent=False&error_description=Denied+by+fixture",
                )
            }
            "head" => p.method = "HEAD",
            _ => panic!("callback/{label}"),
        }
        p.repeat = label == "repeat";
        return p;
    }
    if label.starts_with("upload-") {
        let mut p = plan("resume", "pending");
        p.profile = label.contains("compound");
        p.repeat = label.ends_with("repeat");
        return p;
    }
    let (source, kind) = label.split_once('-').unwrap();
    let mut p = if action == "start" {
        base(
            START,
            START.into(),
            &format!(
                r#"{{"source_type":"{source}","ews_url":"https://ews.mbox7.test/EWS","ews_username":"service","ews_password":"pw","targets":[{{"source_email":"source@example.test","target_email":"{{TARGET}}","password":"pw"}}]}}"#
            ),
        )
    } else if action == "test-connection" {
        base(
            TEST,
            TEST.into(),
            &format!(
                r#"{{"source_type":"{source}","url":"https://ews.mbox7.test/EWS","username":"service","password":"pw"}}"#
            ),
        )
    } else {
        let mut p = plan(
            action,
            if kind == "foreign" {
                "foreign"
            } else if kind == "invalid" {
                "invalid"
            } else {
                "failed"
            },
        );
        p.profile = false;
        p.setup = Setup::None;
        p
    };
    p.profile = false;
    p.repeat = kind == "repeat";
    if kind == "invalid" {
        p.body = "{".into();
    }
    p
}
