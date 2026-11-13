//! #400 identity-source runtime: seed-plus-one-tick oracle for the catalog `ldap:`/`ad:`
//! source manager. Record mode starts frozen Go on a seeded catalog (its manager
//! reconciles at boot and every source runs one cycle) and waits for the database to
//! settle; replay runs the Rust manager's `start` on the same seed and compares rows and
//! directory operations. Directories are in-process fakes on random loopback ports
//! (catalog sources name their own host and port; there is no DNS discovery).
//!
//! Record: GOFREE_RECORD_GO_BINARY=<frozen mailserverd> GOFREE_GO_SOURCE=<commit>
//! cargo test -p setjoin-gateway --test identity_source_runtime -- --test-threads=1
use base64::Engine;
use serde_json::{json, Value};
use setjoin_conformance::ldap_fake::{Entry, FakeLdap, Transport, CA_PEM};
use setjoin_conformance::{fixture, golden, harness::Db};
use setjoin_directory_sync::catalog::{IdentitySourceRuntime, SourceConfig};
use std::sync::Arc;
use std::time::{Duration, Instant};

mod common;
use common::BoxError;

const KEY: &str = "22";
const PW: &str = "pw";
const BASE: &str = "DC=corp,DC=example,DC=test";

type Opt = Result<(), BoxError>;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Secret {
    Set,
    /// An envelope without the `bindPassword` secret.
    Missing,
    /// No envelope at all (what the seeded `legacy:ad` row has).
    NoEnvelope,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Reach {
    Up,
    /// Nothing listens on the source's port.
    Down,
    /// The directory rejects the bind password.
    BadPassword,
}

#[derive(Clone, Copy)]
struct Src {
    key: &'static str,
    kind: &'static str,
    state: &'static str,
    starttls: bool,
    secret: Secret,
    reach: Reach,
    subject: &'static str,
    filter: &'static str,
    /// Committed cursor JSON seeded on the source row.
    cursor: Option<&'static str>,
    dir: u8,
}

const fn src(key: &'static str, kind: &'static str, state: &'static str, dir: u8) -> Src {
    Src {
        key,
        kind,
        state,
        starttls: false,
        secret: Secret::Set,
        reach: Reach::Up,
        subject: if matches!(kind.as_bytes(), b"ad") {
            "objectGUID"
        } else {
            "entryUUID"
        },
        filter: "",
        cursor: None,
        dir,
    }
}

fn sources(case: &str) -> Vec<Src> {
    let mut all = vec![
        src("ldap:alpha", "ldap", "active", 1),
        src("ad:beta", "ad", "active", 2),
        Src {
            starttls: true,
            filter: "(&(objectClass=person)(mail=*))",
            ..src("ldap:gamma", "ldap", "active", 3)
        },
        Src {
            subject: "msDS-ConsistencyGuid",
            filter: "(&(objectClass=user)(objectCategory=person)(department=Eng*))",
            ..src("ad:consist", "ad", "active", 4)
        },
        src("ldap:paused", "ldap", "paused", 1),
        src("ad:retired", "ad", "retired", 2),
        Src {
            secret: Secret::Missing,
            ..src("ldap:nosecret", "ldap", "active", 1)
        },
        Src {
            secret: Secret::NoEnvelope,
            ..src("ad:noenvelope", "ad", "active", 2)
        },
        src("ldap:draft", "ldap", "draft", 1),
    ];
    match case {
        "incremental" => {
            all[0].cursor = Some("{\"modifyTimestamp\":\"20260101000002Z\"}");
            all[1].cursor = Some("{\"usn\":\"1002\"}");
        }
        "failures" => {
            all[0].reach = Reach::Down;
            all[1].reach = Reach::BadPassword;
        }
        _ => {}
    }
    all
}

fn guid(dir: u8, n: u8) -> [u8; 16] {
    let mut g = [0u8; 16];
    for (i, b) in g.iter_mut().enumerate() {
        *b = (dir << 4) | (n.wrapping_add(i as u8) & 0x0f);
    }
    g[0] = 0x40 + dir;
    g[1] = n;
    g
}

fn entries(s: &Src, dom: &str) -> Vec<Entry> {
    let dn = |cn: &str| format!("CN={cn},OU=People,{BASE}");
    let ldap_person = |cn: &str, n: u32, extra: &[(&str, &str)]| {
        let mail = format!("{cn}@{dom}");
        let uuid = format!("uuid-{}-{cn}", s.dir);
        let stamp = format!("202601010000{:02}Z", n);
        let mut attrs: Vec<(&str, &str)> = vec![
            ("objectClass", "person"),
            ("cn", cn),
            ("mail", &mail),
            ("displayName", cn),
            ("entryUUID", &uuid),
            ("modifyTimestamp", &stamp),
        ];
        attrs.extend_from_slice(extra);
        Entry::new(&dn(cn), &attrs)
    };
    let ad_person = |cn: &str, n: u8, usn: u32, extra: &[(&str, &str)]| {
        let mail = format!("{cn}@{dom}");
        let usn = usn.to_string();
        let mut attrs: Vec<(&str, &str)> = vec![
            ("objectClass", "user"),
            ("objectCategory", "person"),
            ("sAMAccountName", cn),
            ("mail", &mail),
            ("displayName", cn),
            ("uSNChanged", &usn),
        ];
        attrs.extend_from_slice(extra);
        Entry::new(&dn(cn), &attrs).with_bin(s.subject, &guid(s.dir, n))
    };
    match s.dir {
        1 => vec![
            ldap_person(
                "ann",
                1,
                &[("title", "Engineer"), ("department", "Engineering")],
            ),
            ldap_person("bob", 2, &[("manager", &dn("ann"))]),
            ldap_person("cat", 3, &[("nsAccountLock", "TRUE")]),
            Entry::new(
                &dn("nomail"),
                &[
                    ("objectClass", "person"),
                    ("cn", "nomail"),
                    ("entryUUID", "uuid-1-nomail"),
                    ("modifyTimestamp", "20260101000004Z"),
                ],
            ),
        ],
        2 => vec![
            ad_person(
                "amy",
                1,
                1001,
                &[("givenName", "Amy"), ("sn", "A"), ("manager", &dn("abe"))],
            ),
            ad_person(
                "abe",
                2,
                1002,
                &[("userAccountControl", "514"), ("department", "Ops")],
            ),
            ad_person(
                "ada",
                3,
                1003,
                &[("userPrincipalName", "ada@corp.example.test")],
            ),
        ],
        3 => vec![
            ldap_person("gus", 5, &[("manager", &dn("gina"))]),
            ldap_person("gina", 6, &[]),
            Entry::new(
                &dn("nobody"),
                &[
                    ("objectClass", "person"),
                    ("cn", "nobody"),
                    ("entryUUID", "uuid-3-nobody"),
                    ("modifyTimestamp", "20260101000007Z"),
                ],
            ),
        ],
        _ => vec![
            ad_person("dee", 1, 2001, &[("department", "Eng"), ("title", "Dev")]),
            ad_person("dan", 2, 2002, &[("department", "Sales")]),
        ],
    }
}

fn codec(deployment: &str) -> Result<Arc<setjoin_config_secret::ConfigSecretCodec>, BoxError> {
    let keyring = setjoin_config_secret::keyring_from_lookup(deployment, |name| match name {
        "DB_ENCRYPTION_KEY" => Some(KEY.repeat(32)),
        _ => None,
    })?;
    Ok(Arc::new(setjoin_config_secret::ConfigSecretCodec::new(
        keyring,
    )?))
}

fn decode(
    codec: Option<&setjoin_config_secret::ConfigSecretCodec>,
    key: &str,
    kind: &str,
    envelope: &[u8],
) -> Result<SourceConfig, String> {
    let c = setjoin_admin_identity::idv2_source::decode_runtime(codec, key, kind, envelope)?;
    Ok(SourceConfig {
        source_key: c.source_key,
        kind: c.kind,
        host: c.host,
        port: c.port,
        transport: c.transport,
        base_dn: c.base_dn,
        bind_dn: c.bind_dn,
        subject_attribute: c.subject_attribute,
        user_filter: c.user_filter,
        group_filter: c.group_filter,
        password: c.password,
    })
}

fn envelope(
    codec: &setjoin_config_secret::ConfigSecretCodec,
    s: &Src,
    port: u16,
) -> Result<Vec<u8>, BoxError> {
    let mut spec = json!({
        "type": s.kind,
        "endpoint": {"host": "127.0.0.1", "port": port, "tls": if s.starttls { "starttls" } else { "ldaps" }},
        "subjectAttribute": s.subject,
        "baseDN": BASE,
        "bindDN": format!("CN=svc,{BASE}"),
    });
    if !s.filter.is_empty() {
        spec["userFilter"] = json!(s.filter);
    }
    let document = json!({
        "apiVersion": "setjoin.io/v1", "kind": "IdentitySource",
        "metadata": {"sourceKey": s.key, "displayName": s.key},
        "spec": spec,
    });
    let mut secrets = std::collections::BTreeMap::new();
    if s.secret == Secret::Set {
        secrets.insert(
            "bindPassword".to_owned(),
            base64::engine::general_purpose::STANDARD.encode(PW),
        );
    }
    let plain =
        setjoin_admin_identity::idv2_source::stored_plaintext(&document.to_string(), &secrets);
    Ok(codec.encrypt(&format!("identity_source.{}", s.key), plain.as_bytes())?)
}

/// Run-specific values replaced by stable names.
fn mask(v: &mut Value, domain: &str) {
    match v {
        Value::String(s) => {
            *s = s.replace(domain, "host-a.test");
            if s.starts_with("2026-") && s.len() > 18 && (s.ends_with('Z') || s.ends_with("+00:00"))
            {
                *s = "<timestamp>".into();
            }
        }
        Value::Array(xs) => xs.iter_mut().for_each(|x| mask(x, domain)),
        Value::Object(map) => {
            for (k, x) in map.iter_mut() {
                if k == "duration_ms" {
                    *x = json!("<ms>");
                } else if k == "batch_id" || k == "batchId" || k == "process_instance_id" {
                    *x = json!("<uuid>");
                } else if (k.ends_with("_id") || k == "id") && x.is_number() {
                    *x = json!("<id>");
                } else {
                    mask(x, domain);
                }
            }
        }
        _ => {}
    }
}

async fn rows(
    c: &tokio_postgres::Client,
    sql: &str,
    args: &[&(dyn tokio_postgres::types::ToSql + Sync)],
) -> Result<Vec<Value>, BoxError> {
    c.query(sql, args)
        .await?
        .iter()
        .map(|r| serde_json::from_str(&r.get::<_, String>(0)).map_err(Into::into))
        .collect()
}

async fn snapshot(
    c: &tokio_postgres::Client,
    domain: i64,
    keys: &[String],
) -> Result<Value, BoxError> {
    Ok(json!({
        "sources": rows(c, "SELECT jsonb_build_object('key',source_key,'state',state,'generation',generation,\
            'cursor',committed_cursor,'pending',pending_cursor,'success',last_success_at IS NOT NULL,\
            'failure',last_failure_at IS NOT NULL,'error',last_error_code)::text \
            FROM identity_sources WHERE source_key=ANY($1) ORDER BY source_key", &[&keys]).await?,
        "users": rows(c, "SELECT jsonb_build_object('email',u.email,'sync_source',u.sync_source,'enabled',u.enabled,\
            'display_name',u.display_name,'first_name',u.first_name,'last_name',u.last_name,'job_title',u.job_title,\
            'phone',u.phone,'krb5_principal',u.krb5_principal,'ad_upn',u.ad_upn,'username',u.username,\
            'manager',(SELECT m.email FROM users m WHERE m.id=u.manager_id),\
            'department',(SELECT d.path FROM departments d WHERE d.id=u.department_id),\
            'local_overrides',u.local_overrides)::text FROM users u WHERE u.domain_id=$1 ORDER BY u.email", &[&domain]).await?,
        "links": rows(c, "SELECT jsonb_build_object('source',s.source_key,'subject',l.external_subject,'user',u.email,\
            'state',l.state,'purposes',l.purposes,'method',l.link_method)::text \
            FROM user_identity_links l JOIN users u ON u.id=l.user_id JOIN identity_sources s ON s.id=l.source_id \
            WHERE u.domain_id=$1 ORDER BY 1", &[&domain]).await?,
        "batches": rows(c, "SELECT jsonb_build_object('source',s.source_key,'generation',b.source_generation,\
            'cursor',b.remote_cursor,'state',b.state,'entries',b.entry_count,'applied',b.applied_count,\
            'quarantined',b.quarantined_count,'error',b.last_error_code)::text \
            FROM identity_source_batches b JOIN identity_sources s ON s.id=b.source_id \
            WHERE s.source_key=ANY($1) ORDER BY 1", &[&keys]).await?,
        "inbox": rows(c, "SELECT jsonb_build_object('source',s.source_key,'object_key',i.object_key,'state',i.state,\
            'subject',i.immutable_subject,'payload',i.sanitized_payload,'attempts',i.attempt_count,\
            'error',i.last_error_code)::text \
            FROM identity_source_inbox i JOIN identity_sources s ON s.id=i.source_id \
            WHERE s.source_key=ANY($1) ORDER BY 1", &[&keys]).await?,
        "quarantine": rows(c, "SELECT jsonb_build_object('source',s.source_key,'object_key',q.object_key,\
            'reason',q.reason_code,'occurrences',q.occurrences)::text \
            FROM identity_source_quarantines q JOIN identity_sources s ON s.id=q.source_id \
            WHERE s.source_key=ANY($1) ORDER BY 1", &[&keys]).await?,
        "leases": rows(c, "SELECT jsonb_build_object('source',s.source_key,'generation',l.source_generation)::text \
            FROM identity_source_leases l JOIN identity_sources s ON s.id=l.source_id \
            WHERE s.source_key=ANY($1) ORDER BY 1", &[&keys]).await?,
        "sync_log": rows(c, "SELECT jsonb_build_object('source',l.source,'key',s.source_key,'checked',l.users_checked,\
            'created',l.users_created,'updated',l.users_updated,'disabled',l.users_disabled,\
            'skipped',l.fields_skipped,'conflicts',l.conflicts_found,'error',l.error,'details',l.details)::text \
            FROM identity_sync_log l JOIN identity_sources s ON s.id=l.source_id \
            WHERE s.source_key=ANY($1) ORDER BY 1", &[&keys]).await?,
    }))
}

struct Directory {
    fake: Option<FakeLdap>,
    port: u16,
}

async fn directory(s: &Src, dom: &str) -> Result<Directory, BoxError> {
    let listener = setjoin_conformance::ports::listener().await;
    let port = listener.local_addr()?.port();
    if s.reach == Reach::Down {
        drop(listener);
        return Ok(Directory { fake: None, port });
    }
    let fake = FakeLdap::on(
        listener,
        if s.starttls {
            Transport::StartTls
        } else {
            Transport::Ldaps
        },
    )?;
    fake.set_credentials(
        &format!("CN=svc,{BASE}"),
        if s.reach == Reach::BadPassword {
            "other"
        } else {
            PW
        },
    );
    fake.set_entries(entries(s, dom));
    Ok(Directory {
        fake: Some(fake),
        port,
    })
}

/// Poll until the observed rows stop changing (after at least `floor`).
async fn settle(
    owner: &tokio_postgres::Client,
    domain: i64,
    keys: &[String],
    floor: Duration,
) -> Result<Value, BoxError> {
    let started = Instant::now();
    let mut last = String::new();
    let mut stable = 0;
    loop {
        let now = snapshot(owner, domain, keys).await?.to_string();
        if now == last {
            stable += 1;
        } else {
            stable = 0;
            last = now;
        }
        if stable >= 5 && started.elapsed() >= floor {
            return Ok(serde_json::from_str(&last)?);
        }
        if started.elapsed() > Duration::from_secs(120) {
            return Err("catalog sources did not settle".into());
        }
        tokio::time::sleep(Duration::from_millis(400)).await;
    }
}

static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

struct Setup {
    db: Db,
    owner: tokio_postgres::Client,
    account: fixture::Account,
    domain: String,
    codec: Arc<setjoin_config_secret::ConfigSecretCodec>,
    saved: Vec<(String, String)>,
    saved_toggle: bool,
    audit_start: i64,
    log_after: i64,
}

async fn setup() -> Result<Option<Setup>, BoxError> {
    let ca = std::env::temp_dir().join("setjoin-identity-source-oracle-ca.pem");
    std::fs::write(&ca, CA_PEM)?;
    std::env::set_var("SSL_CERT_FILE", &ca);
    let Some(db) = Db::for_case("identity-source-runtime") else {
        return Ok(None);
    };
    let owner = db.connect().await?;
    let account = fixture::account(&owner, "is7-admin").await?;
    let domain: String = owner
        .query_one("SELECT name FROM domains WHERE id=$1", &[&account.domain])
        .await?
        .get(0);
    let deployment: String = owner
        .query_one(
            "SELECT value #>> '{}' FROM system_config WHERE key='identity.deployment_id'",
            &[],
        )
        .await?
        .get(0);
    let saved: Vec<(String, String)> = owner
        .query("SELECT source_key,state FROM identity_sources WHERE source_key IN ('legacy:ad','legacy:ldap','legacy:scim')", &[])
        .await?
        .iter()
        .map(|r| (r.get(0), r.get(1)))
        .collect();
    let saved_toggle: bool = owner
        .query_one(
            "SELECT enabled FROM feature_toggles WHERE key='feature.identity_model_v2'",
            &[],
        )
        .await?
        .get(0);
    let audit_start: i64 = owner
        .query_one("SELECT COALESCE(max(id),0) FROM admin_audit_log", &[])
        .await?
        .get(0);
    let log_after: i64 = owner
        .query_one("SELECT COALESCE(max(id),0) FROM identity_sync_log", &[])
        .await?
        .get(0);
    let codec = codec(&deployment)?;
    Ok(Some(Setup {
        db,
        owner,
        account,
        domain,
        codec,
        saved,
        saved_toggle,
        audit_start,
        log_after,
    }))
}

async fn seed(
    st: &Setup,
    list: &[Src],
    dirs: &[Directory],
    gate: bool,
    fault: Option<&str>,
) -> Opt {
    let o = &st.owner;
    // Baseline: the legacy catalog rows as the schema seeds them, so only the new sources matter.
    o.batch_execute("UPDATE identity_sources SET state='active' WHERE source_key='legacy:ad'; UPDATE identity_sources SET state='paused' WHERE source_key='legacy:ldap'").await?;
    for (s, d) in list.iter().zip(dirs) {
        let env = if s.secret == Secret::NoEnvelope {
            None
        } else {
            Some(envelope(&st.codec, s, d.port)?)
        };
        o.execute(
            "INSERT INTO identity_sources(source_key,display_name,kind,capabilities,state,config_envelope) \
             VALUES($1,$1,$2,'{\"authenticate\":false,\"provision_lifecycle\":true,\"stable_immutable_subject\":true}'::jsonb,$3,$4)",
            &[&s.key, &s.kind, &s.state, &env],
        )
        .await?;
        if let Some(cursor) = s.cursor {
            o.execute(
                "UPDATE identity_sources SET committed_cursor=$1::text::jsonb, committed_cursor_digest=digest($1::text,'sha256') WHERE source_key=$2",
                &[&cursor, &s.key],
            )
            .await?;
        }
    }
    // A local account Go and Rust must treat alike when the directory presents the same address.
    o.execute(
        "INSERT INTO users(username,email,domain_id,display_name,password_hash,sync_source,enabled) VALUES($1,$1,$2,'Bob Local','x','local',true)",
        &[&format!("bob@{}", st.domain), &st.account.domain],
    )
    .await?;
    o.execute(
        "UPDATE feature_toggles SET enabled=$1 WHERE key='feature.identity_model_v2'",
        &[&gate],
    )
    .await?;
    match fault {
        Some("drop-links") => o.batch_execute("CREATE FUNCTION public.is7_fault() RETURNS trigger LANGUAGE plpgsql AS $f$ BEGIN RETURN NULL; END $f$; CREATE TRIGGER is7_fault BEFORE INSERT ON user_identity_links FOR EACH ROW EXECUTE FUNCTION public.is7_fault();").await?,
        Some("touch-users") => o.batch_execute("CREATE FUNCTION public.is7_fault() RETURNS trigger LANGUAGE plpgsql AS $f$ BEGIN NEW.job_title := COALESCE(NEW.job_title,'') || '!'; RETURN NEW; END $f$; CREATE TRIGGER is7_fault BEFORE INSERT OR UPDATE ON users FOR EACH ROW EXECUTE FUNCTION public.is7_fault();").await?,
        _ => {}
    }
    Ok(())
}

async fn cleanup(st: &Setup, keys: &[String]) -> Opt {
    let o = &st.owner;
    // The seeded legacy rows are restored, never deleted.
    let keys: Vec<String> = keys
        .iter()
        .filter(|k| !k.starts_with("legacy:"))
        .cloned()
        .collect();
    let ids: Vec<i64> = o
        .query(
            "SELECT id FROM users WHERE domain_id=$1",
            &[&st.account.domain],
        )
        .await?
        .iter()
        .map(|r| r.get(0))
        .collect();
    let mailboxes: Vec<i64> = o
        .query(
            "SELECT id FROM mailboxes WHERE domain_id=$1",
            &[&st.account.domain],
        )
        .await?
        .iter()
        .map(|r| r.get(0))
        .collect();
    let boxes = mailboxes
        .iter()
        .map(i64::to_string)
        .collect::<Vec<_>>()
        .join(",");
    let list = ids.iter().map(i64::to_string).collect::<Vec<_>>().join(",");
    o.batch_execute("DROP TRIGGER IF EXISTS is7_fault ON user_identity_links; DROP TRIGGER IF EXISTS is7_fault ON users; DROP FUNCTION IF EXISTS public.is7_fault();").await?;
    o.batch_execute(&format!("BEGIN; SET LOCAL session_replication_role=replica; DELETE FROM admin_audit_log WHERE id>{}; DELETE FROM mailbox_audit_log WHERE mailbox_id=ANY('{{{boxes}}}'); COMMIT;", st.audit_start)).await?;
    o.execute("DELETE FROM sync_conflicts WHERE user_id=ANY($1)", &[&ids])
        .await?;
    o.execute("DELETE FROM field_policy WHERE user_id=ANY($1)", &[&ids])
        .await?;
    let quoted = keys
        .iter()
        .map(|k| format!("'{k}'"))
        .collect::<Vec<_>>()
        .join(",");
    // The same list inside a `format()` literal needs doubled quotes.
    let in_literal = quoted.replace('\'', "''");
    o.batch_execute(&format!("BEGIN; SET LOCAL session_replication_role=replica; DO $c$ DECLARE r record; BEGIN \
        FOR r IN SELECT k.conrelid::regclass AS t, a.attname AS c FROM pg_constraint k \
            JOIN pg_attribute a ON a.attrelid=k.conrelid AND a.attnum=k.conkey[1] \
            WHERE k.contype='f' AND k.confrelid='user_identity_links'::regclass AND k.conrelid<>'user_identity_links'::regclass LOOP \
          EXECUTE format('DELETE FROM %s WHERE %I IN (SELECT id FROM user_identity_links WHERE user_id = ANY(ARRAY[{list}]::bigint[]) OR source_id IN (SELECT id FROM identity_sources WHERE source_key IN ({in_literal})))', r.t, r.c); \
        END LOOP; \
        FOR r IN SELECT k.conrelid::regclass AS t, a.attname AS c FROM pg_constraint k \
            JOIN pg_attribute a ON a.attrelid=k.conrelid AND a.attnum=k.conkey[1] \
            WHERE k.contype='f' AND k.confrelid='identity_sources'::regclass LOOP \
          EXECUTE format('DELETE FROM %s WHERE %I IN (SELECT id FROM identity_sources WHERE source_key IN ({in_literal}))', r.t, r.c); \
        END LOOP; \
        DELETE FROM user_identity_links WHERE user_id = ANY(ARRAY[{list}]::bigint[]); \
        DELETE FROM identity_sources WHERE source_key IN ({quoted}); \
      END $c$; COMMIT;")).await?;
    o.execute("DELETE FROM identity_sync_log WHERE id>$1 AND source_id IS NULL AND source IN ('ldap','ad')", &[&st.log_after]).await?;
    o.execute(
        "DELETE FROM departments WHERE path IN ('Engineering','Ops','Eng','Sales')",
        &[],
    )
    .await?;
    for (key, state) in &st.saved {
        o.execute(
            "UPDATE identity_sources SET state=$1 WHERE source_key=$2",
            &[state, key],
        )
        .await?;
    }
    o.execute(
        "UPDATE feature_toggles SET enabled=$1 WHERE key='feature.identity_model_v2'",
        &[&st.saved_toggle],
    )
    .await?;
    o.execute("UPDATE admin_role_assignments SET expires_at=now()-interval '1 hour' WHERE user_id=ANY($1)", &[&ids]).await?;
    o.execute(
        "DELETE FROM admin_role_assignments WHERE user_id=ANY($1)",
        &[&ids],
    )
    .await?;
    o.batch_execute(&format!("BEGIN; DELETE FROM messages WHERE mailbox_id=ANY('{{{boxes}}}'); DELETE FROM mailboxes WHERE domain_id={0}; DELETE FROM users WHERE domain_id={0}; COMMIT;", st.account.domain)).await?;
    o.execute("DELETE FROM domains WHERE id=$1", &[&st.account.domain])
        .await?;
    Ok(())
}

fn golden_path(case: &str) -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/conformance/directory-sync/goldens")
        .join(format!("identity-source-{case}.json"))
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Mutant {
    None,
    /// The Rust manager is never started.
    SkipStart,
    Fault(&'static str),
}

async fn run(case: &str, gate: bool, mutant: Mutant) -> Opt {
    let _serial = SERIAL.lock().await;
    let Some(st) = setup().await? else {
        return Ok(());
    };
    let list = sources(case);
    let mut keys: Vec<String> = list.iter().map(|s| s.key.to_owned()).collect();
    keys.push("legacy:ad".into());
    let mut dirs = vec![];
    for s in &list {
        dirs.push(directory(s, &st.domain).await?);
    }
    let fault = match mutant {
        Mutant::Fault(f) => Some(f),
        _ => None,
    };
    let result = async {
        seed(&st, &list, &dirs, gate, fault).await?;
        let before = snapshot(&st.owner, st.account.domain, &keys).await?;
        for d in &dirs {
            if let Some(f) = &d.fake {
                f.clear_log();
            }
        }
        let recording = std::env::var_os("GOFREE_RECORD_GO_BINARY").is_some() && mutant == Mutant::None;
        let after = if recording {
            let s3 = common::fake_upstream(|_| async { hyper::Response::new(common::full("")) }).await;
            std::env::set_var(
                "GOFREE_ORACLE_EXTRA_ENV",
                "SSL_CERT_FILE=/src/server-rust/tests/conformance/directory-sync/ldap-fixture/ca.pem",
            );
            let go = common::go_oracle::start_named_with_env(&st.db, s3, "gofree-dirsync7-source", &[]).await?;
            let go = go.ok_or("GOFREE_RECORD_GO_BINARY is not set")?;
            let after = settle(&st.owner, st.account.domain, &keys, Duration::from_secs(4)).await?;
            drop(go);
            after
        } else {
            let runtime = IdentitySourceRuntime::with_parts(
                setjoin_pg::workers::WorkerDatabase::new(&st.db.dsn)?,
                Some(st.codec.clone()),
                decode,
                15,
                15,
            );
            if mutant != Mutant::SkipStart {
                runtime.start().await?;
            }
            let after = settle(&st.owner, st.account.domain, &keys, Duration::from_secs(2)).await?;
            runtime.stop().await;
            after
        };
        let mut directory = serde_json::Map::new();
        for (s, d) in list.iter().zip(&dirs) {
            directory.insert(
                s.key.to_owned(),
                json!(d.fake.as_ref().map(FakeLdap::log).unwrap_or_default()),
            );
        }
        let mut observation = json!({"case": case, "gate": gate, "before": before, "after": after, "directory": directory});
        mask(&mut observation, &st.domain);
        // Run-specific ports never reach the logs, but keep the comparison honest about them.
        let text = observation.to_string();
        for d in &dirs {
            if text.contains(&format!(":{}", d.port)) {
                return Err("a directory port leaked into the observation".into());
            }
        }
        let path = golden_path(case);
        if recording {
            let source = std::env::var("GOFREE_GO_SOURCE")?;
            let value = json!({"format": 1, "case": case, "go_source": source, "observation": observation});
            if std::env::var_os("GOFREE_VERIFY_GO").is_some() {
                let expected: Value = serde_json::from_slice(&std::fs::read(&path)?)?;
                golden::compare(&expected, &value)?;
            } else {
                golden::record(&path, &value)?;
            }
        } else {
            let expected: Value = serde_json::from_slice(&std::fs::read(&path)?)?;
            let compared = golden::compare(&expected["observation"], &observation);
            match mutant {
                Mutant::None => {
                    compared?;
                    eprintln!("GOLDEN-REPLAY: identity-source-runtime :: {case}");
                }
                _ => {
                    if compared.is_ok() {
                        return Err("planted mutant survived".into());
                    }
                    eprintln!("MUTANT-REJECTED: identity-source-runtime :: {case}");
                }
            }
        }
        Ok::<_, BoxError>(())
    }
    .await;
    cleanup(&st, &keys).await?;
    result
}

#[tokio::test]
async fn tick_seeded_catalog() -> Opt {
    run("tick", true, Mutant::None).await
}
#[tokio::test]
async fn tick_incremental_cursors() -> Opt {
    run("incremental", true, Mutant::None).await
}
#[tokio::test]
async fn tick_failing_directories() -> Opt {
    run("failures", true, Mutant::None).await
}
#[tokio::test]
async fn tick_master_gate_off() -> Opt {
    run("gate-off", false, Mutant::None).await
}
#[tokio::test]
async fn mutant_manager_never_started() -> Opt {
    run("tick", true, Mutant::SkipStart).await
}
#[tokio::test]
async fn mutant_links_dropped() -> Opt {
    run("tick", true, Mutant::Fault("drop-links")).await
}
#[tokio::test]
async fn mutant_users_touched() -> Opt {
    run("tick", true, Mutant::Fault("touch-users")).await
}

async fn until<F, Fut>(what: &str, mut check: F) -> Opt
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    let deadline = Instant::now() + Duration::from_secs(90);
    while !check().await {
        if Instant::now() > deadline {
            return Err(format!("timed out waiting for {what}").into());
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    Ok(())
}

/// Reconciliation behaviour the one-tick oracle cannot show: a notification
/// wakes the manager at once, the poll closes the lost-notification window,
/// a moved generation replaces a worker, a paused source and a closed gate stop it.
#[tokio::test]
async fn manager_follows_the_catalog() -> Opt {
    let _serial = SERIAL.lock().await;
    let Some(st) = setup().await? else {
        return Ok(());
    };
    let list = sources("tick");
    let mut keys: Vec<String> = list.iter().map(|s| s.key.to_owned()).collect();
    keys.push("legacy:ad".into());
    let mut dirs = vec![];
    for s in &list {
        dirs.push(directory(s, &st.domain).await?);
    }
    let result = async {
        seed(&st, &list, &dirs, true, None).await?;
        let id = |key: &str| {
            let owner = &st.owner;
            let key = key.to_owned();
            async move {
                owner
                    .query_one(
                        "SELECT id FROM identity_sources WHERE source_key=$1",
                        &[&key],
                    )
                    .await
                    .map(|r| r.get::<_, i64>(0))
            }
        };
        let (alpha, beta, gamma, consist) = (
            id("ldap:alpha").await?,
            id("ad:beta").await?,
            id("ldap:gamma").await?,
            id("ad:consist").await?,
        );
        // A long poll: only the trigger can wake the manager inside this test.
        let runtime = Arc::new(
            IdentitySourceRuntime::with_parts(
                setjoin_pg::workers::WorkerDatabase::new(&st.db.dsn)?,
                Some(st.codec.clone()),
                decode,
                15,
                15,
            )
            .with_poll(Duration::from_secs(3600)),
        );
        runtime.start().await?;
        let mut expected = vec![(alpha, 1), (beta, 1), (gamma, 1), (consist, 1)];
        expected.sort_unstable();
        assert_eq!(
            runtime.running().await,
            expected,
            "active sources with usable secrets run"
        );

        let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
        let looped = runtime.clone();
        let task = tokio::spawn(async move {
            looped
                .run_until(async move {
                    let _ = stopped.await;
                })
                .await
        });

        // Pause one source and notify: it stops at once.
        st.owner
            .execute(
                "UPDATE identity_sources SET state='paused' WHERE id=$1",
                &[&gamma],
            )
            .await?;
        runtime.trigger.notify_one();
        until("the paused source to stop", || async {
            runtime.running().await.iter().all(|(i, _)| *i != gamma)
        })
        .await?;

        // A moved generation replaces the worker, which runs its first cycle again.
        let binds = |d: &Directory| {
            d.fake
                .as_ref()
                .map(|f| f.log().iter().filter(|l| l.starts_with("bind")).count())
                .unwrap_or(0)
        };
        let consist_dir = &dirs[3];
        // The generation is moved by a plain UPDATE (not the upsert reducer that retires a
        // source's open batch), so let the first generation's cycle finish: a cycle still
        // running when it moves leaves a generation-1 batch that blocks every later cycle.
        until("the first generation's cycle to finish", || async {
            binds(consist_dir) > 0
                && st
                    .owner
                    .query_one(
                        "SELECT count(*) FROM identity_source_leases WHERE source_id=$1",
                        &[&consist],
                    )
                    .await
                    .map(|r| r.get::<_, i64>(0) == 0)
                    .unwrap_or(false)
        })
        .await?;
        let before = binds(consist_dir);
        st.owner
            .execute(
                "UPDATE identity_sources SET generation=2 WHERE id=$1",
                &[&consist],
            )
            .await?;
        runtime.trigger.notify_one();
        until("the new generation to run", || async {
            runtime.running().await.contains(&(consist, 2))
        })
        .await?;
        until("the replacement worker's first cycle", || async {
            binds(consist_dir) > before
        })
        .await?;

        // Closing the master gate stops every worker.
        st.owner
            .execute(
                "UPDATE feature_toggles SET enabled=FALSE WHERE key='feature.identity_model_v2'",
                &[],
            )
            .await?;
        runtime.trigger.notify_one();
        until("the closed gate to stop everything", || async {
            runtime.running().await.is_empty()
        })
        .await?;
        let _ = stop.send(());
        task.await?;
        Ok::<_, BoxError>(())
    }
    .await;
    cleanup(&st, &keys).await?;
    result
}

/// With no notification at all the poll still sees the catalog change.
#[tokio::test]
async fn poll_closes_the_lost_notification_window() -> Opt {
    let _serial = SERIAL.lock().await;
    let Some(st) = setup().await? else {
        return Ok(());
    };
    let list = sources("tick");
    let mut keys: Vec<String> = list.iter().map(|s| s.key.to_owned()).collect();
    keys.push("legacy:ad".into());
    let mut dirs = vec![];
    for s in &list {
        dirs.push(directory(s, &st.domain).await?);
    }
    let result = async {
        seed(&st, &list, &dirs, true, None).await?;
        let runtime = Arc::new(
            IdentitySourceRuntime::with_parts(
                setjoin_pg::workers::WorkerDatabase::new(&st.db.dsn)?,
                Some(st.codec.clone()),
                decode,
                15,
                15,
            )
            .with_poll(Duration::from_millis(300)),
        );
        runtime.start().await?;
        assert_eq!(runtime.running().await.len(), 4);
        let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
        let looped = runtime.clone();
        let task = tokio::spawn(async move {
            looped
                .run_until(async move {
                    let _ = stopped.await;
                })
                .await
        });
        st.owner
            .execute(
                "UPDATE feature_toggles SET enabled=FALSE WHERE key='feature.identity_model_v2'",
                &[],
            )
            .await?;
        until("the poll to stop everything", || async {
            runtime.running().await.is_empty()
        })
        .await?;
        st.owner
            .execute(
                "UPDATE feature_toggles SET enabled=TRUE WHERE key='feature.identity_model_v2'",
                &[],
            )
            .await?;
        until("the poll to restart the sources", || async {
            runtime.running().await.len() == 4
        })
        .await?;
        let _ = stop.send(());
        task.await?;
        assert!(
            runtime.running().await.is_empty(),
            "shutdown joins every worker"
        );
        Ok::<_, BoxError>(())
    }
    .await;
    cleanup(&st, &keys).await?;
    result
}

/// A worker stopped mid-cycle still frees its source lease (Go releases it on a context that
/// survives the cancel). Without it the replacement worker, a new instance, skips its immediate
/// cycle against the abandoned lease and waits a whole interval (#472).
#[tokio::test]
async fn a_stopped_workers_lease_is_released() -> Opt {
    let _serial = SERIAL.lock().await;
    let Some(st) = setup().await? else {
        return Ok(());
    };
    let list = sources("tick");
    let mut keys: Vec<String> = list.iter().map(|s| s.key.to_owned()).collect();
    keys.push("legacy:ad".into());
    let mut dirs = vec![];
    for s in &list {
        dirs.push(directory(s, &st.domain).await?);
    }
    let result = async {
        seed(&st, &list, &dirs, true, None).await?;
        let (source, generation): (i64, i64) = {
            let row = st
                .owner
                .query_one(
                    "SELECT id,generation FROM identity_sources WHERE source_key='ad:consist'",
                    &[],
                )
                .await?;
            (row.get(0), row.get(1))
        };
        let instance = "6f0c7a52-2a47-4d6e-9c0e-5a1f0f7a9b11";
        let held: bool = st
            .owner
            .query_one(
                "SELECT identity_source_lease_acquire($1,$2,$3::text::uuid,45)",
                &[&source, &generation, &instance],
            )
            .await?
            .get(0);
        assert!(held, "the abandoned cycle held the lease");
        let other = "0b1a2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4d";
        let db = setjoin_pg::workers::WorkerDatabase::new(&st.db.dsn)?;
        setjoin_directory_sync::ldap::normalized::release_abandoned(&db, other).await?;
        let still: i64 = st
            .owner
            .query_one(
                "SELECT count(*) FROM identity_source_leases WHERE source_id=$1",
                &[&source],
            )
            .await?
            .get(0);
        assert_eq!(still, 1, "another instance's lease is left alone");
        setjoin_directory_sync::ldap::normalized::release_abandoned(&db, instance).await?;
        let left: i64 = st
            .owner
            .query_one(
                "SELECT count(*) FROM identity_source_leases WHERE source_id=$1",
                &[&source],
            )
            .await?
            .get(0);
        assert_eq!(left, 0, "the stopped worker's lease is released");
        Ok::<_, BoxError>(())
    }
    .await;
    cleanup(&st, &keys).await?;
    result
}
