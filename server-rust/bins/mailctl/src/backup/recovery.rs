//! Application recovery sets: authenticated API + exported owner snapshot.
use super::*;
use crate::{
    client::{Api, Failure},
    Options,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use setjoin_backup::recovery::{self as format, Counts, Envelope, Manifest, ProtectedKey};
use setjoin_pg::operator::OperatorConnection;
use std::{
    collections::BTreeMap,
    time::{Duration, Instant},
};
struct Opts {
    dsn: String,
    password: String,
    store: Store,
    recovery_key: Vec<u8>,
    protected_key: Vec<u8>,
    protected_id: String,
    reason: String,
    timeout: Duration,
    id: String,
    json: bool,
}
fn defaults(f: &flags::Flags, key: &str, default: &str) -> String {
    if f.set(key) {
        f.get(key).into()
    } else {
        default.into()
    }
}
fn stable(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 128
        && s.as_bytes()[0].is_ascii_alphanumeric()
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._:-".contains(&b))
}
fn opts(action: &str, args: &[String]) -> Result<Opts, Failure> {
    let f = flags::parse(
        &format!("backup {action}"),
        args,
        &[
            "dsn",
            "provider",
            "endpoint",
            "region",
            "bucket",
            "access-key",
            "secret-key",
            "access-key-file",
            "secret-key-file",
            "recovery-key-file",
            "protected-key-file",
            "protected-key-id",
            "reason",
            "timeout",
        ],
        &["pre-upgrade", "json"],
        false,
    );
    if !f.boolean("pre-upgrade") {
        return Err("--pre-upgrade is required".into());
    }
    let reason = defaults(
        &f,
        "reason",
        "create pre-upgrade application recovery point",
    );
    if reason.trim().len() < 8 || reason.contains(['\r', '\n', '\0']) {
        return Err("--reason must contain 8-1024 safe characters".into());
    }
    let timeout = crate::part_b::duration(&defaults(&f, "timeout", "10m"))
        .filter(|d| *d >= Duration::from_secs(1) && *d <= Duration::from_secs(3600))
        .ok_or("--timeout must be between 1s and 1h")?;
    let raw_dsn = owner_dsn(f.get("dsn"));
    if raw_dsn.is_empty() && action == "create" {
        return Err("no direct owner DSN: pass --dsn or configure owner-first DB_*_DSN".into());
    }
    let key_file = field(&f, "recovery-key-file", "RECOVERY_SET_HMAC_KEY_FILE");
    let protected_file = field(&f, "protected-key-file", "DB_ENCRYPTION_KEY_FILE");
    if key_file.is_empty() || protected_file.is_empty() {
        return Err("--recovery-key-file and --protected-key-file are required".into());
    }
    let protected_id = defaults(&f, "protected-key-id", "db-encryption-key");
    if !stable(&protected_id) {
        return Err("invalid --protected-key-id".into());
    }
    let bucket = field(&f, "bucket", "BACKUP_BUCKET");
    let mut access = field(&f, "access-key", "BACKUP_ACCESS_KEY");
    let mut secret = field(&f, "secret-key", "BACKUP_SECRET_KEY");
    let access_file = field(&f, "access-key-file", "BACKUP_ACCESS_KEY_FILE");
    let secret_file = field(&f, "secret-key-file", "BACKUP_SECRET_KEY_FILE");
    if bucket.is_empty()
        || (access.is_empty() && access_file.is_empty())
        || (secret.is_empty() && secret_file.is_empty())
    {
        return Err(
            "backup bucket and access/secret credentials (prefer 0600 files) are required".into(),
        );
    }
    let id = if action == "verify" {
        if f.positional.len() != 1 {
            return Err("exactly one recovery-set ID is required".into());
        }
        let id = &f.positional[0];
        if !crate::identity_checks::valid_uuid(id) || crate::part_b::uuid(id).as_deref() != Some(id)
        {
            return Err("recovery-set ID must be a canonical UUID".into());
        }
        id.clone()
    } else {
        if !f.positional.is_empty() {
            return Err("backup create accepts no positional arguments".into());
        }
        String::new()
    };
    let recovery_key = private_file(&key_file, "recovery HMAC key", 32, 16384)?;
    let protected_key = private_file(&protected_file, "protected configuration key", 32, 16384)?;
    if !access_file.is_empty() {
        access = credential_file(&access_file, "backup access key")?;
    }
    if !secret_file.is_empty() {
        secret = credential_file(&secret_file, "backup secret key")?;
    }
    let store = Store::new(
        &field(&f, "endpoint", "BACKUP_ENDPOINT"),
        &field(&f, "region", "BACKUP_REGION"),
        &bucket,
        &access,
        &secret,
    )?;
    let (dsn, password) = credentials(&f)?;
    Ok(Opts {
        dsn,
        password,
        store,
        recovery_key,
        protected_key,
        protected_id,
        reason: reason.trim().into(),
        timeout,
        id,
        json: f.boolean("json"),
    })
}
#[derive(Serialize, Deserialize, Default, PartialEq)]
#[serde(default)]
struct ConfigEntry {
    value: String,
    encrypted: bool,
}
#[derive(Serialize)]
struct Toggle {
    key: String,
    enabled: bool,
}
struct Snapshot {
    installation: String,
    timeline: String,
    schema: i32,
    counts: Counts,
    hashes: Vec<String>,
    config: BTreeMap<String, ConfigEntry>,
    feature: String,
    representative: Option<Vec<String>>,
}
async fn snapshot(opts: &Opts, dump: &Path, list: &Path) -> Result<Snapshot, Failure> {
    let mut db = OperatorConnection::connect_password(&opts.dsn, &opts.password)
        .await
        .map_err(|e| format!("connect direct owner database: {e}"))?;
    let tx = db
        .backup_snapshot()
        .await
        .map_err(|e| format!("begin recovery snapshot: {e}"))?;
    let exported: String = tx
        .query("SELECT pg_export_snapshot()", &[])
        .await
        .map_err(|e| format!("export PostgreSQL snapshot: {e}"))?[0]
        .get(0);
    let identity=tx.query("SELECT installation_id::text,timeline_id::text FROM upgrade_control_state WHERE singleton",&[]).await.map_err(|e|format!("read upgrade control identity: {e}"))?;
    let identity = identity
        .first()
        .ok_or("read upgrade control identity: no rows in result set")?;
    let schema: i32 = tx
        .query(
            "SELECT COALESCE(max(version),0) FROM schema_migrations",
            &[],
        )
        .await
        .map_err(|e| format!("read schema version: {e}"))?[0]
        .get(0);
    let users: i64 = tx
        .query("SELECT count(*) FROM users", &[])
        .await
        .map_err(|e| format!("count users: {e}"))?[0]
        .get(0);
    let mailboxes: i64 = tx
        .query("SELECT count(*) FROM mailboxes", &[])
        .await
        .map_err(|e| format!("count mailboxes: {e}"))?[0]
        .get(0);
    let blobs = tx
        .query(
            "SELECT sha256,size_bytes FROM blobs WHERE ref_count>0 ORDER BY sha256",
            &[],
        )
        .await
        .map_err(|e| format!("read blob inventory: {e}"))?;
    let hashes = blobs.iter().map(|r| r.get(0)).collect::<Vec<String>>();
    let bytes = blobs.iter().map(|r| r.get::<_, i64>(1)).sum();
    let config = tx
        .query(
            "SELECT key,value::text,encrypted FROM system_config ORDER BY key",
            &[],
        )
        .await
        .map_err(|e| format!("read protected configuration inventory: {e}"))?
        .into_iter()
        .map(|r| {
            (
                r.get(0),
                ConfigEntry {
                    value: r.get(1),
                    encrypted: r.get(2),
                },
            )
        })
        .collect();
    let toggles = tx
        .query("SELECT key,enabled FROM feature_toggles ORDER BY key", &[])
        .await
        .map_err(|e| format!("read feature-toggle inventory: {e}"))?
        .into_iter()
        .map(|r| Toggle {
            key: r.get(0),
            enabled: r.get(1),
        })
        .collect::<Vec<_>>();
    let feature = setjoin_backup::digest(
        setjoin_backup::json(&if toggles.is_empty() {
            None
        } else {
            Some(toggles)
        })
        .as_bytes(),
    );
    let mut representative = vec![];
    for query in [
        "SELECT 'user:'||id::text FROM users ORDER BY id LIMIT 4",
        "SELECT 'mailbox:'||id::text FROM mailboxes ORDER BY id LIMIT 4",
        "SELECT 'blob:'||sha256 FROM blobs WHERE ref_count>0 ORDER BY sha256 LIMIT 4",
    ] {
        for row in tx
            .query(query, &[])
            .await
            .map_err(|e| format!("read representative IDs: {e}"))?
        {
            representative.push(row.get::<_, String>(0));
        }
    }
    let result = tokio::process::Command::new("pg_dump")
        .kill_on_drop(true)
        .args([
            "--format=custom",
            &format!("--file={}", dump.display()),
            &format!("--snapshot={exported}"),
            &opts.dsn,
        ])
        .envs(if opts.password.is_empty() {
            vec![]
        } else {
            vec![("PGPASSWORD", opts.password.as_str())]
        })
        .output()
        .await
        .map_err(|e| e.to_string())?;
    if !result.status.success() {
        return Err(format!(
            "pg_dump recovery snapshot failed: exit status {}: {}",
            result.status.code().unwrap_or(1),
            String::from_utf8_lossy(&result.stderr)
                .trim()
                .chars()
                .take(4096)
                .collect::<String>()
        )
        .into());
    }
    validate_dump(dump)?;
    let output = std::fs::OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(list)
        .map_err(|e| format!("create pg_restore list: {e}"))?;
    let result = tokio::process::Command::new("pg_restore")
        .kill_on_drop(true)
        .arg("--list")
        .arg(dump)
        .stdout(Stdio::from(output))
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| e.to_string())?
        .wait_with_output()
        .await
        .map_err(|e| e.to_string())?;
    if !result.status.success() {
        return Err(format!(
            "produce pg_restore list: exit status {}: {}",
            result.status.code().unwrap_or(1),
            String::from_utf8_lossy(&result.stderr)
                .trim()
                .chars()
                .take(4096)
                .collect::<String>()
        )
        .into());
    }
    tx.commit()
        .await
        .map_err(|e| format!("finish exported recovery snapshot: {e}"))?;
    Ok(Snapshot {
        installation: identity.get(0),
        timeline: identity.get(1),
        schema,
        counts: Counts {
            blobs: hashes.len() as i64,
            blob_bytes: bytes,
            users,
            mailboxes,
        },
        hashes,
        config,
        feature,
        representative: if representative.is_empty() {
            None
        } else {
            Some(representative)
        },
    })
}
#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct Inventory {
    #[serde(rename = "timestamp")]
    _timestamp: String,
    #[serde(rename = "type")]
    _kind: String,
    hashes: Option<Vec<String>>,
    count: i64,
    total_size: i64,
}
async fn read_object(store: &Store, key: &str) -> Result<Vec<u8>, Failure> {
    let size = store.head(key).await?;
    if size > 256 << 20 {
        return Err("recovery component exceeds size limit".into());
    }
    let raw = store.get(key, 256 << 20).await?;
    if raw.len() as u64 != size {
        return Err("recovery component size changed while reading".into());
    }
    Ok(raw)
}
async fn compare(
    store: &Store,
    blob_key: &str,
    config_key: &str,
    snapshot: &Snapshot,
) -> Result<(), Failure> {
    let raw = read_object(store, blob_key)
        .await
        .map_err(|e| format!("read immutable blob inventory: {e}"))?;
    let i: Inventory =
        serde_json::from_slice(&raw).map_err(|_| "backup blob inventory is malformed")?;
    let mut got = i.hashes.unwrap_or_default();
    got.sort();
    if i.count != got.len() as i64
        || i.count != snapshot.counts.blobs
        || i.total_size != snapshot.counts.blob_bytes
        || got != snapshot.hashes
    {
        return Err(Failure::from("gateway blob backup and exported PostgreSQL snapshot differ; rerun after write activity settles").exit(2));
    }
    let raw = read_object(store, config_key)
        .await
        .map_err(|e| format!("read immutable configuration backup: {e}"))?;
    let config: BTreeMap<String, ConfigEntry> =
        serde_json::from_slice(&raw).map_err(|_| "backup configuration inventory is malformed")?;
    if config != snapshot.config {
        return Err(Failure::from("gateway configuration backup and exported PostgreSQL snapshot differ; rerun after configuration changes settles".replace("changes settles","changes settle")).exit(2));
    }
    Ok(())
}
fn register(api: &Api, e: &Envelope, reason: &str) -> Result<(), Failure> {
    let m = &e.manifest;
    let body = json!({"recoverySetId":m.recovery_set_id,"timelineId":m.timeline_id,"sourceReleaseId":m.source_release_id,"schemaVersion":m.schema_version,"manifestDigest":e.manifest_sha256,"checks":{"database":true,"databaseRestoreList":true,"blobs":true,"configuration":true,"protectedKey":true,"featureToggles":true,"hmac":true},"createdAt":m.created_at,"expiresAt":m.expires_at,"reason":reason});
    api.with_headers(
        "POST",
        "/admin/system/upgrades/recovery-sets",
        Some(body),
        true,
        &[("X-Audit-Reason", reason.into())],
        64 << 10,
    )
    .map_err(|e| format!("record verified recovery set: {e}"))?;
    Ok(())
}
fn output(options: &Options, v: &Value) {
    if options.json || options.quiet {
        options.output(v);
        return;
    }
    let mut v = v.clone();
    for k in ["createdAt", "expiresAt"] {
        if let Some(s) = v[k].as_str() {
            if let Ok(t) = chrono::DateTime::parse_from_rfc3339(s) {
                let s = t
                    .with_timezone(&chrono::Utc)
                    .format("%Y-%m-%d %H:%M:%S%.f +0000 UTC")
                    .to_string();
                v[k] = s.into();
            }
        }
    }
    options.output(&v);
}
pub(super) fn run(
    api: &Api,
    options: &Options,
    action: &str,
    args: &[String],
) -> Result<(), Failure> {
    let opts = opts(action, args)?;
    let options = Options {
        json: options.json || opts.json,
        quiet: options.quiet,
        yes: options.yes,
    };
    let context = api
        .with_headers(
            "GET",
            "/admin/system/upgrades/recovery-context",
            None,
            true,
            &[],
            64 << 10,
        )
        .map_err(|e| format!("read recovery context: {e}"))?;
    let installation = context["installationId"].as_str().unwrap_or("");
    let timeline = context["timelineId"].as_str().unwrap_or("");
    let schema = context["schemaVersion"].as_i64().unwrap_or(0);
    if crate::part_b::uuid(installation).is_none() {
        return Err("server returned an invalid installation identity".into());
    }
    if crate::part_b::uuid(timeline).is_none() {
        return Err("server returned an invalid recovery timeline".into());
    }
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| e.to_string())?;
    if action == "verify" {
        let e = rt
            .block_on(format::load_verified(
                &opts.store,
                &opts.id,
                &opts.recovery_key,
                installation,
                timeline,
            ))
            .map_err(|e| {
                Failure::from(format!("pre-upgrade recovery set is not eligible: {e}")).exit(2)
            })?;
        if e.manifest.protected_key_evidence.fingerprint
            != setjoin_backup::digest(&opts.protected_key)
        {
            return Err(Failure::from(
                "protected configuration key does not match recovery-set evidence",
            )
            .exit(2));
        }
        register(api, &e, &opts.reason)?;
        output(
            &options,
            &json!({"status":"verified","recoverySetId":e.manifest.recovery_set_id,"manifestDigest":e.manifest_sha256,"fresh":true,"createdAt":e.manifest.created_at,"expiresAt":e.manifest.expires_at}),
        );
        return Ok(());
    }
    binary("pg_dump")?;
    binary("pg_restore")?;
    let start = Instant::now();
    let created = api
        .with_headers(
            "POST",
            "/admin/system/backup",
            None,
            true,
            &[("X-Audit-Reason", opts.reason.clone())],
            16 << 10,
        )
        .map_err(|e| format!("enqueue gateway blob/config backup: {e}"))?;
    let id = created["run_id"].as_i64().unwrap_or(0);
    if id <= 0 {
        return Err("gateway returned an invalid backup run ID".into());
    }
    let stamp = loop {
        let runs = api
            .with_headers("GET", "/admin/system/backup/list", None, true, &[], 1 << 20)
            .map_err(|e| format!("read backup run: {e}"))?;
        let mut stamp = None;
        for run in runs
            .as_array()
            .into_iter()
            .flatten()
            .filter(|r| r["id"] == id)
        {
            match run["status"].as_str().unwrap_or("") {
                "completed" => {
                    let s = run["manifest_timestamp"].as_str().unwrap_or("");
                    if s.len() != 16
                        || !s.bytes().enumerate().all(|(i, b)| {
                            if i == 8 {
                                b == b'T'
                            } else if i == 15 {
                                b == b'Z'
                            } else {
                                b.is_ascii_digit()
                            }
                        })
                    {
                        return Err(
                            "completed backup lacks a canonical immutable manifest timestamp"
                                .into(),
                        );
                    }
                    stamp = Some(s.to_owned());
                }
                "failed" => return Err("gateway blob/config backup failed".into()),
                "pending" | "running" => {}
                s => return Err(format!("gateway returned unknown backup state {s:?}").into()),
            }
        }
        if let Some(stamp) = stamp {
            break stamp;
        }
        if start.elapsed() >= opts.timeout {
            return Err("wait for gateway backup: context deadline exceeded".into());
        }
        std::thread::sleep(
            Duration::from_secs(1).min(opts.timeout.saturating_sub(start.elapsed())),
        );
    };
    let dump = TempFile::new("mailctl-recovery-set-", ".dump")?;
    let list = TempFile::new("mailctl-recovery-set-", ".list")?;
    let snapshot = rt
        .block_on(async {
            tokio::time::timeout(
                opts.timeout.saturating_sub(start.elapsed()),
                snapshot(&opts, &dump.path, &list.path),
            )
            .await
        })
        .map_err(|_| "pg_dump recovery snapshot failed: context deadline exceeded")??;
    if snapshot.installation != installation
        || snapshot.timeline != timeline
        || snapshot.schema as i64 != schema
    {
        return Err(
            "operator DSN and authenticated server resolve to different recovery context".into(),
        );
    }
    let blob_key = format!("manifests/incr-{stamp}.json");
    let config_key = format!("config-{stamp}.json");
    let set_id = crate::part_b::new_uuid()?;
    let components = rt.block_on(async {
        compare(&opts.store, &blob_key, &config_key, &snapshot)
            .await
            .map_err(|e| e.exit(2))?;
        let db_key = format!("recovery-sets/{set_id}/database.dump");
        let list_key = format!("recovery-sets/{set_id}/database.list");
        opts.store
            .put_file(&db_key, &dump.path)
            .await
            .map_err(|e| format!("upload {db_key}: {e}"))?;
        opts.store
            .put_file(&list_key, &list.path)
            .await
            .map_err(|e| format!("upload {list_key}: {e}"))?;
        Ok::<_, Failure>((
            format::artifact(&opts.store, &db_key).await?,
            format::artifact(&opts.store, &list_key).await?,
            format::artifact(&opts.store, &blob_key).await?,
            format::artifact(&opts.store, &config_key).await?,
        ))
    })?;
    let version = api
        .with_headers("GET", "/admin/system/version", None, true, &[], 16 << 10)
        .map_err(|e| format!("read source release: {e}"))?;
    let now = chrono::Utc::now();
    let m = Manifest {
        version: 1,
        recovery_set_id: set_id,
        installation_id: snapshot.installation,
        timeline_id: snapshot.timeline,
        source_release_id: version["version"]
            .as_str()
            .unwrap_or("")
            .strip_prefix('v')
            .unwrap_or(version["version"].as_str().unwrap_or(""))
            .into(),
        schema_version: snapshot.schema,
        created_at: format::time(now),
        expires_at: format::time(now + chrono::Duration::hours(24)),
        database: components.0,
        database_restore_list: components.1,
        blobs: components.2,
        configuration: components.3,
        protected_key_evidence: ProtectedKey {
            mode: "external".into(),
            key_id: opts.protected_id,
            fingerprint: setjoin_backup::digest(&opts.protected_key),
        },
        feature_toggle_sha256: snapshot.feature,
        counts: snapshot.counts,
        representative_ids: snapshot.representative,
    };
    let e = rt
        .block_on(format::commit(&opts.store, m, &opts.recovery_key))
        .map_err(|e| format!("commit recovery set: {e}"))?;
    register(api, &e, &opts.reason)?;
    output(
        &options,
        &json!({"status":"verified","recoverySetId":e.manifest.recovery_set_id,"manifestDigest":e.manifest_sha256,"createdAt":e.manifest.created_at,"expiresAt":e.manifest.expires_at}),
    );
    Ok(())
}
