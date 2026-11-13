//! Frozen backup.Engine: one worker credential, CAS claims, manifest-last commit.
use crate::{digest, json, store::Store};
use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine as _};
use ring::signature::{Ed25519KeyPair, KeyPair};
use setjoin_pg::{
    workers::{DirectListener, WorkerConnection, WorkerDatabase},
    Type,
};
use std::{
    collections::{BTreeMap, BTreeSet},
    future::Future,
};
#[derive(serde::Serialize)]
struct ConfigEntry {
    value: String,
    encrypted: bool,
}
#[derive(Clone)]
struct Blob {
    hash: String,
    size: i64,
}
#[derive(serde::Serialize)]
struct Manifest {
    timestamp: String,
    #[serde(rename = "type")]
    kind: &'static str,
    hashes: Vec<String>,
    count: usize,
    total_size: i64,
}
#[derive(serde::Serialize)]
struct Index {
    schema_version: i32,
    timestamp: String,
    config_size_bytes: usize,
    config_sha256: String,
    blob_manifest: Manifest,
    blob_count: usize,
    blob_total_size_bytes: i64,
    signing_key_id: String,
    signing_public_key: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    signature: String,
}
pub struct Engine {
    db: WorkerDatabase,
    direct: String,
    primary: Store,
    backup: Store,
    signer: Ed25519KeyPair,
    replica: Option<Store>,
}
fn env(k: &str) -> String {
    std::env::var(k).unwrap_or_default()
}
fn fallback(k: &str, default: &str) -> String {
    let v = env(k);
    if v.is_empty() {
        default.into()
    } else {
        v
    }
}
impl Engine {
    /// Backup configuration enables the transferred worker. The existing Go
    /// launcher must be explicitly disabled before Rust can take shared effects.
    pub fn from_environment() -> Result<Option<Self>, String> {
        if env("BACKUP_PROVIDER").is_empty() || env("BACKUP_BUCKET").is_empty() {
            return Ok(None);
        }
        if env("RUST_BACKUP_ENGINE_ENABLED") == "false" {
            return Ok(None);
        }
        let signer = (|| {
            use std::os::unix::fs::PermissionsExt;
            let path = env("BACKUP_SIGNING_KEY_FILE");
            if path.trim().is_empty() {
                return Err(
                    "BACKUP_SIGNING_KEY_FILE is required when backups are enabled".to_owned(),
                );
            }
            let m = std::fs::symlink_metadata(&path)
                .map_err(|_| "backup signing key must be a regular non-symlink 0600 file")?;
            if !m.is_file() || m.permissions().mode() & 0o077 != 0 {
                return Err("backup signing key must be a regular non-symlink 0600 file".into());
            }
            let raw = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
            let raw = raw.trim();
            let seed = if raw.len() == 64 && raw.is_ascii() {
                (0..64)
                    .step_by(2)
                    .map(|i| u8::from_str_radix(&raw[i..i + 2], 16))
                    .collect::<Result<Vec<_>, _>>()
                    .ok()
            } else {
                None
            }
            .ok_or("backup signing key must contain one 32-byte hex Ed25519 seed")?;
            Ed25519KeyPair::from_seed_unchecked(&seed)
                .map_err(|_| "backup signing key must contain one 32-byte hex Ed25519 seed".into())
        })();
        let signer = match signer {
            Ok(s) => s,
            Err(e) => {
                eprintln!("backup signing key invalid — backups disabled: {e}");
                return Ok(None);
            }
        };
        if !env("GO_WORKERS_OFF")
            .split(',')
            .any(|s| s.trim() == "backup-engine")
        {
            return Err("backup-engine requires GO_WORKERS_OFF=backup-engine before Rust starts shared backup effects".into());
        }
        let request = env("DB_DSN");
        if request.is_empty() {
            return Err("DB_DSN is required for backup-engine".into());
        }
        let direct = env("DB_DIRECT_DSN");
        if direct.is_empty() {
            return Err("DB_DIRECT_DSN is required for backup-engine LISTEN".into());
        }
        let worker = env("DB_WORKER_DSN");
        let db = WorkerDatabase::from_dsns(&request, Some(&worker)).map_err(|e| e.to_string())?;
        let primary_endpoint =
            fallback("S3_ENDPOINT", &fallback("MINIO_ENDPOINT", "127.0.0.1:9000"));
        let primary_endpoint = if primary_endpoint.contains("://") {
            primary_endpoint
        } else {
            format!(
                "{}://{primary_endpoint}",
                if fallback("S3_SECURE", &fallback("MINIO_SECURE", "false")) == "true" {
                    "https"
                } else {
                    "http"
                }
            )
        };
        let primary = Store::new(
            &primary_endpoint,
            "us-east-1",
            &fallback("S3_BUCKET", &fallback("MINIO_BUCKET", "mailblobs")),
            &fallback("S3_ACCESS_KEY", &env("MINIO_ACCESS_KEY")),
            &fallback("S3_SECRET_KEY", &env("MINIO_SECRET_KEY")),
        )?;
        let backup = match Store::driver(
            &env("BACKUP_PROVIDER"),
            &env("BACKUP_ENDPOINT"),
            &env("BACKUP_REGION"),
            &env("BACKUP_BUCKET"),
            &env("BACKUP_ACCESS_KEY"),
            &env("BACKUP_SECRET_KEY"),
        ) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("backup driver init failed — backups disabled: {e}");
                return Ok(None);
            }
        };
        let replica = if !env("BACKUP_REPLICA_PROVIDER").is_empty()
            && !env("BACKUP_REPLICA_BUCKET").is_empty()
        {
            match Store::driver(
                &env("BACKUP_REPLICA_PROVIDER"),
                &env("BACKUP_REPLICA_ENDPOINT"),
                &env("BACKUP_REPLICA_REGION"),
                &env("BACKUP_REPLICA_BUCKET"),
                &env("BACKUP_REPLICA_ACCESS_KEY"),
                &env("BACKUP_REPLICA_SECRET_KEY"),
            ) {
                Ok(s) => Some(s),
                Err(e) => {
                    eprintln!("replica driver init failed: {e}");
                    None
                }
            }
        } else {
            None
        };
        Ok(Some(Self {
            db,
            direct,
            primary,
            backup,
            signer,
            replica,
        }))
    }
    pub async fn run(self, stop: impl Future<Output = ()>) -> Result<(), String> {
        tokio::pin!(stop);
        let mut initialized = false;
        let mut replicas = tokio::task::JoinSet::new();
        loop {
            let connected = tokio::select! {_=&mut stop=>{replicas.abort_all(); while replicas.join_next().await.is_some() {} return Ok(());},r=DirectListener::connect(&self.direct,"backup_run")=>r};
            let mut listener = match connected {
                Ok(l) => l,
                Err(e) => {
                    eprintln!("backup listener: {e}");
                    tokio::select! {_=&mut stop=>return Ok(()),_=tokio::time::sleep(std::time::Duration::from_secs(1))=>{}}
                    continue;
                }
            };
            let result = tokio::select! {_=&mut stop=>Ok(()),r=self.serve(&mut listener,&mut initialized,&mut replicas)=>r};
            let close = listener.close().await.map_err(|e| e.to_string());
            match result {
                Ok(()) => {
                    replicas.abort_all();
                    while replicas.join_next().await.is_some() {}
                    close?;
                    return Ok(());
                }
                Err(e) => {
                    eprintln!("backup listener reconnect: {e}");
                }
            }
        }
    }
    async fn serve(
        &self,
        listener: &mut DirectListener,
        initialized: &mut bool,
        replicas: &mut tokio::task::JoinSet<()>,
    ) -> Result<(), String> {
        let db = self.db.connect().await.map_err(|e| e.to_string())?;
        if !*initialized {
            if let Err(e)=db.query("UPDATE backup_runs SET status='pending',started_at=NULL WHERE status='running'",&[]).await{eprintln!("backup stale-running reclaim: {e}");}
            match db
                .query(
                    "SELECT id FROM backup_runs WHERE status='pending' ORDER BY id",
                    &[],
                )
                .await
            {
                Ok(rows) => {
                    for row in rows {
                        self.process(&db, row.get(0), replicas).await;
                    }
                }
                Err(e) => eprintln!("backup pending drain: {e}"),
            }
            *initialized = true;
        }
        while let Some(n) = listener.recv().await {
            while replicas.try_join_next().is_some() {}
            if let Ok(id) = n.payload().parse::<i64>() {
                self.process(&db, id, replicas).await;
            }
        }
        Err("backup_run LISTEN connection closed".into())
    }
    async fn process(
        &self,
        db: &WorkerConnection,
        id: i64,
        replicas: &mut tokio::task::JoinSet<()>,
    ) {
        if let Err(e) = self.process_inner(db, id, replicas).await {
            eprintln!("backup run {id}: {e}");
        }
    }
    async fn process_inner(
        &self,
        db: &WorkerConnection,
        id: i64,
        replicas: &mut tokio::task::JoinSet<()>,
    ) -> Result<(), String> {
        let claim=db.query("UPDATE backup_runs SET status='running',started_at=now() WHERE id=$1 AND status='pending' RETURNING id",&[(&id,Type::INT8)]).await?;
        if claim.is_empty() {
            return Ok(());
        }
        let rows = match db
            .query(
                "SELECT b.sha256,b.size_bytes FROM blobs b WHERE b.ref_count>0",
                &[],
            )
            .await
        {
            Ok(rows) => rows,
            Err(e) => return self.fail(db, id, vec![e], 0, 0, 0).await,
        };
        let blobs = rows
            .iter()
            .map(|r| Blob {
                hash: r.get(0),
                size: r.get(1),
            })
            .collect::<Vec<_>>();
        let mut copied = 0i32;
        let mut skipped = 0i32;
        let mut errors = vec![];
        for blob in &blobs {
            if blob.hash.len() != 64
                || !blob
                    .hash
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                || blob.size < 0
            {
                errors.push(format!(
                    "blob {:?} has invalid inventory metadata",
                    blob.hash
                ));
                continue;
            }
            let key = format!("blobs/{}", blob.hash);
            if self
                .backup
                .head(&key)
                .await
                .is_ok_and(|s| s as i64 == blob.size)
                && verify(&self.backup, blob).await.is_ok()
            {
                skipped += 1;
                continue;
            }
            // minio-go obtains source object metadata before streaming a copy.
            if self.backup.needs_source_metadata() {
                let _ = self.primary.head(&key).await;
            }
            if let Err(e) = self
                .backup
                .copy_from(&self.primary, &key, blob.size as u64)
                .await
            {
                errors.push(format!("blob {}: copy/close: {e}", blob.hash));
                continue;
            }
            if let Err(e) = verify(&self.backup, blob).await {
                errors.push(format!(
                    "backup integrity check failed for {}: {e}",
                    blob.hash
                ));
                continue;
            }
            copied += 1;
        }
        if !errors.is_empty() {
            return self
                .fail(db, id, errors, blobs.len() as i32, copied, skipped)
                .await;
        }
        let config = match db
            .query(
                "SELECT key,value::text,encrypted FROM system_config ORDER BY key",
                &[],
            )
            .await
        {
            Ok(rows) => rows
                .into_iter()
                .map(|r| {
                    (
                        r.get::<_, String>(0),
                        ConfigEntry {
                            value: r.get(1),
                            encrypted: r.get(2),
                        },
                    )
                })
                .collect::<BTreeMap<_, _>>(),
            Err(e) => {
                return self
                    .fail(db, id, vec![e], blobs.len() as i32, copied, skipped)
                    .await
            }
        };
        let config = json(&config).into_bytes();
        let stamp = chrono::Utc::now().format("%Y%m%dT%H%M%SZ").to_string();
        let manifest = Manifest {
            timestamp: stamp.clone(),
            kind: "incr",
            hashes: blobs.iter().map(|b| b.hash.clone()).collect(),
            count: blobs.len(),
            total_size: blobs.iter().map(|b| b.size).sum(),
        };
        let mut index = Index {
            schema_version: 1,
            timestamp: stamp.clone(),
            config_size_bytes: config.len(),
            config_sha256: digest(&config),
            blob_count: manifest.count,
            blob_total_size_bytes: manifest.total_size,
            blob_manifest: manifest,
            signing_key_id: digest(self.signer.public_key().as_ref()),
            signing_public_key: STANDARD_NO_PAD.encode(self.signer.public_key().as_ref()),
            signature: String::new(),
        };
        index.signature =
            STANDARD_NO_PAD.encode(self.signer.sign(json(&index).as_bytes()).as_ref());
        let writes = [
            (
                format!("manifests/incr-{stamp}.json"),
                json(&index.blob_manifest).into_bytes(),
                "write blob manifest",
            ),
            (
                format!("config-{stamp}.json"),
                config.clone(),
                "write config",
            ),
            ("config.json".into(), config.clone(), "write latest config"),
            (
                format!("backup-manifest-{stamp}.json"),
                json(&index).into_bytes(),
                "write index",
            ),
            (
                "backup-manifest.json".into(),
                json(&index).into_bytes(),
                "write latest index",
            ),
        ];
        for (key, data, context) in writes {
            if let Err(e) = self.backup.put(&key, data).await {
                return self
                    .fail(
                        db,
                        id,
                        vec![format!("{context}: {e}")],
                        blobs.len() as i32,
                        copied,
                        skipped,
                    )
                    .await;
            }
        }
        let count = blobs.len() as i32;
        let size = config.len() as i64;
        let total = index.blob_total_size_bytes;
        if let Err(e)=db.query("UPDATE backup_runs SET status='completed',completed_at=now(),blob_count=$1,blobs_copied=$2,blobs_skipped=$3,config_size=$4,blob_total_size=$5,manifest_timestamp=$6 WHERE id=$7",&[(&count,Type::INT4),(&copied,Type::INT4),(&skipped,Type::INT4),(&size,Type::INT8),(&total,Type::INT8),(&stamp,Type::TEXT),(&id,Type::INT8)]).await{eprintln!("backup terminal completed-UPDATE failed: {e}");}
        if let Some(replica) = &self.replica {
            let backup = self.backup.clone();
            let replica = replica.clone();
            replicas.spawn(async move {
                replicate(backup, replica, blobs, stamp).await;
            });
        }
        if let Err(e) = self.retention(db).await {
            eprintln!("backup retention: {e}");
        }
        Ok(())
    }
    async fn fail(
        &self,
        db: &WorkerConnection,
        id: i64,
        errors: Vec<String>,
        count: i32,
        copied: i32,
        skipped: i32,
    ) -> Result<(), String> {
        let errors = json(&errors);
        db.query("UPDATE backup_runs SET status='failed',completed_at=now(),blob_count=$1,blobs_copied=$2,blobs_skipped=$3,error_log=$4::jsonb WHERE id=$5",&[(&count,Type::INT4),(&copied,Type::INT4),(&skipped,Type::INT4),(&errors,Type::TEXT),(&id,Type::INT8)]).await?;
        Ok(())
    }
    async fn retention(&self, db: &WorkerConnection) -> Result<(), String> {
        let mut scheme = "7d4w12m".to_owned();
        if let Ok(rows) = db
            .query(
                "SELECT value::text FROM system_config WHERE key='backup.retention_policy'",
                &[],
            )
            .await
        {
            if let Some(row) = rows.first() {
                if let Ok(v) = serde_json::from_str::<serde_json::Value>(&row.get::<_, String>(0)) {
                    if let Some(s) = v["gfs"].as_str().filter(|s| !s.is_empty()) {
                        scheme = s.into();
                    }
                }
            }
        }
        let mut depths = [7usize, 4, 12];
        let bytes = scheme.as_bytes();
        let mut i = 0;
        while i < bytes.len() {
            if !bytes[i].is_ascii_digit() {
                i += 1;
                continue;
            }
            let start = i;
            while i < bytes.len() && bytes[i].is_ascii_digit() {
                i += 1;
            }
            if let Ok(n) = scheme[start..i].parse::<usize>() {
                if let Some(unit) = bytes.get(i) {
                    if let Some(index) = b"dwm".iter().position(|b| b == unit) {
                        depths[index] = n;
                    }
                }
            }
        }
        let rows=db.query("SELECT id,manifest_timestamp FROM backup_runs WHERE status='completed' AND manifest_timestamp IS NOT NULL ORDER BY created_at DESC,id DESC",&[]).await?;
        let mut seen: [BTreeSet<String>; 3] = Default::default();
        use chrono::Datelike;
        for row in rows {
            let id: i64 = row.get(0);
            let stamp: String = row.get(1);
            let time = match chrono::NaiveDateTime::parse_from_str(&stamp, "%Y%m%dT%H%M%SZ") {
                Ok(t) if t.format("%Y%m%dT%H%M%SZ").to_string() == stamp => t,
                _ => continue,
            };
            let week = time.iso_week();
            let keys = [
                time.format("%Y-%m-%d").to_string(),
                format!("{}-W{}", week.year(), week.week()),
                time.format("%Y-%m").to_string(),
            ];
            let mut keep = false;
            for n in 0..3 {
                if depths[n] > 0 && !seen[n].contains(&keys[n]) && seen[n].len() < depths[n] {
                    seen[n].insert(keys[n].clone());
                    keep = true;
                }
            }
            if keep {
                continue;
            }
            let mut removed = true;
            for key in [
                format!("manifests/incr-{stamp}.json"),
                format!("config-{stamp}.json"),
                format!("backup-manifest-{stamp}.json"),
            ] {
                if let Err(e) = self.backup.delete(&key).await {
                    eprintln!("backup retention keeps run {id} for retry: {e}");
                    removed = false;
                    break;
                }
            }
            if removed {
                if let Err(e) = db
                    .query("DELETE FROM backup_runs WHERE id=$1", &[(&id, Type::INT8)])
                    .await
                {
                    eprintln!("backup retention row delete: {e}");
                }
            }
        }
        Ok(())
    }
}
async fn verify(store: &Store, blob: &Blob) -> Result<(), String> {
    let key = format!("blobs/{}", blob.hash);
    let size = store
        .head(&key)
        .await
        .map_err(|e| format!("head object: {e}"))?;
    if size as i64 != blob.size {
        return Err(format!(
            "size mismatch (expected {}, got {size})",
            blob.size
        ));
    }
    let (hash, size) = store
        .body_digest(&key)
        .await
        .map_err(|e| format!("read/close object: {e}"))?;
    if size as i64 != blob.size {
        return Err(format!(
            "read size mismatch (expected {}, got {size})",
            blob.size
        ));
    }
    if hash != blob.hash {
        return Err(format!("sha-256 mismatch (got {hash})"));
    }
    Ok(())
}

async fn replicate(backup: Store, replica: Store, blobs: Vec<Blob>, stamp: String) {
    for blob in blobs {
        let key = format!("blobs/{}", blob.hash);
        if replica
            .head(&key)
            .await
            .is_ok_and(|n| n as i64 == blob.size)
            && verify(&replica, &blob).await.is_ok()
        {
            continue;
        }
        // minio obtains metadata before opening the source stream.
        if replica.needs_source_metadata() {
            let _ = backup.head(&key).await;
        }
        let result = async {
            replica.copy_from(&backup, &key, blob.size as u64).await?;
            verify(&replica, &blob).await
        }
        .await;
        if let Err(e) = result {
            eprintln!("replica blob {}: {e}", blob.hash);
        }
    }
    for key in [
        format!("manifests/incr-{stamp}.json"),
        format!("config-{stamp}.json"),
        "config.json".into(),
        format!("backup-manifest-{stamp}.json"),
        "backup-manifest.json".into(),
    ] {
        let result = async {
            let bytes = backup.get(&key, usize::MAX).await?;
            replica.put(&key, bytes).await
        }
        .await;
        if let Err(e) = result {
            eprintln!("replica manifest {key}: {e}");
        }
    }
}
