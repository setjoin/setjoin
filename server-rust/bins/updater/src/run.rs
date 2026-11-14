use crate::{
    control::Connection,
    files::*,
    host::{self, Probe},
    journal::Journal,
    migration, stage,
};
use anyhow::{anyhow, bail, ensure, Result};
use serde::Deserialize;
use serde_json::{json, Value};
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    time::Duration,
};

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct Config {
    version: i32,
    #[serde(default)]
    enabled: bool,
    #[serde(default)]
    install_root: PathBuf,
    #[serde(default)]
    recovery_provider: String,
    #[serde(default)]
    recovery_endpoint: String,
    #[serde(default)]
    recovery_region: String,
    #[serde(default)]
    recovery_bucket: String,
}
impl Config {
    fn read(path: &Path) -> Result<Self> {
        let c: Self = if path.try_exists()? {
            serde_json::from_slice(&read(path, 65536, false)?)?
        } else {
            Self {
                version: 1,
                enabled: false,
                install_root: PathBuf::new(),
                recovery_provider: String::new(),
                recovery_endpoint: String::new(),
                recovery_region: String::new(),
                recovery_bucket: String::new(),
            }
        };
        ensure!(
            c.version == 1,
            "unsupported updater execution config version"
        );
        if c.enabled {
            ensure!(
                c.install_root.is_absolute()
                    && c.install_root != Path::new("/")
                    && !c.install_root.components().any(|p| matches!(
                        p,
                        std::path::Component::ParentDir | std::path::Component::CurDir
                    )),
                "safe absolute install root required"
            );
            ensure!(
                c.recovery_provider == "s3"
                    && (3..=63).contains(&c.recovery_bucket.len())
                    && c.recovery_bucket.bytes().all(|b| b.is_ascii_lowercase()
                        || b.is_ascii_digit()
                        || b".-".contains(&b))
                    && c.recovery_bucket.as_bytes()[0].is_ascii_alphanumeric()
                    && c.recovery_bucket.as_bytes()[c.recovery_bucket.len() - 1]
                        .is_ascii_alphanumeric(),
                "invalid recovery store"
            );
            ensure!(
                c.recovery_region.len() <= 128 && !c.recovery_region.contains(['\r', '\n', '\0']),
                "invalid recovery region"
            );
            ensure!(
                !c.recovery_endpoint.is_empty()
                    && c.recovery_endpoint.len() <= 2048
                    && !c.recovery_endpoint.contains(['\r', '\n', '\0']),
                "invalid recovery endpoint"
            );
            // Store's audited HTTP client enforces TLS; cleartext is loopback only.
        }
        Ok(c)
    }
}
fn normalized_endpoint(raw: &str) -> Result<String> {
    let explicit = raw.contains("://");
    let normalized = if explicit {
        raw.into()
    } else {
        format!("https://{raw}")
    };
    let parsed = reqwest::Url::parse(&normalized)?;
    ensure!(
        matches!(parsed.scheme(), "http" | "https")
            && parsed.host_str().is_some()
            && parsed.username().is_empty()
            && parsed.password().is_none()
            && parsed.query().is_none()
            && parsed.fragment().is_none(),
        "invalid recovery endpoint"
    );
    let authority = normalized.split_once("://").unwrap().1;
    ensure!(
        !authority.contains('/'),
        "recovery endpoint must not contain a path"
    );
    ensure!(
        parsed.scheme() == "https"
            || matches!(
                parsed
                    .host_str()
                    .unwrap()
                    .trim_matches(['[', ']'])
                    .to_ascii_lowercase()
                    .as_str(),
                "127.0.0.1" | "::1" | "localhost"
            ),
        "recovery endpoint must use https unless loopback"
    );
    Ok(normalized)
}
struct Adapters {
    config: Config,
    owner: Connection,
    store: setjoin_backup::store::Store,
    key: Vec<u8>,
    probe: Probe,
}
fn take(f: &mut BTreeMap<String, String>, key: &str, default: &str) -> String {
    f.remove(key).unwrap_or_else(|| default.into())
}
pub async fn execute(mut f: BTreeMap<String, String>) -> Result<()> {
    let office = crate::office::Office::take(&mut f)?;
    if f.remove("--office-app-only").is_some() {
        ensure!(
            f.keys()
                .all(|k| matches!(k.as_str(), "--once" | "--poll-interval" | "--executor-id")),
            "app-only mode accepts no core-update arguments"
        );
        let office =
            office.ok_or_else(|| anyhow!("office-app-only requires office-app-execution"))?;
        return office.once().await;
    }
    let state = PathBuf::from(take(&mut f, "--state-dir", "/var/lib/setjoin/updater"));
    let store = PathBuf::from(take(&mut f, "--release-store", "/var/lib/setjoin/releases"));
    let dsn_path = PathBuf::from(take(
        &mut f,
        "--dsn-file",
        "/run/credentials/setjoin-updater.service/updater-dsn",
    ));
    let config_path = PathBuf::from(take(
        &mut f,
        "--execution-config",
        "/etc/setjoin-updater/execution.json",
    ));
    let owner_path = PathBuf::from(take(
        &mut f,
        "--owner-dsn-file",
        "/run/credentials/setjoin-updater.service/owner-dsn",
    ));
    let access_path = PathBuf::from(take(
        &mut f,
        "--recovery-access-key-file",
        "/run/credentials/setjoin-updater.service/recovery-access-key",
    ));
    let secret_path = PathBuf::from(take(
        &mut f,
        "--recovery-secret-key-file",
        "/run/credentials/setjoin-updater.service/recovery-secret-key",
    ));
    let key_path = PathBuf::from(take(
        &mut f,
        "--recovery-hmac-key-file",
        "/run/credentials/setjoin-updater.service/recovery-hmac-key",
    ));
    let probe_path = PathBuf::from(take(
        &mut f,
        "--probe-credential-file",
        "/run/credentials/setjoin-updater.service/probe-credential",
    ));
    let executor = take(&mut f, "--executor-id", "setjoin-updater");
    ensure!(identifier(&executor), "invalid executor ID");
    let interval = duration(&take(&mut f, "--poll-interval", "15s"))?;
    ensure!(
        (Duration::from_secs(1)..=Duration::from_secs(900)).contains(&interval),
        "poll interval must be between 1 second and 15 minutes"
    );
    let once = f.remove("--once").is_some();
    ensure!(f.is_empty(), "unknown updater flags: {:?}", f.keys());
    secure_dir(&state, 0o700)?;
    existing_dir(&store)?;
    let dsn = credential(&dsn_path)?;
    let control = Connection::connect(&dsn).await?;
    let config = Config::read(&config_path)?;
    let mut adapters = if config.enabled {
        let owner_dsn = credential(&owner_path)?;
        let c: tokio_postgres::Config = dsn.parse()?;
        let o: tokio_postgres::Config = owner_dsn.parse()?;
        ensure!(
            c.get_user() == Some("setjoin_updater")
                && o.get_user().is_some()
                && c.get_user() != o.get_user()
                && dsn != owner_dsn,
            "migration-owner credential must be distinct from setjoin_updater"
        );
        let key = read(&key_path, 16384, true)?;
        ensure!(key.len() >= 32, "private key must be at least 32 bytes");
        let access = credential(&access_path)?;
        let secret = credential(&secret_path)?;
        let endpoint = normalized_endpoint(&config.recovery_endpoint)?;
        let recovery_store = setjoin_backup::store::Store::driver(
            "s3",
            &endpoint,
            &config.recovery_region,
            &config.recovery_bucket,
            &access,
            &secret,
        )
        .map_err(|e| anyhow!(e))?;
        Some(Adapters {
            probe: Probe::read(&probe_path)?,
            owner: Connection::connect(&owner_dsn).await?,
            store: recovery_store,
            key,
            config,
        })
    } else {
        None
    };
    if once {
        once_run(&state, &store, &executor, &control, &mut adapters).await?;
        if let Some(office) = office {
            office.once().await?;
        }
        return Ok(());
    }
    let core = async {
        let mut terminate =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
        loop {
            tokio::select! {result=once_run(&state,&store,&executor,&control,&mut adapters)=>{if let Err(e)=result{eprintln!("updater iteration paused: {e:#}");}},_=terminate.recv()=>return Ok(()),_=tokio::signal::ctrl_c()=>return Ok(())}
            tokio::select! {_=tokio::time::sleep(interval)=>(),_=terminate.recv()=>return Ok(()),_=tokio::signal::ctrl_c()=>return Ok(())}
        }
    };
    if let Some(office) = office {
        office.supervise(core).await
    } else {
        core.await
    }
}
fn duration(s: &str) -> Result<Duration> {
    let (number, multiplier) = if let Some(n) = s.strip_suffix("ms") {
        (n, 0.001)
    } else if let Some(n) = s.strip_suffix('s') {
        (n, 1.0)
    } else if let Some(n) = s.strip_suffix('m') {
        (n, 60.0)
    } else if let Some(n) = s.strip_suffix('h') {
        (n, 3600.0)
    } else {
        bail!("invalid poll duration")
    };
    let seconds = number.parse::<f64>()? * multiplier;
    ensure!(seconds.is_finite() && seconds >= 0.0, "invalid duration");
    Ok(Duration::try_from_secs_f64(seconds)?)
}
async fn once_run(
    state: &Path,
    store: &Path,
    executor: &str,
    control: &Connection,
    adapters: &mut Option<Adapters>,
) -> Result<()> {
    let mut j = Journal::open(state)?;
    control.lock().await?;
    if let Some(last) = j.events.last().cloned() {
        if last.terminal() {
            if !j.reconciled {
                control.mutate(&last).await?;
                j.compact()?;
            }
            let remote = control.latest().await?;
            if adapters.is_none() || remote.as_ref().is_none_or(|i| i.id == last.intent_id) {
                return Ok(());
            }
            ensure!(
                remote
                    .as_ref()
                    .is_some_and(|i| matches!(i.state.as_str(), "approved" | "scheduled")),
                "new intent is not claimable"
            );
            j.archive()?;
        }
    }
    if j.events.is_empty() {
        if adapters.is_none() {
            return Ok(());
        }
        let Some(intent) = control.latest().await? else {
            return Ok(());
        };
        if !matches!(intent.state.as_str(), "approved" | "scheduled") {
            return Ok(());
        }
        stage::verify_tree(store, &intent.release_id, &intent.manifest_digest)?;
        j.append(intent.prepared(executor))?;
    }
    let last = j.events.last().unwrap().clone();
    if matches!(last.state.as_str(), "approved" | "scheduled") {
        let claimed = control.claim(&last).await?;
        ensure!(
            claimed.generation == last.generation + 1,
            "claim generation differs"
        );
        j.next("claimed", "claimed", json!({"claimed":true}))?;
    }
    let last = j.events.last().unwrap();
    stage::verify_tree(store, &last.release_id, &last.manifest_digest)?;
    // A durable local boundary is authoritative after a lost reducer response.
    let remote = control
        .latest()
        .await?
        .ok_or_else(|| anyhow!("active intent missing"))?;
    let last = j.events.last().unwrap();
    ensure!(
        remote.id == last.intent_id,
        "local and database transactions differ"
    );
    ensure!(
        remote.generation <= last.generation
            || (remote.state == "cancel_requested" && remote.generation == last.generation + 1),
        "database is ahead of local journal"
    );
    for e in &j.events {
        if e.generation < remote.generation {
            continue;
        }
        if e.generation == remote.generation {
            ensure!(
                e.state == remote.state,
                "database and journal states differ"
            );
            continue;
        }
        if !matches!(
            e.state.as_str(),
            "approved" | "scheduled" | "claimed" | "cancel_requested"
        ) {
            control.mutate(e).await?;
        }
    }
    let a = adapters
        .as_mut()
        .ok_or_else(|| anyhow!("updater execution adapters are not installed"))?;
    for (name, to) in [
        ("preflight", "preflight"),
        ("recovery_point", "recovery_point"),
        ("stage_release", "staged"),
        ("stop_core", "maintenance"),
        ("apply_migrations", "migrations"),
        ("switch_release", "switched"),
        ("start_and_readiness", "readiness"),
        ("commit_checks", "committed"),
    ] {
        if j.events.iter().any(|e| e.step == name) {
            continue;
        }
        let last = j.events.last().unwrap().clone();
        ensure!(
            matches!(
                (last.state.as_str(), to),
                ("claimed", "preflight")
                    | ("preflight", "recovery_point")
                    | ("recovery_point", "staged")
                    | ("staged", "maintenance")
                    | ("maintenance", "migrations")
                    | ("migrations", "switched")
                    | ("switched", "readiness")
                    | ("readiness", "committed")
            ),
            "illegal upgrade transition {} -> {to}",
            last.state
        );
        let remote = control
            .latest()
            .await?
            .ok_or_else(|| anyhow!("active intent missing"))?;
        ensure!(remote.id == last.intent_id, "active intent changed");
        if remote.state == "cancel_requested" {
            j.next(
                "cancel_requested",
                "cancel_observed",
                json!({"cancel_requested":true}),
            )?;
            let e = j.next("cancelled", "cancelled", json!({"cancelled":true}))?;
            control.mutate(&e).await?;
            j.compact()?;
            bail!("upgrade cancelled before step execution");
        }
        match step(a, control, store, &last, name).await {
            Ok(evidence) => {
                let e = j.next(to, name, evidence)?;
                control.mutate(&e).await?;
            }
            Err(error) => {
                let evidence =
                    json!({"category":"step_failed","step":name,"summary":bounded(&error)});
                if maintenance(&last.state) || maintenance(to) {
                    let rolling = j.next("rolling_back", "rolling_back", evidence)?;
                    control.mutate(&rolling).await?;
                    let rollback = rollback(a, &last, name, &error).await;
                    let (state, evidence) = match rollback {
                        Ok(e) => ("rolled_back", e),
                        Err(e) => (
                            "recovery_required",
                            json!({"category":"rollback_failed","failed_step":name,"upgrade_error":bounded(&error),"rollback_error":format!("{}\nstep evidence is empty, invalid, or exceeds 64 KiB",bounded(&e)).chars().take(512).collect::<String>()}),
                        ),
                    };
                    let terminal = j.next(state, state, evidence)?;
                    control.mutate(&terminal).await?;
                    j.compact()?;
                } else {
                    let terminal = j.next("failed", "failed", evidence)?;
                    control.mutate(&terminal).await?;
                    j.compact()?;
                }
                return Err(error);
            }
        }
    }
    ensure!(
        j.events.last().unwrap().state == "committed",
        "step catalog stopped before committed"
    );
    let terminal = j.next("verified", "verified", json!({"verified":true}))?;
    control.mutate(&terminal).await?;
    j.compact()?;
    Ok(())
}
fn maintenance(s: &str) -> bool {
    matches!(
        s,
        "maintenance" | "migrations" | "switched" | "readiness" | "committed" | "rolling_back"
    )
}
fn bounded(e: &anyhow::Error) -> String {
    e.to_string().chars().take(512).collect()
}
async fn step(
    a: &mut Adapters,
    control: &Connection,
    store: &Path,
    e: &crate::journal::Event,
    name: &str,
) -> Result<Value> {
    let root = &a.config.install_root;
    match name {
        "preflight" => {
            let m = stage::verify_tree(store, &e.release_id, &e.manifest_digest)?;
            let registry = if m.feature_registry.is_none() && m.schema_to < 183 {
                json!({"present":false,"unknown_rows":0})
            } else {
                migration::registry(&a.owner, &m, root, "current", "preflight").await?
            };
            host::preflight().await?;
            Ok(json!({"preflight":"passed","feature_registry":registry}))
        }
        "recovery_point" => {
            let identity = control
                .json("SELECT upgrade_recovery_identity_read()", &[])
                .await?;
            let installation = identity["installationId"]
                .as_str()
                .ok_or_else(|| anyhow!("invalid recovery identity"))?;
            let timeline = identity["timelineId"]
                .as_str()
                .ok_or_else(|| anyhow!("invalid recovery timeline"))?;
            ensure!(
                !installation.is_empty() && !timeline.is_empty(),
                "invalid recovery identity"
            );
            let verified = setjoin_backup::recovery::load_verified(
                &a.store,
                &e.recovery_set_id,
                &a.key,
                installation,
                timeline,
            )
            .await
            .map_err(|e| anyhow!(e))?;
            ensure!(
                verified.manifest_sha256 == e.recovery_set_digest,
                "recovery set digest differs from authorized intent"
            );
            Ok(
                json!({"recovery_set_id":verified.manifest.recovery_set_id,"manifest_sha256":verified.manifest_sha256,"created_at":verified.manifest.created_at,"expires_at":verified.manifest.expires_at}),
            )
        }
        "stage_release" => {
            let staged = stage::stage(store, root, &e.release_id, &e.manifest_digest)?;
            host::require_unit_binaries(&staged)?;
            Ok(json!({"release_id":e.release_id,"installed_path":e.release_id}))
        }
        "stop_core" => {
            host::stop().await?;
            Ok(json!({"core_services":"stopped"}))
        }
        "apply_migrations" => {
            let m = stage::verify_tree(store, &e.release_id, &e.manifest_digest)?;
            migration::apply(&mut a.owner, root, &m, &e.manifest_digest).await?;
            Ok(json!({"schema_from":m.schema_from,"schema_to":m.schema_to}))
        }
        "switch_release" => {
            stage::activate(root, &e.release_id)?;
            Ok(json!({"current_release":e.release_id}))
        }
        "start_and_readiness" => {
            host::start().await?;
            host::readiness().await?;
            Ok(json!({"core_readiness":"passed"}))
        }
        "commit_checks" => {
            a.probe.data_contract().await?;
            a.probe.post_commit().await?;
            let m = stage::verify_tree(store, &e.release_id, &e.manifest_digest)?;
            let registry = if m.feature_registry.is_none() && m.schema_to < 183 {
                json!({"present":false,"unknown_rows":0})
            } else {
                migration::registry(&a.owner, &m, root, "previous", "post_commit").await?
            };
            Ok(json!({"data_contract":"passed","post_commit":"passed","feature_registry":registry}))
        }
        _ => bail!("unknown step"),
    }
}
async fn rollback(
    a: &Adapters,
    e: &crate::journal::Event,
    failed: &str,
    cause: &anyhow::Error,
) -> Result<Value> {
    let root = &a.config.install_root;
    if stage::active(root, "current")? == e.release_id {
        stage::previous(root, &e.release_id)?;
    }
    host::start().await?;
    host::readiness().await?;
    a.probe.data_contract().await?;
    a.probe.post_commit().await?;
    let target = migration::installed_manifest(root, "current")?;
    migration::installed_manifest(root, "previous")?;
    let state = if let Some(target) = target {
        migration::registry(&a.owner, &target, root, "previous", "rollback").await?
    } else {
        bail!("feature registry release contract differs: target manifest is unavailable during rollback")
    };
    Ok(
        json!({"rollback":"verified","failed_release":e.release_id,"failed_step":failed,"upgrade_error":bounded(cause),"feature_registry":state}),
    )
}
