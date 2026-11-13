//! Offline update store. Only authenticated metadata can advertise bytes.
use chrono::{DateTime, FixedOffset, Utc};
use serde::{Deserialize, Serialize};
use setjoin_release_format::{marshal_go, Purpose, TrustStore};
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    sync::RwLock,
};

macro_rules! go_object {
    ($name:ident {$($field:ident:$ty:ty),+$(,)?})=>{
        #[derive(Default,Clone,Serialize)]
        pub struct $name {$(pub $field:$ty),+}
        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D:serde::Deserializer<'de>>(decoder:D)->Result<Self,D::Error>{
                struct Fields;
                impl<'de> serde::de::Visitor<'de> for Fields {
                    type Value=$name;
                    fn expecting(&self,f:&mut std::fmt::Formatter<'_>)->std::fmt::Result{f.write_str("offline update metadata")}
                    fn visit_unit<E:serde::de::Error>(self)->Result<Self::Value,E>{Ok($name::default())}
                    fn visit_map<M:serde::de::MapAccess<'de>>(self,mut fields:M)->Result<Self::Value,M::Error>{
                        let mut body=$name::default();
                        while let Some(key)=fields.next_key::<String>()? {
                            let key:String=key.chars().map(|c|match c {'ſ'=>'s','K'=>'k',_=>c.to_ascii_lowercase()}).collect();
                            match key.as_str() {$(stringify!($field)=>if let Some(value)=fields.next_value::<Option<$ty>>()? {body.$field=value;},)+
                                _=>return Err(serde::de::Error::custom("unknown offline metadata field")),
                            }
                        }
                        Ok(body)
                    }
                }
                decoder.deserialize_any(Fields)
            }
        }
    };
}
go_object!(Target {
    schema_version: i32,
    metadata_version: u64,
    expires_at: String,
    slug: String,
    version: String,
    platform: String,
    filename: String,
    size_bytes: i64,
    sha256: String,
    key_id: String,
    signature: String,
});
#[derive(Default, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Bundle {
    pub version: String,
    pub platform: String,
    pub slug: String,
    pub filename: String,
    pub sha256: String,
    pub size_bytes: i64,
    pub uploaded_at: String,
    pub metadata_version: u64,
    pub expires_at: String,
    pub key_id: String,
    pub target_metadata: String,
}
struct Admitted {
    bundle: Bundle,
    expiry: DateTime<FixedOffset>,
}
#[derive(Default)]
struct State {
    bundles: BTreeMap<String, Admitted>,
    floor: BTreeMap<String, u64>,
}
pub struct Store {
    dir: PathBuf,
    trust: Option<TrustStore>,
    state: RwLock<State>,
}
/// Persisted per-slug anti-rollback floor (#542, owner-approved security fix 2026-11-05).
/// Frozen Go rebuilt the floor only from surviving sidecars, so pruning an old bundle (or an
/// operator deleting one) lowered it and a signed older target could be uploaded again. The
/// floor now lives in a sibling file of the store directory (`<dir>.floor`, never inside it:
/// the directory's contents are the served index) and only ever rises.
fn floor_path(dir: &Path) -> PathBuf {
    let mut name = dir.as_os_str().to_owned();
    name.push(".floor");
    PathBuf::from(name)
}
fn read_floor(dir: &Path) -> Result<BTreeMap<String, u64>, String> {
    match std::fs::read(floor_path(dir)) {
        Ok(raw) => serde_json::from_slice(&raw).map_err(|e| e.to_string()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(BTreeMap::new()),
        Err(error) => Err(error.to_string()),
    }
}
fn write_floor(dir: &Path, floor: &BTreeMap<String, u64>) -> std::io::Result<()> {
    use std::io::Write;
    let path = floor_path(dir);
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let mut file = tempfile::Builder::new()
        .prefix(".airgap-floor-")
        .tempfile_in(parent)?;
    file.write_all(&serde_json::to_vec(floor).map_err(std::io::Error::other)?)?;
    file.as_file().sync_all()?;
    file.persist(path).map_err(|e| e.error)?;
    Ok(())
}
impl Target {
    fn parse(raw: &str) -> Result<(Self, DateTime<FixedOffset>), String> {
        let target: Self =
            serde_json::from_str(raw).map_err(|_| "invalid offline target metadata")?;
        if target.schema_version != 1
            || target.metadata_version == 0
            || target.slug.is_empty()
            || target.filename.is_empty()
            || target.size_bytes <= 0
            || target.sha256.len() != 64
        {
            return Err("invalid offline target metadata".into());
        }
        let expiry = DateTime::parse_from_rfc3339(&target.expires_at)
            .map_err(|_| "offline target metadata is expired")?;
        Ok((target, expiry))
    }
    fn canonical(&self) -> Result<Vec<u8>, String> {
        let mut target = self.clone();
        target.signature.clear();
        marshal_go(&target).map_err(|e| e.to_string())
    }
}
pub fn valid_part(part: &str) -> bool {
    !part.is_empty() && !matches!(part, "." | "..") && !part.contains(['/', '\\'])
}
impl Store {
    pub fn load(dir: impl AsRef<Path>, root: impl AsRef<Path>) -> Result<Self, String> {
        use std::os::unix::fs::DirBuilderExt;
        let trust = match std::fs::read(root) {
            Ok(raw) => Some(
                TrustStore::parse_roots(&raw, Purpose::OfflineUpdate, false)
                    .map_err(|e| format!("updates: parse offline trust roots: {e}"))?,
            ),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
            Err(error) => return Err(format!("updates: read offline trust roots: {error}")),
        };
        let dir = dir.as_ref().to_owned();
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o750)
            .create(&dir)
            .map_err(|e| format!("updates: cannot create store dir: {e}"))?;
        let store = Self {
            dir,
            trust,
            state: RwLock::new(State::default()),
        };
        let mut paths = std::fs::read_dir(&store.dir)
            .into_iter()
            .flatten()
            .filter_map(Result::ok)
            .map(|p| p.path())
            .filter(|p| p.extension().is_some_and(|e| e == "json"))
            .collect::<Vec<_>>();
        paths.sort();
        let mut state = store.state.write().expect("airgap store");
        // Test-only bug restoration (airgap-floor-sidecar-only): ignore the persisted floor.
        if !setjoin_contracts::mutants::on("airgap-floor-sidecar-only") {
            state.floor = read_floor(&store.dir)
                .map_err(|e| format!("updates: read anti-rollback floor: {e}"))?;
        }
        for path in paths {
            let Some(bundle) = std::fs::read(&path)
                .ok()
                .and_then(|raw| serde_json::from_slice::<Bundle>(&raw).ok())
            else {
                continue;
            };
            if !valid_part(&bundle.slug) || !valid_part(&bundle.filename) || bundle.size_bytes < 0 {
                continue;
            }
            let Ok((metadata, expiry)) = store.authenticate(&bundle) else {
                continue;
            };
            state
                .floor
                .entry(bundle.slug.clone())
                .and_modify(|floor| *floor = (*floor).max(metadata.metadata_version))
                .or_insert(metadata.metadata_version);
            if expiry > Utc::now() {
                let mut bundle = bundle;
                bundle.expires_at = metadata.expires_at;
                bundle.key_id = metadata.key_id;
                state
                    .bundles
                    .insert(bundle.slug.clone(), Admitted { bundle, expiry });
            }
        }
        drop(state);
        Ok(store)
    }
    fn authenticate(&self, bundle: &Bundle) -> Result<(Target, DateTime<FixedOffset>), String> {
        let trust = self
            .trust
            .as_ref()
            .ok_or("air-gap bundle lacks authenticated target metadata")?;
        let (target, expiry) = Target::parse(&bundle.target_metadata)?;
        trust
            .verify_detached(
                Purpose::OfflineUpdate,
                &target.key_id,
                &target.canonical()?,
                &target.signature,
            )
            .map_err(|e| e.to_string())?;
        if target.slug != bundle.slug
            || target.filename != bundle.filename
            || target.version != bundle.version
            || target.platform != bundle.platform
            || target.sha256 != bundle.sha256
            || target.size_bytes != bundle.size_bytes
            || target.metadata_version != bundle.metadata_version
        {
            return Err("air-gap bundle does not match its authenticated target metadata".into());
        }
        Ok((target, expiry))
    }
    pub fn file(&self, slug: &str, filename: &str) -> Option<PathBuf> {
        let state = self.state.read().expect("airgap store");
        let admitted = state.bundles.get(slug)?;
        (admitted.expiry > Utc::now() && admitted.bundle.filename == filename)
            .then(|| self.dir.join(format!("{slug}_{filename}")))
    }
    pub fn appcast(&self) -> String {
        #[derive(Serialize)]
        struct Entry<'a> {
            version: &'a str,
            slug: &'a str,
            url: String,
            sha256: &'a str,
            size_bytes: i64,
        }
        #[derive(Serialize)]
        struct Feed<'a> {
            updates: Vec<Entry<'a>>,
        }
        let state = self.state.read().expect("airgap store");
        let updates = state
            .bundles
            .values()
            .filter(|entry| entry.expiry > Utc::now())
            .map(|entry| {
                let b = &entry.bundle;
                Entry {
                    version: &b.version,
                    slug: &b.slug,
                    url: format!("/updates/{}/{}", b.slug, b.filename),
                    sha256: &b.sha256,
                    size_bytes: b.size_bytes,
                }
            })
            .collect();
        String::from_utf8(marshal_go(&Feed { updates }).expect("offline update feed"))
            .expect("JSON UTF8")
            + "\n"
    }
}

pub struct Failure {
    pub status: u16,
    pub detail: String,
}
fn failed(status: u16, detail: impl Into<String>) -> Failure {
    Failure {
        status,
        detail: detail.into(),
    }
}
fn internal(_: impl std::fmt::Display) -> Failure {
    failed(500, "internal server error")
}
fn time_text(time: DateTime<FixedOffset>) -> String {
    let mut text = time.format("%Y-%m-%dT%H:%M:%S").to_string();
    let nanos = time.timestamp_subsec_nanos();
    if nanos > 0 {
        text.push('.');
        text.push_str(format!("{nanos:09}").trim_end_matches('0'));
    }
    if time.offset().local_minus_utc() == 0 {
        text.push('Z');
    } else {
        text.push_str(&time.format("%:z").to_string());
    }
    text
}
impl Store {
    /// The HTTP adapter already read the bounded multipart form. Go similarly
    /// holds <=100MiB in memory before validating its fields and staging bytes.
    pub fn upload(
        &self,
        slug: String,
        raw: String,
        file: Option<(String, Vec<u8>)>,
    ) -> Result<Bundle, Failure> {
        use sha2::{Digest, Sha256};
        use std::io::Write;
        use std::os::unix::fs::PermissionsExt;
        if slug.is_empty() {
            return Err(failed(400, "slug is required"));
        }
        if !valid_part(&slug) {
            return Err(failed(400, "invalid slug"));
        }
        let trust = self
            .trust
            .as_ref()
            .ok_or_else(|| failed(503, "offline update trust roots are not installed"))?;
        let (target, expiry) = Target::parse(&raw)
            .map_err(|_| failed(400, "signed offline target metadata is required"))?;
        if expiry <= Utc::now() {
            return Err(failed(400, "signed offline target metadata is required"));
        }
        let (filename, bytes) = file.ok_or_else(|| failed(400, "file is required"))?;
        // filepath.Base on Unix; backslash is intentionally not a separator here.
        let trimmed = filename.trim_end_matches('/');
        let safe = if filename.is_empty() {
            "."
        } else if trimmed.is_empty() {
            "/"
        } else {
            trimmed.rsplit('/').next().unwrap_or(trimmed)
        };
        if matches!(safe, "." | "..") || safe.contains('/') {
            return Err(failed(400, "invalid filename"));
        }
        let mut staged = tempfile::Builder::new()
            .prefix(".airgap-upload-")
            .tempfile_in(&self.dir)
            .map_err(internal)?;
        staged.write_all(&bytes).map_err(internal)?;
        staged.as_file().sync_all().map_err(internal)?;
        let written = bytes.len() as i64;
        let hash = format!("{:x}", Sha256::digest(&bytes));
        if target.slug != slug
            || target.filename != safe
            || target.size_bytes != written
            || target.sha256 != hash
        {
            return Err(failed(
                400,
                "offline target metadata does not match uploaded bytes",
            ));
        }
        trust
            .verify_detached(
                Purpose::OfflineUpdate,
                &target.key_id,
                &target.canonical().map_err(internal)?,
                &target.signature,
            )
            .map_err(|_| failed(400, "offline target signature verification failed"))?;
        let bundle = Bundle {
            version: target.version.clone(),
            platform: target.platform.clone(),
            slug: slug.clone(),
            filename: safe.to_owned(),
            sha256: hash,
            size_bytes: written,
            uploaded_at: time_text(Utc::now().fixed_offset()),
            metadata_version: target.metadata_version,
            expires_at: time_text(expiry),
            key_id: target.key_id.clone(),
            target_metadata: raw,
        };
        let (_, checked_expiry) = self
            .authenticate(&bundle)
            .map_err(|_| failed(400, "offline target metadata failed re-verification"))?;
        if checked_expiry <= Utc::now() {
            return Err(failed(
                400,
                "offline target metadata failed re-verification",
            ));
        }
        let mut state = self.state.write().expect("airgap store");
        let floor = state.floor.get(&slug).copied().unwrap_or(0).max(
            state
                .bundles
                .get(&slug)
                .map(|b| b.bundle.metadata_version)
                .unwrap_or(0),
        );
        if floor != 0 && target.metadata_version <= floor {
            return Err(failed(409, "offline target metadata rollback detected"));
        }
        let used = state
            .bundles
            .iter()
            .filter(|(key, _)| **key != slug)
            .fold(0i64, |n, (_, b)| n.wrapping_add(b.bundle.size_bytes));
        if written < 0 || used > (20i64 << 30) - written {
            return Err(failed(507, "air-gap update store quota exceeded"));
        }
        let capacity = rustix::fs::statfs(&self.dir).map_err(|e| {
            failed(
                507,
                format!("cannot determine air-gap update filesystem capacity: {e}"),
            )
        })?;
        let total = capacity.f_blocks.wrapping_mul(capacity.f_bsize as u64);
        let free = capacity.f_bavail.wrapping_mul(capacity.f_bsize as u64);
        if total == 0 || free.wrapping_mul(100) < total.wrapping_mul(10) {
            return Err(failed(
                507,
                "air-gap update store requires at least 10% free filesystem space",
            ));
        }
        // Persist the raised floor before the new bytes become visible; it never decreases.
        let mut raised = state.floor.clone();
        raised
            .entry(slug.clone())
            .and_modify(|floor| *floor = (*floor).max(target.metadata_version))
            .or_insert(target.metadata_version);
        write_floor(&self.dir, &raised).map_err(internal)?;
        // The disk floor is already raised: keep memory in step even if publishing fails below.
        // Test-only bug restoration (airgap-floor-memory-lags): memory only follows a publish.
        if !setjoin_contracts::mutants::on("airgap-floor-memory-lags") {
            state.floor = raised;
        }
        let previous = state.bundles.get(&slug).map(|b| b.bundle.filename.clone());
        let destination = self.dir.join(format!("{slug}_{safe}"));
        staged.persist(&destination).map_err(internal)?;
        let publish = (|| -> Result<(), Failure> {
            let data = marshal_go(&bundle).map_err(internal)?;
            let mut sidecar = tempfile::Builder::new()
                .prefix(".airgap-metadata-")
                .tempfile_in(&self.dir)
                .map_err(internal)?;
            sidecar
                .as_file()
                .set_permissions(std::fs::Permissions::from_mode(0o640))
                .map_err(internal)?;
            sidecar.write_all(&data).map_err(internal)?;
            sidecar.as_file().sync_all().map_err(internal)?;
            sidecar
                .persist(self.dir.join(format!("{slug}.json")))
                .map_err(internal)?;
            Ok(())
        })();
        if let Err(error) = publish {
            let _ = std::fs::remove_file(destination);
            return Err(error);
        }
        state.bundles.insert(
            slug.clone(),
            Admitted {
                bundle: bundle.clone(),
                expiry: checked_expiry,
            },
        );
        state
            .floor
            .entry(slug.clone())
            .and_modify(|floor| *floor = (*floor).max(target.metadata_version))
            .or_insert(target.metadata_version);
        if let Some(previous) = previous.filter(|previous| previous != safe) {
            let _ = std::fs::remove_file(self.dir.join(format!("{slug}_{previous}")));
        }
        let mut candidates = state
            .bundles
            .iter()
            .filter(|(_, b)| b.bundle.platform == target.platform)
            .map(|(slug, b)| {
                (
                    slug.clone(),
                    DateTime::parse_from_rfc3339(&b.bundle.uploaded_at)
                        .map(|at| at.timestamp_nanos_opt().unwrap_or(i64::MIN))
                        .unwrap_or(i64::MIN),
                    b.bundle.metadata_version,
                )
            })
            .collect::<Vec<_>>();
        candidates.sort_by(|a, b| b.1.cmp(&a.1).then(b.2.cmp(&a.2)));
        for (slug, _, _) in candidates.into_iter().skip(3) {
            if let Some(stale) = state.bundles.remove(&slug) {
                let _ = std::fs::remove_file(
                    self.dir.join(format!("{slug}_{}", stale.bundle.filename)),
                );
                let _ = std::fs::remove_file(self.dir.join(format!("{slug}.json")));
            }
        }
        Ok(bundle)
    }
    pub fn encode_bundle(bundle: &Bundle) -> String {
        String::from_utf8(marshal_go(bundle).expect("offline update bundle")).expect("JSON UTF8")
            + "\n"
    }
}
