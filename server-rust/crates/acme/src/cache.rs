//! Certificate cache shared with frozen Go's `acme.DirCache`: one blob per domain at
//! `hex(sha256(domain))`, a 0600 file in a 0700 directory, written through a same-directory
//! temp file plus rename so a reader sees the old blob or the whole new one.
use sha2::{Digest, Sha256};
use std::{
    io::Write,
    os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
};

#[derive(Clone, Debug)]
pub struct DirCache {
    dir: PathBuf,
}

impl DirCache {
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self { dir: dir.into() }
    }

    pub fn path(&self, domain: &str) -> PathBuf {
        let digest = Sha256::digest(domain.as_bytes());
        self.dir.join(
            digest
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>(),
        )
    }

    pub fn get(&self, domain: &str) -> std::io::Result<Vec<u8>> {
        std::fs::read(self.path(domain))
    }

    pub fn put(&self, domain: &str, data: &[u8]) -> Result<(), String> {
        write_atomic(&self.path(domain), data, 0o600)
    }
}

/// Go's `writeFileAtomic`: `MkdirAll(dir, 0700)`, temp `.acme-*.tmp`, fsync, chmod, rename.
pub fn write_atomic(path: &Path, data: &[u8], mode: u32) -> Result<(), String> {
    let dir = path.parent().ok_or("acme cache path has no directory")?;
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)
        .map_err(|e| format!("acme cache mkdir: {e}"))?;
    let mut tmp = None;
    for attempt in 0..16u32 {
        let nonce = {
            let mut bytes = [0u8; 8];
            ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut bytes)
                .map_err(|_| "acme cache temp: no randomness")?;
            u64::from_le_bytes(bytes) ^ u64::from(attempt)
        };
        let candidate = dir.join(format!(".acme-{nonce}.tmp"));
        match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&candidate)
        {
            Ok(file) => {
                tmp = Some((candidate, file));
                break;
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(format!("acme cache temp: {e}")),
        }
    }
    let (name, mut file) = tmp.ok_or("acme cache temp: no free name")?;
    let result = (|| {
        file.write_all(data)
            .map_err(|e| format!("acme cache write: {e}"))?;
        file.sync_all()
            .map_err(|e| format!("acme cache sync: {e}"))?;
        drop(file);
        std::fs::set_permissions(&name, std::fs::Permissions::from_mode(mode))
            .map_err(|e| format!("acme cache chmod: {e}"))?;
        std::fs::rename(&name, path).map_err(|e| format!("acme cache rename: {e}"))
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&name);
    }
    result
}
