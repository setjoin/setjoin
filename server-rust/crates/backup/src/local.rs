//! Frozen POSIX object layout: two-byte shard, confined names, durable rename.
use std::path::{Path, PathBuf};
#[derive(Clone)]
pub(crate) struct Local(pub PathBuf);
impl Local {
    pub fn new(root: &str) -> Result<Self, String> {
        if root.is_empty() {
            return Err("posix: root path required".into());
        }
        let path = Path::new(root);
        Ok(Self(if path.is_absolute() {
            path.into()
        } else {
            std::env::current_dir()
                .map_err(|e| e.to_string())?
                .join(path)
        }))
    }
    pub fn path(&self, key: &str, leaf: bool) -> Result<PathBuf, String> {
        use std::os::unix::ffi::OsStrExt;
        if key.is_empty()
            || key.len() > 1024
            || key.contains(['\0', '\\'])
            || key.starts_with('/')
            || key.split('/').any(|s| matches!(s, "" | "." | ".."))
        {
            return Err("posix: invalid object key".into());
        }
        let shard = std::ffi::OsStr::from_bytes(&key.as_bytes()[..key.len().min(2)]);
        let path = self.0.join(shard).join(key);
        let relative = path
            .strip_prefix(&self.0)
            .map_err(|_| "posix: object path escapes storage root")?;
        let components = relative.components().collect::<Vec<_>>();
        let mut current = self.0.clone();
        for (i, part) in components.iter().enumerate() {
            if !leaf && i == components.len() - 1 {
                break;
            }
            current.push(part);
            match std::fs::symlink_metadata(&current) {
                Ok(m) if m.file_type().is_symlink() => {
                    return Err("posix: symbolic links are not allowed in object paths".into())
                }
                Ok(m) if i < components.len() - 1 && !m.is_dir() => {
                    return Err("posix: object parent is not a directory".into())
                }
                Ok(_) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => break,
                Err(e) => return Err(format!("posix: inspect confined object path: {e}")),
            }
        }
        Ok(path)
    }
    pub fn stage(&self, key: &str) -> Result<Write, String> {
        use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
        let dest = self.path(key, false)?;
        let parent = dest.parent().unwrap();
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o750)
            .create(parent)
            .map_err(|e| format!("posix: mkdir: {e}"))?;
        self.path(key, false)?;
        let mut random = [0; 16];
        ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut random)
            .map_err(|_| "posix: generate temp name")?;
        let temp = parent.join(format!(".tmp-{}", crate::hex(&random)));
        let file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temp)
            .map_err(|e| format!("posix: create temp: {e}"))?;
        Ok(Write {
            dest,
            temp,
            file: tokio::fs::File::from_std(file),
        })
    }
}
pub(crate) struct Write {
    pub temp: PathBuf,
    dest: PathBuf,
    pub file: tokio::fs::File,
}
impl Write {
    pub async fn commit(self) -> Result<(), String> {
        self.file
            .sync_all()
            .await
            .map_err(|e| format!("posix: fsync temp: {e}"))?;
        tokio::fs::rename(&self.temp, &self.dest)
            .await
            .map_err(|e| format!("posix: rename: {e}"))?;
        std::fs::File::open(self.dest.parent().unwrap())
            .and_then(|f| f.sync_all())
            .map_err(|e| format!("posix: fsync destination directory: {e}"))
    }
}
impl Drop for Write {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.temp);
    }
}
