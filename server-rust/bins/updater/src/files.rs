//! Private host-local files. All callers use fixed names or validated identifiers.
use anyhow::{ensure, Context, Result};
use setjoin_release_format::{hash_artifact, sha256};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
};

pub fn entry_exists(path: &Path) -> Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(e.into()),
    }
}
pub fn identifier(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 128
        && s.as_bytes()[0].is_ascii_alphanumeric()
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._:-".contains(&b))
}
pub fn digest(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
/// Root (the euid, which is root in production) must own every path the updater
/// trusts; anything else could be rewritten by an unprivileged account.
pub fn trusted_owner(uid: u32) -> bool {
    #[cfg(feature = "oracle-mutants")]
    {
        let _ = uid;
        return true;
    }
    #[cfg(not(feature = "oracle-mutants"))]
    {
        // SAFETY: geteuid has no preconditions or memory effects.
        uid == 0 || uid == unsafe { libc::geteuid() }
    }
}
pub fn secure_dir(path: &Path, mode: u32) -> Result<()> {
    ensure!(path.is_absolute(), "directory must be absolute");
    if fs::symlink_metadata(path).is_err() {
        // #505/#506: each missing component is created with its final mode in the
        // same mkdir(2), so it never exists with umask-derived permissions.
        use std::os::unix::fs::DirBuilderExt;
        let missing: Vec<_> = path
            .ancestors()
            .take_while(|a| fs::symlink_metadata(a).is_err())
            .map(Path::to_path_buf)
            .collect();
        fs::DirBuilder::new()
            .recursive(true)
            .mode(mode)
            .create(path)?;
        // The kernel applies the umask to mkdir; restore the exact requested mode.
        for created in &missing {
            fs::set_permissions(created, fs::Permissions::from_mode(mode))?;
        }
    }
    let m = fs::symlink_metadata(path)?;
    ensure!(
        m.is_dir() && m.mode() & 0o022 == 0,
        "directory is indirect or mutable: {}",
        path.display()
    );
    ensure!(
        trusted_owner(m.uid()),
        "directory owner must be root: {}",
        path.display()
    );
    Ok(())
}
pub fn existing_dir(path: &Path) -> Result<()> {
    ensure!(path.is_absolute(), "directory must be absolute");
    let m = fs::symlink_metadata(path)?;
    ensure!(
        m.is_dir() && m.mode() & 0o022 == 0,
        "directory is indirect or mutable"
    );
    Ok(())
}
pub fn open(path: &Path, private: bool) -> Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .with_context(|| format!("open {}", path.display()))?;
    let m = file.metadata()?;
    ensure!(
        trusted_owner(m.uid()),
        "file owner must be root: {}",
        path.display()
    );
    ensure!(
        m.is_file()
            && m.nlink() == 1
            && m.mode() & 0o7022 == 0
            && (!private || m.mode() & 0o077 == 0),
        "unsafe regular file: {}",
        path.display()
    );
    Ok(file)
}
pub fn read(path: &Path, limit: u64, private: bool) -> Result<Vec<u8>> {
    let f = open(path, private)?;
    ensure!(f.metadata()?.len() <= limit, "file exceeds limit");
    let mut bytes = Vec::new();
    f.take(limit + 1).read_to_end(&mut bytes)?;
    ensure!(bytes.len() as u64 <= limit, "file exceeds limit");
    Ok(bytes)
}
pub fn credential(path: &Path) -> Result<String> {
    let v = String::from_utf8(read(path, 16384, true)?)?
        .trim()
        .to_owned();
    ensure!(
        !v.is_empty() && !v.contains(['\r', '\n', '\0']),
        "invalid credential"
    );
    Ok(v)
}
pub fn sync_dir(path: &Path) -> Result<()> {
    File::open(path)?.sync_all()?;
    Ok(())
}
pub fn write_new(path: &Path, bytes: &[u8], mode: u32) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .open(path)?;
    f.write_all(bytes)?;
    f.sync_all()?;
    Ok(())
}
pub fn atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    let temp = path.with_file_name(format!(
        ".{}.{}.new",
        path.file_name().unwrap().to_string_lossy(),
        uuid::Uuid::new_v4()
    ));
    let result = (|| {
        write_new(&temp, bytes, 0o600)?;
        fs::rename(&temp, path)?;
        sync_dir(path.parent().unwrap())
    })();
    if temp.exists() {
        let _ = fs::remove_file(temp);
    }
    result
}
pub fn tree_entries(root: &Path) -> Result<Vec<PathBuf>> {
    fn walk(root: &Path, result: &mut Vec<PathBuf>) -> Result<()> {
        for item in fs::read_dir(root)? {
            let p = item?.path();
            let m = fs::symlink_metadata(&p)?;
            ensure!(
                (m.is_dir() || m.is_file()) && m.mode() & 0o7022 == 0,
                "unsafe tree entry"
            );
            ensure!(
                trusted_owner(m.uid()),
                "tree entry owner must be root: {}",
                p.display()
            );
            result.push(p.clone());
            if m.is_dir() {
                walk(&p, result)?;
            }
        }
        Ok(())
    }
    secure_dir(root, 0o700)?;
    let mut paths = Vec::new();
    walk(root, &mut paths)?;
    paths.sort();
    Ok(paths)
}
pub fn tree_digest(root: &Path, exclude: &str) -> Result<String> {
    let mut bytes = Vec::new();
    let mut files = 0;
    for path in tree_entries(root)? {
        let relative = path
            .strip_prefix(root)?
            .to_str()
            .context("non-UTF8 release path")?;
        if relative == exclude {
            ensure!(
                fs::symlink_metadata(path)?.is_file(),
                "excluded evidence is not regular"
            );
            continue;
        }
        let dir = path.is_dir();
        let hash = if dir {
            String::new()
        } else {
            files += 1;
            hash_artifact(open(&path, false)?)?.1
        };
        bytes.extend_from_slice(
            format!("{}\0{relative}\0{hash}\0", if dir { "d" } else { "f" }).as_bytes(),
        );
    }
    ensure!(files > 0, "empty release tree");
    Ok(sha256(&bytes))
}
pub fn immutable(root: &Path) -> Result<()> {
    let mut paths = tree_entries(root)?;
    paths.push(root.into());
    for path in paths.iter().rev() {
        let m = fs::symlink_metadata(path)?;
        let mode = if m.is_dir() || m.mode() & 0o111 != 0 {
            0o555
        } else {
            0o444
        };
        fs::set_permissions(path, fs::Permissions::from_mode(mode))?;
        File::open(path)?.sync_all()?;
    }
    Ok(())
}
pub fn remove_tree(root: &Path) -> Result<()> {
    if !root.try_exists()? {
        return Ok(());
    }
    let paths = tree_entries(root)?;
    fs::set_permissions(root, fs::Permissions::from_mode(0o700))?;
    for path in paths {
        if path.is_dir() {
            fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
        }
    }
    fs::remove_dir_all(root)?;
    Ok(())
}
