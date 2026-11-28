//! Frozen Go's idempotent, no-follow config.env bootstrap.
use ring::rand::{SecureRandom, SystemRandom};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::{
    fs::{self, File, OpenOptions, Permissions},
    io::Write,
    path::Path,
};
use zeroize::Zeroizing;

pub(crate) fn bootstrap(path: &Path) -> Result<(), String> {
    match fs::symlink_metadata(path) {
        Ok(info) => {
            safe(&info)?;
            if info.len() > 0 {
                if info.permissions().mode() & 0o077 != 0 {
                    OpenOptions::new()
                        .read(true)
                        .custom_flags(libc::O_NOFOLLOW)
                        .open(path)
                        .and_then(|file| file.set_permissions(Permissions::from_mode(0o600)))
                        .map_err(|e| e.to_string())?;
                }
                return Ok(());
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e.to_string()),
    }
    let mut file = open(path)?;
    let jwt = Zeroizing::new(hex(32)?);
    let db = Zeroizing::new(hex(32)?);
    let api = Zeroizing::new(hex(32)?);
    let vapid = Zeroizing::new(vapid()?);
    let access = Zeroizing::new(hex(20)?);
    let secret = Zeroizing::new(hex(40)?);
    let contents = Zeroizing::new(format!("# Auto-generated on first boot.\n# Change these in the Admin Portal under Settings > System.\n\nJWT_SECRET={}\nDB_ENCRYPTION_KEY={}\nINTERNAL_API_KEY={}\nVAPID_PRIVATE_KEY={}\nMINIO_ACCESS_KEY={}\nMINIO_SECRET_KEY={}\n",*jwt,*db,*api,*vapid,*access,*secret));
    file.write_all(contents.as_bytes())
        .map_err(|e| e.to_string())
}

fn safe(info: &fs::Metadata) -> Result<(), String> {
    if !info.is_file() || (info.len() == 0 && info.permissions().mode() & 0o077 != 0) {
        return Err("refusing unsafe secret file; remove it so an owner-only regular file (0600) can be generated, then restart".into());
    }
    Ok(())
}
fn open(path: &Path) -> Result<File, String> {
    for _ in 0..4 {
        match fs::symlink_metadata(path) {
            Ok(info) => {
                safe(&info)?;
                let file = OpenOptions::new()
                    .write(true)
                    .truncate(true)
                    .custom_flags(libc::O_NOFOLLOW)
                    .open(path)
                    .map_err(|e| e.to_string())?;
                file.set_permissions(Permissions::from_mode(0o600))
                    .map_err(|e| e.to_string())?;
                return Ok(file);
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                match OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .custom_flags(libc::O_NOFOLLOW)
                    .mode(0o600)
                    .open(path)
                {
                    Ok(file) => return Ok(file),
                    Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
                    Err(e) => return Err(e.to_string()),
                }
            }
            Err(e) => return Err(e.to_string()),
        }
    }
    Err("secret file changed state repeatedly during open; refusing".into())
}
fn hex(n: usize) -> Result<String, String> {
    let mut bytes = Zeroizing::new(vec![0u8; n]);
    SystemRandom::new()
        .fill(&mut bytes)
        .map_err(|_| "crypto/rand failed".to_string())?;
    Ok(bytes.iter().map(|b| format!("{b:02x}")).collect())
}
fn vapid() -> Result<String, String> {
    use base64::Engine;
    loop {
        let mut bytes = Zeroizing::new([0u8; 32]);
        SystemRandom::new()
            .fill(&mut *bytes)
            .map_err(|_| "ECDSA key generation failed".to_string())?;
        if let Ok(key) = p256::SecretKey::from_slice(&*bytes) {
            let der = key.to_sec1_der().map_err(|e| e.to_string())?;
            return Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&*der));
        }
    }
}
