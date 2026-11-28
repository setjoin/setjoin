use super::*;
use setjoin_pg::Type;
use std::io::{BufRead, IsTerminal, Read, Write};
use unicode_properties::{GeneralCategory, GeneralCategoryGroup, UnicodeGeneralCategory};
use zeroize::Zeroize;

pub async fn execute(action: &str, args: &[String]) -> Result<(), String> {
    let all_args = std::iter::once(action.to_owned())
        .chain(args.iter().cloned())
        .collect::<Vec<_>>();
    let (fs, positional) =
        parse_silent(&all_args, &["email", "password-file"], &["password-stdin"])?;
    if let Some(arg) = positional.first() {
        return Err(format!("unexpected argument {arg:?}"));
    }
    let email = value(&fs, "email").trim().to_lowercase();
    let valid = mailparse::addrparse(&email)
        .ok()
        .and_then(|v| v.extract_single_info())
        .is_some_and(|a| a.addr == email);
    let local_raw = email.rsplit_once('@').map(|(local, _)| local).unwrap_or("");
    if !valid
        || email.len() > 254
        || email.contains(['<', '>', '(', ')', '"'])
        || local_raw.starts_with('.')
        || local_raw.ends_with('.')
        || local_raw.contains("..")
    {
        return Err("--email must be one valid mailbox address".into());
    }
    let local = email
        .rsplit_once('@')
        .map(|(a, _)| a.trim_matches('"'))
        .unwrap_or("");
    if [
        "postmaster",
        "abuse",
        "webmaster",
        "hostmaster",
        "mailer-daemon",
        "nobody",
    ]
    .contains(&local)
    {
        return Err("--email must not use a reserved local-part (RFC 2142)".into());
    }
    if !value(&fs, "password-file").is_empty() && truth(value(&fs, "password-stdin")) {
        return Err("choose only one of --password-file or --password-stdin".into());
    }
    let db = database(true).await?;
    let mut password = password(&fs)?;
    let result = provision(&db, &email, &password).await;
    // Do not keep plaintext after the command; no secret enters diagnostics.
    password.zeroize();
    result
}

fn password(fs: &BTreeMap<String, String>) -> Result<String, String> {
    let path = value(fs, "password-file");
    if !path.is_empty() {
        let info = std::fs::symlink_metadata(path).map_err(|e| {
            format!(
                "inspect password file: lstat {path}: {}",
                crate::flags::go_io_error(&e)
            )
        })?;
        #[cfg(unix)]
        let private = {
            use std::os::unix::fs::PermissionsExt;
            info.permissions().mode() & 0o077 == 0
        };
        #[cfg(not(unix))]
        let private = true;
        if !info.is_file() || !private {
            return Err("password file must be a regular file with mode 0600 or stricter".into());
        }
        let bytes = std::fs::read(path).map_err(|e| {
            format!(
                "read password file: open {path}: {}",
                crate::flags::go_io_error(&e)
            )
        })?;
        return Ok(String::from_utf8_lossy(&bytes)
            .trim_end_matches(['\r', '\n'])
            .to_owned());
    }
    if truth(value(fs, "password-stdin")) || !std::io::stdin().is_terminal() {
        let mut line = Vec::new();
        std::io::BufReader::new(std::io::stdin().take(74))
            .read_until(b'\n', &mut line)
            .map_err(|e| format!("read password from stdin: {e}"))?;
        return Ok(String::from_utf8_lossy(&line)
            .trim_end_matches(['\r', '\n'])
            .to_owned());
    }
    print!("Administrator password: ");
    std::io::stdout().flush().map_err(|e| e.to_string())?;
    let first = rpassword::read_password().map_err(|e| e.to_string())?;
    println!();
    print!("Confirm password: ");
    std::io::stdout().flush().map_err(|e| e.to_string())?;
    let second = rpassword::read_password().map_err(|e| e.to_string())?;
    println!();
    if first != second {
        return Err("password confirmation does not match".into());
    }
    Ok(first)
}

async fn provision(db: &OperatorConnection, email: &str, password: &str) -> Result<(), String> {
    let rows = db.query("SELECT COALESCE((SELECT (value->>0)::INT FROM system_config WHERE key='password_min_length'),8), COALESCE((SELECT (value->>0)::BOOL FROM system_config WHERE key='password_require_uppercase'),true), COALESCE((SELECT (value->>0)::BOOL FROM system_config WHERE key='password_require_lowercase'),true), COALESCE((SELECT (value->>0)::BOOL FROM system_config WHERE key='password_require_digit'),true), COALESCE((SELECT (value->>0)::BOOL FROM system_config WHERE key='password_require_special'),true)",&[]).await.map_err(|e|format!("load password policy: {e}"))?;
    let row = &rows[0];
    let min: i32 = row.get(0);
    let reason = if password.is_empty() {
        Some("password must not be empty")
    } else if password.len() > 72 {
        Some("password exceeds 72 UTF-8 bytes")
    } else if password.chars().count() < (if min < 1 { 8 } else { min as usize }) {
        Some("password too short")
    } else if row.get::<_, bool>(1)
        && !password
            .chars()
            .any(|c| c.general_category() == GeneralCategory::UppercaseLetter)
    {
        Some("password must contain an uppercase letter")
    } else if row.get::<_, bool>(2)
        && !password
            .chars()
            .any(|c| c.general_category() == GeneralCategory::LowercaseLetter)
    {
        Some("password must contain a lowercase letter")
    } else if row.get::<_, bool>(3)
        && !password
            .chars()
            .any(|c| c.general_category() == GeneralCategory::DecimalNumber)
    {
        Some("password must contain a digit")
    } else if row.get::<_, bool>(4)
        && !password.chars().any(|c| {
            matches!(
                c.general_category_group(),
                GeneralCategoryGroup::Punctuation | GeneralCategoryGroup::Symbol
            )
        })
    {
        Some("password must contain a special character")
    } else if email.rsplit_once('@').is_some_and(|(a, b)| {
        password.to_lowercase().contains(a.trim_matches('"')) || password.to_lowercase().contains(b)
    }) {
        Some("password must not contain your email address")
    } else {
        None
    };
    if let Some(reason) = reason {
        return Err(format!("validation failed for password: {reason}"));
    }
    let hash = if matches!(env("CRYPTO_PROFILE").as_str(), "smx" | "hybrid") {
        use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine};
        use ring::rand::SecureRandom;
        let mut salt = [0; 16];
        ring::rand::SystemRandom::new()
            .fill(&mut salt)
            .map_err(|_| "hash password: sm3 salt: random generation failed")?;
        let mut key = [0; 32];
        pbkdf2::pbkdf2_hmac::<sm3::Sm3>(password.as_bytes(), &salt, 100_000, &mut key);
        let salt = STANDARD_NO_PAD.encode(salt);
        let key = STANDARD_NO_PAD.encode(key);
        format!("$sm3$100000${salt}${key}")
    } else {
        bcrypt::hash_with_result(password, 10)
            .map_err(|e| format!("hash password: {e}"))?
            .format_for_version(bcrypt::Version::TwoA)
    };
    let rows = db
        .query(
            "SELECT ensure_default_admin($1,$2)::text",
            &[(&email, Type::TEXT), (&hash, Type::TEXT)],
        )
        .await
        .map_err(|e| format!("bootstrap administrator: {e}"))?;
    let result: serde_json::Value = serde_json::from_str(rows[0].get::<_, &str>(0))
        .map_err(|e| format!("decode bootstrap result: {e}"))?;
    if result["admin_created"] != true {
        return Err(format!(
            "bootstrap refused: {}",
            result["reason"].as_str().unwrap_or_default()
        ));
    }
    println!(
        "First administrator created: {} (user {})",
        result["email"].as_str().unwrap_or_default(),
        result["user_id"]
    );
    Ok(())
}
