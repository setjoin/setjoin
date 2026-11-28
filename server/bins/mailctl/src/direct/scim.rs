use super::*;
use setjoin_pg::Type;

pub async fn execute(action: &str, args: &[String]) -> Result<(), String> {
    if action == "list-tokens" {
        return list().await;
    }
    if action != "create-token" {
        return Err(format!(
            "unknown scim action: {action}. Try: create-token, list-tokens"
        ));
    }
    let (fs, positional) =
        parse_silent(args, &["name", "source", "expiry", "deletion-policy"], &[])?;
    if !positional.is_empty() {
        return Err("unexpected positional arguments".into());
    }
    let duration = parse_duration(value(&fs, "expiry")).map_err(|_| {
        format!(
            "invalid value {:?} for flag -expiry: parse error",
            value(&fs, "expiry")
        )
    })?;
    let name = value(&fs, "name");
    let source = value(&fs, "source");
    let policy = fs
        .get("deletion-policy")
        .map(String::as_str)
        .unwrap_or("soft");
    if name.is_empty() {
        return Err("--name is required".into());
    }
    if name.trim() != name || name.len() > 128 {
        return Err("--name must be trimmed and at most 128 bytes".into());
    }
    if source.is_empty() {
        return Err("--source is required".into());
    }
    if source.trim() != source || source.len() > 64 {
        return Err("--source must be a trimmed identity source key of at most 64 bytes".into());
    }
    if duration < 0 {
        return Err("--expiry must not be negative".into());
    }
    if !matches!(policy, "soft" | "hard") {
        return Err("--deletion-policy must be 'soft' or 'hard'".into());
    }
    let db = database(false).await?;
    let plaintext = random_hex()?;
    let hash = bcrypt::hash_with_result(&plaintext, 10)
        .map_err(|e| format!("bcrypt hashing failed: {e}"))?
        .format_for_version(bcrypt::Version::TwoA);
    let lookup: String = ring::digest::digest(&ring::digest::SHA256, plaintext.as_bytes())
        .as_ref()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let now = chrono::Utc::now();
    let expiry: Option<String> = if duration > 0 {
        Some(
            (now + chrono::Duration::nanoseconds(duration))
                .to_rfc3339_opts(chrono::SecondsFormat::Nanos, true),
        )
    } else {
        None
    };
    db.query(
        "SELECT scim_token_create($1,$2,$3,$4::timestamptz,$5,'mailctl',$6)::text",
        &[
            (&source, Type::TEXT),
            (&name, Type::TEXT),
            (&hash, Type::TEXT),
            (&expiry, Type::TEXT),
            (&policy, Type::TEXT),
            (&lookup, Type::TEXT),
        ],
    )
    .await
    .map_err(|e| format!("token creation failed: {e}"))?;
    let expires = if duration > 0 {
        (now + chrono::Duration::nanoseconds(duration))
            .to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
    } else {
        "never".into()
    };
    println!("SCIM token created successfully.\n\n  Name:            {name}\n  Source:          {source}\n  Deletion policy: {policy}\n  Expires:         {expires}\n\n  Token (save now — cannot be recovered):\n  {plaintext}\n\n  Authorization header:\n  Authorization: Bearer {plaintext}\n\nCopy this header into your IdP provisioning configuration:\n  - Entra ID: Enterprise Applications → Provisioning → Admin Credentials\n  - Okta: Applications → Provisioning → API Integration");
    Ok(())
}

// Go duration grammar: signed sequences of decimal values with unit suffixes.
fn parse_duration(raw: &str) -> Result<i64, ()> {
    if raw.is_empty() || matches!(raw, "0" | "+0" | "-0") {
        return Ok(0);
    }
    let (negative, mut rest) = if let Some(v) = raw.strip_prefix('-') {
        (true, v)
    } else {
        (false, raw.strip_prefix('+').unwrap_or(raw))
    };
    let mut total = 0_f64;
    while !rest.is_empty() {
        let n = rest
            .find(|c: char| !c.is_ascii_digit() && c != '.')
            .unwrap_or(rest.len());
        if n == 0 {
            return Err(());
        }
        let amount: f64 = rest[..n].parse().map_err(|_| ())?;
        rest = &rest[n..];
        let (unit, scale) = [
            ("ns", 1.),
            ("us", 1e3),
            ("µs", 1e3),
            ("μs", 1e3),
            ("ms", 1e6),
            ("s", 1e9),
            ("m", 60e9),
            ("h", 3600e9),
        ]
        .into_iter()
        .find(|(u, _)| rest.starts_with(u))
        .ok_or(())?;
        total += (amount * scale).trunc();
        rest = &rest[unit.len()..];
    }
    if !total.is_finite() || total > i64::MAX as f64 {
        return Err(());
    }
    Ok(if negative {
        -(total as i64)
    } else {
        total as i64
    })
}

async fn list() -> Result<(), String> {
    let db = database(false).await?;
    let rows = db.query(r#"SELECT token_id,name,source_key,
      to_char(created_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS"Z"'),
      COALESCE(to_char(last_used_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS"Z"'),'-'),
      COALESCE(to_char(expires_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS"Z"'),'never'),
      CASE WHEN revoked_at IS NOT NULL THEN 'revoked' WHEN expires_at < now() THEN 'expired' WHEN source_state <> 'active' THEN source_state ELSE 'active' END,
      deletion_policy,token_hash_prefix FROM scim_token_list()"#, &[]).await.map_err(|e|format!("token query failed: {e}"))?;
    println!(
        "{:<4} {:<24} {:<24} {:<20} {:<20} {:<20} {:<12} {:<6} HASH",
        "ID", "NAME", "SOURCE", "CREATED", "LAST USED", "EXPIRES", "STATUS", "POLICY"
    );
    println!("──── ─────────────────────── ─────────────────────── ──────────────────── ──────────────────── ──────────────────── ──────────── ────── ────────");
    let mut count = 0;
    for row in &rows {
        let id: i64 = row.get(0);
        let strings = (1..9)
            .map(|i| row.try_get::<_, String>(i))
            .collect::<Result<Vec<_>, _>>();
        let Ok(v) = strings else {
            continue;
        };
        let truncate = |s: &str| {
            if s.len() > 23 {
                format!("{}…", String::from_utf8_lossy(&s.as_bytes()[..22]))
            } else {
                s.to_owned()
            }
        };
        println!(
            "{:<4} {:<24} {:<24} {:<20} {:<20} {:<20} {:<12} {:<6} {}...",
            id,
            truncate(&v[0]),
            truncate(&v[1]),
            v[2],
            v[3],
            v[4],
            v[5],
            v[6],
            v[7]
        );
        count += 1;
    }
    if count == 0 {
        println!("(no SCIM tokens configured)");
    } else {
        println!("\n{count} token(s)");
    }
    Ok(())
}
