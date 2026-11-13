use super::*;
use num_bigint::BigUint;
use setjoin_pg::Type;
use x509_parser::{
    der_parser::{ber::BerObject, der::parse_der},
    prelude::*,
};

pub async fn execute(action: &str, args: &[String]) -> Result<(), String> {
    if action != "import" {
        return Err(format!("unknown smime action: {action}. Try: import"));
    }
    let (flags, positional): (Vec<_>, Vec<_>) =
        args.iter().cloned().partition(|a| a.starts_with('-'));
    let fs = crate::flags::parse("smime import", &flags, &[], &["dry-run", "default"], false);
    if positional.len() != 1 {
        return Err("usage: smime import <manifest.csv> [--dry-run] [--default]\n  manifest CSV columns: email,cert_path,key_path[,label]".into());
    }
    let dry = fs.boolean("dry-run");
    let encryption_key = env("DB_ENCRYPTION_KEY");
    if !dry && encryption_key.is_empty() {
        return Err("DB_ENCRYPTION_KEY is required to encrypt imported private keys (set it to the SAME value the gateway uses, or pass --dry-run to validate only)".into());
    }
    let path = &positional[0];
    let data = std::fs::read(path).map_err(|e| {
        format!(
            "open manifest: open {path}: {}",
            crate::flags::go_io_error(&e)
        )
    })?;
    let mut reader = csv::ReaderBuilder::new()
        .has_headers(false)
        .flexible(true)
        .from_reader(data.as_slice());
    let mut rows = vec![];
    for (i, record) in reader.records().enumerate() {
        let record =
            record.map_err(|e| format!("manifest parse error near line {}: {e}", i + 1))?;
        let first = record.get(0).unwrap_or_default().trim();
        if first.is_empty()
            || first.starts_with('#')
            || (i == 0 && first.eq_ignore_ascii_case("email"))
        {
            continue;
        }
        if record.len() < 3 {
            return Err(format!(
                "manifest line {}: need at least email,cert_path,key_path",
                i + 1
            ));
        }
        let row = record
            .iter()
            .map(|s| s.trim().to_owned())
            .collect::<Vec<_>>();
        if row.iter().take(3).any(|s| s.is_empty()) {
            return Err(format!(
                "manifest line {}: email, cert_path, key_path are all required",
                i + 1
            ));
        }
        rows.push(row);
    }
    if rows.is_empty() {
        return Err(format!("manifest {path} has no data rows"));
    }
    let db = if dry {
        None
    } else {
        Some(database(false).await?)
    };
    let mut imported = 0;
    for (i, row) in rows.iter().enumerate() {
        let n = i + 1;
        let email = &row[0];
        let cert_path = &row[1];
        let key_path = &row[2];
        let label = row
            .get(3)
            .filter(|s| !s.is_empty())
            .map(String::as_str)
            .unwrap_or("imported");
        let cert = match read_file(cert_path) {
            Ok(v) => v,
            Err(e) => {
                println!("  [{n}] {email}: SKIP — read cert {cert_path}: {e}");
                continue;
            }
        };
        let key = match read_file(key_path) {
            Ok(v) => v,
            Err(e) => {
                println!("  [{n}] {email}: SKIP — read key {key_path}: {e}");
                continue;
            }
        };
        let cert_pem = String::from_utf8_lossy(&cert).into_owned();
        let key_pem = String::from_utf8_lossy(&key).into_owned();
        let cert = match certificate(&cert) {
            Ok(v) => v,
            Err(e) => {
                println!("  [{n}] {email}: SKIP — invalid certificate: {e}");
                continue;
            }
        };
        if let Err(e) = validate_key(&key) {
            println!("  [{n}] {email}: SKIP — invalid private key: {e}");
            continue;
        }
        if !cert
            .emails
            .iter()
            .any(|s| s.eq_ignore_ascii_case(email.trim()))
        {
            println!("  [{n}] {email}: WARN — cert SAN/CN does not include {email}");
        }
        if let Some(db) = &db {
            let found = db
                .query(
                    "SELECT id FROM users WHERE lower(email)=lower($1)",
                    &[(&email.as_str(), Type::TEXT)],
                )
                .await;
            let user = match found {
                Ok(rows) if !rows.is_empty() => rows[0].get::<_, i64>(0),
                _ => {
                    println!("  [{n}] {email}: SKIP — no such user");
                    continue;
                }
            };
            let issued = chrono::DateTime::from_timestamp(cert.not_before, 0)
                .ok_or("invalid certificate time")?
                .to_rfc3339();
            let expires = chrono::DateTime::from_timestamp(cert.not_after, 0)
                .ok_or("invalid certificate time")?
                .to_rfc3339();
            let as_default = fs.boolean("default");
            let result=db.query("INSERT INTO user_smime_certs (user_id,label,cert_pem,private_key_enc,issued_at,expires_at,is_default) VALUES ($1,$2,$3,pgp_sym_encrypt($4,$5),$6::timestamptz,$7::timestamptz,CASE WHEN $8 THEN TRUE ELSE NOT EXISTS (SELECT 1 FROM user_smime_certs WHERE user_id=$1) END) ON CONFLICT (user_id,label) DO UPDATE SET cert_pem=EXCLUDED.cert_pem,private_key_enc=EXCLUDED.private_key_enc,issued_at=EXCLUDED.issued_at,expires_at=EXCLUDED.expires_at",
                &[(&user,Type::INT8),(&label,Type::TEXT),(&cert_pem,Type::TEXT),(&key_pem,Type::TEXT),(&encryption_key,Type::TEXT),(&issued,Type::TEXT),(&expires,Type::TEXT),(&as_default,Type::BOOL)]).await;
            if let Err(e) = result {
                println!("  [{n}] {email}: SKIP — store failed: {e}");
                continue;
            }
            if as_default {
                if let Err(e) = db
                    .query(
                        "UPDATE user_smime_certs SET is_default=(label=$2) WHERE user_id=$1",
                        &[(&user, Type::INT8), (&label, Type::TEXT)],
                    )
                    .await
                {
                    println!("  [{n}] {email}: WARN — stored, but set-default failed: {e}");
                }
            }
            println!("  [{n}] {email}: imported (label={label:?})");
        } else {
            println!("  [{n}] {email}: OK (dry-run) cert={cert_path} label={label:?}");
        }
        imported += 1;
    }
    let skipped = rows.len() - imported;
    let verb = if dry { "validated" } else { "imported" };
    println!(
        "smime import: {imported} {verb}, {skipped} skipped (of {} rows)",
        rows.len()
    );
    if imported == 0 {
        return Err(format!("no rows {verb} — see SKIP lines above"));
    }
    Ok(())
}
fn read_file(path: &str) -> Result<Vec<u8>, String> {
    std::fs::read(path).map_err(|e| format!("open {path}: {}", crate::flags::go_io_error(&e)))
}
struct Certificate {
    emails: Vec<String>,
    not_before: i64,
    not_after: i64,
}
fn certificate(raw: &[u8]) -> Result<Certificate, String> {
    let (_, pem) = x509_parser::pem::parse_x509_pem(raw).map_err(|_| "not PEM-encoded")?;
    let (_, cert) =
        X509Certificate::from_der(&pem.contents).map_err(|_| "x509: malformed certificate")?;
    let mut emails = vec![];
    if let Ok(Some(san)) = cert.subject_alternative_name() {
        for name in &san.value.general_names {
            if let GeneralName::RFC822Name(email) = name {
                emails.push(email.to_string());
            }
        }
    }
    if let Some(cn) = cert
        .subject()
        .iter_common_name()
        .next()
        .and_then(|a| a.as_str().ok())
    {
        emails.push(cn.trim().to_owned());
    }
    Ok(Certificate {
        emails,
        not_before: cert.validity().not_before.timestamp(),
        not_after: cert.validity().not_after.timestamp(),
    })
}
pub(super) fn validate_key(raw: &[u8]) -> Result<(), String> {
    let (_, pem) = x509_parser::pem::parse_x509_pem(raw).map_err(|_| "not PEM-encoded")?;
    if pem.label.contains("ENCRYPTED")
        || String::from_utf8_lossy(raw)
            .lines()
            .any(|l| l.starts_with("Proc-Type:") && l.contains("ENCRYPTED"))
    {
        return Err("private key is passphrase-encrypted; decrypt it first".into());
    }
    let valid = (|| -> Option<()> {
        let (_, object) = parse_der(&pem.contents).ok()?;
        let seq = object.as_sequence().ok()?;
        if rsa(seq).is_some() || ec(seq, None).is_some() {
            return Some(());
        }
        if seq.len() < 3 {
            return None;
        }
        let alg = seq[1].as_sequence().ok()?;
        let oid = alg.first()?.as_oid().ok()?.to_id_string();
        let inner = seq[2].as_slice().ok()?;
        let (_, object) = parse_der(inner).ok()?;
        match oid.as_str() {
            "1.2.840.113549.1.1.1" => rsa(object.as_sequence().ok()?),
            "1.2.840.10045.2.1" => ec(
                object.as_sequence().ok()?,
                Some(alg.get(1)?.as_oid().ok()?.to_id_string()),
            ),
            "1.3.101.112" if alg.len() == 1 && object.as_slice().ok()?.len() == 32 => Some(()),
            _ => None,
        }
    })();
    valid.ok_or_else(|| "unrecognized key (need unencrypted PKCS#8, PKCS#1, or SEC1 EC PEM)".into())
}
fn rsa(seq: &[BerObject<'_>]) -> Option<()> {
    if seq.len() < 9 || seq[0].as_u32().ok()? > 1 {
        return None;
    }
    let ints = seq[1..9]
        .iter()
        .map(|v| v.as_biguint().ok())
        .collect::<Option<Vec<_>>>()?;
    let (n, e, d, p, q) = (&ints[0], &ints[1], &ints[2], &ints[3], &ints[4]);
    let one = BigUint::from(1_u8);
    if e < &BigUint::from(2_u8) || e > &BigUint::from(i32::MAX as u32) || p <= &one || q <= &one {
        return None;
    }
    let mut product = p * q;
    let mut primes = vec![p.clone(), q.clone()];
    if seq.len() > 9 {
        for row in seq[9].as_sequence().ok()? {
            let prime = row.as_sequence().ok()?.first()?.as_biguint().ok()?;
            product *= &prime;
            primes.push(prime);
        }
    }
    if &product != n
        || primes
            .iter()
            .any(|p| p <= &one || (e * d) % (p - &one) != one)
    {
        return None;
    }
    if ints[5] != d % (p - &one) || ints[6] != d % (q - &one) || (&ints[7] * q) % p != one {
        return None;
    }
    Some(())
}
fn ec(seq: &[BerObject<'_>], curve: Option<String>) -> Option<()> {
    if seq.len() < 2 || seq[0].as_u32().ok()? != 1 {
        return None;
    }
    let key = BigUint::from_bytes_be(seq[1].as_slice().ok()?);
    let curve = curve.or_else(|| {
        seq.iter().skip(2).find_map(|v| {
            let bytes = v.as_slice().ok()?;
            let (_, obj) = parse_der(bytes).ok()?;
            obj.as_oid().ok().map(|o| o.to_id_string())
        })
    })?;
    let order=match curve.as_str() {
        "1.3.132.0.33"=>"FFFFFFFFFFFFFFFFFFFFFFFFFFFF16A2E0B8F03E13DD29455C5C2A3D",
        "1.2.840.10045.3.1.7"=>"FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551",
        "1.3.132.0.34"=>"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973",
        "1.3.132.0.35"=>"01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFA51868783BF2F966B7FCC0148F709A5D03BB5C9B8899C47AEBB6FB71E91386409",_=>return None,
    };
    if key == BigUint::from(0_u8) || key >= BigUint::parse_bytes(order.as_bytes(), 16)? {
        None
    } else {
        Some(())
    }
}
