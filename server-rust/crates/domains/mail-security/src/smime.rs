//! Slice `smime` (#328): Go's `admin.TrustAnchorHandler` (list, import, delete of the global
//! `smime_trust_anchors` store) and the per-recipient-domain trust cache the
//! `smime_trust_changed` listener invalidates.
//!
//! The table is global admin configuration (no RLS): the gateway adapter checks the console
//! gate (`requireMailPerm` for the list, `requireMailSecurity` for writes) and passes the
//! caller's domain scope, resolved from the verified token (0 is deployment-wide). Writes are
//! receipted reducers (`rust_mailsec_smime_anchor_import|delete`) that store the rows and send
//! the `smime_trust_changed` notification in one transaction. Certificate parsing uses
//! `x509-parser` and a port of Go's `pem.Decode`; nothing here touches cryptographic keys.
use super::{command, deadline, done, envelope, invalid, s, scope};
use setjoin_authz::AuthContext;
use setjoin_pg::{CommandOutcome, ScopedExecutor, StatementFailure, Type};

pub mod trust;

pub use setjoin_certificates::{fingerprint, parse_chain, validate_chain, ChainError, ParsedCert, first_certificate_dates, first_certificate_encrypt_capable, first_certificate_email, first_pem_bytes};

// ---- reads and writes ----

/// `GET /admin/smime/trust-anchors`: `{"anchors":[...]}` newest first. A row whose validity
/// bounds are NULL fails Go's `time.Time` scan, which ends the iteration there. `scope` 0 sees everything.
pub async fn list(worker: &ScopedExecutor, domain_scope: i64) -> Result<String, StatementFailure> {
    let iso = |c: &str| format!("to_char({c} AT TIME ZONE 'UTC','YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"')");
    let rows = worker
        .read(
            &format!(
                "SELECT id, label, COALESCE(subject_cn,''), fingerprint, domain_id, {}, {}, {} \
                 FROM smime_trust_anchors \
                 WHERE ($1::bigint = 0 OR domain_id IS NULL OR domain_id = $1::bigint) \
                 ORDER BY created_at DESC, id DESC",
                iso("not_before"),
                iso("not_after"),
                iso("created_at")
            ),
            &[(&domain_scope, Type::INT8)],
        )
        .await?;
    let mut items = Vec::new();
    for row in &rows {
        let (Ok(Some(not_before)), Ok(Some(not_after))) = (
            row.try_get::<_, Option<String>>(5),
            row.try_get::<_, Option<String>>(6),
        ) else {
            // pgx closes the result set on a failed `Scan`: this row and every later row are
            // gone, and Go never looks at `rows.Err()`.
            break;
        };
        let domain = row
            .try_get::<_, Option<i64>>(4)
            .map_err(|_| invalid())?
            .map_or("null".to_owned(), |d| d.to_string());
        let text = |i: usize| row.try_get::<_, String>(i).map_err(|_| invalid());
        items.push(format!(
            "{{\"id\":{},\"label\":{},\"subjectCn\":{},\"fingerprint\":{},\"domainId\":{domain},\"notBefore\":{},\"notAfter\":{},\"createdAt\":{}}}",
            row.try_get::<_, i64>(0).map_err(|_| invalid())?,
            s(&text(1)?),
            s(&text(2)?),
            s(&text(3)?),
            s(&not_before),
            s(&not_after),
            s(&text(7)?),
        ));
    }
    Ok(done(format!("{{\"anchors\":[{}]}}", items.join(","))))
}

/// `POST /admin/smime/trust-anchors` after validation: every certificate row and the
/// notification, one transaction. Returns the number stored.
pub async fn import(
    worker: &ScopedExecutor,
    actor: &AuthContext,
    label: &str,
    certs: &[ParsedCert],
    domain_scope: i64,
    operation: [u8; 16],
) -> CommandOutcome<i32, StatementFailure> {
    let rows: Vec<serde_json::Value> = certs
        .iter()
        .map(|c| {
            serde_json::json!({
                "pem": c.pem, "fingerprint": c.fingerprint, "subject_cn": c.subject_cn,
                "not_before": c.not_before, "not_after": c.not_after,
            })
        })
        .collect();
    let document = serde_json::Value::Array(rows).to_string();
    let auth = scope(actor);
    let digest = format!(
        "smime.anchor.import:{domain_scope}:{label}:{}",
        certs
            .iter()
            .map(|c| c.fingerprint.as_str())
            .collect::<Vec<_>>()
            .join(",")
    );
    setjoin_pg::run_receipted_command(
        worker,
        command("smime.anchor.import"),
        &envelope(&auth, operation, &digest),
        &auth,
        deadline(),
        "SELECT rust_mailsec_smime_anchor_import($4::text,$5::text::jsonb,$6::bigint,$2::bigint) \
         WHERE $1::bigint>0 AND $2::bigint>0 AND $3::text<>''",
        &[
            (&label, Type::TEXT),
            (&document, Type::TEXT),
            (&domain_scope, Type::INT8),
        ],
        |rows| {
            rows.first()
                .and_then(|r| r.try_get::<_, i32>(0).ok())
                .ok_or_else(invalid)
        },
    )
    .await
}

/// `DELETE /admin/smime/trust-anchors/{id}`: `Committed(false)` is Go's 404.
pub async fn delete(
    worker: &ScopedExecutor,
    actor: &AuthContext,
    id: i64,
    domain_scope: i64,
    operation: [u8; 16],
) -> CommandOutcome<bool, StatementFailure> {
    let auth = scope(actor);
    setjoin_pg::run_receipted_command(
        worker,
        command("smime.anchor.delete"),
        &envelope(
            &auth,
            operation,
            &format!("smime.anchor.delete:{domain_scope}:{id}"),
        ),
        &auth,
        deadline(),
        "SELECT rust_mailsec_smime_anchor_delete($4::bigint,$5::bigint) \
         WHERE $1::bigint>0 AND $2::bigint>0 AND $3::text<>''",
        &[(&id, Type::INT8), (&domain_scope, Type::INT8)],
        |rows| {
            rows.first()
                .and_then(|r| r.try_get::<_, bool>(0).ok())
                .ok_or_else(invalid)
        },
    )
    .await
}

/// `GET /user/cert-status`: metadata from this request's own TLS peer leaf.
/// A plain HTTP request has no peer certificate, irrespective of its headers.
pub fn cert_status_body(leaf: Option<&[u8]>) -> String {
    let Some(der) = leaf else {
        return done("{\"status\":\"none\"}".into());
    };
    let Ok(cert) = crate::certificate::parse(der) else {
        return done("{\"status\":\"none\"}".into());
    };
    let cn = crate::certificate::common_name(cert.subject());
    let timestamp = cert.validity().not_after.timestamp();
    let duration = std::time::Duration::from_secs(timestamp.unsigned_abs());
    let expires = if timestamp < 0 {
        std::time::UNIX_EPOCH.checked_sub(duration)
    } else {
        std::time::UNIX_EPOCH.checked_add(duration)
    };
    let Some(expires) = expires else {
        return done("{\"status\":\"none\"}".into());
    };
    let now = std::time::SystemTime::now();
    let mut days_field = String::new();
    let status = if now > expires {
        "expired"
    } else {
        // Go truncates time.Until(...).Hours()/24 before comparing with 30.
        // For a nonnegative remaining duration that is whole-day division.
        let days = expires.duration_since(now).unwrap_or_default().as_secs() / 86_400;
        if days <= 30 {
            days_field = format!(",\"expires_in_days\":{days}");
            "expiring"
        } else {
            "valid"
        }
    };
    done(format!(
        "{{\"expires_at\":{}{days_field},\"status\":{},\"subject_cn\":{}}}",
        s(&crate::tls::rfc3339(cert.validity().not_after)),
        s(status),
        s(&cn)
    ))
}

/// `{"fingerprint":...,"ok":true}` (a Go map: sorted keys).
pub fn import_body(fingerprint: &str) -> String {
    done(format!(
        "{{\"fingerprint\":{},\"ok\":true}}",
        s(fingerprint)
    ))
}

/// `{"ok":true}`.
pub fn ok_body() -> String {
    done("{\"ok\":true}".into())
}
