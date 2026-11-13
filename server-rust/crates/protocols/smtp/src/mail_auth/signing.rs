//! Outbound DKIM signing and inbound ARC sealing through `mail-auth`.
//!
//! Owner-approved security fix 2026-11-05 (#492, #493). Frozen Go's signing
//! queried columns the active schema lacks (so it never signed), emitted a bare
//! header value without the `DKIM-Signature:` field name, sealed ARC without
//! authenticating the incoming chain (any prior seal gave `cv=pass`), scanned
//! message bodies for ARC instances and let the counter wrap. Here keys come from
//! the active `domain_signing_keys` columns, the header is a complete standard
//! field, the incoming chain is verified (`cv=pass` only on a verified chain,
//! `cv=fail` otherwise, no seal on a chain that already failed) and instances
//! come from the parsed chain.
use super::{
    bridge::{authenticator, TxtCache},
    Dns,
};
use mail_auth::{
    arc::ArcSealer,
    common::{
        crypto::{Ed25519Key, RsaKey, Sha256},
        headers::HeaderWriter,
        verify::VerifySignature,
    },
    dkim::DkimSigner,
    AuthenticatedMessage, AuthenticationResults, DmarcOutput, DmarcResult, Error, Parameters,
    SpfOutput, SpfResult,
};
use setjoin_pg::{workers::WorkerDatabase, Type};

/// Headers a DKIM signature covers. Absent names are over-signed so none can be
/// added in transit.
const SIGNED: [&str; 10] = [
    "From",
    "To",
    "Cc",
    "Subject",
    "Date",
    "Message-ID",
    "In-Reply-To",
    "References",
    "MIME-Version",
    "Content-Type",
];
/// ARC-Message-Signature header set, minus anything an intermediary adds.
const ARC_SIGNED: [&str; 7] = [
    "From",
    "To",
    "Subject",
    "Date",
    "Message-ID",
    "MIME-Version",
    "Content-Type",
];
const EXPIRY_SECONDS: u64 = 7 * 24 * 3600;

enum Key {
    Rsa(RsaKey<Sha256>),
    Ed25519(Ed25519Key),
}
/// A signing key row (`domain_signing_keys`), parsed on use.
pub struct Loaded {
    selector: String,
    domain: String,
    algorithm: String,
    pem: String,
}
macro_rules! with_key {
    ($loaded:expr, $k:ident => $body:expr) => {
        match $loaded.key() {
            Err(error) => Err(error),
            Ok(Key::Rsa($k)) => $body,
            Ok(Key::Ed25519($k)) => $body,
        }
    };
}
impl Loaded {
    /// `algorithm` is a `domain_signing_keys.algorithm` value; `pem` its
    /// `private_key_pem`. RSA accepts PKCS#8 or PKCS#1; Ed25519 PKCS#8.
    pub fn new(domain: &str, selector: &str, algorithm: &str, pem: &str) -> Result<Self, String> {
        let loaded = Self {
            selector: selector.into(),
            domain: domain.into(),
            algorithm: algorithm.into(),
            pem: pem.into(),
        };
        loaded.key()?;
        Ok(loaded)
    }
    fn key(&self) -> Result<Key, String> {
        Ok(match self.algorithm.as_str() {
            "rsa-sha256" => {
                use rustls_pki_types::{PrivateKeyDer, PrivatePkcs1KeyDer, PrivatePkcs8KeyDer};
                let (_, block) = x509_parser::pem::parse_x509_pem(self.pem.as_bytes())
                    .map_err(|_| "no PEM block found".to_string())?;
                RsaKey::<Sha256>::from_key_der(PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
                    block.contents.as_slice(),
                )))
                .or_else(|_| {
                    RsaKey::<Sha256>::from_key_der(PrivateKeyDer::Pkcs1(PrivatePkcs1KeyDer::from(
                        block.contents.as_slice(),
                    )))
                })
                .map(Key::Rsa)
                .map_err(|e| e.to_string())?
            }
            "ed25519-sha256" => {
                let (_, block) = x509_parser::pem::parse_x509_pem(self.pem.as_bytes())
                    .map_err(|_| "no PEM block found".to_string())?;
                Ed25519Key::from_pkcs8_maybe_unchecked_der(&block.contents)
                    .map(Key::Ed25519)
                    .map_err(|e| e.to_string())?
            }
            other => return Err(format!("unsupported signing algorithm {other}")),
        })
    }
    /// A complete `DKIM-Signature: ...\r\n` field for `raw`.
    pub fn dkim_header(&self, raw: &[u8]) -> Result<String, String> {
        with_key!(self, key => DkimSigner::from_key(key)
            .domain(self.domain.as_str())
            .selector(self.selector.as_str())
            .headers(SIGNED)
            .expiration(EXPIRY_SECONDS)
            .sign(raw)
            .map(|s| s.to_header())
            .map_err(|e| e.to_string()))
    }
}
/// First active key of `domain`, newest first (R1: the domain is the server-derived
/// sender/author domain, resolved on the explicit worker credential).
pub async fn load_signer(db: &WorkerDatabase, domain: &str) -> Option<Loaded> {
    if domain.is_empty() {
        return None;
    }
    let conn = db.connect_session().await.ok()?;
    if crate::mutants::on("dkim-sign-legacy-columns") {
        // Frozen Go queried columns the active schema lacks, so it never signed.
        conn.query(
            "SELECT private_key FROM domain_signing_keys WHERE domain=$1 AND enabled=TRUE LIMIT 1",
            &[(&domain, Type::TEXT)],
        )
        .await
        .ok()?;
    }
    let rows = conn
        .query(
            "SELECT k.selector,k.algorithm,k.private_key_pem FROM domain_signing_keys k \
             JOIN domains d ON d.id=k.domain_id \
             WHERE lower(d.name)=lower($1) AND k.active \
             ORDER BY k.created_at DESC,k.id DESC LIMIT 1",
            &[(&domain, Type::TEXT)],
        )
        .await
        .ok()?;
    let row = rows.first()?;
    Loaded::new(
        domain,
        &row.get::<_, String>(0),
        &row.get::<_, String>(1),
        &row.get::<_, String>(2),
    )
    .ok()
}

/// Everything ARC records about the message, as the receiver derived it.
pub(crate) struct ArcInputs<'a> {
    pub ip: &'a str,
    pub helo: &'a str,
    pub mail_from: &'a str,
    pub spf: &'a str,
    pub dmarc: &'a str,
    pub from_domain: &'a str,
    /// The receiving (recipient's hosted) domain: the only legitimate ARC sealer.
    pub seal_domain: &'a str,
}
fn spf_result(value: &str) -> SpfResult {
    match value {
        "pass" => SpfResult::Pass,
        "fail" => SpfResult::Fail,
        "softfail" => SpfResult::SoftFail,
        "neutral" => SpfResult::Neutral,
        "temperror" => SpfResult::TempError,
        "permerror" => SpfResult::PermError,
        _ => SpfResult::None,
    }
}
fn dmarc_result(value: &str) -> DmarcResult {
    match value {
        "pass" => DmarcResult::Pass,
        "fail" => DmarcResult::Fail(Error::NotAligned),
        "temperror" => DmarcResult::TempError(Error::DnsError("temporary failure".into())),
        "permerror" => DmarcResult::PermError(Error::ParseError),
        _ => DmarcResult::None,
    }
}
/// Verify the incoming chain, then prepend this receiver's ARC set. `None` means
/// the message is stored unsealed: no key, an unsealable chain (the previous
/// seal already says `cv=fail`, or the chain is malformed), or a sealing error.
pub(crate) async fn seal_inbound(
    dns: &dyn Dns,
    db: &WorkerDatabase,
    raw: &[u8],
    inputs: &ArcInputs<'_>,
) -> Option<Vec<u8>> {
    let signer = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        load_signer(
            db,
            if crate::mutants::on("arc-seal-with-from-domain") {
                // Frozen Go sealed with the attacker-controlled From-header domain.
                inputs.from_domain
            } else {
                inputs.seal_domain
            },
        ),
    )
    .await
    .ok()??;
    let message = AuthenticatedMessage::parse(raw)?;
    let cache = TxtCache::default();
    for header in &message.dkim_headers {
        if let Ok(signature) = &header.header {
            cache.fetch_key(dns, &signature.domain_key()).await;
        }
    }
    if let Some(Ok(signature)) = message.ams_headers.last().map(|h| &h.header) {
        cache.fetch_key(dns, &signature.domain_key()).await;
    }
    for seal in &message.as_headers {
        if let Ok(seal) = &seal.header {
            cache.fetch_key(dns, &seal.domain_key()).await;
        }
    }
    let auth = authenticator();
    let dkim = auth
        .verify_dkim(Parameters::new(&message).with_txt_cache(&cache))
        .await;
    let mut arc = auth
        .verify_arc(Parameters::new(&message).with_txt_cache(&cache))
        .await;
    let has_chain = !message.ams_headers.is_empty()
        || !message.as_headers.is_empty()
        || !message.aar_headers.is_empty();
    if has_chain && arc.sets().is_empty() {
        // Counted-but-unparsable or oversized chain: there is nothing to extend.
        return None;
    }
    if crate::mutants::on("arc-trust-presence") && has_chain {
        // Frozen Go: any prior seal yields cv=pass without authenticating it.
        arc = arc.with_result(mail_auth::DkimResult::Pass);
    }
    let ip: std::net::IpAddr = inputs.ip.parse().ok()?;
    let spf = SpfOutput::new(inputs.from_domain.to_owned()).with_result(spf_result(inputs.spf));
    let dmarc_value = dmarc_result(inputs.dmarc);
    let dmarc = DmarcOutput::new(inputs.from_domain.to_owned())
        .with_spf_result(dmarc_value.clone())
        .with_dkim_result(dmarc_value);
    let mut results = AuthenticationResults::new("mailserver").with_spf_mailfrom_result(
        &spf,
        ip,
        inputs.mail_from,
        inputs.helo,
    );
    for output in &dkim {
        results.set_dkim_result(output, inputs.from_domain);
    }
    let results = results.with_dmarc_result(&dmarc);
    let header = with_key!(&signer, key => ArcSealer::from_key(key)
        .domain(signer.domain.as_str())
        .selector(signer.selector.as_str())
        .headers(ARC_SIGNED)
        .seal(&message, &results, &arc)
        .map(|set| set.to_header())
        .map_err(|e| e.to_string()))
    .ok()?;
    let mut sealed = header.into_bytes();
    sealed.extend_from_slice(raw);
    Some(sealed)
}
/// Outbound signing stage for #350: prepend a complete DKIM-Signature field when
/// the sender's domain has an active key; otherwise the message is unchanged.
///
/// Owner-approved security fix 2026-11-05: a signature asserts that this domain
/// authored the message, so it is added only to a message the domain originated:
/// never to a rule-forward (`forwarded`: the queue sends it as
/// `noreply-forward@<primary>` with the original, possibly spoofed, `From`
/// untouched) and only when the `From` header's domain equals the signing domain.
pub async fn sign_outbound(
    db: &WorkerDatabase,
    envelope: &str,
    raw: &[u8],
    forwarded: bool,
) -> Vec<u8> {
    let domain = envelope.rsplit_once('@').map_or("", |(_, d)| d);
    if forwarded && !crate::mutants::on("dkim-sign-forwards") {
        return raw.to_vec();
    }
    let (_, from) = setjoin_mime::parse_from(&setjoin_mime::extract_header(raw, "From"));
    let from = setjoin_mime::go_lossy(&from);
    let from_domain = from.rsplit_once('@').map_or("", |(_, d)| d);
    if !from_domain.eq_ignore_ascii_case(domain) && !crate::mutants::on("dkim-sign-foreign-from") {
        return raw.to_vec();
    }
    let Some(signer) = load_signer(db, domain).await else {
        return raw.to_vec();
    };
    let Ok(header) = signer.dkim_header(raw) else {
        return raw.to_vec();
    };
    // Frozen Go prepended SignDKIM's bare value without the field name.
    let header = if crate::mutants::on("dkim-sign-bare-header") {
        header
            .strip_prefix("DKIM-Signature: ")
            .unwrap_or(&header)
            .to_owned()
    } else {
        header
    };
    let mut message = header.into_bytes();
    message.extend_from_slice(raw);
    message
}
/// Go's sendData body frame (dot stuffing and the extra final CRLF), kept for
/// the wire-compatible remote DATA exchange of #350.
pub fn outbound_data_frame(raw: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(raw.len() + raw.len() / 50 + 5);
    let mut i = 0;
    while i < raw.len() {
        let c = raw[i];
        if c == b'\r' || c == b'\n' {
            if c == b'\r' && raw.get(i + 1) == Some(&b'\n') {
                i += 1
            }
            out.extend_from_slice(b"\r\n");
            if raw.get(i + 1) == Some(&b'.') {
                out.push(b'.')
            }
        } else {
            if i == 0 && c == b'.' {
                out.push(b'.')
            }
            out.push(c)
        }
        i += 1
    }
    out.extend_from_slice(b"\r\n.\r\n");
    out
}
