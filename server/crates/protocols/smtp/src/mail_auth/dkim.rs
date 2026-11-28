//! DKIM verification by `mail-auth` (RFC 6376/8463) over keys fetched through
//! [`Dns`]. Owner-approved security fix 2026-11-05 (#492, #493): frozen Go
//! ignored `x=` expiry, hashed the Ed25519 input wrongly, rebuilt the signature
//! header with a fixed layout and treated `l=0` differently from signing. All
//! parsing, canonicalization, hashing and signature checks are `mail-auth`'s
//! (ring backend); nothing cryptographic is implemented here.
use super::bridge::{authenticator, TxtCache};
use super::Dns;
use mail_auth::{
    common::verify::VerifySignature, dkim::Canonicalization, AuthenticatedMessage, DkimResult,
    Error, Parameters,
};

#[derive(Debug, Clone)]
pub struct DkimVerification {
    pub result: &'static str,
    /// d= of the signature that decided `result` (the first passing signature
    /// when any passes, otherwise the first signature). Authenticated only on pass.
    pub domain: String,
    /// l= fence of the passing signature. Zero means full body; non-pass clears it.
    pub signed_len: i64,
    pub canonical: String,
    /// d= of every signature that verified. DMARC alignment accepts any of them.
    pub domains: Vec<String>,
}
impl Default for DkimVerification {
    fn default() -> Self {
        Self {
            result: "none",
            domain: String::new(),
            signed_len: 0,
            canonical: String::new(),
            domains: Vec::new(),
        }
    }
}
fn canonical(ch: Canonicalization, cb: Canonicalization) -> String {
    let name = |c| match c {
        Canonicalization::Relaxed => "relaxed",
        Canonicalization::Simple => "simple",
    };
    format!("{}/{}", name(ch), name(cb))
}
fn category(result: &DkimResult) -> &'static str {
    match result {
        DkimResult::Pass => "pass",
        DkimResult::None => "none",
        DkimResult::Fail(_) => "fail",
        DkimResult::TempError(_) => "temperror",
        DkimResult::PermError(_) => "permerror",
        // mail-auth reports an expired signature and a body-hash mismatch as
        // neutral; RFC 6376 makes both verification failures.
        DkimResult::Neutral(Error::SignatureExpired | Error::FailedBodyHashMatch) => "fail",
        DkimResult::Neutral(_) => "permerror",
    }
}
pub async fn verify(dns: &dyn Dns, raw: &[u8]) -> DkimVerification {
    let Some(mut message) = AuthenticatedMessage::parse(raw) else {
        return DkimVerification::default();
    };
    if message.dkim_headers.is_empty() {
        return DkimVerification::default();
    }
    if crate::mutants::on("dkim-ignore-expiry") {
        // Frozen Go never looked at x=.
        for header in &mut message.dkim_headers {
            if let Ok(signature) = &mut header.header {
                signature.x = 0;
            }
        }
    }
    let cache = TxtCache::default();
    for header in &message.dkim_headers {
        if let Ok(signature) = &header.header {
            cache.fetch_key(dns, &signature.domain_key()).await;
        }
    }
    let outputs = authenticator()
        .verify_dkim(Parameters::new(&message).with_txt_cache(&cache))
        .await;
    let mut passes = Vec::new();
    let mut first_failure = None;
    for output in &outputs {
        let result = category(output.result());
        match (result, output.signature()) {
            ("pass", Some(signature)) => passes.push(signature),
            (result, signature) => {
                first_failure.get_or_insert((result, signature));
            }
        }
    }
    if let Some(first) = passes.first() {
        return DkimVerification {
            result: "pass",
            domain: first.d.clone(),
            signed_len: i64::try_from(first.l).unwrap_or(i64::MAX),
            canonical: canonical(first.ch, first.cb),
            domains: passes.iter().map(|s| s.d.clone()).collect(),
        };
    }
    let mut out = DkimVerification::default();
    if let Some((result, signature)) = first_failure {
        out.result = result;
        if let Some(signature) = signature {
            out.domain = signature.d.clone();
            out.canonical = canonical(signature.ch, signature.cb);
        }
    }
    out
}
