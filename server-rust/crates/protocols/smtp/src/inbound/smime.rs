//! Pristine detached-CMS verification, then recipient-owned best-effort harvest.
//! OpenSSL performs signature/digest and chain verification; no custom crypto.
use super::Pipeline;
use base64::Engine as _;
use openssl::{
    pkcs7::{Pkcs7, Pkcs7Flags},
    stack::{Stack, StackRef},
    x509::{
        store::{X509Store, X509StoreBuilder},
        verify::{X509VerifyFlags, X509VerifyParam},
        X509PurposeId, X509StoreContext, X509,
    },
};
use setjoin_certificates::{certificate, fingerprint};
use setjoin_pg::{workers::WorkerConnection, Type};
use std::sync::OnceLock;
use x509_parser::extensions::{GeneralName, ParsedExtension};

#[derive(Default)]
pub(crate) struct Verdict {
    pub status: &'static str,
    pub email: String,
    pub cn: String,
    pub issuer: String,
    pub leaf: Vec<u8>,
    pub anchor: Vec<u8>,
}
impl Pipeline {
    pub async fn smime(
        &self,
        conn: &WorkerConnection,
        to: &str,
        from: &str,
        msg: &[u8],
        harvest: bool,
    ) -> Option<Verdict> {
        self.smime_checked(conn, to, from, msg, harvest, true)
            .await
            .map(|(v, _)| v)
    }
    pub(super) async fn smime_checked(
        &self,
        conn: &WorkerConnection,
        to: &str,
        from: &str,
        msg: &[u8],
        harvest: bool,
        revocation: bool,
    ) -> Option<(Verdict, Vec<u8>)> {
        let (content, signature) = extract(msg)?;
        let domain = match to.rsplit_once('@') {
            Some((_, domain)) => conn
                .query(
                    "SELECT id FROM domains WHERE lower(name)=lower($1)",
                    &[(&domain, Type::TEXT)],
                )
                .await
                .ok()
                .and_then(|r| r.first().and_then(|r| r.try_get(0).ok()))
                .unwrap_or(0),
            None => 0,
        };
        let pool = self.config.trust_cache.pool_for_session(conn, domain).await;
        let roots: Vec<String> = pool.certificates().map(str::to_owned).collect();
        let from = from.to_owned();
        let claimed = from.clone();
        let (mut verdict, content) = tokio::task::spawn_blocking(move || {
            (verify(&content, &signature, &from, &roots), content)
        })
        .await
        .ok()?;
        if verdict.status == "valid" {
            let fp = fingerprint(&verdict.leaf);
            let revoked = revocation && !crate::mutants::on("inbound-smime-ignore-revocation") && conn
                .query(
                    "SELECT EXISTS(SELECT 1 FROM smime_revocation_blocklist WHERE fingerprint=$1)",
                    &[(&fp, Type::TEXT)],
                )
                .await
                .ok()
                .is_some_and(|r| r[0].get::<_, bool>(0));
            if revoked {
                verdict.status = "untrusted";
                verdict.leaf.clear();
                verdict.anchor.clear();
            } else if harvest && !crate::mutants::on("inbound-no-smime-harvest") {
                // Go's alias-only owner lookup is intentionally preserved.
                let owner=conn.query("SELECT m.user_id FROM mailboxes m JOIN aliases a ON a.mailbox_id=m.id WHERE a.email=lower($1) AND m.enabled=TRUE LIMIT 1", &[(&to,Type::TEXT)]).await.ok().and_then(|r|r.first().and_then(|r|r.get::<_,Option<i64>>(0)));
                if let Some(owner) = owner.filter(|id| *id != 0) {
                    let pem = X509::from_der(&verdict.leaf)
                        .and_then(|c| c.to_pem())
                        .ok()
                        .and_then(|p| String::from_utf8(p).ok());
                    if let (Ok(cert), Some(pem)) = (certificate::parse(&verdict.leaf), pem) {
                        let email = claimed.trim().to_lowercase();
                        let before = cert.validity().not_before.timestamp();
                        let after = cert.validity().not_after.timestamp();
                        let _=conn.query("SELECT smime_harvest_recipient_cert($1,$2,$3,$4,to_timestamp($5::bigint::double precision),to_timestamp($6::bigint::double precision))", &[(&owner,Type::INT8),(&email,Type::TEXT),(&pem,Type::TEXT),(&fp,Type::TEXT),(&before,Type::INT8),(&after,Type::INT8)]).await;
                    }
                }
            }
        }
        Some((verdict, content))
    }
}
fn verify(content: &[u8], signature: &[u8], from: &str, roots: &[String]) -> Verdict {
    verify_inner(content, signature, from, roots).unwrap_or_else(|_| Verdict {
        status: "invalid",
        ..Default::default()
    })
}
fn verify_inner(
    content: &[u8],
    signature: &[u8],
    from: &str,
    roots: &[String],
) -> Result<Verdict, ()> {
    // Go's BER2DER consumes a prefix too: trailing CMS octets still verify.
    // The framing recording pins that leniency, indefinite BER and truncation.
    let signed = Pkcs7::from_der(signature).map_err(|_| ())?;
    let embedded = signed.signed().and_then(|s| s.certificates()).ok_or(())?;
    let mut clock = None;
    for cert in embedded {
        let bytes = cert.to_der().map_err(|_| ())?;
        let parsed = certificate::parse(&bytes)?;
        let ca = parsed
            .basic_constraints()
            .map_err(|_| ())?
            .is_some_and(|c| c.value.ca);
        if clock.is_none() || !ca {
            clock = Some(parsed.validity().not_before.timestamp());
            if !ca {
                break;
            }
        }
    }
    // Go parses every embedded certificate, including unused ones.
    for cert in embedded {
        certificate::parse(&cert.to_der().map_err(|_| ())?)?;
    }
    let empty = Stack::new().map_err(|_| ())?;
    let integrity_roots = store(embedded.iter().map(|c| c.to_owned()).collect(), clock)?;
    if !crate::mutants::on("inbound-smime-ignore-integrity") {
        signed
            .verify(
                &empty,
                &integrity_roots,
                Some(content),
                None,
                Pkcs7Flags::BINARY | Pkcs7Flags::NOVERIFY,
            )
            .map_err(|_| ())?;
    }
    let signers = signed
        .signers(&empty, Pkcs7Flags::empty())
        .map_err(|_| ())?;
    if signers.is_empty() {
        return Err(());
    }
    for leaf in &signers {
        chain(leaf, embedded, &integrity_roots).ok_or(())?;
    }
    let leaf = signers[0].to_der().map_err(|_| ())?;
    let parsed = certificate::parse(&leaf)?;
    let emails = emails(&parsed);
    let mut verdict = Verdict {
        status: "untrusted",
        email: emails.first().cloned().unwrap_or_default(),
        cn: certificate::common_name(parsed.subject()),
        issuer: certificate::common_name(parsed.issuer()),
        ..Default::default()
    };
    let mut trusted = bundled().clone();
    if crate::mutants::on("inbound-smime-ignore-trust") {
        trusted.extend(embedded.iter().map(|c| c.to_owned()));
    }
    trusted.extend(
        roots
            .iter()
            .filter_map(|p| X509::from_pem(p.as_bytes()).ok()),
    );
    let Ok(trusted) = store(trusted, None) else {
        return Ok(verdict);
    };
    let mut anchor = Vec::new();
    for signer in &signers {
        let Some(path) = chain(signer, embedded, &trusted) else {
            return Ok(verdict);
        };
        for (index, cert) in path.iter().enumerate() {
            let bytes = cert.to_der().map_err(|_| ())?;
            let parsed = certificate::parse(&bytes)?;
            // Go checks EmailProtection EKU on every chain certificate, but does
            // not enforce OpenSSL's additional S/MIME keyUsage/Netscape policy.
            if parsed
                .extended_key_usage()
                .map_err(|_| ())?
                .is_some_and(|e| !e.value.any && !e.value.email_protection)
            {
                return Ok(verdict);
            }
            if index + 1 < path.len() {
                // Go rejects MD2/MD5/SHA1 chain signatures (a trust anchor's own
                // self-signature is not verified). OpenSSL auth_level=0 permits
                // Go's supported small public keys, so retain this policy here.
                let oid = parsed.signature_algorithm.algorithm.to_id_string();
                if matches!(
                    oid.as_str(),
                    "1.2.840.113549.1.1.2"
                        | "1.2.840.113549.1.1.3"
                        | "1.2.840.113549.1.1.4"
                        | "1.2.840.113549.1.1.5"
                        | "1.2.840.10040.4.3"
                        | "1.2.840.10045.4.1"
                ) {
                    return Ok(verdict);
                }
            }
        }
        if anchor.is_empty() {
            anchor = path.last().ok_or(())?.to_der().map_err(|_| ())?;
        }
    }
    if !crate::mutants::on("inbound-smime-ignore-from")
        && (from.trim().is_empty()
            || !emails
                .iter()
                .any(|e| setjoin_authz::address::equal_fold(e.trim(), from.trim())))
    {
        return Ok(verdict);
    }
    verdict.status = "valid";
    verdict.leaf = leaf;
    verdict.anchor = anchor;
    Ok(verdict)
}
fn bundled() -> &'static Vec<X509> {
    static ROOTS: OnceLock<Vec<X509>> = OnceLock::new();
    ROOTS.get_or_init(|| X509::stack_from_pem(include_bytes!("cacert.pem")).unwrap_or_default())
}
fn store(certs: Vec<X509>, time: Option<i64>) -> Result<X509Store, ()> {
    let mut builder = X509StoreBuilder::new().map_err(|_| ())?;
    let mut params = X509VerifyParam::new().map_err(|_| ())?;
    params.set_auth_level(0);
    params.set_purpose(X509PurposeId::ANY).map_err(|_| ())?;
    params
        .set_flags(X509VerifyFlags::PARTIAL_CHAIN | X509VerifyFlags::TRUSTED_FIRST)
        .map_err(|_| ())?;
    if let Some(time) = time {
        params.set_time(time);
    }
    builder.set_param(&params).map_err(|_| ())?;
    for cert in certs {
        builder.add_cert(cert).map_err(|_| ())?;
    }
    Ok(builder.build())
}
fn chain(
    leaf: &openssl::x509::X509Ref,
    embedded: &StackRef<X509>,
    store: &X509Store,
) -> Option<Vec<X509>> {
    let mut context = X509StoreContext::new().ok()?;
    context
        .init(store, leaf, embedded, |c| {
            if !c.verify_cert()? {
                return Ok(None);
            }
            Ok(c.chain().map(|c| c.iter().map(|c| c.to_owned()).collect()))
        })
        .ok()?
}
fn emails(cert: &x509_parser::certificate::X509Certificate<'_>) -> Vec<String> {
    let mut values = Vec::new();
    for extension in cert.extensions() {
        if let ParsedExtension::SubjectAlternativeName(san) = extension.parsed_extension() {
            for name in &san.general_names {
                if let GeneralName::RFC822Name(email) = name {
                    values.push((*email).to_owned());
                }
            }
        }
    }
    for attr in cert.subject().iter_attributes() {
        if attr.attr_type().to_id_string() == "1.2.840.113549.1.9.1" {
            if let Ok(email) = attr.as_str() {
                values.push(email.to_owned());
            }
        }
    }
    values
}
/// The pre-#544 pick: the first line starting exactly `Content-Type:` (case-sensitive,
/// folding ignored). Kept only for the `smime-line-boundary` mutant.
fn legacy_boundary(headers: &[u8]) -> Option<Vec<u8>> {
    let mut boundary = None;
    for line in headers.split(|b| *b == b'\n') {
        if line.starts_with(b"Content-Type:") {
            for part in line.split(|b| *b == b';') {
                let part = setjoin_mime::trim_space(part);
                if let Some(value) = part.strip_prefix(b"boundary=") {
                    boundary = Some(value.trim_ascii().strip_prefix(b"\"").unwrap_or(value));
                    boundary = boundary.map(|v| v.strip_suffix(b"\"").unwrap_or(v));
                    break;
                }
            }
        }
        if boundary.is_some() {
            break;
        }
    }
    boundary.map(<[u8]>::to_vec)
}
fn find(data: &[u8], needle: &[u8]) -> Option<usize> {
    data.windows(needle.len()).position(|w| w == needle)
}
fn separator(data: &[u8]) -> Option<(usize, usize)> {
    find(data, b"\r\n\r\n")
        .map(|p| (p, 4))
        .or_else(|| find(data, b"\n\n").map(|p| (p, 2)))
}
/// Go's extractor is case-sensitive and splits on the literal boundary substring.
/// Keep its framing semantics rather than substituting a more permissive walker.
fn extract(data: &[u8]) -> Option<(Vec<u8>, Vec<u8>)> {
    let (header_end, header_sep) = separator(data)?;
    let headers = &data[..header_end];
    if find(headers, b"protocol=\"application/pkcs7-signature\"").is_none()
        && find(headers, b"protocol=\"application/x-pkcs7-signature\"").is_none()
    {
        return None;
    }
    let boundary = if crate::mutants::on("smime-line-boundary") {
        legacy_boundary(headers)
    } else {
        // #544 (owner-approved security fix 2026-11-05): the body walkers (link
        // rewriting, phish banners) take the first Content-Type, case-insensitive and
        // unfolded (`setjoin_mime::extract_header`). Pick the boundary exactly the same
        // way and refuse a second Content-Type, so the signed part and the rendered parts
        // can never be framed by different headers.
        let content_types = setjoin_mime::unfold_headers(headers)
            .split(|b| *b == b'\n')
            .filter(|line| {
                line.iter()
                    .position(|b| *b == b':')
                    .is_some_and(|i| setjoin_mime::trim_space(&line[..i]).eq_ignore_ascii_case(b"content-type"))
            })
            .count();
        if content_types != 1 {
            return None;
        }
        let ct = setjoin_mime::extract_header(data, "Content-Type");
        let (media, params) = setjoin_mime::parse_media_type(&ct).ok()?;
        if !media.starts_with(b"multipart/") {
            return None;
        }
        params.get(b"boundary".as_slice()).cloned()
    };
    let boundary = boundary.filter(|b| !b.is_empty())?;
    let mut delimiter = b"--".to_vec();
    delimiter.extend_from_slice(&boundary);
    if !crate::mutants::on("smime-line-boundary") {
        // The preamble precedes the first delimiter and is never signed: text there is
        // rendered by a walker framing the message differently.
        let body = data.get(header_end + header_sep..)?;
        if !find(body, &delimiter).is_some_and(|first| body[..first].trim_ascii().is_empty()) {
            return None;
        }
    }
    let mut content = None;
    let mut signature = None;
    let mut closed = false;
    let mut remaining = data;
    while let Some(pos) = find(remaining, &delimiter) {
        remaining = &remaining[pos + delimiter.len()..];
        let end = find(remaining, &delimiter).unwrap_or(remaining.len());
        let part = &remaining[..end];
        let trimmed = part.trim_ascii_start();
        // #544 (owner-approved security fix 2026-11-05): a signature covers only the
        // first part. Anything after the closing delimiter, a second content part or
        // a second signature part is unsigned bytes riding on a valid signature
        // (replay with an extra part). Such a message is not fully signed: no verdict,
        // so it is processed like unsigned mail.
        if !crate::mutants::on("smime-trailing-parts-ignored") {
            if closed && !part.trim_ascii().is_empty() {
                return None;
            }
            if trimmed.starts_with(b"--") && !trimmed[2..].trim_ascii().is_empty() {
                return None;
            }
        }
        if trimmed.starts_with(b"--") {
            closed = true;
            continue;
        }
        if part.trim_ascii().is_empty() {
            continue;
        }
        let part = part
            .strip_prefix(b"\r\n")
            .or_else(|| part.strip_prefix(b"\n"))
            .unwrap_or(part);
        let Some((sep, len)) = separator(part) else {
            continue;
        };
        let lower = setjoin_mime::to_lower(&part[..sep]);
        if find(&lower, b"application/pkcs7-signature").is_some()
            || find(&lower, b"application/x-pkcs7-signature").is_some()
        {
            let body: Vec<u8> = part[sep + len..]
                .iter()
                .copied()
                .filter(|b| !matches!(b, b'\r' | b'\n' | b' ' | b'\t'))
                .collect();
            let engine = base64::engine::GeneralPurpose::new(
                &base64::alphabet::STANDARD,
                base64::engine::GeneralPurposeConfig::new().with_decode_allow_trailing_bits(true),
            );
            if signature.is_some() && !crate::mutants::on("smime-trailing-parts-ignored") {
                return None;
            }
            signature = Some(engine.decode(body).ok()?);
        } else if content.is_some() && !crate::mutants::on("smime-trailing-parts-ignored") {
            return None;
        } else if content.is_none() {
            let part = part
                .strip_suffix(b"\r\n")
                .or_else(|| part.strip_suffix(b"\n"))
                .unwrap_or(part);
            let mut canonical = Vec::with_capacity(part.len());
            let mut i = 0;
            while i < part.len() {
                if part[i..].starts_with(b"\r\n") {
                    i += 1;
                }
                if part[i] == b'\n' {
                    canonical.extend_from_slice(b"\r\n");
                } else {
                    canonical.push(part[i]);
                }
                i += 1;
            }
            content = Some(canonical);
        }
    }
    Some((
        content.filter(|c| !c.is_empty())?,
        signature.filter(|c| !c.is_empty())?,
    ))
}

pub(super) fn is_signed(data: &[u8]) -> bool {
    let end = separator(data).map_or(0, |(p, _)| p);
    let header = &data[..end];
    find(header, b"protocol=\"application/pkcs7-signature\"").is_some()
        || find(header, b"protocol=\"application/x-pkcs7-signature\"").is_some()
}
pub(super) fn bundled_anchor(anchor: &[u8]) -> bool {
    bundled()
        .iter()
        .any(|c| c.to_der().is_ok_and(|der| der == anchor))
}
#[cfg(test)]
mod tests {
    use super::extract;
    const HEAD: &str = "Content-Type: multipart/signed; protocol=\"application/pkcs7-signature\"; boundary=\"b\"\r\n\r\n";
    const SIGNED: &str = "--b\r\nContent-Type: text/plain\r\n\r\nhello\r\n";
    const SIGNATURE: &str = "--b\r\nContent-Type: application/pkcs7-signature\r\nContent-Transfer-Encoding: base64\r\n\r\nQUJD\r\n";
    const UNSIGNED: &str = "Content-Type: text/plain\r\n\r\nclick https://evil.example\r\n";
    fn message(parts: &[&str], tail: &str) -> Vec<u8> {
        format!("{HEAD}{}--b--\r\n{tail}", parts.concat()).into_bytes()
    }
    #[test]
    fn exactly_the_signed_part_and_the_signature_extract() {
        for tail in ["", "\r\n", "  \r\n\r\n"] {
            let (content, signature) = extract(&message(&[SIGNED, SIGNATURE], tail)).expect(tail);
            assert_eq!(content, b"Content-Type: text/plain\r\n\r\nhello");
            assert_eq!(signature, b"ABC");
        }
    }
    #[test]
    fn nothing_unsigned_may_ride_on_a_valid_signature() {
        // #544: parts after the closing boundary, extra parts and a second signature are
        // outside the signed pair, so the message is not fully signed (never extracted).
        let after_text = message(&[SIGNED, SIGNATURE], UNSIGNED);
        let after_part = message(&[SIGNED, SIGNATURE], &format!("--b\r\n{UNSIGNED}--b--\r\n"));
        let between = message(&[SIGNED, &format!("--b\r\n{UNSIGNED}"), SIGNATURE], "");
        let before = message(&[&format!("--b\r\n{UNSIGNED}"), SIGNED, SIGNATURE], "");
        let twice = message(&[SIGNED, SIGNATURE, SIGNATURE], "");
        for (name, data) in [
            ("text after the closing boundary", after_text),
            ("a part after the closing boundary", after_part),
            ("an unsigned part between content and signature", between),
            ("an unsigned part before the signed content", before),
            ("a second signature", twice),
        ] {
            assert!(extract(&data).is_none(), "{name}");
        }
    }
    #[test]
    fn an_unsigned_part_cannot_hide_behind_a_second_content_type_or_the_preamble() {
        // #544: the body walkers frame the message by the first Content-Type (any case,
        // unfolded). The attack names multipart/mixed first and puts its part in the
        // preamble of the signed message; none of these may extract.
        let signed = "Content-Type: multipart/signed; protocol=\"application/pkcs7-signature\"; boundary=\"b\"\r\n";
        let attack = format!("--B\r\n{UNSIGNED}--B--\r\n");
        let body = format!("{SIGNED}{SIGNATURE}--b--\r\n");
        let lower = format!("content-type: multipart/mixed; boundary=B\r\n{signed}\r\n{attack}{body}");
        let folded = format!("Content-Type: multipart/mixed;\r\n boundary=B\r\n{signed}\r\n{attack}{body}");
        let after = format!("{signed}Content-Type: multipart/mixed; boundary=B\r\n\r\n{attack}{body}");
        let preamble = format!("{signed}\r\n{attack}{body}");
        for (name, data) in [("lowercase", lower), ("folded", folded), ("second header after", after), ("preamble only", preamble)] {
            assert!(extract(data.as_bytes()).is_none(), "{name}");
        }
        // One header in any case, folded or not, with a blank preamble still verifies.
        for header in [
            "content-type: multipart/signed; protocol=\"application/pkcs7-signature\"; boundary=\"b\"\r\n",
            "Content-Type: multipart/signed;\r\n protocol=\"application/pkcs7-signature\"; boundary=b\r\n",
        ] {
            let data = format!("{header}\r\n\r\n{body}");
            assert!(extract(data.as_bytes()).is_some(), "{header}");
        }
    }
}
