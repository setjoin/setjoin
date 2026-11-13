//! Serialization bridge for Go 1.26 crypto/tls and pinned rustls 0.23.46.
//! This handles session metadata only; both TLS stacks own all key schedules,
//! transcript authentication and PSK binders. Unknown/malformed states miss closed.
use std::time::{SystemTime, UNIX_EPOCH};

struct Reader<'a>(&'a [u8]);
impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let (head, tail) = self.0.split_at_checked(n)?;
        self.0 = tail;
        Some(head)
    }
    fn byte(&mut self) -> Option<u8> {
        Some(self.take(1)?[0])
    }
    fn vector(&mut self, n: usize) -> Option<&'a [u8]> {
        let mut length = 0usize;
        for b in self.take(n)? {
            length = length.checked_mul(256)?.checked_add(*b as usize)?;
        }
        self.take(length)
    }
}
fn vector(out: &mut Vec<u8>, n: usize, value: &[u8]) -> Option<()> {
    if value.len() >= (1usize << (8 * n)) {
        return None;
    }
    let len = value.len().to_be_bytes();
    out.extend_from_slice(&len[len.len() - n..]);
    out.extend_from_slice(value);
    Some(())
}

pub(crate) fn for_rustls(
    plain: &[u8],
    server_name: Option<&str>,
    negotiated: Option<u16>,
) -> Option<Vec<u8>> {
    let mut input = Reader(plain);
    let version = input.take(2)?;
    if !matches!(version, [3, 3] | [3, 4]) || input.byte()? != 1 {
        return None;
    }
    let mut cipher: [u8; 2] = input.take(2)?.try_into().ok()?;
    // Go permits TLS 1.3 PSKs across suites with the same transcript hash.
    // rustls compares exact suite IDs, so bind its metadata to the selected
    // SHA256 AEAD; the stack still verifies the PSK binder/key schedule.
    if version == [3, 4] {
        if let Some(selected) = negotiated {
            if matches!(u16::from_be_bytes(cipher), 0x1301 | 0x1303)
                && matches!(selected, 0x1301 | 0x1303)
            {
                cipher = selected.to_be_bytes();
            }
        }
    }
    let created = input.take(8)?;
    let age = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()?
        .as_secs()
        .saturating_sub(u64::from_be_bytes(created.try_into().ok()?));
    if age > 7 * 86400 {
        return None;
    }
    let secret = input.vector(1)?;
    if secret.is_empty() {
        return None;
    }
    let mut extra = Reader(input.vector(3)?);
    while !extra.0.is_empty() {
        extra.vector(3)?;
    }
    let ems = input.byte()?;
    if ems > 1 || input.byte()? != 0 {
        return None;
    }
    let mut certificates = Reader(input.vector(3)?);
    let mut chain = Vec::new();
    while !certificates.0.is_empty() {
        let der = certificates.vector(3)?;
        if der.is_empty() {
            return None;
        }
        vector(&mut chain, 3, der)?;
        certificates.vector(2)?; // TLS CertificateEntry extensions
    }
    input.vector(3)?; // Go's verified chains; rustls retains the authenticated peer chain.
    if version == [3, 3] {
        input.take(2)?;
    }
    let mut out = Vec::new();
    if let Some(name) = server_name {
        out.push(1);
        vector(&mut out, 1, name.as_bytes())?;
    } else {
        out.push(0);
    }
    out.extend_from_slice(version);
    out.extend_from_slice(&cipher);
    vector(&mut out, 1, secret)?;
    out.push(ems);
    if chain.is_empty() {
        out.push(0)
    } else {
        out.push(1);
        vector(&mut out, 3, &chain)?;
    }
    out.push(0); // TCP Go tickets do not bind ALPN (early_data=false).
    out.extend_from_slice(&[0, 0]); // application_data
    out.extend_from_slice(created);
    out.extend_from_slice(&[0; 4]); // age_add is used only for 0-RTT, which remains disabled.
    Some(out)
}

pub(crate) fn for_go(plain: &[u8]) -> Option<Vec<u8>> {
    let mut input = Reader(plain);
    match input.byte()? {
        0 => {}
        1 => {
            input.vector(1)?;
        }
        _ => return None,
    }
    let version = input.take(2)?;
    if !matches!(version, [3, 3] | [3, 4]) {
        return None;
    }
    let cipher = input.take(2)?;
    let secret = input.vector(1)?;
    if secret.is_empty() {
        return None;
    }
    let ems = input.byte()?;
    if ems > 1 {
        return None;
    }
    let mut certificate_list = Vec::new();
    match input.byte()? {
        0 => {}
        1 => {
            let mut chain = Reader(input.vector(3)?);
            while !chain.0.is_empty() {
                vector(&mut certificate_list, 3, chain.vector(3)?)?;
                certificate_list.extend_from_slice(&[0, 0]);
            }
        }
        _ => return None,
    }
    match input.byte()? {
        0 => {}
        1 => {
            input.vector(1)?;
        }
        _ => return None,
    }
    // No application resumption data is installed by this TCP listener.
    if !input.vector(2)?.is_empty() {
        return None;
    }
    let created = input.take(8)?;
    input.take(4)?; // age_add matters only to 0-RTT, disabled on this TCP listener.
    if !input.0.is_empty() {
        return None;
    }
    let mut out = Vec::new();
    out.extend_from_slice(version);
    out.push(1);
    out.extend_from_slice(cipher);
    out.extend_from_slice(created);
    vector(&mut out, 1, secret)?;
    out.extend_from_slice(&[0, 0, 0]); // Go Extra
    out.push(ems);
    out.push(0); // ext_master_secret, early_data
    vector(&mut out, 3, &certificate_list)?;
    out.extend_from_slice(&[0, 0, 0]); // rustls does not serialize Go's verified_chains cache
    if version == [3, 3] {
        out.extend_from_slice(&[0, 0]);
    } // curve_id is observational in resumed TLS 1.2
    Some(out)
}
