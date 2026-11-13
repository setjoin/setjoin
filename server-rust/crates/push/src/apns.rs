use super::*;

pub(crate) fn identity(path: &str, password: &str) -> Result<Vec<u8>, String> {
    let bytes =
        std::fs::read(path).map_err(|e| format!("apns2 cert: open {path}: {}", io_error(&e)))?;
    if let Some(oid) = mac_oid(&bytes) {
        if oid != "1.3.14.3.2.26" {
            return Err(format!(
                "apns2 cert: pkcs12: unknown digest algorithm: {oid}"
            ));
        }
    }
    let store = p12_keystore::KeyStore::from_pkcs12(
        &bytes,
        password,
        p12_keystore::Pkcs12ImportPolicy::Relaxed,
    )
    .map_err(|e| match e {
        p12_keystore::error::Error::MacError(_) | p12_keystore::error::Error::UnpadError => {
            "apns2 cert: pkcs12: decryption password incorrect".into()
        }
        _ => format!("apns2 cert: pkcs12: {e}"),
    })?;
    let (_, chain) = store
        .private_key_chain()
        .ok_or("apns2 cert: tls: failed to find any PEM data in certificate input")?;
    let mut identity = Vec::new();
    for cert in chain.certs() {
        identity.extend(pem_block("CERTIFICATE", cert.as_der()));
    }
    identity.extend(pem_block("PRIVATE KEY", chain.key().as_der()));
    Ok(identity)
}
fn pem_block(kind: &str, der: &[u8]) -> Vec<u8> {
    use base64::engine::general_purpose::STANDARD;
    let encoded = STANDARD.encode(der);
    let mut text = format!("-----BEGIN {kind}-----\n");
    for line in encoded.as_bytes().chunks(64) {
        text.push_str(std::str::from_utf8(line).unwrap());
        text.push('\n');
    }
    text.push_str(&format!("-----END {kind}-----\n"));
    text.into_bytes()
}
// Only inspect the outer MAC algorithm. Go's PKCS#12 decoder accepts SHA-1,
// whereas the Rust decoder also supports newer files; retain the Go boundary.
fn mac_oid(data: &[u8]) -> Option<String> {
    let root = fields(data)?;
    let pfx = fields(root.first()?.1)?;
    let mac = fields(pfx.get(2)?.1)?;
    let digest = fields(mac.first()?.1)?;
    let algorithm = fields(digest.first()?.1)?;
    let oid = algorithm.first()?;
    if oid.0 != 6 || oid.1.is_empty() {
        return None;
    }
    let first = u32::from(oid.1[0]);
    let mut numbers = vec![first / 40, first % 40];
    let mut value = 0_u32;
    for byte in &oid.1[1..] {
        value = value.checked_mul(128)?.checked_add(u32::from(byte & 127))?;
        if byte & 128 == 0 {
            numbers.push(value);
            value = 0;
        }
    }
    Some(
        numbers
            .into_iter()
            .map(|n| n.to_string())
            .collect::<Vec<_>>()
            .join("."),
    )
}
fn fields(mut data: &[u8]) -> Option<Vec<(u8, &[u8])>> {
    let mut out = vec![];
    while !data.is_empty() {
        let tag = *data.first()?;
        let first = *data.get(1)?;
        let mut head = 2;
        let length = if first & 128 == 0 {
            usize::from(first)
        } else {
            let n = usize::from(first & 127);
            if n == 0 || n > 4 {
                return None;
            }
            head += n;
            let mut length = 0_usize;
            for byte in data.get(2..head)? {
                length = length.checked_mul(256)?.checked_add(usize::from(*byte))?;
            }
            length
        };
        let end = head.checked_add(length)?;
        out.push((tag, data.get(head..end)?));
        data = data.get(end..)?;
    }
    Some(out)
}

pub(crate) async fn send(
    identity: &[u8],
    cached: &mut Option<reqwest::Client>,
    bundle: &str,
    production: bool,
    device: &str,
    payload: &[u8],
) -> Result<(), String> {
    use base64::engine::general_purpose::STANDARD;
    let host = if production {
        "api.push.apple.com"
    } else {
        "api.sandbox.push.apple.com"
    };
    if cached.is_none() {
        let certificate = reqwest::Identity::from_pem(identity)
            .map_err(|e| format!("apns2 push: {}", scrub(&e.to_string())))?;
        let builder = reqwest::Client::builder()
            .identity(certificate)
            .http2_prior_knowledge()
            .no_proxy()
            .timeout(std::time::Duration::from_secs(60));
        #[cfg(feature = "oracle-loopback")]
        let builder = if let Some(addr) = std::env::var("MAILCTL_ORACLE_APNS_ADDR")
            .ok()
            .and_then(|v| v.parse::<std::net::SocketAddr>().ok())
            .filter(|a| a.ip().is_loopback())
        {
            builder.resolve(host, addr)
        } else {
            builder
        };
        *cached = Some(
            builder
                .build()
                .map_err(|e| format!("apns2 push: {}", scrub(&e.to_string())))?,
        );
    }
    let client = cached.as_ref().unwrap();
    let body = serde_json::json!({"aps":{"content-available":1,"mutable-content":1,"alert":{"title":"SetJoin","body":"You have a new notification"}},"data":STANDARD.encode(payload)});
    let response = client
        .post(format!("https://{host}/3/device/{device}"))
        .header("apns-topic", bundle)
        .header("apns-push-type", "alert")
        .header("apns-priority", "10")
        .header("content-type", "application/json; charset=utf-8")
        .body(body.to_string())
        .send()
        .await
        .map_err(|e| format!("apns2 push: {}", scrub(&e.to_string())))?;
    if response.status().as_u16() == 200 {
        let _ = response.bytes().await;
        return Ok(());
    }
    let status = response.status().as_u16();
    let id = response
        .headers()
        .get("apns-id")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_owned();
    let body: serde_json::Value =
        serde_json::from_slice(&response.bytes().await.unwrap_or_default()).unwrap_or_default();
    let reason = body["reason"].as_str().unwrap_or_default();
    if status == 410 || matches!(reason, "Unregistered" | "BadDeviceToken") {
        return Err(format!(
            "apns2 rejected {reason}: push: device token no longer registered"
        ));
    }
    Err(format!("apns2 rejected: {reason} {id}"))
}
