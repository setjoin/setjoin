use super::*;
use p256::elliptic_curve::sec1::ToSec1Point;
use ring::{
    aead, agreement, hmac,
    rand::{SecureRandom, SystemRandom},
    signature,
};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

fn expand(key: &[u8], info: &[u8], size: usize) -> Vec<u8> {
    let mut input = info.to_vec();
    input.push(1);
    hmac::sign(&hmac::Key::new(hmac::HMAC_SHA256, key), &input).as_ref()[..size].to_vec()
}
fn extract(salt: &[u8], key: &[u8]) -> Vec<u8> {
    hmac::sign(&hmac::Key::new(hmac::HMAC_SHA256, salt), key)
        .as_ref()
        .to_vec()
}

pub(crate) async fn send(
    private: &[u8],
    subject: &str,
    device: &str,
    payload: &[u8],
) -> Result<(), String> {
    let sub: serde_json::Value =
        serde_json::from_str(device).map_err(|e| format!("webpush subscription: {e}"))?;
    let endpoint = sub["endpoint"].as_str().unwrap_or_default();
    let peer = raw_url_decode(
        sub["keys"]["p256dh"]
            .as_str()
            .unwrap_or_default()
            .trim_end_matches('='),
    )
    .map_err(|e| format!("webpush send: {e}"))?;
    let auth = raw_url_decode(
        sub["keys"]["auth"]
            .as_str()
            .unwrap_or_default()
            .trim_end_matches('='),
    )
    .map_err(|e| format!("webpush send: {e}"))?;
    let rng = SystemRandom::new();
    let sender = agreement::EphemeralPrivateKey::generate(&agreement::ECDH_P256, &rng)
        .map_err(|_| "webpush send: could not generate key")?;
    let sender_public = sender
        .compute_public_key()
        .map_err(|_| "webpush send: could not generate key")?;
    let secret = agreement::agree_ephemeral(
        sender,
        &agreement::UnparsedPublicKey::new(&agreement::ECDH_P256, &peer),
        |key| key.to_vec(),
    )
    .map_err(|_| "webpush send: invalid public key")?;
    let mut info = b"WebPush: info\0".to_vec();
    info.extend(&peer);
    info.extend(sender_public.as_ref());
    let ikm = expand(&extract(&auth, &secret), &info, 32);
    let mut salt = [0; 16];
    rng.fill(&mut salt)
        .map_err(|_| "webpush send: random generation failed")?;
    let prk = extract(&salt, &ikm);
    let key = expand(&prk, b"Content-Encoding: aes128gcm\0", 16);
    let nonce = expand(&prk, b"Content-Encoding: nonce\0", 12);
    if payload.len() > 3993 {
        return Err("webpush send: payload too large".into());
    }
    let mut body = payload.to_vec();
    body.push(2);
    body.resize(3994, 0);
    let key = aead::LessSafeKey::new(
        aead::UnboundKey::new(&aead::AES_128_GCM, &key)
            .map_err(|_| "webpush send: invalid encryption key")?,
    );
    key.seal_in_place_append_tag(
        aead::Nonce::try_assume_unique_for_key(&nonce)
            .map_err(|_| "webpush send: invalid nonce")?,
        aead::Aad::empty(),
        &mut body,
    )
    .map_err(|_| "webpush send: encryption failed")?;
    let mut encrypted = salt.to_vec();
    encrypted.extend(4096_u32.to_be_bytes());
    encrypted.push(65);
    encrypted.extend(sender_public.as_ref());
    encrypted.extend(body);
    let parsed = url::Url::parse(endpoint).map_err(|e| format!("webpush send: {e}"))?;
    let host = parsed
        .host_str()
        .ok_or("webpush send: missing endpoint host")?;
    let authority = parsed[url::Position::BeforeHost..url::Position::AfterPort].to_owned();
    let audience = format!("{}://{authority}", parsed.scheme());
    let subject = if subject.starts_with("https:") {
        subject.to_owned()
    } else {
        format!("mailto:{subject}")
    };
    let vapid = p256::SecretKey::from_slice(private)
        .map_err(|_| "webpush send: invalid VAPID private key")?;
    let public = vapid.public_key().to_sec1_point(false);
    let vapid = signature::EcdsaKeyPair::from_private_key_and_public_key(
        &signature::ECDSA_P256_SHA256_FIXED_SIGNING,
        private,
        public.as_bytes(),
        &rng,
    )
    .map_err(|_| "webpush send: invalid VAPID private key")?;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let header = URL_SAFE_NO_PAD.encode(br#"{"typ":"JWT","alg":"ES256"}"#);
    let claims = URL_SAFE_NO_PAD
        .encode(serde_json::json!({"aud":audience,"exp":now()+43200,"sub":subject}).to_string());
    let unsigned = format!("{header}.{claims}");
    let sig = vapid
        .sign(&rng, unsigned.as_bytes())
        .map_err(|_| "webpush send: could not sign VAPID")?;
    // Frozen Go supplies only VAPIDPrivateKey, leaving the advertised public key empty.
    let authorization = format!(
        "vapid t={unsigned}.{}, k=",
        URL_SAFE_NO_PAD.encode(sig.as_ref())
    );
    let denied = || {
        format!(
            "webpush send: Post {:?}: URL is not allowed (must be http/https to a public host)",
            format!("{}://{authority}/[redacted]", parsed.scheme())
        )
    };
    let port = parsed.port_or_known_default().ok_or_else(denied)?;
    let addresses = tokio::net::lookup_host((host.trim_matches(['[', ']']), port))
        .await
        .map_err(|_| denied())?
        .collect::<Vec<_>>();
    #[cfg(not(feature = "oracle-loopback"))]
    let allow_loopback = false;
    #[cfg(feature = "oracle-loopback")]
    let allow_loopback = env("MAILCTL_ORACLE_WEBPUSH_LOOPBACK") == "1"
        && addresses.iter().all(|a| a.ip().is_loopback());
    if addresses.is_empty() || (!allow_loopback && addresses.iter().any(|a| blocked(a.ip()))) {
        return Err(denied());
    }
    let client = reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(std::time::Duration::from_secs(30))
        .resolve_to_addrs(host, &addresses)
        .build()
        .map_err(|e| format!("webpush send: {}", scrub(&e.to_string())))?;
    let response = client
        .post(endpoint)
        .header("TTL", "60")
        .header("Content-Encoding", "aes128gcm")
        .header("Content-Type", "application/octet-stream")
        .header("Authorization", authorization)
        .body(encrypted)
        .send()
        .await
        .map_err(|e| format!("webpush send: {}", scrub(&e.to_string())))?;
    let status = response.status().as_u16();
    if matches!(status, 404 | 410) {
        return Err(format!(
            "webpush gone {status}: push: device token no longer registered"
        ));
    }
    if status >= 300 {
        return Err(format!("webpush: HTTP {status}"));
    }
    Ok(())
}
fn blocked(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => blocked_v4(ip),
        IpAddr::V6(ip) => {
            if let Some(v4) = ip.to_ipv4_mapped() {
                blocked_v4(v4)
            } else {
                blocked_v6(ip)
            }
        }
    }
}
fn blocked_v4(ip: Ipv4Addr) -> bool {
    if ip.is_private()
        || ip.is_loopback()
        || ip.is_link_local()
        || ip.is_multicast()
        || ip.is_unspecified()
    {
        return true;
    }
    let number = u32::from(ip);
    [
        ("0.0.0.0", 8),
        ("100.64.0.0", 10),
        ("192.0.0.0", 24),
        ("192.0.2.0", 24),
        ("198.51.100.0", 24),
        ("203.0.113.0", 24),
        ("192.31.196.0", 24),
        ("192.52.193.0", 24),
        ("192.88.99.0", 24),
        ("192.175.48.0", 24),
        ("198.18.0.0", 15),
        ("240.0.0.0", 4),
    ]
    .into_iter()
    .any(|(network, bits)| {
        number & (u32::MAX << (32 - bits)) == u32::from(network.parse::<Ipv4Addr>().unwrap())
    })
}
fn blocked_v6(ip: Ipv6Addr) -> bool {
    if ip.is_loopback()
        || ip.is_unspecified()
        || ip.is_multicast()
        || ip.is_unique_local()
        || ip.is_unicast_link_local()
    {
        return true;
    }
    let number = u128::from(ip);
    [("100::", 64), ("2001:db8::", 32), ("64:ff9b::", 96)]
        .into_iter()
        .any(|(network, bits)| {
            number & (u128::MAX << (128 - bits)) == u128::from(network.parse::<Ipv6Addr>().unwrap())
        })
}
