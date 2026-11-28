//! Independent consumer of the stored Go/Rust artifact wire format.
//! Opens AEADs with ring and checks the public binding, bytes and SQL metadata.
use super::{common, BoxError, Fx};
use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine};
use ring::{aead, hkdf};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
fn hash(b: &[u8]) -> String {
    format!("{:x}", Sha256::digest(b))
}
fn hex(b: &[u8]) -> String {
    b.iter().map(|b| format!("{b:02x}")).collect()
}
struct Len(usize);
impl hkdf::KeyType for Len {
    fn len(&self) -> usize {
        self.0
    }
}
fn derive(secret: &[u8], salt: &[u8], len: usize) -> Result<Vec<u8>, BoxError> {
    let prk = hkdf::Salt::new(hkdf::HKDF_SHA256, salt).extract(secret);
    let okm = prk.expand(&[], Len(len)).map_err(|_| "HKDF")?;
    let mut out = vec![0; len];
    okm.fill(&mut out).map_err(|_| "HKDF")?;
    Ok(out)
}
fn open(frame: &[u8], key: &[u8], aad: &[u8]) -> Result<Vec<u8>, BoxError> {
    if frame.len() < 41
        || &frame[..4] != b"EK01"
        || frame[9..13] != [0, 0, 0, 12]
        || u32::from_be_bytes(frame[5..9].try_into()?) as usize != key.len()
    {
        return Err("bad EK01 header".into());
    }
    if frame[4] == 1 {
        use aes_gcm::aead::{Aead, KeyInit, Payload};
        type Sm4Gcm = aes_gcm::AesGcm<sm4::Sm4, aes_gcm::aead::consts::U12>;
        let cipher = Sm4Gcm::new_from_slice(key).map_err(|_| "SM4 key")?;
        return cipher
            .decrypt(
                (&frame[13..25]).into(),
                Payload {
                    msg: &frame[25..],
                    aad,
                },
            )
            .map_err(|_| "SM4 AEAD authentication".into());
    }
    if frame[4] != 0 {
        return Err("unknown AEAD algorithm".into());
    }
    let nonce: [u8; 12] = frame[13..25].try_into()?;
    let mut payload = frame[25..].to_vec();
    let key = aead::UnboundKey::new(&aead::AES_256_GCM, key).map_err(|_| "AES key")?;
    Ok(aead::LessSafeKey::new(key)
        .open_in_place(
            aead::Nonce::assume_unique_for_key(nonce),
            aead::Aad::from(aad),
            &mut payload,
        )
        .map_err(|_| "AEAD authentication")?
        .to_vec())
}
pub async fn inspect(fx: &Fx, row: &mut Value) -> Result<Value, BoxError> {
    let key = row["object_key"].as_str().ok_or("object key")?.to_owned();
    let run = row["run_id"].as_i64().ok_or("artifact run")?;
    let (domain, project) = if run == fx.ra {
        (fx.a.domain, fx.pa)
    } else if run == fx.rb {
        (fx.b.domain, fx.pb)
    } else {
        return Err("foreign artifact run".into());
    };
    let canonical = remember_key(fx, &key, run)?;
    let address = fx.storage.lock().unwrap().ok_or("fake storage missing")?;
    let response = common::send(
        address,
        hyper::Request::get(format!("/mailblobs/{key}")).body(common::full(""))?,
    )
    .await;
    if response.status() != 200 {
        return Err("committed artifact has no object".into());
    }
    let bytes = common::body_bytes(response).await;
    let envelope: Value = serde_json::from_slice(&bytes)?;
    if envelope["schemaVersion"] != "setjoin.exchange.artifact-envelope/v1"
        || envelope["profile"] != fx.profile
    {
        return Err("wrong envelope schema/profile".into());
    }
    let binding = &envelope["binding"];
    let kind = if row["kind"] == "bundle" {
        "exchange-assessment-bundle"
    } else {
        "exchange-assessment-receipt"
    };
    let expected = json!({"installationId":fx.installation,"tenantId":domain,"projectId":project,"kind":kind,"plainSha256":row["sha256"]});
    if *binding != expected {
        return Err("artifact binding mismatch".into());
    }
    let aad = format!(
        "{{\"installationId\":{},\"tenantId\":{},\"projectId\":{},\"kind\":{},\"plainSha256\":{}}}",
        binding["installationId"], domain, project, binding["kind"], binding["plainSha256"]
    );
    let wrapped = STANDARD_NO_PAD.decode(envelope["wrappedDek"].as_str().ok_or("wrapped key")?)?;
    let ciphertext =
        STANDARD_NO_PAD.decode(envelope["ciphertext"].as_str().ok_or("ciphertext")?)?;
    let wrapping = derive(
        "22".repeat(32).as_bytes(),
        b"exchange-assessment-artifact-dek/v1",
        if fx.profile == "smx" { 16 } else { 32 },
    )?;
    let column = derive(
        &wrapping,
        b"mailserver-db-encryption-v1",
        if fx.profile == "smx" { 16 } else { 32 },
    )?;
    let dek = open(&wrapped, &column, aad.as_bytes())?;
    let plain = open(&ciphertext, &dek, aad.as_bytes())?;
    if hash(&plain) != row["sha256"]
        || hash(aad.as_bytes()) != row["aad_sha256"]
        || ciphertext.len() as i64 != row["ciphertext_size"]
        || row["nonce"] != format!("\\x{}", hex(&ciphertext[13..25]))
        || row["wrapped_dek"] != format!("\\x{}", hex(&wrapped))
    {
        return Err("artifact metadata does not describe object bytes".into());
    }
    if row["kind"] == "bundle" && plain != super::plan::BUNDLE.as_bytes() {
        return Err("wrong bundle plaintext".into());
    }
    if row["kind"] == "receipt" {
        let v: Value = serde_json::from_slice(&plain)?;
        verify_receipt(fx, &v)?;
        let canonical = format!(
            "{{\"claims\":{},\"algorithm\":\"ed25519\",\"signature\":{}}}",
            receipt_bytes(&v["claims"], false)?,
            v["signature"]
        );
        if plain != canonical.as_bytes() {
            return Err("noncanonical receipt bytes".into());
        }
        fx.crypto_literals.lock().unwrap().push((
            format!("\"ciphertext_size\":{}", ciphertext.len()),
            "\"ciphertext_size\":\"<receipt ciphertext size>\"".into(),
        ));
        row["ciphertext_size"] = json!("<receipt ciphertext size>");
    }
    let key_digest = hash(key.as_bytes());
    fx.object_digests.lock().unwrap().push(key_digest);
    for (name, placeholder) in [
        ("nonce", "<12-byte nonce>"),
        ("wrapped_dek", "<wrapped-DEK>"),
        ("aad_sha256", "<binding-sha256>"),
    ] {
        fx.crypto_literals.lock().unwrap().push((
            serde_json::to_string(&row[name])?,
            serde_json::to_string(placeholder)?,
        ));
    }
    row["nonce"] = json!("<12-byte nonce>");
    row["wrapped_dek"] = json!("<wrapped-DEK>");
    row["aad_sha256"] = json!("<binding-sha256>");
    Ok(
        json!({"key":canonical,"schema":envelope["schemaVersion"],"profile":envelope["profile"],"plaintext":String::from_utf8(plain)?,"ciphertext_size":ciphertext.len(),"wrapped_key_size":wrapped.len()}),
    )
}

pub fn remember_key(fx: &Fx, key: &str, run: i64) -> Result<String, BoxError> {
    let (domain, project, tag) = if run == fx.ra {
        (fx.a.domain, fx.pa, "a")
    } else if run == fx.rb {
        (fx.b.domain, fx.pb, "b")
    } else {
        return Err("foreign object run".into());
    };
    let prefix = format!("exchange-assessment/{domain}/{project}/{run}/");
    let suffix = key.strip_prefix(&prefix).ok_or("wrong object namespace")?;
    let filename = suffix.strip_prefix("receipts/").unwrap_or(suffix);
    let uuid = filename.strip_suffix(".sjae").ok_or("object suffix")?;
    if uuid.len() != 36
        || uuid.as_bytes()[14] != b'4'
        || !matches!(uuid.as_bytes()[19], b'8' | b'9' | b'a' | b'b')
    {
        return Err("object UUID is not v4".into());
    }
    let canonical = {
        let mut objects = fx.objects.lock().unwrap();
        if let Some((_, value)) = objects.iter().find(|(k, _)| k == key) {
            value.clone()
        } else {
            let n = objects.len();
            let value=format!("exchange-assessment/<domain-{tag}>/<project-{tag}>/<run-{tag}>/{}<object-{n}>.sjae",if suffix.starts_with("receipts/"){"receipts/"}else{""});
            objects.push((key.to_owned(), value.clone()));
            value
        }
    };
    Ok(canonical)
}

// Canonicalize independently from the producer's struct serialization.
pub(super) fn receipt_bytes(c: &Value, blank: bool) -> Result<String, BoxError> {
    let mut fields = Vec::new();
    for k in [
        "schemaVersion",
        "receiptId",
        "kind",
        "subjectSha256",
        "installationId",
        "tenantId",
        "projectId",
        "keyId",
        "issuedAt",
        "disposition",
    ] {
        if c.get(k).is_none() {
            return Err("missing receipt claim".into());
        }
        fields.push(format!(
            "\"{k}\":{}",
            if k == "receiptId" && blank {
                "\"\"".into()
            } else {
                c[k].to_string()
            }
        ));
    }
    Ok(format!("{{{}}}", fields.join(",")))
}
fn verify_receipt(fx: &Fx, v: &Value) -> Result<Vec<u8>, BoxError> {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use ring::signature::{Ed25519KeyPair, KeyPair, UnparsedPublicKey, ED25519};
    let c = &v["claims"];
    let key = Ed25519KeyPair::from_seed_unchecked(&[0x22; 32]).map_err(|_| "test Ed25519")?;
    let signature = URL_SAFE_NO_PAD.decode(v["signature"].as_str().ok_or("signature")?)?;
    UnparsedPublicKey::new(&ED25519, key.public_key())
        .verify(receipt_bytes(c, false)?.as_bytes(), &signature)
        .map_err(|_| "receipt signature mismatch")?;
    if c["receiptId"] != hash(receipt_bytes(c, true)?.as_bytes())
        || c["schemaVersion"] != "setjoin.exchange.receipt/v1"
        || c["kind"] != "publication"
        || c["subjectSha256"] != fx.pub_digest
        || c["installationId"] != fx.installation
        || c["tenantId"] != fx.a.domain
        || c["projectId"] != fx.pa
        || c["keyId"] != "blobs1-test-continuity"
        || c["disposition"] != "published_evidence_snapshot"
        || v["algorithm"] != "ed25519"
    {
        return Err("receipt claims mismatch".into());
    }
    let time = c["issuedAt"].as_str().ok_or("issuedAt")?;
    let parsed = chrono::DateTime::parse_from_rfc3339(time)?;
    if time.len() != 20
        || !time.ends_with('Z')
        || (chrono::Utc::now() - parsed.to_utc()).num_seconds().abs() > 120
    {
        return Err("receipt issuance time".into());
    }
    let canonical = format!(
        "{{\"claims\":{},\"algorithm\":\"ed25519\",\"signature\":{}}}",
        receipt_bytes(c, false)?,
        v["signature"]
    );
    for (value, placeholder) in [
        (c["receiptId"].as_str().unwrap(), "<receipt-id>"),
        (v["signature"].as_str().unwrap(), "<Ed25519 signature>"),
    ] {
        fx.crypto_literals.lock().unwrap().push((
            serde_json::to_string(value)?,
            serde_json::to_string(placeholder)?,
        ));
    }
    fx.crypto_literals.lock().unwrap().push((
        serde_json::to_string(&hash(canonical.as_bytes()))?,
        "\"<receipt-sha256>\"".into(),
    ));
    Ok(signature)
}
pub fn inspect_receipt_row(fx: &Fx, row: &mut Value) -> Result<(), BoxError> {
    let sig = verify_receipt(fx, &row["receipt"])?;
    if row["signature_algorithm"] != "ed25519"
        || row["signing_key_id"] != "blobs1-test-continuity"
        || row["signature"] != format!("\\x{}", hex(&sig))
        || row["subject_digest"] != fx.pub_digest
    {
        return Err("stored receipt signature metadata".into());
    }
    row["signature"] = json!("<64-byte Ed25519 signature>");
    Ok(())
}
