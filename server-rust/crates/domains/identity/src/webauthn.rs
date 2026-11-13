//! Frozen-Go WebAuthn profile. Only sealed authentication proofs select owners.
use crate::session::Session;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use setjoin_contracts::ids::{ActorId, OperationId};
use setjoin_pg::{CommandOutcome, ScopedExecutor, StatementFailure, Type};

pub async fn list(exec: &ScopedExecutor, session: &Session) -> Result<String, StatementFailure> {
    // The frozen list drops late row-iteration errors; this is display only.
    let rows=exec.read_iterated("SELECT id,COALESCE(device_name,''),to_char(created_at AT TIME ZONE 'UTC','YYYY-MM-DD\"T\"HH24:MI:SS.US'),uv_capable FROM passkey_credentials WHERE user_id=$1 AND revoked_at IS NULL ORDER BY created_at DESC",&[(&session.user(),Type::INT8)]).await?;
    let mut credentials = Vec::new();
    for row in rows {
        let (Ok(id), Ok(name), Ok(created), Ok(uv)) = (
            row.try_get::<_, Vec<u8>>(0),
            row.try_get::<_, String>(1),
            row.try_get::<_, String>(2),
            row.try_get::<_, bool>(3),
        ) else {
            continue;
        };
        let created = format!("{}Z", created.trim_end_matches('0').trim_end_matches('.'));
        credentials.push(format!(
            "{{\"id\":{},\"device_name\":{},\"created_at\":{},\"uv_capable\":{uv}}}",
            serde_json::json!(URL_SAFE_NO_PAD.encode(id)),
            serde_json::json!(name),
            serde_json::json!(created)
        ));
    }
    Ok(format!("{{\"credentials\":[{}]}}\n", credentials.join(",")))
}

pub async fn name(
    exec: &ScopedExecutor,
    session: &Session,
    id: &[u8],
    name: &str,
) -> setjoin_pg::CommandOutcome<(), StatementFailure> {
    let Ok(actor) = setjoin_contracts::ids::ActorId::new(session.user()) else {
        return setjoin_pg::CommandOutcome::RolledBack(setjoin_pg::Rejection::Unavailable);
    };
    exec.clone().with_user_receipt(setjoin_pg::ReceiptCommand{family:"F21",command:"webauthn-name"}).run_user_command(actor,setjoin_contracts::ids::OperationId(*uuid::Uuid::new_v4().as_bytes()),
        "UPDATE passkey_credentials SET device_name=$1 WHERE id=$2 AND user_id=$3 AND revoked_at IS NULL",
        &[(&name,Type::TEXT),(&id,Type::BYTEA),(&session.user(),Type::INT8)],|_|Ok(())).await
}

/// Go-stored raw COSE verification. Core0.6 remains unmodified. The facts-check
/// compatibility layer supplies the algorithms/key sizes core cannot import.
/// Cryptographic verification, including PSS's auto salt length, is library-owned.
pub fn verify_stored_signature(raw: &[u8], message: &[u8], signature: &[u8]) -> bool {
    verify_signature_inner(raw, message, signature).unwrap_or(false)
}
fn verify_signature_inner(raw: &[u8], message: &[u8], signature: &[u8]) -> Option<bool> {
    use serde_cbor_2::Value as C;
    let value: C = serde_cbor_2::from_slice(raw).ok()?;
    let C::Map(map) = &value else { return None };
    let integer = |key| match map.get(&C::Integer(key))? {
        C::Integer(n) => Some(*n),
        _ => None,
    };
    let bytes = |key| match map.get(&C::Integer(key))? {
        C::Bytes(b) => Some(b.as_slice()),
        _ => None,
    };
    let (kty, alg) = (integer(1)?, integer(3)?);
    if matches!((kty, alg), (2, -7) | (2, -35) | (3, -257)) {
        if let Ok(key) = webauthn_rs_core::proto::COSEKey::try_from(&value) {
            return Some(key.verify_signature(signature, message).unwrap_or(false));
        }
    }
    match (kty, alg) {
        (1, -8) if integer(-1) == Some(6) => Some(
            ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, bytes(-2)?)
                .verify(message, signature)
                .is_ok(),
        ),
        (2, -36) if integer(-1) == Some(3) => {
            use p521::ecdsa::{signature::Verifier, Signature, VerifyingKey};
            let (x, y) = (bytes(-2)?, bytes(-3)?);
            if x.len() != 66 || y.len() != 66 {
                return None;
            }
            let mut point = Vec::with_capacity(133);
            point.push(4);
            point.extend_from_slice(x);
            point.extend_from_slice(y);
            let key = VerifyingKey::from_sec1_bytes(&point).ok()?;
            let sig = Signature::from_der(signature).ok()?;
            Some(key.verify(message, &sig).is_ok())
        }
        (3, -257 | -258 | -259 | -37 | -38 | -39) => {
            use rsa::sha2::{Digest, Sha256, Sha384, Sha512};
            use rsa::{BoxedUint, RsaPublicKey};
            let (n, e) = (bytes(-1)?, bytes(-2)?);
            let n = BoxedUint::from_be_slice_vartime(n);
            // Go 1.26 crypto/rsa refuses verification with keys below 1024 bits.
            if n.bits() < 1024 {
                return Some(false);
            }
            let e = BoxedUint::from_be_slice_vartime(e);
            let key = RsaPublicKey::new_with_max_size(n, e, raw.len().saturating_mul(8).max(4096))
                .ok()?;
            let valid = match alg {
                -257 => key.verify(
                    rsa::Pkcs1v15Sign::new::<Sha256>(),
                    &Sha256::digest(message),
                    signature,
                ),
                -258 => key.verify(
                    rsa::Pkcs1v15Sign::new::<Sha384>(),
                    &Sha384::digest(message),
                    signature,
                ),
                -259 => key.verify(
                    rsa::Pkcs1v15Sign::new::<Sha512>(),
                    &Sha512::digest(message),
                    signature,
                ),
                -37 => key.verify(
                    rsa::Pss {
                        blinded: false,
                        digest: Sha256::new(),
                        salt_len: None,
                    },
                    &Sha256::digest(message),
                    signature,
                ),
                -38 => key.verify(
                    rsa::Pss {
                        blinded: false,
                        digest: Sha384::new(),
                        salt_len: None,
                    },
                    &Sha384::digest(message),
                    signature,
                ),
                -39 => key.verify(
                    rsa::Pss {
                        blinded: false,
                        digest: Sha512::new(),
                        salt_len: None,
                    },
                    &Sha512::digest(message),
                    signature,
                ),
                _ => return None,
            };
            Some(valid.is_ok())
        }
        _ => None,
    }
}

/// Frozen Go's HKDF-domain-separated AES256-GCM cookie transport. Cookie
/// ciphertext is padded base64url(nonce || ciphertext || tag), without EK01.
pub struct CookieCipher([u8; 32]);
impl CookieCipher {
    pub fn new(secret: &[u8]) -> Self {
        let salt = ring::hkdf::Salt::new(ring::hkdf::HKDF_SHA256, b"mailserver-cookie-key-v1");
        let prk = salt.extract(secret);
        let mut key = [0; 32];
        prk.expand(&[b""], ring::hkdf::HKDF_SHA256)
            .expect("fixed HKDF length")
            .fill(&mut key)
            .expect("fixed key length");
        Self(key)
    }
    pub fn seal(&self, plain: &[u8]) -> Result<String, &'static str> {
        use ring::{
            aead,
            rand::{SecureRandom, SystemRandom},
        };
        let mut nonce = [0; 12];
        SystemRandom::new()
            .fill(&mut nonce)
            .map_err(|_| "cookie RNG failed")?;
        let key = aead::LessSafeKey::new(
            aead::UnboundKey::new(&aead::AES_256_GCM, &self.0).map_err(|_| "cookie key")?,
        );
        let mut data = plain.to_vec();
        key.seal_in_place_append_tag(
            aead::Nonce::assume_unique_for_key(nonce),
            aead::Aad::empty(),
            &mut data,
        )
        .map_err(|_| "cookie encryption")?;
        let mut wire = nonce.to_vec();
        wire.extend_from_slice(&data);
        Ok(base64::engine::general_purpose::URL_SAFE.encode(wire))
    }
    pub fn open(&self, wire: &str) -> Option<Vec<u8>> {
        use ring::aead;
        let wire = wire.replace(['\r', '\n'], "");
        let engine = base64::engine::GeneralPurpose::new(
            &base64::alphabet::URL_SAFE,
            base64::engine::general_purpose::GeneralPurposeConfig::new()
                .with_decode_allow_trailing_bits(true),
        );
        let mut data = engine.decode(wire).ok()?;
        if data.len() < 28 {
            return None;
        }
        let nonce: [u8; 12] = data[..12].try_into().ok()?;
        let key = aead::LessSafeKey::new(aead::UnboundKey::new(&aead::AES_256_GCM, &self.0).ok()?);
        key.open_in_place(
            aead::Nonce::assume_unique_for_key(nonce),
            aead::Aad::empty(),
            &mut data[12..],
        )
        .ok()
        .map(|v| v.to_vec())
    }
}

pub struct RelyingParty {
    pub cookies: CookieCipher,
    rp_id: String,
    rp_name: String,
    origin: String,
    core: webauthn_rs_core::WebauthnCore,
    decoy: [u8; 32],
}
struct StoredCredential {
    id: Vec<u8>,
    key: Vec<u8>,
    _attestation: String,
    _count: u32,
}
struct User {
    id: i64,
    _email: String,
    _display: String,
    handle: Vec<u8>,
    credentials: Vec<StoredCredential>,
}
pub struct LoginBegin {
    pub user: i64,
    pub options: String,
    pub session: Vec<u8>,
}
impl RelyingParty {
    pub fn new(secret: &[u8], id: &str, name: &str, origin: &str) -> Result<Self, &'static str> {
        use ring::rand::{SecureRandom, SystemRandom};
        if id.is_empty() || id.contains(['/', ':', ' ']) || name.is_empty() {
            return Err("invalid relying party");
        }
        let origin_url = origin.parse().map_err(|_| "invalid relying-party origin")?;
        let core = webauthn_rs_core::WebauthnCore::new_unsafe_experts_only(
            name,
            id,
            vec![origin_url],
            std::time::Duration::from_secs(300),
            Some(false),
            Some(false),
        );
        let mut decoy = [0; 32];
        SystemRandom::new()
            .fill(&mut decoy)
            .map_err(|_| "decoy RNG")?;
        Ok(Self {
            cookies: CookieCipher::new(secret),
            rp_id: id.into(),
            rp_name: name.into(),
            origin: origin.into(),
            core,
            decoy,
        })
    }
    async fn load_user(
        &self,
        exec: &ScopedExecutor,
        id: i64,
        initialize: bool,
    ) -> Result<User, String> {
        use ring::rand::{SecureRandom, SystemRandom};
        use setjoin_contracts::ids::{ActorId, OperationId};
        use setjoin_pg::CommandOutcome;
        let actor = ActorId::new(id).map_err(|_| "no rows in result set".to_owned())?;
        let rows=exec.read_user_scoped(actor,"SELECT email,display_name,webauthn_user_handle FROM users WHERE id=$1 AND enabled=TRUE",&[(&id,Type::INT8)]).await.map_err(|e|e.message)?;
        let r = rows.first().ok_or("no rows in result set")?;
        let mut handle = r.get::<_, Option<Vec<u8>>>(2).unwrap_or_default();
        if handle.is_empty() && initialize {
            let mut candidate = [0; 32];
            SystemRandom::new()
                .fill(&mut candidate)
                .map_err(|_| "webauthn: generate user handle")?;
            match exec.run_user_command(actor,OperationId(*uuid::Uuid::new_v4().as_bytes()),"UPDATE users SET webauthn_user_handle=COALESCE(webauthn_user_handle,$1) WHERE id=$2 RETURNING webauthn_user_handle",&[(&candidate.as_slice(),Type::BYTEA),(&id,Type::INT8)],|rows|Ok(rows[0].get::<_,Vec<u8>>(0))).await {
                CommandOutcome::Committed(h)=>handle=h,
                _=>return Err("webauthn: persist user handle".into()),
            }
        }
        if handle.is_empty() {
            handle = id.to_string().into_bytes();
        }
        let rows=exec.read_user_scoped(actor,"SELECT id,public_key,attestation_type,sign_count FROM passkey_credentials WHERE user_id=$1 AND revoked_at IS NULL",&[(&id,Type::INT8)]).await.map_err(|e|e.message)?;
        let credentials = rows
            .iter()
            .map(|r| {
                Ok(StoredCredential {
                    id: r.get(0),
                    key: r.get(1),
                    _attestation: r.get(2),
                    _count: u32::try_from(r.get::<_, i32>(3))
                        .map_err(|_| "invalid credential counter")?,
                })
            })
            .collect::<Result<Vec<_>, String>>()?;
        Ok(User {
            id,
            _email: r.get(0),
            _display: r.get(1),
            handle,
            credentials,
        })
    }
    pub async fn begin_login(
        &self,
        exec: &ScopedExecutor,
        email: &str,
    ) -> Result<LoginBegin, &'static str> {
        let email = setjoin_authz::address::canonical(email);
        let rows = exec
            .read(
                "SELECT id FROM users WHERE email=$1 AND enabled=TRUE",
                &[(&email.as_str(), Type::TEXT)],
            )
            .await;
        let user = match rows
            .ok()
            .and_then(|r| r.first().map(|r| r.get::<_, i64>(0)))
        {
            Some(id) => self
                .load_user(exec, id, true)
                .await
                .ok()
                .filter(|u| !u.credentials.is_empty()),
            None => None,
        };
        let (uid, handle, ids) = if let Some(u) = user {
            (
                u.id,
                u.handle,
                u.credentials.into_iter().map(|c| c.id).collect::<Vec<_>>(),
            )
        } else {
            let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, &self.decoy);
            let id = ring::hmac::sign(&key, email.as_str().as_bytes())
                .as_ref()
                .to_vec();
            let handle = ring::hmac::sign(&key, format!("uh:{}", email.as_str()).as_bytes())
                .as_ref()
                .to_vec();
            (0, handle, vec![id])
        };
        let challenge = random_challenge()?;
        let credentials = ids
            .iter()
            .map(|id| {
                format!(
                    "{{\"type\":\"public-key\",\"id\":{}}}",
                    serde_json::json!(URL_SAFE_NO_PAD.encode(id))
                )
            })
            .collect::<Vec<_>>()
            .join(",");
        let options=format!("{{\"publicKey\":{{\"challenge\":{},\"timeout\":300000,\"rpId\":{},\"allowCredentials\":[{credentials}]}}}}",serde_json::json!(challenge),serde_json::json!(self.rp_id));
        let session=serde_json::json!({"challenge":challenge,"rpId":self.rp_id,"user_id":base64::engine::general_purpose::STANDARD.encode(handle),"allowed_credentials":ids.iter().map(|id|base64::engine::general_purpose::STANDARD.encode(id)).collect::<Vec<_>>(),"expires":"0001-01-01T00:00:00Z"}).to_string().into_bytes();
        Ok(LoginBegin {
            user: uid,
            options,
            session,
        })
    }
}
fn random_challenge() -> Result<String, &'static str> {
    use ring::rand::{SecureRandom, SystemRandom};
    let mut challenge = [0; 32];
    SystemRandom::new()
        .fill(&mut challenge)
        .map_err(|_| "challenge RNG")?;
    Ok(URL_SAFE_NO_PAD.encode(challenge))
}
pub fn query_value(query: &str, key: &str) -> String {
    form_urlencoded::parse(query.as_bytes())
        .find(|(k, _)| k == key)
        .map(|(_, v)| v.into_owned())
        .unwrap_or_default()
}

pub struct LoginTransport {
    user: i64,
    session: Vec<u8>,
}
impl LoginTransport {
    pub fn user(&self) -> i64 {
        self.user
    }
}
pub struct LoginProof {
    user: i64,
}
pub enum LoginFailure {
    Refused(String),
    Unknown(setjoin_contracts::ids::OperationId),
}
impl RelyingParty {
    pub fn login_transport(
        &self,
        uid: &str,
        session: &str,
    ) -> Result<LoginTransport, &'static str> {
        let uid = self.cookies.open(uid).ok_or("invalid uid cookie")?;
        let user = std::str::from_utf8(&uid)
            .ok()
            .and_then(|s| s.parse::<i64>().ok())
            .ok_or("invalid uid cookie")?;
        let session = self.cookies.open(session).ok_or("invalid session cookie")?;
        Ok(LoginTransport { user, session })
    }
    pub async fn finish_login(
        &self,
        exec: &ScopedExecutor,
        transport: &LoginTransport,
        raw: &[u8],
    ) -> Result<LoginProof, LoginFailure> {
        let refuse = |s: &str| LoginFailure::Refused(s.into());
        let user = self
            .load_user(exec, transport.user, true)
            .await
            .map_err(LoginFailure::Refused)?;
        let session: serde_json::Value = serde_json::from_slice(&transport.session)
            .map_err(|_| refuse("invalid session data"))?;
        let request: serde_json::Value =
            serde_json::from_slice(raw).map_err(|_| refuse("Parse error for Assertion"))?;
        let parsed = parse_assertion(&request).map_err(LoginFailure::Refused)?;
        let handle = decode_standard(session["user_id"].as_str().unwrap_or(""))
            .ok_or_else(|| refuse("invalid session data"))?;
        if user.handle != handle {
            return Err(refuse("ID mismatch for User and Session"));
        }
        if session_expired(&session) {
            return Err(refuse("Session has Expired"));
        }
        let allowed = session
            .get("allowed_credentials")
            .and_then(serde_json::Value::as_array)
            .map(|a| {
                a.iter()
                    .map(|id| decode_standard(id.as_str().unwrap_or("")))
                    .collect::<Option<Vec<_>>>()
            })
            .unwrap_or(Some(Vec::new()))
            .ok_or_else(|| refuse("invalid session data"))?;
        if !allowed.is_empty() {
            if allowed
                .iter()
                .any(|id| !user.credentials.iter().any(|c| c.id == *id))
            {
                return Err(refuse(
                    "User does not own all credentials from the allowed credential list",
                ));
            }
            if !user.credentials.iter().any(|c| c.id == parsed.id) {
                return Err(refuse(
                    "The credential ID provided is not owned by the user",
                ));
            }
            if !allowed.contains(&parsed.id) {
                return Err(refuse(
                    "The credential ID provided is not in the sessions allowed credential list",
                ));
            }
        }
        if !parsed.handle.is_empty() && parsed.handle != user.handle {
            return Err(refuse("User handle and User ID do not match"));
        }
        let credential = user
            .credentials
            .iter()
            .find(|c| c.id == parsed.id)
            .ok_or_else(|| {
                refuse("Unable to find the credential for the returned credential ID")
            })?;
        self.verify_client(&parsed.client, &session, "webauthn.get")
            .map_err(LoginFailure::Refused)?;
        self.verify_auth_data(&parsed.auth, &session, true)
            .map_err(LoginFailure::Refused)?;
        use sha2::{Digest, Sha256};
        let mut message = parsed.auth.clone();
        message.extend_from_slice(&Sha256::digest(&parsed.client));
        if !verify_stored_signature(&credential.key, &message, &parsed.signature) {
            return Err(refuse(&signature_error(&credential.key)));
        }
        // Frozen Go loads no backup flags from its normalized credential row.
        if parsed.auth[32] & 8 != 0 {
            return Err(refuse(
                "Backup Eligible flag inconsistency detected during login validation",
            ));
        }
        if parsed.auth[32] & 16 != 0 {
            return Err(refuse(
                "Backup State Flag is true but Backup Eligible flag is false which is invalid",
            ));
        }
        let count = u32::from_be_bytes(parsed.auth[33..37].try_into().unwrap());
        let count = i32::try_from(count).map_err(|_| refuse("invalid credential counter"))?;
        let actor = setjoin_contracts::ids::ActorId::new(user.id)
            .map_err(|_| refuse("no rows in result set"))?;
        let op = setjoin_contracts::ids::OperationId(*uuid::Uuid::new_v4().as_bytes());
        match exec.clone().with_user_receipt(setjoin_pg::ReceiptCommand{family:"F21",command:"webauthn-counter"}).run_user_command(actor,op,"SELECT rust_identity_webauthn_login_claim($1,$2,$3,$4,$5)",&[(&user.id,Type::INT8),(&credential.id,Type::BYTEA),(&credential.key,Type::BYTEA),(&count,Type::INT4),(&Sha256::digest(session["challenge"].as_str().unwrap_or("").as_bytes()).to_vec(),Type::BYTEA)],|rows|Ok(rows[0].get::<_,String>(0))).await{
            setjoin_pg::CommandOutcome::Committed(status) if status=="accepted"=>Ok(LoginProof{user:user.id}),
            setjoin_pg::CommandOutcome::Committed(detail)=>Err(refuse(&detail)),
            setjoin_pg::CommandOutcome::Unknown{operation}=>Err(LoginFailure::Unknown(operation)),
            setjoin_pg::CommandOutcome::RolledBack(setjoin_pg::Rejection::Statement(failure))=>Err(refuse(&statement_error(&failure))),
            _=>Err(refuse("database error")),
        }
    }
    fn verify_client(
        &self,
        raw: &[u8],
        session: &serde_json::Value,
        kind: &str,
    ) -> Result<(), String> {
        use subtle::ConstantTimeEq;
        let client: serde_json::Value =
            serde_json::from_slice(raw).map_err(|_| "invalid client data")?;
        if client["type"] != kind {
            return Err("Error validating ceremony type".into());
        }
        let actual = client["challenge"].as_str().unwrap_or("");
        let expected = session["challenge"].as_str().unwrap_or("");
        if !bool::from(actual.as_bytes().ct_eq(expected.as_bytes())) {
            return Err("Error validating challenge".into());
        }
        let origin = client["origin"].as_str().unwrap_or("");
        let canonical = |s: &str| -> Option<String> {
            if s.starts_with("android:apk-key-hash:") {
                return Some(s.into());
            }
            let mut u = url::Url::parse(s).ok()?;
            u.set_path("");
            u.set_query(None);
            u.set_fragment(None);
            let _ = u.set_username("");
            let _ = u.set_password(None);
            Some(u.as_str().trim_end_matches('/').to_owned())
        };
        if canonical(origin).is_none() || canonical(origin) != canonical(&self.origin) {
            return Err("Error validating origin".into());
        }
        if client["crossOrigin"] == true {
            return Err("Error validating cross origin flag".into());
        }
        if client
            .get("topOrigin")
            .and_then(serde_json::Value::as_str)
            .is_some_and(|s| !s.is_empty())
        {
            return Err("Error validating topOrigin".into());
        }
        Ok(())
    }
    fn verify_auth_data(
        &self,
        auth: &[u8],
        session: &serde_json::Value,
        presence: bool,
    ) -> Result<(), String> {
        use sha2::{Digest, Sha256};
        if auth.len() < 37 {
            return Err("Error unmarshalling auth data".into());
        }
        if auth[..32] != Sha256::digest(self.rp_id.as_bytes())[..]
            || presence && auth[32] & 1 == 0
            || session["userVerification"] == "required" && auth[32] & 4 == 0
        {
            return Err("Error validating the authenticator response".into());
        }
        Ok(())
    }
}
struct Assertion {
    id: Vec<u8>,
    handle: Vec<u8>,
    auth: Vec<u8>,
    client: Vec<u8>,
    signature: Vec<u8>,
}
fn parse_assertion(request: &serde_json::Value) -> Result<Assertion, String> {
    let id = request["id"].as_str().unwrap_or("");
    if id.is_empty() {
        return Err("CredentialAssertionResponse with ID missing".into());
    }
    if decode_url(id).is_none() {
        return Err("CredentialAssertionResponse with ID not base64url encoded".into());
    }
    if request["type"] != "public-key" {
        return Err("CredentialAssertionResponse with bad type".into());
    }
    let decode = |value: &serde_json::Value| {
        decode_url(value.as_str().unwrap_or(""))
            .ok_or_else(|| "Parse error for Assertion".to_owned())
    };
    let response = &request["response"];
    let client = decode(&response["clientDataJSON"])?;
    let auth = decode(&response["authenticatorData"])?;
    // Delegate authenticator framing/extensions to the unmodified low-level parser.
    webauthn_rs_core::internals::AuthenticatorData::<webauthn_rs_core::proto::Authentication>::try_from(auth.as_slice()).map_err(|_|"Error unmarshalling auth data")?;
    Ok(Assertion {
        id: decode(&request["rawId"])?,
        handle: decode(&response["userHandle"])?,
        client,
        auth,
        signature: decode(&response["signature"])?,
    })
}
pub fn decode_url(text: &str) -> Option<Vec<u8>> {
    let text = text.replace(['\r', '\n'], "");
    let config = base64::engine::general_purpose::GeneralPurposeConfig::new()
        .with_decode_padding_mode(base64::engine::DecodePaddingMode::Indifferent)
        .with_decode_allow_trailing_bits(true);
    base64::engine::GeneralPurpose::new(&base64::alphabet::URL_SAFE, config)
        .decode(text)
        .ok()
}
fn decode_standard(text: &str) -> Option<Vec<u8>> {
    base64::engine::general_purpose::STANDARD
        .decode(text.replace(['\r', '\n'], ""))
        .ok()
}
fn session_expired(session: &serde_json::Value) -> bool {
    let text = session["expires"]
        .as_str()
        .unwrap_or("0001-01-01T00:00:00Z");
    if text == "0001-01-01T00:00:00Z" {
        return false;
    }
    chrono::DateTime::parse_from_rfc3339(text).is_ok_and(|t| {
        t.timestamp()
            < std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs() as i64
    })
}
fn signature_error(key: &[u8]) -> String {
    let algorithm = serde_cbor_2::from_slice::<serde_cbor_2::Value>(key)
        .ok()
        .and_then(|v| {
            if let serde_cbor_2::Value::Map(m) = v {
                m.get(&serde_cbor_2::Value::Integer(3)).cloned()
            } else {
                None
            }
        });
    let detail = if matches!(
        algorithm,
        Some(serde_cbor_2::Value::Integer(
            -257 | -258 | -259 | -37 | -38 | -39
        ))
    ) {
        "crypto/rsa: verification error"
    } else {
        "<nil>"
    };
    format!("Error validating the assertion signature: {detail}")
}
impl LoginProof {
    /// Frozen Go passes an empty session binding for the passkey first factor.
    /// Only this sealed, successfully claimed assertion can invoke this seam.
    pub async fn push_challenge(&self, exec:&ScopedExecutor)->setjoin_pg::CommandOutcome<crate::push::Generated,StatementFailure>{
        crate::push::generate_for(exec,self.user,"").await
    }

    pub async fn completion(
        &self,
        exec: &ScopedExecutor,
    ) -> Result<Option<crate::totp::CompletionUser>, StatementFailure> {
        let rows=exec.read("SELECT email,EXISTS(SELECT 1 FROM admin_role_assignments ara WHERE ara.user_id=u.id AND (ara.expires_at IS NULL OR ara.expires_at>now())) FROM users u WHERE u.id=$1 AND u.enabled",&[(&self.user,Type::INT8)]).await?;
        Ok(rows.first().map(|r| crate::totp::CompletionUser {
            user: self.user,
            email: r.get(0),
            admin: r.get(1),
        }))
    }
    pub async fn factors(&self, exec: &ScopedExecutor) -> (bool, bool) {
        exec.read("SELECT COALESCE(totp_enabled,FALSE),COALESCE(push_mfa_enabled,FALSE) FROM users WHERE id=$1 AND enabled",&[(&self.user,Type::INT8)]).await.ok().and_then(|r|r.first().map(|r|(r.get(0),r.get(1)))).unwrap_or((false,false))
    }
    pub async fn mint(
        &self,
        exec: &ScopedExecutor,
        refresh: &str,
        expiry: i64,
        family: &str,
    ) -> setjoin_pg::CommandOutcome<serde_json::Value, StatementFailure> {
        use sha2::{Digest, Sha256};
        let actor =
            setjoin_contracts::ids::ActorId::new(self.user).expect("verified passkey owner");
        let op = setjoin_contracts::ids::OperationId(
            *uuid::Uuid::parse_str(family)
                .expect("server family")
                .as_bytes(),
        );
        exec.clone()
            .with_user_receipt(setjoin_pg::ReceiptCommand {
                family: "F21",
                command: "webauthn-mint",
            })
            .run_user_command(
                actor,
                op,
                "SELECT rust_identity_mfa_mint($1,'{}'::jsonb,$2,$3,$4::text::uuid)::text",
                &[
                    (&self.user, Type::INT8),
                    (&Sha256::digest(refresh.as_bytes()).to_vec(), Type::BYTEA),
                    (&expiry, Type::INT8),
                    (&family, Type::TEXT),
                ],
                |rows| {
                    serde_json::from_str(&rows[0].get::<_, String>(0)).map_err(|_| {
                        StatementFailure {
                            sqlstate: None,
                            hint: None,
                            message: "invalid mint result".into(),
                        }
                    })
                },
            )
            .await
    }
}

pub struct RegistrationBegin {
    pub outcome: serde_json::Value,
    pub options: Option<String>,
    pub session: Option<Vec<u8>>,
}
impl RelyingParty {
    pub async fn begin_registration(
        &self,
        exec: &ScopedExecutor,
        session: &Session,
        token: &str,
    ) -> setjoin_pg::CommandOutcome<RegistrationBegin, StatementFailure> {
        use ring::rand::{SecureRandom, SystemRandom};
        use sha2::{Digest, Sha256};
        let mut candidate = [0; 32];
        if SystemRandom::new().fill(&mut candidate).is_err() {
            return setjoin_pg::CommandOutcome::RolledBack(setjoin_pg::Rejection::Unavailable);
        }
        let challenge = match random_challenge() {
            Ok(c) => c,
            Err(_) => {
                return setjoin_pg::CommandOutcome::RolledBack(setjoin_pg::Rejection::Unavailable)
            }
        };
        let challenge_hash = format!("{:x}", Sha256::digest(challenge.as_bytes()));
        let token_hash = format!("{:x}", Sha256::digest(token.as_bytes()));
        let claims = serde_json::Value::Object(session.claims().clone()).to_string();
        let Ok(actor) = setjoin_contracts::ids::ActorId::new(session.user()) else {
            return setjoin_pg::CommandOutcome::RolledBack(setjoin_pg::Rejection::Unavailable);
        };
        exec.clone().with_user_receipt(setjoin_pg::ReceiptCommand{family:"F21",command:"webauthn-register-begin"}).run_user_command(actor,setjoin_contracts::ids::OperationId(*uuid::Uuid::new_v4().as_bytes()),"SELECT rust_identity_webauthn_begin($1,$2::text::jsonb,$3,$4,$5)::text",&[(&session.user(),Type::INT8),(&claims,Type::TEXT),(&token_hash,Type::TEXT),(&challenge_hash,Type::TEXT),(&candidate.as_slice(),Type::BYTEA)],|rows|{
            let outcome:serde_json::Value=serde_json::from_str(&rows[0].get::<_,String>(0)).map_err(|_|bad_result())?;
            if outcome["status"]!="created"{return Ok(RegistrationBegin{outcome,options:None,session:None});}
            let handle=hex_bytes(outcome["handle"].as_str().unwrap_or("")).ok_or_else(bad_result)?;
            let params=credential_parameters();
            let options=format!("{{\"publicKey\":{{\"rp\":{{\"name\":{},\"id\":{}}},\"user\":{{\"name\":{},\"displayName\":{},\"id\":{}}},\"challenge\":{},\"pubKeyCredParams\":{params},\"timeout\":300000,\"authenticatorSelection\":{{}}}}}}",serde_json::json!(self.rp_name),serde_json::json!(self.rp_id),outcome["email"],outcome["display"],serde_json::json!(URL_SAFE_NO_PAD.encode(&handle)),serde_json::json!(challenge));
            let session=serde_json::json!({"challenge":challenge,"rpId":self.rp_id,"user_id":base64::engine::general_purpose::STANDARD.encode(handle),"expires":"0001-01-01T00:00:00Z","credParams":serde_json::from_str::<serde_json::Value>(&params).unwrap()}).to_string().into_bytes();
            Ok(RegistrationBegin{outcome,options:Some(options),session:Some(session)})
        }).await
    }
}
fn bad_result() -> StatementFailure {
    StatementFailure {
        sqlstate: None,
        hint: None,
        message: "invalid WebAuthn reducer result".into(),
    }
}
fn credential_parameters() -> String {
    format!(
        "[{}]",
        [-7, -35, -36, -257, -258, -259, -37, -38, -39, -8]
            .iter()
            .map(|a| format!("{{\"type\":\"public-key\",\"alg\":{a}}}"))
            .collect::<Vec<_>>()
            .join(",")
    )
}
fn hex_bytes(raw: &str) -> Option<Vec<u8>> {
    if raw.len() % 2 != 0 {
        return None;
    }
    (0..raw.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(raw.get(i..i + 2)?, 16).ok())
        .collect()
}

struct Registration {
    id: Vec<u8>,
    key: Vec<u8>,
    attestation: String,
    count: i32,
    uv: bool,
}
impl RelyingParty {
    fn verify_registration(
        &self,
        handle: &[u8],
        session: &serde_json::Value,
        raw: &[u8],
    ) -> Result<Registration, String> {
        use serde_cbor_2::Value as C;
        let request: serde_json::Value =
            serde_json::from_slice(raw).map_err(|_| "Parse error for Registration")?;
        if request["id"]
            .as_str()
            .filter(|s| !s.is_empty())
            .and_then(decode_url)
            .is_none()
            || request["type"] != "public-key"
        {
            return Err("Parse error for Registration".into());
        }
        let response = &request["response"];
        let client = decode_url(response["clientDataJSON"].as_str().unwrap_or(""))
            .ok_or("Parse error for Registration")?;
        let encoded = decode_url(response["attestationObject"].as_str().unwrap_or(""))
            .ok_or("Parse error for Registration")?;
        let (object, _) = go_cbor_first(&encoded).ok_or("Error parsing attestation response")?;
        let C::Map(object) = object else {
            return Err("Error parsing attestation response".into());
        };
        let fmt = match object.get(&C::Text("fmt".into())) {
            Some(C::Text(s)) => s.as_str(),
            _ => "",
        };
        let auth = match object.get(&C::Text("authData".into())) {
            Some(C::Bytes(b)) => b.as_slice(),
            _ => return Err("Error parsing attestation response".into()),
        };
        if auth.len() <= 55 || auth[32] & 0x40 == 0 {
            return Err("Error parsing attestation response".into());
        }
        let length = u16::from_be_bytes(auth[53..55].try_into().unwrap()) as usize;
        if length > 1023 || auth.len() < 55 + length {
            return Err("Error parsing attestation response".into());
        }
        let id = auth[55..55 + length].to_vec();
        let (value, used) =
            go_cbor_first(&auth[55 + length..]).ok_or("Error parsing attestation response")?;
        let key = serde_cbor_2::to_vec(&value).map_err(|_| "Error parsing attestation response")?;
        let remaining = auth.len().saturating_sub(55 + length + used);
        if auth[32] & 0x80 == 0 && remaining != 0 || auth[32] & 0x80 != 0 && remaining == 0 {
            return Err("Error parsing attestation response".into());
        }
        let cookie_handle = decode_standard(session["user_id"].as_str().unwrap_or(""))
            .ok_or("invalid session data")?;
        if cookie_handle != handle {
            return Err("ID mismatch for User and Session".into());
        }
        if session_expired(session) {
            return Err("Session has Expired".into());
        }
        self.verify_client(&client, session, "webauthn.create")?;
        self.verify_auth_data(auth, session, session["mediation"] != "conditional")?;
        let algorithm = if let C::Map(m) = &value {
            match m.get(&C::Integer(3)) {
                Some(C::Integer(a)) => *a,
                _ => return Err("Invalid attestation format".into()),
            }
        } else {
            return Err("Invalid attestation format".into());
        };
        if !session["credParams"].as_array().is_some_and(|p| {
            p.iter()
                .any(|p| p["alg"].as_i64().map(i128::from) == Some(algorithm))
        }) {
            return Err("Invalid attestation format".into());
        }
        let statement = object.get(&C::Text("attStmt".into()));
        if fmt == "none" {
            if statement
                .is_some_and(|s| !matches!(s,C::Map(m) if m.is_empty()) && !matches!(s, C::Null))
            {
                return Err("Invalid attestation format".into());
            }
            // Go's none verifier checks the advertised algorithm, not key shape.
            // Core cannot import EdDSA/PSS (facts#330); preserve the exact COSE
            // bytes even for a Go-accepted, unusable key. Login verifies it fully.
            if let Ok(cose) = webauthn_rs_core::proto::COSEKey::try_from(&value) {
                let _ = self.core_registration(&request, session, &cose);
            }
        } else if fmt == "packed"
            && matches!(statement,Some(C::Map(m)) if !m.contains_key(&C::Text("x5c".into())))
        {
            let Some(C::Map(m)) = statement else {
                return Err("Invalid attestation format".into());
            };
            if m.contains_key(&C::Text("ecdaaKeyId".into())) {
                return Err("Invalid attestation format".into());
            }
            let Some(C::Integer(att_alg)) = m.get(&C::Text("alg".into())) else {
                return Err("Invalid attestation format".into());
            };
            let Some(C::Bytes(signature)) = m.get(&C::Text("sig".into())) else {
                return Err("Invalid attestation format".into());
            };
            if *att_alg != algorithm {
                return Err("Invalid attestation data".into());
            }
            use sha2::{Digest, Sha256};
            let mut message = auth.to_vec();
            message.extend_from_slice(&Sha256::digest(&client));
            if !verify_stored_signature(&key, &message, signature) {
                return Err("Invalid attestation data".into());
            }
        } else if fmt == "android-safetynet" {
            safetynet_policy(statement, auth, &client)?;
        } else {
            let cose = webauthn_rs_core::proto::COSEKey::try_from(&value)
                .map_err(|_| "Invalid attestation format")?;
            if !matches!(fmt, "packed" | "tpm" | "android-key" | "fido-u2f" | "apple") {
                return Err("Invalid attestation format".into());
            }
            self.core_registration(&request, session, &cose)?;
        }
        let attestation = match fmt {
            "none" => "none",
            "packed" if !matches!(statement,Some(C::Map(m)) if m.contains_key(&C::Text("x5c".into()))) => {
                "basic_surrogate"
            }
            "tpm" => "attca",
            "apple" => "anonca",
            _ => "basic_full",
        };
        Ok(Registration {
            id,
            key,
            attestation: attestation.into(),
            count: i32::try_from(u32::from_be_bytes(auth[33..37].try_into().unwrap()))
                .map_err(|_| "invalid credential counter")?,
            uv: auth[32] & 4 != 0,
        })
    }
    fn core_registration(
        &self,
        request: &serde_json::Value,
        session: &serde_json::Value,
        key: &webauthn_rs_core::proto::COSEKey,
    ) -> Result<(), String> {
        let registration: webauthn_rs_core::proto::RegisterPublicKeyCredential =
            serde_json::from_value(request.clone())
                .map_err(|_| "Error parsing attestation response")?;
        let state:webauthn_rs_core::proto::RegistrationState=serde_json::from_value(serde_json::json!({"policy":if session["userVerification"]=="required"{"required"}else{"preferred"},"exclude_credentials":[],"challenge":session["challenge"],"credential_algorithms":[key.type_],"require_resident_key":false,"authenticator_attachment":null,"extensions":{},"allow_synchronised_authenticators":true})).map_err(|_|"invalid session data")?;
        self.core
            .register_credential(&registration, &state, None)
            .map(|_| ())
            .map_err(|_| "Error validating the attestation data provided".into())
    }
    pub async fn finish_registration(
        &self,
        exec: &ScopedExecutor,
        session: &Session,
        cookie: &str,
        raw: &[u8],
        token: &str,
        ip: &str,
    ) -> setjoin_pg::CommandOutcome<serde_json::Value, StatementFailure> {
        use setjoin_pg::ProvenStatement;
        use sha2::{Digest, Sha256};
        let transport = self
            .cookies
            .open(cookie)
            .and_then(|b| serde_json::from_slice::<serde_json::Value>(&b).ok());
        let Some(transport) = transport else {
            return setjoin_pg::CommandOutcome::Committed(
                serde_json::json!({"status":"invalid_cookie"}),
            );
        };
        let challenge_hash = format!(
            "{:x}",
            Sha256::digest(transport["challenge"].as_str().unwrap_or("").as_bytes())
        );
        let token_hash = format!("{:x}", Sha256::digest(token.as_bytes()));
        let claims = serde_json::Value::Object(session.claims().clone()).to_string();
        let Ok(actor) = setjoin_contracts::ids::ActorId::new(session.user()) else {
            return setjoin_pg::CommandOutcome::RolledBack(setjoin_pg::Rejection::Unavailable);
        };
        exec.clone().with_user_receipt(setjoin_pg::ReceiptCommand{family:"F21",command:"webauthn-register-finish"}).run_user_proof_command(actor,setjoin_contracts::ids::OperationId(*uuid::Uuid::new_v4().as_bytes()),"SELECT rust_identity_webauthn_registration_read($1,$2::text::jsonb)::text",&[(&session.user(),Type::INT8),(&claims,Type::TEXT)],|rows|{
            let result:serde_json::Value=serde_json::from_str(&rows[0].get::<_,String>(0)).map_err(|_|bad_result())?;
            if result["status"]!="ready"{return Ok(ProvenStatement::new("SELECT $1::text").bind(result.to_string(),Type::TEXT));}
            let handle=hex_bytes(result["handle"].as_str().unwrap_or("")).ok_or_else(bad_result)?;
            let credential=self.verify_registration(&handle,&transport,raw).map_err(|detail|StatementFailure{sqlstate:None,hint:Some("webauthn-verification".into()),message:detail})?;
            Ok(ProvenStatement::new("SELECT rust_identity_webauthn_finish($1,$2::text::jsonb,$3,$4,$5,$6,$7,$8,$9,$10)::text")
                .bind(session.user(),Type::INT8).bind(claims.clone(),Type::TEXT).bind(token_hash,Type::TEXT).bind(challenge_hash,Type::TEXT)
                .bind(credential.id,Type::BYTEA).bind(credential.key,Type::BYTEA).bind(credential.attestation,Type::TEXT).bind(credential.count,Type::INT4).bind(credential.uv,Type::BOOL).bind(ip.to_owned(),Type::TEXT))
        },|rows|serde_json::from_str(&rows[0].get::<_,String>(0)).map_err(|_|bad_result())).await
    }
}

pub async fn revoke(
    exec: &ScopedExecutor,
    session: &Session,
    id: &[u8],
    token: &str,
    ip: &str,
) -> setjoin_pg::CommandOutcome<serde_json::Value, StatementFailure> {
    use sha2::{Digest, Sha256};
    let Ok(actor) = setjoin_contracts::ids::ActorId::new(session.user()) else {
        return setjoin_pg::CommandOutcome::RolledBack(setjoin_pg::Rejection::Unavailable);
    };
    let claims = serde_json::Value::Object(session.claims().clone()).to_string();
    let token_hash = format!("{:x}", Sha256::digest(token.as_bytes()));
    let target = URL_SAFE_NO_PAD.encode(id);
    exec.clone()
        .with_user_receipt(setjoin_pg::ReceiptCommand {
            family: "F21",
            command: "webauthn-revoke",
        })
        .run_user_command(
            actor,
            setjoin_contracts::ids::OperationId(*uuid::Uuid::new_v4().as_bytes()),
            "SELECT rust_identity_webauthn_revoke($1,$2::text::jsonb,$3,$4,$5,$6)::text",
            &[
                (&session.user(), Type::INT8),
                (&claims, Type::TEXT),
                (&token_hash, Type::TEXT),
                (&target, Type::TEXT),
                (&id, Type::BYTEA),
                (&ip, Type::TEXT),
            ],
            |rows| serde_json::from_str(&rows[0].get::<_, String>(0)).map_err(|_| bad_result()),
        )
        .await
}

/// Code-owned receipt categories; caller input never chooses a SQL command name.
#[derive(Clone, Copy)]
pub enum Operation {
    Name,
    Counter,
    Mint,
    RegisterBegin,
    RegisterFinish,
    Revoke,
}
impl Operation {
    fn command(self) -> &'static str {
        match self {
            Self::Name => "webauthn-name",
            Self::Counter => "webauthn-counter",
            Self::Mint => "webauthn-mint",
            Self::RegisterBegin => "webauthn-register-begin",
            Self::RegisterFinish => "webauthn-register-finish",
            Self::Revoke => "webauthn-revoke",
        }
    }
}
/// Receipt recovery revalidates a fresh authenticated user and durable revocation.
pub async fn lookup_operation(
    exec: &ScopedExecutor,
    session: &Session,
    operation: OperationId,
    kind: Operation,
) -> Result<bool, StatementFailure> {
    let invalid = || StatementFailure {
        sqlstate: None,
        hint: None,
        message: "WebAuthn lookup authority unavailable".into(),
    };
    if !matches!(session.text("typ"), "access" | "mfa_pending") || session.bound() {
        return Err(invalid());
    }
    let actor = ActorId::new(session.user()).map_err(|_| invalid())?;
    let op = setjoin_pg::operation_hex(operation);
    let claims = serde_json::Value::Object(session.claims().clone()).to_string();
    let result=exec.run_user_command(actor,operation,
        "SELECT EXISTS(SELECT 1 FROM rust_operation_receipts WHERE operation_id=substr(encode(digest($2::text || ':' || $1::text,'sha256'),'hex'),1,32)::uuid AND family='F21' AND command=$3) WHERE EXISTS(SELECT 1 FROM users u WHERE u.id=$1 AND u.enabled AND identity_transition_admission_allowed(u.id) AND (COALESCE($4::text::jsonb->>'credential_fence','')='' OR rtrim(translate(encode(digest(u.password_hash,'sha256'),'base64'),'+/','-_'),'=')=$4::text::jsonb->>'credential_fence')) AND NOT EXISTS(SELECT 1 FROM session_revocations WHERE user_id=$1 AND (expires_at IS NULL OR expires_at>now()) AND ((scope='jti' AND jti=COALESCE($4::text::jsonb->>'jti','')) OR (scope='family' AND family_id=COALESCE($4::text::jsonb->>'fam','')) OR (scope='all' AND to_timestamp(COALESCE(($4::text::jsonb->>'iat')::double precision,0))<=not_before)))",
        &[(&session.user(),Type::INT8),(&op,Type::TEXT),(&kind.command(),Type::TEXT),(&claims,Type::TEXT)],
        |rows|rows.first().and_then(|r|r.try_get(0).ok()).ok_or_else(invalid)).await;
    match result {
        CommandOutcome::Committed(found) => Ok(found),
        _ => Err(invalid()),
    }
}

/// The Go CTAP decoder reads one value and limits nested maps/arrays to four.
/// Extension bytes stay opaque, as in Go's AuthenticatorData.Unmarshal.
fn go_cbor_first(bytes: &[u8]) -> Option<(serde_cbor_2::Value, usize)> {
    use serde::de::DeserializeSeed;
    let mut decoder = serde_cbor_2::Deserializer::from_slice(bytes);
    let value = GoCborSeed(0).deserialize(&mut decoder).ok()?;
    Some((value, decoder.byte_offset()))
}

// Serde owns all CBOR decoding. This schema visitor preserves Go's duplicate,
// definite-length, untagged and four-container rules before values lose their
// wire distinctions. With from_slice, definite strings/bytes are borrowed;
// indefinite concatenations use the non-borrowed visitor methods and are refused.
struct GoCborSeed(u8);
struct GoCborVisitor(u8);
impl<'de> serde::de::DeserializeSeed<'de> for GoCborSeed {
    type Value = serde_cbor_2::Value;
    fn deserialize<D: serde::Deserializer<'de>>(self, decoder: D) -> Result<Self::Value, D::Error> {
        decoder.deserialize_any(GoCborVisitor(self.0))
    }
}
impl<'de> serde::de::Visitor<'de> for GoCborVisitor {
    type Value = serde_cbor_2::Value;
    fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Go CTAP2 CBOR")
    }
    fn visit_borrowed_str<E: serde::de::Error>(self, v: &'de str) -> Result<Self::Value, E> {
        Ok(serde_cbor_2::Value::Text(v.into()))
    }
    fn visit_borrowed_bytes<E: serde::de::Error>(self, v: &'de [u8]) -> Result<Self::Value, E> {
        Ok(serde_cbor_2::Value::Bytes(v.into()))
    }
    fn visit_u64<E: serde::de::Error>(self, v: u64) -> Result<Self::Value, E> {
        Ok(serde_cbor_2::Value::Integer(v.into()))
    }
    fn visit_i64<E: serde::de::Error>(self, v: i64) -> Result<Self::Value, E> {
        Ok(serde_cbor_2::Value::Integer(v.into()))
    }
    fn visit_i128<E: serde::de::Error>(self, v: i128) -> Result<Self::Value, E> {
        Ok(serde_cbor_2::Value::Integer(v))
    }
    fn visit_f64<E: serde::de::Error>(self, v: f64) -> Result<Self::Value, E> {
        Ok(serde_cbor_2::Value::Float(v))
    }
    fn visit_bool<E: serde::de::Error>(self, v: bool) -> Result<Self::Value, E> {
        Ok(serde_cbor_2::Value::Bool(v))
    }
    fn visit_unit<E: serde::de::Error>(self) -> Result<Self::Value, E> {
        Ok(serde_cbor_2::Value::Null)
    }
    fn visit_none<E: serde::de::Error>(self) -> Result<Self::Value, E> {
        self.visit_unit()
    }
    fn visit_seq<A: serde::de::SeqAccess<'de>>(self, mut a: A) -> Result<Self::Value, A::Error> {
        use serde::de::Error;
        if self.0 >= 4 || a.size_hint().is_none() {
            return Err(A::Error::custom("CTAP2 array profile"));
        }
        let mut values = Vec::new();
        while let Some(value) = a.next_element_seed(GoCborSeed(self.0 + 1))? {
            values.push(value);
        }
        Ok(serde_cbor_2::Value::Array(values))
    }
    fn visit_map<A: serde::de::MapAccess<'de>>(self, mut a: A) -> Result<Self::Value, A::Error> {
        use serde::de::Error;
        if self.0 >= 4 || a.size_hint().is_none() {
            return Err(A::Error::custom("CTAP2 map profile"));
        }
        let mut values = std::collections::BTreeMap::new();
        while let Some(key) = a.next_key_seed(GoCborSeed(self.0 + 1))? {
            if values.contains_key(&key) {
                return Err(A::Error::custom("duplicate CTAP2 map key"));
            }
            let value = a.next_value_seed(GoCborSeed(self.0 + 1))?;
            values.insert(key, value);
        }
        Ok(serde_cbor_2::Value::Map(values))
    }
}

/// Owner-approved security fix 2026-11-05 (#504): android-safetynet attestation is
/// refused outright. Frozen Go accepted any JWT whose x5c leaf was issued to
/// attest.android.com without anchoring it in a trusted chain (a self-signed leaf or a
/// made-up CA passed), and Google has shut the SafetyNet API down, so no real
/// authenticator can produce one.
fn safetynet_policy(
    statement: Option<&serde_cbor_2::Value>,
    auth: &[u8],
    client: &[u8],
) -> Result<(), String> {
    #[cfg(feature = "oracle-mutants")]
    if setjoin_contracts::mutants::on("safetynet-accepted") {
        return verify_safetynet(statement, auth, client);
    }
    let _ = (statement, auth, client);
    Err("Invalid attestation format".into())
}

/// Frozen Go's SafetyNet profile, kept only so the test-only mutant can restore it.
#[cfg(feature = "oracle-mutants")]
/// Leaf JWT signature, hostname, nonce, CTS and
/// timestamp; Go does not anchor the supplied leaf in a trusted certificate chain.
/// DER parsing, DNS validation and RSA verification remain library-owned.
fn verify_safetynet(
    statement: Option<&serde_cbor_2::Value>,
    auth: &[u8],
    client: &[u8],
) -> Result<(), String> {
    use rsa::pkcs8::DecodePublicKey;
    use rsa::traits::PublicKeyParts;
    use serde_cbor_2::Value as C;
    use sha2::{Digest, Sha256};
    use subtle::ConstantTimeEq;
    let invalid = || "Invalid attestation data".to_owned();
    let Some(C::Map(m)) = statement else {
        return Err("Invalid attestation format".into());
    };
    if !matches!(m.get(&C::Text("ver".into())),Some(C::Text(s)) if !s.is_empty()) {
        return Err("Invalid attestation format".into());
    }
    let Some(C::Bytes(raw)) = m.get(&C::Text("response".into())) else {
        return Err("Invalid attestation format".into());
    };
    let token = std::str::from_utf8(raw).map_err(|_| invalid())?;
    let parts: Vec<_> = token.split('.').collect();
    if parts.len() != 3 {
        return Err(invalid());
    }
    let header: serde_json::Value =
        serde_json::from_slice(&decode_url(parts[0]).ok_or_else(invalid)?)
            .map_err(|_| invalid())?;
    let claims: serde_json::Value =
        serde_json::from_slice(&decode_url(parts[1]).ok_or_else(invalid)?)
            .map_err(|_| invalid())?;
    if header["alg"] != "RS256" {
        return Err(invalid());
    }
    let cert =
        decode_standard(header["x5c"][0].as_str().ok_or_else(invalid)?).ok_or_else(invalid)?;
    let (_, parsed) = x509_parser::parse_x509_certificate(&cert).map_err(|_| invalid())?;
    // Owner-approved security fix 2026-11-05 (#504): a self-signed (self-issued)
    // leaf proves nothing about Google's attestation service, so it is refused.
    if parsed.issuer().as_raw() == parsed.subject().as_raw() {
        return Err(invalid());
    }
    let der = cert.as_slice().into();
    let leaf = webpki::EndEntityCert::try_from(&der).map_err(|_| invalid())?;
    leaf.verify_is_valid_for_subject_name(&"attest.android.com".try_into().map_err(|_| invalid())?)
        .map_err(|_| invalid())?;
    let key =
        rsa::RsaPublicKey::from_public_key_der(parsed.public_key().raw).map_err(|_| invalid())?;
    if key.n().bits() < 1024 {
        return Err(invalid());
    }
    key.verify(
        rsa::Pkcs1v15Sign::new::<rsa::sha2::Sha256>(),
        &Sha256::digest(format!("{}.{}", parts[0], parts[1]).as_bytes()),
        &decode_url(parts[2]).ok_or_else(invalid)?,
    )
    .map_err(|_| invalid())?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| invalid())?
        .as_secs_f64();
    for (name, before) in [("exp", false), ("nbf", true)] {
        if let Some(value) = claims.get(name) {
            let n = value.as_f64().ok_or_else(invalid)?;
            if if before { now < n } else { now >= n } {
                return Err(invalid());
            }
        }
    }
    let mut message = auth.to_vec();
    message.extend_from_slice(&Sha256::digest(client));
    let nonce =
        decode_standard(claims["nonce"].as_str().ok_or_else(invalid)?).ok_or_else(invalid)?;
    if !bool::from(Sha256::digest(&message)[..].ct_eq(&nonce)) || claims["ctsProfileMatch"] != true
    {
        return Err(invalid());
    }
    let timestamp = claims
        .get("timestampMs")
        .and_then(serde_json::Value::as_f64)
        .unwrap_or(0.0);
    if (timestamp / 1000.0).trunc() > now {
        return Err(invalid());
    }
    // The response must be fresh (one minute, as Go enforces only with metadata
    // enabled). Owner-approved security fix 2026-11-05 (#504): always enforced.
    if (timestamp / 1000.0).trunc() < now - 60.0 {
        return Err(invalid());
    }
    Ok(())
}

/// Match pgx's PostgreSQL error rendering at the frozen public error seam.
pub fn statement_error(failure: &StatementFailure) -> String {
    match &failure.sqlstate {
        Some(code) => format!("ERROR: {} (SQLSTATE {code})", failure.message),
        None => failure.message.clone(),
    }
}

/// Go RawURLEncoding accepts unused trailing bits and CR/LF, but no padding.
pub fn decode_credential_id(text: &str) -> Option<Vec<u8>> {
    use base64::{
        alphabet,
        engine::{DecodePaddingMode, GeneralPurpose, GeneralPurposeConfig},
    };
    let codec = GeneralPurpose::new(
        &alphabet::URL_SAFE,
        GeneralPurposeConfig::new()
            .with_decode_padding_mode(DecodePaddingMode::RequireNone)
            .with_decode_allow_trailing_bits(true),
    );
    codec
        .decode(text.replace(['\r', '\n'], ""))
        .ok()
        .filter(|id| !id.is_empty())
}

impl RelyingParty {
    pub(crate) fn management_challenge(&self)->Result<String,&'static str>{random_challenge()}
    pub(crate) fn management_options(&self,snapshot:&serde_json::Value,challenge:&str)->String{
        let ids=snapshot["keys"].as_array().expect("owned keys").iter().map(|key|{
            let raw=key["id"].as_str().expect("credential hex");
            let bytes=data_encoding::HEXLOWER.decode(raw.as_bytes()).expect("database hex");
            format!("{{\"type\":\"public-key\",\"id\":{}}}",serde_json::json!(URL_SAFE_NO_PAD.encode(bytes)))
        }).collect::<Vec<_>>().join(",");
        let allowed=if ids.is_empty(){String::new()}else{format!(",\"allowCredentials\":[{ids}]")};
        format!("{{\"publicKey\":{{\"challenge\":{},\"timeout\":300000,\"rpId\":{}{allowed},\"userVerification\":\"required\"}}}}",serde_json::json!(challenge),serde_json::json!(self.rp_id))
    }
}

pub(crate) enum ManagementResult { Malformed, Rejected, Accepted(Vec<u8>) }
impl RelyingParty {
    pub(crate) fn management_verify(&self,snapshot:&serde_json::Value,hash:&str,raw:&[u8])->ManagementResult{
        use sha2::{Digest,Sha256};use subtle::ConstantTimeEq;
        if snapshot["force_invalid"]==true{return ManagementResult::Rejected;}
        let Ok(request)=serde_json::from_slice::<serde_json::Value>(raw)else{return ManagementResult::Malformed;};
        let Ok(parsed)=parse_assertion(&request)else{return ManagementResult::Malformed;};
        let Ok(client)=serde_json::from_slice::<serde_json::Value>(&parsed.client)else{return ManagementResult::Malformed;};
        if ["type","challenge","origin"].iter().any(|key|client.get(*key).is_some_and(|v|!v.is_null()&&!v.is_string())){return ManagementResult::Malformed;}
        let challenge=client["challenge"].as_str().unwrap_or("");
        let presented=format!("{:x}",Sha256::digest(challenge.as_bytes()));
        if !bool::from(presented.as_bytes().ct_eq(hash.as_bytes())){return ManagementResult::Rejected;}
        let Some(keys)=snapshot["keys"].as_array()else{return ManagementResult::Rejected;};
        let decode=|text:&str|data_encoding::HEXLOWER.decode(text.as_bytes()).ok();
        let Some(handle)=snapshot["handle"].as_str().and_then(decode)else{return ManagementResult::Rejected;};
        if !parsed.handle.is_empty()&&parsed.handle!=handle{return ManagementResult::Rejected;}
        let Some(key)=keys.iter().find(|key|key["id"].as_str().and_then(decode).is_some_and(|id|id==parsed.id))else{return ManagementResult::Rejected;};
        let session=serde_json::json!({"challenge":challenge,"userVerification":"required"});
        if self.verify_client(&parsed.client,&session,"webauthn.get").is_err()||self.verify_auth_data(&parsed.auth,&session,true).is_err(){return ManagementResult::Rejected;}
        if parsed.auth[32]&(8|16)!=0{return ManagementResult::Rejected;}
        let Some(public)=key["key"].as_str().and_then(decode)else{return ManagementResult::Rejected;};
        let mut message=parsed.auth.clone();message.extend_from_slice(&Sha256::digest(&parsed.client));
        if !verify_stored_signature(&public,&message,&parsed.signature){return ManagementResult::Rejected;}
        ManagementResult::Accepted(parsed.id)
    }
}

#[cfg(test)]
mod secfix3_safetynet {
    //! Owner-approved security fix 2026-11-05 (#504): android-safetynet is refused outright,
    //! including a fresh response chained to a made-up CA. Fixtures are synthetic (see fixtures/safetynet).
    use super::safetynet_policy;
    use base64::{engine::general_purpose::STANDARD, Engine};
    use serde_cbor_2::Value as C;
    use sha2::{Digest, Sha256};

    const KEY: &[u8] = include_bytes!("../tests/fixtures/safetynet/leaf.p8");
    const SELF_SIGNED: &[u8] = include_bytes!("../tests/fixtures/safetynet/self-signed.der");
    const CHAINED: &[u8] = include_bytes!("../tests/fixtures/safetynet/chained.der");
    const CA: &[u8] = include_bytes!("../tests/fixtures/safetynet/ca.der");

    fn statement(chain: &[&[u8]], age_ms: i64, auth: &[u8], client: &[u8]) -> C {
        let now_ms = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis() as i64;
        let header = serde_json::json!({"alg":"RS256","x5c":chain.iter().map(|c| STANDARD.encode(c)).collect::<Vec<_>>()});
        let mut message = auth.to_vec();
        message.extend_from_slice(&Sha256::digest(client));
        let claims = serde_json::json!({"nonce":STANDARD.encode(Sha256::digest(&message)),"ctsProfileMatch":true,"timestampMs":now_ms-age_ms});
        let url = base64::engine::general_purpose::URL_SAFE_NO_PAD;
        let signed = format!("{}.{}", url.encode(header.to_string()), url.encode(claims.to_string()));
        let pair = ring::signature::RsaKeyPair::from_pkcs8(KEY).unwrap();
        let mut sig = vec![0; pair.public().modulus_len()];
        pair.sign(&ring::signature::RSA_PKCS1_SHA256, &ring::rand::SystemRandom::new(), signed.as_bytes(), &mut sig).unwrap();
        let token = format!("{signed}.{}", url.encode(sig));
        C::Map([(C::Text("ver".into()), C::Text("12".into())), (C::Text("response".into()), C::Bytes(token.into_bytes()))].into_iter().collect())
    }
    const AUTH: &[u8] = b"authenticator-data-fixture";
    const CLIENT: &[u8] = b"client-data-fixture";

    #[test]
    fn a_fresh_chained_response_is_refused() {
        assert!(safetynet_policy(Some(&statement(&[CHAINED, CA], 1000, AUTH, CLIENT)), AUTH, CLIENT).is_err());
    }
    #[test]
    fn a_self_signed_leaf_is_refused() {
        assert!(safetynet_policy(Some(&statement(&[SELF_SIGNED], 1000, AUTH, CLIENT)), AUTH, CLIENT).is_err());
    }
    #[test]
    fn a_stale_response_is_refused() {
        assert!(safetynet_policy(Some(&statement(&[CHAINED, CA], 120_000, AUTH, CLIENT)), AUTH, CLIENT).is_err());
    }
}
