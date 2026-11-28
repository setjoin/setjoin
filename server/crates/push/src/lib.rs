//! Shared push transports, ported on demand for the standalone operator CLI.
#![forbid(unsafe_code)]
mod apns;
mod webpush;
use base64::{
    alphabet::URL_SAFE,
    engine::{general_purpose::GeneralPurpose, GeneralPurposeConfig},
    Engine,
};

pub struct Status {
    pub provider: &'static str,
    pub state: &'static str,
    pub detail: String,
}
fn env(key: &str) -> String {
    std::env::var(key).unwrap_or_default()
}
fn status(provider: &'static str, state: &'static str, detail: String) -> Status {
    Status {
        provider,
        state,
        detail,
    }
}
fn io_error(e: &std::io::Error) -> String {
    match e.kind() {
        std::io::ErrorKind::NotFound => "no such file or directory".into(),
        std::io::ErrorKind::PermissionDenied => "permission denied".into(),
        _ => e.to_string(),
    }
}
pub fn raw_url_decode(value: &str) -> Result<Vec<u8>, String> {
    let clean = value.replace(['\r', '\n'], "");
    let config = GeneralPurposeConfig::new()
        .with_encode_padding(false)
        .with_decode_padding_mode(base64::engine::DecodePaddingMode::RequireNone)
        .with_decode_allow_trailing_bits(true);
    GeneralPurpose::new(&URL_SAFE, config)
        .decode(&clean)
        .map_err(|e| {
            let index = match e {
                base64::DecodeError::InvalidByte(i, _)
                | base64::DecodeError::InvalidLastSymbol(i, _) => i,
                base64::DecodeError::InvalidLength(n) => n.saturating_sub(1),
                _ => clean.find('=').unwrap_or(0),
            };
            format!("illegal base64 data at input byte {index}")
        })
}
enum Provider {
    Webpush {
        private: Vec<u8>,
        subject: String,
    },
    Apns {
        identity: Vec<u8>,
        client: Option<reqwest::Client>,
        bundle: String,
        production: bool,
    },
    Fcm {
        sa: serde_json::Value,
        token: Option<Token>,
    },
    Hms {
        app: String,
        secret: String,
    },
}
struct Token {
    value: String,
    expires: Option<u64>,
}
pub struct Set {
    providers: std::collections::BTreeMap<&'static str, Provider>,
}
impl Set {
    pub fn any(&self) -> bool {
        !self.providers.is_empty()
    }
    pub async fn send(
        &mut self,
        kind: &str,
        device: &str,
        payload: &[u8],
    ) -> Option<Result<(), String>> {
        let provider = self.providers.get_mut(kind)?;
        Some(match provider {
            Provider::Hms { app, secret } => hms_send(app, secret, device, payload).await,
            Provider::Fcm { sa, token } => fcm_send(sa, token, device, payload).await,
            Provider::Apns {
                identity,
                client,
                bundle,
                production,
            } => apns::send(identity, client, bundle, *production, device, payload).await,
            Provider::Webpush { private, subject } => {
                webpush::send(private, subject, device, payload).await
            }
        })
    }
}
pub fn build() -> (Set, Vec<Status>) {
    let mut set = Set {
        providers: std::collections::BTreeMap::new(),
    };
    let mut statuses = ["webpush", "apns", "fcm", "hms"]
        .into_iter()
        .map(|kind| status(kind, "absent", String::new()))
        .collect::<Vec<_>>();
    let vapid = env("VAPID_PRIVATE_KEY");
    if !vapid.is_empty() {
        statuses[0]=match raw_url_decode(&vapid) {
            Err(e)=>status("webpush","invalid",format!("VAPID_PRIVATE_KEY is not valid base64url: {e}")),
            Ok(raw) if raw.len()!=32=>status("webpush","invalid",format!("VAPID_PRIVATE_KEY must decode to the 32-byte P-256 private scalar; got {} bytes",raw.len())),
            Ok(private)=> {let subject=env("VAPID_SUBJECT");let subject=if subject.is_empty() {"mailto:admin@localhost".into()} else {subject};statuses[0].detail=format!("VAPID subject {subject}");set.providers.insert("webpush",Provider::Webpush{private,subject});status("webpush","configured",statuses[0].detail.clone())},
        };
    }
    let production = production();
    let path = env("APNS_CERT_PATH");
    if !path.is_empty() {
        statuses[1] = match apns::identity(&path, &env("APNS_CERT_PASSWORD")) {
            Err(e) => status("apns", "invalid", e),
            Ok(identity) => {
                let bundle = env("APNS_BUNDLE_ID");
                let detail = format!("bundle {bundle}");
                set.providers.insert(
                    "apns",
                    Provider::Apns {
                        identity,
                        client: None,
                        bundle,
                        production,
                    },
                );
                status("apns", "configured", detail)
            }
        };
    }
    let path = env("FCM_SERVICE_ACCOUNT_FILE");
    if !path.is_empty() {
        statuses[2] = match fcm_config(&path) {
            Err(e) => status("fcm", "invalid", e),
            Ok(sa) => {
                let detail = format!("project {}", sa["project_id"].as_str().unwrap_or_default());
                set.providers
                    .insert("fcm", Provider::Fcm { sa, token: None });
                status("fcm", "configured", detail)
            }
        };
    }
    let app = env("HMS_APP_ID");
    if !app.is_empty() {
        let detail = format!("app {app}");
        set.providers.insert(
            "hms",
            Provider::Hms {
                app,
                secret: env("HMS_APP_SECRET"),
            },
        );
        statuses[3] = status("hms", "configured", detail);
    }
    (set, statuses)
}
fn production() -> bool {
    let raw = env("APNS_PRODUCTION");
    match raw.as_str() {
        "1" | "t" | "T" | "TRUE" | "true" | "True" => true,
        "" | "0" | "f" | "F" | "FALSE" | "false" | "False" => false,
        _ => {
            let displayed = if raw
                .chars()
                .any(|c| c.is_whitespace() || c.is_control() || matches!(c, '=' | '"'))
            {
                format!("{raw:?}")
            } else {
                raw
            };
            eprintln!(
                "{} WARN envutil: invalid boolean value; substituting false raw={displayed}",
                chrono::Local::now().format("%Y/%m/%d %H:%M:%S")
            );
            false
        }
    }
}
fn fcm_config(path: &str) -> Result<serde_json::Value, String> {
    let bytes =
        std::fs::read(path).map_err(|e| format!("read SA file: open {path}: {}", io_error(&e)))?;
    let sa: serde_json::Value = serde_json::from_slice(&bytes).map_err(|e| {
        format!(
            "fcm service account: {}",
            if e.is_eof() {
                "unexpected end of JSON input".to_owned()
            } else {
                e.to_string()
            }
        )
    })?;
    let kind = sa["type"].as_str().unwrap_or_default();
    if kind != "service_account" {
        return Err(format!("fcm service account: google: read JWT from JSON credentials: 'type' field is {kind:?} (expected \"service_account\")"));
    }
    if sa["project_id"].as_str().unwrap_or_default().is_empty() {
        return Err("fcm service account: missing project_id".into());
    }
    Ok(sa)
}
pub async fn doctor() -> Vec<Status> {
    let (mut set, mut statuses) = build();
    for status in &mut statuses {
        let outcome = match set.providers.get_mut(status.provider) {
            Some(Provider::Fcm { sa, .. }) => Some(fcm_oauth(sa).await.map(|_| ())),
            Some(Provider::Hms { app, secret }) => Some(hms_oauth(app, secret).await.map(|_| ())),
            _ => None,
        };
        if let Some(Err(e)) = outcome {
            status.state = "invalid";
            status.detail = format!("OAuth failed: {e}");
        }
    }
    statuses
}
fn hex(payload: &[u8]) -> String {
    payload.iter().map(|b| format!("{b:02x}")).collect()
}
fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
async fn hms_send(app: &str, secret: &str, device: &str, payload: &[u8]) -> Result<(), String> {
    let token = hms_oauth(app, secret).await.map_err(|e| scrub(&e))?;
    let body = serde_json::json!({"message":{"token":[device],"data":hex(payload),"android":{"urgency":"HIGH"}}});
    let endpoint = format!("https://push-api.cloud.huawei.com/v3/{app}/messages:send");
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .map_err(|e| format!("hms send: {}", scrub(&e.to_string())))?;
    let response = client
        .post(&endpoint)
        .bearer_auth(token)
        .header("Content-Type", "application/json")
        .body(body.to_string())
        .send()
        .await
        .map_err(|e| format!("hms send: {}", scrub(&e.to_string())))?;
    let status = response.status();
    let bytes = response.bytes().await.unwrap_or_default();
    if status.as_u16() != 200 {
        return Err(format!(
            "hms: HTTP {}: {}",
            status.as_u16(),
            String::from_utf8_lossy(&bytes)
        ));
    }
    let result: serde_json::Value = serde_json::from_slice(&bytes).unwrap_or_default();
    let code = result["code"].as_str().unwrap_or_default();
    if matches!(code, "80300007" | "80100000") {
        return Err(format!(
            "hms rejected {code}: push: device token no longer registered"
        ));
    }
    if !code.is_empty() && code != "80000000" {
        return Err(format!("hms rejected: {code}"));
    }
    Ok(())
}
async fn fcm_send(
    sa: &serde_json::Value,
    token: &mut Option<Token>,
    device: &str,
    payload: &[u8],
) -> Result<(), String> {
    if token
        .as_ref()
        .is_none_or(|t| t.expires.is_some_and(|expiry| expiry <= now() + 10))
    {
        *token = Some(
            fcm_oauth(sa)
                .await
                .map_err(|e| format!("fcm token: {}", scrub(&e)))?,
        );
    }
    let body = serde_json::json!({"message":{"token":device,"data":{"data":hex(payload)},"android":{"priority":"high"}}});
    let endpoint = format!(
        "https://fcm.googleapis.com/v1/projects/{}/messages:send",
        sa["project_id"].as_str().unwrap_or_default()
    );
    let response = reqwest::Client::new()
        .post(endpoint)
        .bearer_auth(&token.as_ref().unwrap().value)
        .header("Content-Type", "application/json")
        .body(body.to_string())
        .send()
        .await
        .map_err(|e| format!("fcm send: {}", scrub(&e.to_string())))?;
    let status = response.status().as_u16();
    if status == 404 {
        return Err("fcm: HTTP 404: push: device token no longer registered".into());
    }
    if status != 200 {
        return Err(format!("fcm: HTTP {status}"));
    }
    Ok(())
}
// Every provider transport error removes URL capabilities before reaching CLI,
// workers or database error sinks. Provider response bodies retain Go's format.
fn scrub(input: &str) -> String {
    let mut result = input.to_owned();
    let mut start = 0;
    loop {
        let tail = &result[start..];
        let lower = tail.to_ascii_lowercase();
        let next = [lower.find("https://"), lower.find("http://")]
            .into_iter()
            .flatten()
            .min();
        let Some(offset) = next else {
            break;
        };
        let offset = start + offset;
        let end = result[offset..]
            .find(|c: char| c.is_whitespace() || matches!(c, '\"' | '\'' | '<' | '>'))
            .map(|n| offset + n)
            .unwrap_or(result.len());
        let raw =
            result[offset..end].trim_end_matches(['.', ',', ';', ':', '!', '?', ')', ']', '}']);
        let replacement = url::Url::parse(raw)
            .ok()
            .filter(|u| u.host_str().is_some())
            .map(|u| {
                format!(
                    "{}://{}/[redacted]",
                    u.scheme(),
                    u[url::Position::BeforeHost..url::Position::AfterPort].to_owned()
                )
            })
            .unwrap_or_else(|| "[redacted]".into());
        let raw_end = offset + raw.len();
        result.replace_range(offset..raw_end, &replacement);
        start = offset + replacement.len();
    }
    result
}

async fn hms_oauth(app: &str, secret: &str) -> Result<String, String> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .map_err(|e| format!("hms oauth: {e}"))?;
    let response = client
        .post("https://oauth-login.cloud.huawei.com/oauth2/v3/token")
        .form(&[
            ("client_id", app),
            ("client_secret", secret),
            ("grant_type", "client_credentials"),
        ])
        .send()
        .await
        .map_err(|e| format!("hms oauth: {e}"))?;
    let bytes = response
        .bytes()
        .await
        .map_err(|e| format!("hms oauth decode: {e}"))?;
    let value: serde_json::Value =
        serde_json::from_slice(&bytes).map_err(|e| format!("hms oauth decode: {e}"))?;
    let token = value["access_token"].as_str().unwrap_or_default();
    if token.is_empty() {
        return Err("hms oauth: empty access_token (bad app id/secret)".into());
    }
    Ok(token.into())
}

fn pem(raw: &str) -> Result<(String, Vec<u8>), String> {
    use base64::engine::general_purpose::STANDARD;
    let (_, rest) = raw.split_once("-----BEGIN ").ok_or("not PEM-encoded")?;
    let (kind, rest) = rest.split_once("-----").ok_or("not PEM-encoded")?;
    let (data, _) = rest
        .split_once(&format!("-----END {kind}-----"))
        .ok_or("not PEM-encoded")?;
    Ok((
        kind.into(),
        STANDARD
            .decode(data.split_whitespace().collect::<String>())
            .map_err(|_| "not PEM-encoded")?,
    ))
}
async fn fcm_oauth(sa: &serde_json::Value) -> Result<Token, String> {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let key_error="private key should be a PEM or plain PKCS1 or PKCS8; parse error: asn1: syntax error: sequence truncated";
    let (kind, key) = pem(sa["private_key"].as_str().unwrap_or_default()).map_err(|_| key_error)?;
    let key = if kind == "RSA PRIVATE KEY" {
        ring::signature::RsaKeyPair::from_der(&key)
    } else {
        ring::signature::RsaKeyPair::from_pkcs8(&key)
    }
    .map_err(|_| key_error)?;
    let mut header = serde_json::json!({"alg":"RS256","typ":"JWT"});
    let kid = sa["private_key_id"].as_str().unwrap_or_default();
    if !kid.is_empty() {
        header["kid"] = kid.into();
    }
    let endpoint = sa["token_uri"]
        .as_str()
        .filter(|v| !v.is_empty())
        .unwrap_or("https://oauth2.googleapis.com/token");
    let issued_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| e.to_string())?
        .as_secs();
    let claims = serde_json::json!({"iss":sa["client_email"].as_str().unwrap_or_default(),"scope":"https://www.googleapis.com/auth/firebase.messaging","aud":endpoint,"exp":issued_at+3600,"iat":issued_at});
    let unsigned = format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(header.to_string()),
        URL_SAFE_NO_PAD.encode(claims.to_string())
    );
    let mut signature = vec![0; key.public().modulus_len()];
    key.sign(
        &ring::signature::RSA_PKCS1_SHA256,
        &ring::rand::SystemRandom::new(),
        unsigned.as_bytes(),
        &mut signature,
    )
    .map_err(|_| "could not sign JWT")?;
    let assertion = format!("{unsigned}.{}", URL_SAFE_NO_PAD.encode(signature));
    let response = reqwest::Client::new()
        .post(endpoint)
        .form(&[
            ("assertion", assertion.as_str()),
            ("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer"),
        ])
        .send()
        .await
        .map_err(|e| format!("oauth2: cannot fetch token: {e}"))?;
    let status = response.status();
    let bytes = response.bytes().await.map_err(|e| e.to_string())?;
    if !status.is_success() {
        return Err(format!(
            "oauth2: cannot fetch token: {status}\nResponse: {}",
            String::from_utf8_lossy(&bytes)
        ));
    }
    let value: serde_json::Value = serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
    let access = value["access_token"]
        .as_str()
        .filter(|s| !s.is_empty())
        .ok_or("oauth2: server response missing access_token")?;
    let seconds = value["expires_in"]
        .as_i64()
        .or_else(|| value["expires_in"].as_str().and_then(|s| s.parse().ok()))
        .unwrap_or(0);
    let expires = if seconds == 0 {
        None
    } else if seconds < 0 {
        Some(0)
    } else {
        Some(now().saturating_add(seconds as u64))
    };
    Ok(Token {
        value: access.into(),
        expires,
    })
}
