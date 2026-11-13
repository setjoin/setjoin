//! #333 first-party token and discovery authority; HTTP framing stays in auth.
use serde_json::{json, Value};
use setjoin_pg::{ScopedExecutor, Type};
use std::collections::BTreeMap;

/// encoding/json struct declaration order, unlike its sorted map encoding.
pub fn object(fields: &[(&str, Value)]) -> String {
    let raw = fields
        .iter()
        .map(|(key, value)| format!("{}:{}", json!(key), value))
        .collect::<Vec<_>>()
        .join(",");
    format!("{{{raw}}}")
        .replace('&', "\\u0026")
        .replace('<', "\\u003c")
        .replace('>', "\\u003e")
        .replace('\u{2028}', "\\u2028")
        .replace('\u{2029}', "\\u2029")
}
fn valid_pair(raw: &str) -> bool {
    if raw.contains(';') {
        return false;
    }
    let b = raw.as_bytes();
    let mut at = 0;
    while at < b.len() {
        if b[at] == b'%' {
            if at + 2 >= b.len() || !b[at + 1].is_ascii_hexdigit() || !b[at + 2].is_ascii_hexdigit()
            {
                return false;
            }
            at += 2;
        }
        at += 1;
    }
    true
}
/// Go URL.Query retains the first value and ignores malformed pairs.
pub fn query(raw: &str) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    for pair in raw.split('&').filter(|p| valid_pair(p)) {
        for (k, v) in form_urlencoded::parse(pair.as_bytes()) {
            out.entry(k.into_owned()).or_insert(v.into_owned());
        }
    }
    out
}
fn semver(raw: &str) -> [i64; 3] {
    let mut out = [0; 3];
    for (i, p) in raw.splitn(3, '.').enumerate() {
        out[i] = p.parse().unwrap_or(0);
    }
    out
}
pub async fn version(exec: &ScopedExecutor, raw: &str, host: &str) -> String {
    let query = query(raw);
    let get = |k| query.get(k).map(String::as_str).unwrap_or("");
    let (client, platform, app) = (get("client"), get("platform"), get("app"));
    let default = "{\"server_version\":\"2.5.0\",\"update_type\":\"up_to_date\"}\n";
    if client.is_empty() || platform.is_empty() || app.is_empty() {
        return default.into();
    }
    let rows=exec.read("SELECT version,sha256,COALESCE(release_notes,''),COALESCE(file_path,''),release_date FROM client_versions WHERE platform=$1 AND app=$2 ORDER BY string_to_array(version,'.')::int[] DESC LIMIT 1",&[(&platform,Type::TEXT),(&app,Type::TEXT)]).await;
    let Ok(rows) = rows else {
        return default.into();
    };
    let Some(r) = rows.first() else {
        return default.into();
    };
    let latest: String = r.get(0);
    let hash: String = r.get(1);
    let notes: String = r.get(2);
    let file: String = r.get(3);
    let date: std::time::SystemTime = r.get(4);
    let date: chrono::DateTime<chrono::Utc> = date.into();
    let c = semver(client);
    let l = semver(&latest);
    let kind = if c >= l {
        "up_to_date"
    } else if c[0] < l[0] {
        "blocked"
    } else if l[1] - c[1] >= 2 {
        "update_required"
    } else {
        "update_available"
    };
    let mut fields = vec![("server_version", json!("2.5.0"))];
    if !latest.is_empty() {
        fields.push(("latest_version", json!(latest)));
    }
    fields.push(("update_type", json!(kind)));
    if kind != "up_to_date" && !file.is_empty() {
        fields.push((
            "update_url",
            json!(format!("https://{host}/clients/{platform}/{latest}/{file}")),
        ));
        if !hash.is_empty() {
            fields.push(("sha256", json!(hash)));
        }
    }
    if !notes.is_empty() {
        fields.push(("release_notes", json!(notes)));
    }
    fields.push((
        "release_date",
        json!(date.to_rfc3339_opts(chrono::SecondsFormat::Secs, true)),
    ));
    object(&fields) + "\n"
}

/// Sealed service/client authority. The caller cannot supply an owning user.
pub struct ClientProof {
    client: Option<String>,
}
impl ClientProof {
    pub fn internal(header: &str, key: &str) -> Option<Self> {
        use subtle::ConstantTimeEq;
        let presented = header.strip_prefix("Bearer ")?;
        (!key.is_empty() && bool::from(presented.as_bytes().ct_eq(key.as_bytes())))
            .then_some(Self { client: None })
    }
    pub async fn authenticate(exec: &ScopedExecutor, client: &str, secret: &str) -> Option<Self> {
        if client.is_empty() {
            return None;
        }
        let rows = exec
            .read(
                "SELECT secret FROM oidc_clients WHERE id=$1 AND enabled=true",
                &[(&client, Type::TEXT)],
            )
            .await;
        let hash = rows
            .ok()
            .and_then(|r| r.first().map(|r| r.get::<_, String>(0)));
        let exists = hash.is_some();
        let hash = hash.unwrap_or_else(|| {
            "$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy".into()
        });
        let secret = secret.to_owned();
        let valid =
            tokio::task::spawn_blocking(move || bcrypt::verify(secret, &hash).unwrap_or(false))
                .await
                .unwrap_or(false);
        (exists && valid).then(|| Self {
            client: Some(client.to_owned()),
        })
    }
}
/// Authenticated service/client + presented token hash grants this read in Go.
/// Introspection is deliberately not restricted to the caller's client_id.
pub async fn introspect(
    exec: &ScopedExecutor,
    _caller: &ClientProof,
    token: &str,
    issuer: &str,
) -> String {
    use sha2::{Digest, Sha256};
    let hash = Sha256::digest(token.as_bytes()).to_vec();
    let rows=exec.read("SELECT o.user_id,u.email,o.client_id,COALESCE(o.scope,'{}'),extract(epoch FROM o.issued_at)::bigint,extract(epoch FROM o.expires_at)::bigint FROM oauth_tokens o JOIN users u ON u.id=o.user_id AND u.enabled=true WHERE o.token_hash=$1 AND o.revoked_at IS NULL AND (o.expires_at IS NULL OR o.expires_at>now())",&[(&hash,Type::BYTEA)]).await;
    let Ok(rows) = rows else {
        return "{\"active\":false}\n".into();
    };
    let Some(r) = rows.first() else {
        return "{\"active\":false}\n".into();
    };
    let user: i64 = r.get(0);
    let email: String = r.get(1);
    let client: Option<String> = r.get(2);
    let scope: Vec<String> = r.get(3);
    let issued: Option<i64> = r.get(4);
    let expiry: Option<i64> = r.get(5);
    let mut fields = vec![("active", json!(true))];
    let scope = scope.join(" ");
    if !scope.is_empty() {
        fields.push(("scope", json!(scope)));
    }
    if let Some(c) = client.filter(|s| !s.is_empty()) {
        fields.push(("client_id", json!(c)));
    }
    if !email.is_empty() {
        fields.push(("username", json!(email)));
    }
    fields.push(("token_type", json!("Bearer")));
    if let Some(exp) = expiry.filter(|v| *v != 0) {
        fields.push(("exp", json!(exp)));
    }
    if let Some(iat) = issued.filter(|v| *v != 0) {
        fields.push(("iat", json!(iat)));
        fields.push(("nbf", json!(iat)));
    }
    fields.extend([
        ("sub", json!(user.to_string())),
        ("aud", json!("mailserver-gateway")),
        ("iss", json!(issuer)),
    ]);
    if !email.is_empty() {
        fields.push(("email", json!(email)));
    }
    object(&fields) + "\n"
}

/// net/http ParseForm's strict percent/semicolon errors (PostForm only).
pub fn form(raw: &[u8]) -> Result<BTreeMap<String, String>, &'static str> {
    let text = String::from_utf8_lossy(raw);
    if !text.split('&').all(valid_pair) {
        return Err("invalid request body");
    }
    Ok(query(&text))
}

/// Go's single-statement RFC7009 transaction. Hash possession plus verified
/// client authority selects the target; the UPDATE repeats both predicates.
pub async fn revoke(
    exec: &ScopedExecutor,
    caller: &ClientProof,
    token: &str,
) -> setjoin_pg::CommandOutcome<(), setjoin_pg::StatementFailure> {
    use setjoin_contracts::ids::{ActorId, OperationId};
    use setjoin_pg::{CommandOutcome, Rejection};
    use sha2::{Digest, Sha256};
    let hash = Sha256::digest(token.as_bytes()).to_vec();
    let rows=match exec.read("SELECT user_id FROM oauth_tokens WHERE token_hash=$1 AND revoked_at IS NULL AND (client_id=$2 OR client_id IS NULL)",&[(&hash,Type::BYTEA),(&caller.client,Type::TEXT)]).await{
        Ok(r)=>r,Err(e)=>return CommandOutcome::RolledBack(Rejection::Statement(e))
    };
    let Some(row) = rows.first() else {
        return CommandOutcome::Committed(());
    };
    let user: i64 = row.get(0);
    let Ok(actor) = ActorId::new(user) else {
        return CommandOutcome::RolledBack(Rejection::Unavailable);
    };
    let operation = OperationId(*uuid::Uuid::new_v4().as_bytes());
    exec.run_user_command(actor,operation,"UPDATE oauth_tokens SET revoked_at=now() WHERE user_id=$1 AND token_hash=$2 AND revoked_at IS NULL AND (client_id=$3 OR client_id IS NULL)",&[(&user,Type::INT8),(&hash,Type::BYTEA),(&caller.client,Type::TEXT)],|_|Ok(())).await
}

/// Sealed authserver identity, without inventing a primary-mailbox requirement.
pub struct SessionProof {
    claims: serde_json::Map<String, Value>,
}
pub enum SessionError {
    Invalid,
    WrongType,
    Bound,
}
impl SessionProof {
    pub fn user(&self) -> i64 {
        self.claims["uid"].as_i64().expect("verified user")
    }
    pub fn claims(&self) -> &serde_json::Map<String, Value> {
        &self.claims
    }
    /// The transport applies its shared process-local revocation snapshot to
    /// this sealed, signature-verified session before constructing route proof.
    pub fn from_session(session: &super::session::Session) -> Result<Self, SessionError> {
        if session.text("typ") != "access" {
            return Err(SessionError::WrongType);
        }
        if session.user() <= 0 {
            return Err(SessionError::Invalid);
        }
        if session.bound() {
            return Err(SessionError::Bound);
        }
        Ok(Self { claims: session.claims().clone() })
    }
    pub async fn pending(
        &self,
        exec: &ScopedExecutor,
    ) -> Result<String, setjoin_pg::StatementFailure> {
        let user = self.user();
        let actor = setjoin_contracts::ids::ActorId::new(user).expect("verified user");
        let rows=exec.read_user_scoped(actor,"SELECT t.id,t.name,t.version,t.body_md,t.require_scroll FROM terms_of_use t LEFT JOIN terms_of_use_acceptance a ON a.tou_id=t.id AND a.user_id=$1 AND a.version=t.version WHERE t.enabled AND a.user_id IS NULL ORDER BY t.id",&[(&user,Type::INT8)]).await?;
        let docs = rows
            .iter()
            .map(|r| {
                object(&[
                    ("id", json!(r.get::<_, i64>(0))),
                    ("name", json!(r.get::<_, String>(1))),
                    ("version", json!(r.get::<_, i32>(2))),
                    ("body_md", json!(r.get::<_, String>(3))),
                    ("require_scroll", json!(r.get::<_, bool>(4))),
                ])
            })
            .collect::<Vec<_>>()
            .join(",");
        Ok(format!("[{docs}]\n"))
    }
}
impl SessionProof {
    pub async fn accept(
        &self,
        exec: &ScopedExecutor,
        tou: i64,
        version: i64,
        ip: &str,
    ) -> setjoin_pg::CommandOutcome<(), setjoin_pg::StatementFailure> {
        use setjoin_contracts::ids::{ActorId, OperationId};
        let user = self.user();
        exec.run_user_command(
            ActorId::new(user).expect("verified user"),
            OperationId(*uuid::Uuid::new_v4().as_bytes()),
            "SELECT record_tou_acceptance($1,$2,$3::int4,$4::text::inet)",
            &[
                (&user, Type::INT8),
                (&tou, Type::INT8),
                (&version, Type::INT8),
                (&ip, Type::TEXT),
            ],
            |_| Ok(()),
        )
        .await
    }
}

/// SCIM's target is selected only after an internal-service proof. It is not
/// an end-user owned identity field: this capability deprovisions org users.
pub async fn disable(
    exec: &ScopedExecutor,
    caller: &ClientProof,
    requested_user: i64,
    external: &str,
) -> setjoin_pg::CommandOutcome<bool, setjoin_pg::StatementFailure> {
    use setjoin_contracts::ids::{ActorId, OperationId};
    use setjoin_pg::{CommandOutcome, Rejection};
    if caller.client.is_some() {
        return CommandOutcome::RolledBack(Rejection::Unavailable);
    }
    let user = if requested_user != 0 {
        requested_user
    } else {
        match exec
            .read(
                "SELECT id FROM users WHERE scim_external_id=$1",
                &[(&external, Type::TEXT)],
            )
            .await
        {
            Ok(r) => match r.first() {
                Some(row) => row.get::<_, i64>(0),
                None => return CommandOutcome::Committed(false),
            },
            Err(_) => return CommandOutcome::Committed(false),
        }
    };
    let Ok(actor) = ActorId::new(user) else {
        return CommandOutcome::RolledBack(Rejection::Unavailable);
    };
    exec.run_user_command(
        actor,
        OperationId(*uuid::Uuid::new_v4().as_bytes()),
        "SELECT revoke_user_sessions($1,'all','token_revoke_all',NULL,NULL,NULL)",
        &[(&user, Type::INT8)],
        |_| Ok(true),
    )
    .await
}

/// Go time.Now().UTC() JSON timestamp; use the same clock only for display.
pub fn now_rfc3339() -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system time");
    chrono::DateTime::from_timestamp(now.as_secs() as i64, now.subsec_nanos())
        .expect("timestamp")
        .to_rfc3339_opts(chrono::SecondsFormat::AutoSi, true)
}

impl SessionProof {
    /// WebPush is a delivery subscription, not a native MFA approval device.
    pub async fn register_webpush(&self,exec:&ScopedExecutor,subscription:&str,name:&str)->setjoin_pg::CommandOutcome<(),setjoin_pg::StatementFailure>{
        exec.run_user_command(setjoin_contracts::ids::ActorId::new(self.user()).expect("verified user"),setjoin_contracts::ids::OperationId(*uuid::Uuid::new_v4().as_bytes()),
            "INSERT INTO push_devices(user_id,push_provider,push_token_enc,device_public_key,device_name) VALUES($1,'webpush',pgp_sym_encrypt($2::text,current_setting('app.encryption_key'))::bytea,NULL,$3) ON CONFLICT DO NOTHING",
            &[(&self.user(),Type::INT8),(&subscription,Type::TEXT),(&name,Type::TEXT)],|_|Ok(())).await
    }
}
