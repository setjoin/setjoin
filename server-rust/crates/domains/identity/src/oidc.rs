//! OIDC Provider profile. Its RS256 universe is separate from first-party JWTs.
use serde_json::json;
mod keys;
pub use keys::SigningKey;
mod requests;
pub use requests::{bind_code, request, Authorization};
mod crypto;
pub use crypto::CodeCipher;
mod grants;
mod operations;
pub use operations::{lookup_authorization, lookup_operation, Operation};
mod consumers;
pub use consumers::{access, authenticate, end_session, introspect, revoke, userinfo};
pub use grants::{code_exchange, refresh_exchange, OAuthError, TokenReply};
use setjoin_pg::{ScopedExecutor, Type};

/// Go schema's scalar decoder uses the last value, unlike URL.Query.Get.
pub fn form_last(raw: &str) -> std::collections::BTreeMap<String, String> {
    form_urlencoded::parse(raw.as_bytes())
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect()
}

/// Go url.Values.Encode ordering and application/x-www-form-urlencoded bytes.
pub fn query_response(uri: &str, fields: &[(&str, &str)], fragment: bool) -> String {
    let (base, hash) = uri
        .split_once('#')
        .map_or((uri, None), |(a, b)| (a, Some(b)));
    let (path, query) = base.split_once('?').unwrap_or((base, ""));
    let mut pairs: Vec<(String, String)> = if fragment {
        Vec::new()
    } else {
        form_urlencoded::parse(query.as_bytes())
            .map(|(k, v)| (k.into_owned(), v.into_owned()))
            .collect()
    };
    pairs.retain(|(k, _)| !fields.iter().any(|(name, _)| *name == k));
    pairs.extend(
        fields
            .iter()
            .filter(|(_, v)| !v.is_empty())
            .map(|(k, v)| (k.to_string(), v.to_string())),
    );
    pairs.sort_by(|a, b| a.0.cmp(&b.0));
    let encoded = form_urlencoded::Serializer::new(String::new())
        .extend_pairs(pairs)
        .finish();
    if fragment {
        format!("{base}#{encoded}")
    } else {
        format!(
            "{path}?{encoded}{}",
            hash.map(|h| format!("#{h}")).unwrap_or_default()
        )
    }
}

/// Public, admin-registered OP client metadata. No user authority comes from
/// this lookup; authorization requests remain unbound until session completion.
pub struct Client {
    pub id: String,
    pub redirects: Vec<String>,
    pub scopes: Vec<String>,
    pub grants: Vec<String>,
    pub public: bool,
}
pub async fn client(exec: &ScopedExecutor, id: &str) -> Result<Client, String> {
    let rows=exec.read("SELECT id,redirect_uris,scopes,grant_types,client_type,enabled FROM oidc_clients WHERE id=$1",&[(&id,Type::TEXT)]).await.map_err(|e|e.message)?;
    let r = rows
        .first()
        .ok_or_else(|| format!("client not found: {id}"))?;
    if !r.get::<_, bool>(5) {
        return Err(format!("client disabled: {id}"));
    }
    let mut grants: Vec<String> = r.get(3);
    grants.retain(|g| matches!(g.as_str(), "authorization_code" | "refresh_token"));
    if grants.is_empty() {
        grants.push("authorization_code".into());
    }
    Ok(Client {
        id: r.get(0),
        redirects: r.get(1),
        scopes: r.get(2),
        grants,
        public: r.get::<_, String>(4) == "public",
    })
}
pub async fn create_request(
    exec: &ScopedExecutor,
    client: &Client,
    redirect: &str,
    state: &str,
    nonce: &str,
    challenge: &str,
    method: &str,
    scopes: &[String],
    operation: setjoin_contracts::ids::OperationId,
) -> setjoin_pg::CommandOutcome<String, setjoin_pg::StatementFailure> {
    let id=match grants::random_hex(16){Ok(id)=>id,Err(e)=>return setjoin_pg::CommandOutcome::RolledBack(setjoin_pg::Rejection::Statement(setjoin_pg::StatementFailure{sqlstate:None,hint:None,message:e.description}))};
    let expiry = std::time::SystemTime::now() + std::time::Duration::from_secs(600);
    // This is Go's entire one-statement transaction. The user is deliberately
    // NULL, including when an id_token_hint or a user_id parameter is supplied.
    exec.run_protocol_command(&format!("oidc-client:{}",client.id),operation,setjoin_pg::ReceiptCommand{family:"F21",command:"oidc-authorize"},"INSERT INTO oidc_auth_requests(id,client_id,redirect_uri,state,nonce,code_challenge,code_challenge_method,scopes,user_id,expires_at,done,auth_time,acr,amr) VALUES($1,$2,$3,$4,$5,$6,$7,$8,NULL,$9,false,NULL,NULL,'{}')",&[(&id,Type::TEXT),(&client.id,Type::TEXT),(&redirect,Type::TEXT),(&state,Type::TEXT),(&nonce,Type::TEXT),(&challenge,Type::TEXT),(&method,Type::TEXT),(&scopes,Type::TEXT_ARRAY),(&expiry,Type::TIMESTAMPTZ)],|_|Ok(id.clone())).await
}

/// The session is the only source of user and authentication context. An
/// unbound request capability can be claimed once; nobody may replace a bind.
pub async fn complete_request(
    exec: &ScopedExecutor,
    session: &crate::session::Session,
    id: &str,
    operation: setjoin_contracts::ids::OperationId,
) -> setjoin_pg::CommandOutcome<bool, setjoin_pg::StatementFailure> {
    let Ok(actor) = setjoin_contracts::ids::ActorId::new(session.user()) else {
        return setjoin_pg::CommandOutcome::RolledBack(setjoin_pg::Rejection::Unavailable);
    };
    let time = session
        .claims()
        .get("auth_time")
        .and_then(serde_json::Value::as_i64)
        .filter(|n| *n > 0)
        .map(|n| std::time::UNIX_EPOCH + std::time::Duration::from_secs(n as u64))
        .unwrap_or_else(std::time::SystemTime::now);
    let acr = if session.text("acr").is_empty() {
        "aal1"
    } else {
        session.text("acr")
    };
    let amr: Vec<String> = session
        .claims()
        .get("amr")
        .and_then(serde_json::Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|v| v.as_str().map(str::to_owned))
        .collect();
    exec.clone().with_user_receipt(setjoin_pg::ReceiptCommand{family:"F21",command:"oidc-complete"}).run_user_command(actor,operation,
        "UPDATE oidc_auth_requests SET user_id=$2,done=true,auth_time=$3,acr=$4,amr=$5 WHERE id=$1 AND expires_at>now() AND done=false AND user_id IS NULL AND $2::bigint=current_setting('app.current_user_id')::bigint RETURNING id",
        &[(&id,Type::TEXT),(&session.user(),Type::INT8),(&time,Type::TIMESTAMPTZ),(&acr,Type::TEXT),(&amr,Type::TEXT_ARRAY)],|rows|Ok(rows.len()==1)).await
}

pub fn valid_origins(configured: &str) -> bool {
    configured.split(',').all(|raw| {
        // Go trims trailing slashes before surrounding whitespace and does not
        // canonicalize shortened/integer IPv4 spellings into loopback hosts.
        let s = raw.trim_end_matches('/').trim();
        if s.is_empty() {
            return true;
        }
        let Ok(u) = url::Url::parse(s) else {
            return false;
        };
        let Some((_, rest)) = s.split_once("://") else {
            return false;
        };
        let boundary = rest.find(['/', '?', '#']).unwrap_or(rest.len());
        let authority = &rest[..boundary];
        let tail = &rest[boundary..];
        let path = tail.split(['?', '#']).next().unwrap_or("");
        if authority.is_empty()
            || authority.contains('@')
            || !path.is_empty()
            || s.contains('*')
            || u.query().is_some_and(|q| !q.is_empty())
            || u.fragment().is_some_and(|f| !f.is_empty())
        {
            return false;
        }
        let host = if authority.starts_with('[') {
            authority
                .split_once(']')
                .map(|p| p.0.trim_start_matches('['))
                .unwrap_or("")
        } else {
            authority.split(':').next().unwrap_or("")
        };
        u.scheme() == "https"
            || (u.scheme() == "http"
                && (host == "localhost"
                    || host
                        .parse::<std::net::IpAddr>()
                        .is_ok_and(|ip| ip.is_loopback())))
    })
}

pub fn metadata(hostname: &str) -> String {
    let base = format!("https://{}", hostname.trim_end_matches('/'));
    crate::issuance::object(&[
        ("issuer", json!(base)),
        ("authorization_endpoint", json!(format!("{base}/authorize"))),
        ("token_endpoint", json!(format!("{base}/oauth/token"))),
        (
            "introspection_endpoint",
            json!(format!("{base}/oauth/introspect")),
        ),
        ("revocation_endpoint", json!(format!("{base}/revoke"))),
        ("jwks_uri", json!(format!("{base}/keys"))),
        ("userinfo_endpoint", json!(format!("{base}/userinfo"))),
        (
            "scopes_supported",
            json!(["openid", "profile", "email", "offline_access"]),
        ),
        ("response_types_supported", json!(["code"])),
        (
            "grant_types_supported",
            json!(["authorization_code", "refresh_token"]),
        ),
        (
            "token_endpoint_auth_methods_supported",
            json!(["client_secret_basic", "client_secret_post", "none"]),
        ),
        (
            "introspection_endpoint_auth_methods_supported",
            json!(["client_secret_basic", "client_secret_post"]),
        ),
        (
            "revocation_endpoint_auth_methods_supported",
            json!(["client_secret_basic", "client_secret_post"]),
        ),
        ("code_challenge_methods_supported", json!(["S256"])),
        ("acr_values_supported", json!(["aal1", "aal2"])),
        (
            "claims_supported",
            json!([
                "sub",
                "email",
                "email_verified",
                "name",
                "acr",
                "amr",
                "iss",
                "aud",
                "exp",
                "iat"
            ]),
        ),
    ]) + "\n"
}

pub fn discovery(hostname: &str) -> String {
    discovery_values(hostname)
        .to_string()
        .replace('&', "\\u0026")
        .replace('<', "\\u003c")
        .replace('>', "\\u003e")
        .replace('\u{2028}', "\\u2028")
        .replace('\u{2029}', "\\u2029")
}
fn discovery_values(hostname: &str) -> serde_json::Value {
    let base = format!("https://{hostname}");
    // Go's discovery wrapper serializes a sorted map, without a newline.
    json!({
        "acr_values_supported":["aal1","aal2"],
        "authorization_endpoint":format!("{base}/authorize"),
        "claims_supported":["sub","aud","exp","iat","iss","auth_time","nonce","acr","amr","c_hash","at_hash","act","scopes","client_id","azp","preferred_username","name","family_name","given_name","locale","email","email_verified","phone_number","phone_number_verified"],
        "code_challenge_methods_supported":["S256"],
        "end_session_endpoint":format!("{base}/end_session"),
        "grant_types_supported":["authorization_code","refresh_token"],
        "id_token_signing_alg_values_supported":["RS256"],
        "introspection_endpoint":format!("{base}/oauth/introspect"),
        "introspection_endpoint_auth_methods_supported":["client_secret_basic"],
        "introspection_endpoint_auth_signing_alg_values_supported":["RS256"],
        "issuer":base,
        "jwks_uri":format!("{base}/keys"),
        "request_uri_parameter_supported":false,
        "response_types_supported":["code"],
        "revocation_endpoint":format!("{base}/revoke"),
        "revocation_endpoint_auth_methods_supported":["none","client_secret_basic","client_secret_post"],
        "revocation_endpoint_auth_signing_alg_values_supported":["RS256"],
        "scopes_supported":["openid","profile","email","phone","address","offline_access"],
        "subject_types_supported":["public"],
        "token_endpoint":format!("{base}/oauth/token"),
        "token_endpoint_auth_methods_supported":["none","client_secret_basic","client_secret_post"],
        "userinfo_endpoint":format!("{base}/userinfo")
    })
}

/// The frozen wrapper only augments GET. Other methods expose the original
/// library projection, including its unsupported capabilities (parity).
pub fn discovery_unwrapped(hostname: &str) -> String {
    let mut doc = discovery_values(hostname);
    doc["response_types_supported"] = json!(["code", "id_token", "id_token token"]);
    doc["grant_types_supported"] = json!([
        "authorization_code",
        "implicit",
        "refresh_token",
        "urn:ietf:params:oauth:grant-type:jwt-bearer"
    ]);
    doc["device_authorization_endpoint"] =
        json!(format!("https://{hostname}/device_authorization"));
    let keys = [
        "issuer",
        "authorization_endpoint",
        "token_endpoint",
        "introspection_endpoint",
        "userinfo_endpoint",
        "revocation_endpoint",
        "end_session_endpoint",
        "device_authorization_endpoint",
        "jwks_uri",
        "scopes_supported",
        "response_types_supported",
        "grant_types_supported",
        "subject_types_supported",
        "id_token_signing_alg_values_supported",
        "token_endpoint_auth_methods_supported",
        "revocation_endpoint_auth_methods_supported",
        "revocation_endpoint_auth_signing_alg_values_supported",
        "introspection_endpoint_auth_methods_supported",
        "introspection_endpoint_auth_signing_alg_values_supported",
        "claims_supported",
        "code_challenge_methods_supported",
        "request_uri_parameter_supported",
    ];
    crate::issuance::object(
        &keys
            .iter()
            .map(|k| (*k, doc[*k].clone()))
            .collect::<Vec<_>>(),
    ) + "\n"
}

/// Native clients may vary loopback scheme/host/port as frozen Go does; path
/// and the raw query still match a registered loopback redirect exactly.
pub fn redirect_error(client:&Client,uri:&str,response_type:&str)->Option<&'static str>{
 const MISSING:&str="The requested redirect_uri is missing in the client configuration. If you have any questions, you may contact the administrator of the application.";
 const HTTP:&str="This client's redirect_uri is http and is not allowed. If you have any questions, you may contact the administrator of the application.";
 const CUSTOM:&str="This client's redirect_uri is using a custom schema and is not allowed. If you have any questions, you may contact the administrator of the application.";
 fn loopback(uri:&str)->Option<url::Url>{let u=url::Url::parse(uri).ok()?;if !matches!(u.scheme(),"http"|"https"){return None;}let host=u.host_str()?.trim_matches(['[',']']);(host=="localhost"||host.parse::<std::net::IpAddr>().is_ok_and(|ip|ip.is_loopback())).then_some(u)}
 let registered=client.redirects.iter().any(|s|s==uri);
 if client.public{
  let parsed=loopback(uri);
  if registered{return if parsed.is_some()||!uri.starts_with("http://"){None}else{Some(HTTP)};}
  let Some(parsed)=parsed else{return Some(MISSING);};return if client.redirects.iter().any(|s|loopback(s).is_some_and(|u|u.path()==parsed.path()&&u.query()==parsed.query())){None}else{Some(MISSING)};
 }
 if !registered{return Some(MISSING);}if uri.starts_with("https://")||(uri.starts_with("http://")&&response_type=="code"){None}else if uri.starts_with("http://"){Some(HTTP)}else{Some(CUSTOM)}
}
