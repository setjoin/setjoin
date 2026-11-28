//! Guest lifecycle reconciliation, independent of admission toggles.
use setjoin_pg::workers::WorkerDatabase;
pub struct GuestLifecycle {
    pub db: WorkerDatabase,
    pub endpoint: Option<String>,
    pub key: String,
    pub secret: String,
}
impl GuestLifecycle {
    pub async fn expire(&self) -> Result<(), String> {
        self.db.guest_expire_due().await.map_err(|e| e.to_string())
    }
    pub async fn drain(&self, user: Option<i64>) -> Result<(), String> {
        let Some(endpoint) = self.endpoint.as_deref() else {
            return Err("guest lifecycle: LiveKit is not configured".into());
        };
        if user.is_some_and(|n| n <= 0) {
            return Err("guest lifecycle: positive user id required".into());
        }
        let c = self.db.connect().await.map_err(|e| e.to_string())?;
        for _ in 0..100 {
            use setjoin_pg::Type;
            let rows=c.query("UPDATE guest_live_eviction_intents SET attempt_count=attempt_count+1,last_attempt_at=now(),next_attempt_at=now()+interval '30 seconds' WHERE id=(SELECT id FROM guest_live_eviction_intents WHERE completed_at IS NULL AND next_attempt_at<=now() AND ($1::bigint IS NULL OR guest_user_id=$1) ORDER BY next_attempt_at,id FOR UPDATE SKIP LOCKED LIMIT 1) RETURNING id,room_name::text,identity,(extract(epoch FROM transition_at)*1000000)::bigint,(extract(epoch FROM retry_until)*1000000)::bigint,attempt_count",&[(&user,Type::INT8)]).await?;
            let Some(row) = rows.first() else {
                return Ok(());
            };
            let id: i64 = row.get(0);
            let room: String = row.get(1);
            let identity: String = row.get(2);
            let transition: i64 = row.get(3);
            let horizon: i64 = row.get(4);
            let attempts: i32 = row.get(5);
            let outcome = self.remove(endpoint, &room, &identity).await;
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_err(|e| e.to_string())?
                .as_micros() as i128;
            if outcome.is_ok() && now >= i128::from(horizon) {
                let _=c.query("UPDATE guest_live_eviction_intents SET completed_at=now(),next_attempt_at=now(),last_error=NULL WHERE id=$1",&[(&id,Type::INT8)]).await;
                continue;
            }
            let error = outcome.err().unwrap_or_default();
            if !error.is_empty() && attempts >= 60 {
                if c.query("UPDATE guest_live_eviction_intents SET next_attempt_at='infinity',last_error=NULLIF($2,'') WHERE id=$1",&[(&id,Type::INT8),(&error,Type::TEXT)]).await.is_ok(){continue}
            }
            let delay: i32 = if !error.is_empty() {
                (1i32 << ((attempts - 1).clamp(0, 9) as u32)).min(300)
            } else if now - i128::from(transition) < 300_000_000 {
                10
            } else {
                60
            };
            let _=c.query("UPDATE guest_live_eviction_intents SET next_attempt_at=now()+make_interval(secs=>$2::integer),last_error=NULLIF($3,'') WHERE id=$1",&[(&id,Type::INT8),(&delay,Type::INT4),(&error,Type::TEXT)]).await;
        }
        Ok(())
    }
    async fn remove(&self, endpoint: &str, room: &str, identity: &str) -> Result<(), String> {
        remove_participant(endpoint, &self.key, &self.secret, room, identity).await
    }

    pub async fn run_until(
        self: std::sync::Arc<Self>,
        stop: impl std::future::Future<Output = ()>,
    ) {
        tokio::pin!(stop);
        tokio::select! {_=&mut stop=>return,_=async{let _=self.expire().await;let _=self.drain(None).await;}=>{}}
        let mut expiry = tokio::time::interval(std::time::Duration::from_secs(3600));
        let mut drain = tokio::time::interval(std::time::Duration::from_secs(5));
        expiry.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        drain.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        expiry.tick().await;
        drain.tick().await;
        loop {
            tokio::select! {_=&mut stop=>return,_=expiry.tick()=>{tokio::select!{_=&mut stop=>return,_=async{let _=self.expire().await;let _=self.drain(None).await;}=>{}}},_=drain.tick()=>{tokio::select!{_=&mut stop=>return,_=self.drain(None)=>{}}}}
        }
    }
}

/// Go's `lkRooms.RemoveParticipant` over the LiveKit Twirp API: a not-found
/// answer is success; any other failure is `twirp error <code>: <msg>`.
pub async fn remove_participant(
    endpoint: &str,
    key: &str,
    secret: &str,
    room: &str,
    identity: &str,
) -> Result<(), String> {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    let now = chrono::Utc::now().timestamp();
    let header = URL_SAFE_NO_PAD.encode(r#"{"alg":"HS256","typ":"JWT"}"#);
    let claims = serde_json::json!({"iss":key,"iat":now,"nbf":now,"exp":now+21600,"video":{"roomAdmin":true,"room":room}});
    let input = format!("{header}.{}", URL_SAFE_NO_PAD.encode(claims.to_string()));
    let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, secret.as_bytes());
    let signature = ring::hmac::sign(&key, input.as_bytes());
    let token = format!("{input}.{}", URL_SAFE_NO_PAD.encode(signature.as_ref()));
    fn varint(mut n: usize, out: &mut Vec<u8>) {
        while n > 127 {
            out.push((n as u8) | 128);
            n >>= 7;
        }
        out.push(n as u8);
    }
    let mut bytes = vec![10];
    varint(room.len(), &mut bytes);
    bytes.extend_from_slice(room.as_bytes());
    bytes.push(18);
    varint(identity.len(), &mut bytes);
    bytes.extend_from_slice(identity.as_bytes());
    let url = endpoint
        .replacen("wss://", "https://", 1)
        .replacen("ws://", "http://", 1);
    let request_url = format!(
        "{}/twirp/livekit.RoomService/RemoveParticipant",
        url.trim_end_matches('/')
    );
    let response = reqwest::Client::new()
        .post(&request_url)
        .header("content-type", "application/protobuf")
        .bearer_auth(token)
        .body(bytes)
        .send()
        .await
        .map_err(|error| removal_transport_error(&request_url, &error))?;
    let succeeded = response.status().is_success();
    let bytes = response
        .bytes()
        .await
        .map_err(|_| "twirp error internal: invalid response".to_owned())?;
    if succeeded {
        // RemoveParticipantResponse has no fields, but Go still unmarshals it.
        // Validate unknown fields and malformed wire data with the protobuf codec.
        // The recorded Go protobuf diagnostic uses NBSP after "proto:".
        use prost::Message;
        RemovalResponse::decode(bytes.as_ref()).map_err(|_|"twirp error internal: failed to unmarshal proto response: proto:\u{a0}cannot parse invalid wire-format data".to_owned())?;
        return Ok(());
    }
    let value: serde_json::Value = serde_json::from_slice(&bytes)
        .map_err(|_| "twirp error internal: invalid response".to_owned())?;
    let code = value["code"].as_str().unwrap_or("internal");
    let msg = value["msg"].as_str().unwrap_or("invalid response");
    if code == "not_found" {
        Ok(())
    } else {
        Err(format!("twirp error {code}: {msg}"))
    }
}

#[derive(Clone, PartialEq, prost::Message)]
struct RemovalResponse {}

fn removal_transport_error(request: &str, error: &reqwest::Error) -> String {
    let mut cause: &(dyn std::error::Error + 'static) = error;
    loop {
        if cause
            .downcast_ref::<std::io::Error>()
            .is_some_and(|e| e.kind() == std::io::ErrorKind::ConnectionRefused)
        {
            if let Ok(mut parsed) = url::Url::parse(request) {
                let ip = match parsed.host() {
                    Some(url::Host::Ipv4(ip)) => Some(std::net::IpAddr::V4(ip)),
                    Some(url::Host::Ipv6(ip)) => Some(std::net::IpAddr::V6(ip)),
                    _ => None,
                };
                if let (Some(ip), Some(port)) = (ip, parsed.port_or_known_default()) {
                    // net/url.URL.Redacted, as used by Go's url.Error.
                    if parsed.password().is_some() {
                        let _ = parsed.set_password(Some("xxxxx"));
                    }
                    return format!("twirp error internal: failed to do request: Post {:?}: dial tcp {}: connect: connection refused",parsed.as_str(),std::net::SocketAddr::new(ip,port));
                }
            }
        }
        let Some(next) = cause.source() else { break };
        cause = next;
    }
    "twirp error unavailable: transport failure".into()
}
