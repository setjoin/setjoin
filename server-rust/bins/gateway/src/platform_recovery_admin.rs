//! F08 recovery administration. F16 owns bytes; existing worker-only reducers own
//! the global recovery permission and incident data. Configuration is shared with F16.
use crate::{Body, RequestContext};
use hyper::Response;
use setjoin_pg::{ScopedExecutor, Type};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Kind {
    List,
    Signals,
    Artifacts,
    Approve,
    Close,
    Open,
    Accept,
}

#[derive(Clone)]
pub(crate) struct RecoveryAdmin {
    pub worker: ScopedExecutor,
    pub ready: bool,
    feature: FeatureCache,
}

pub(crate) fn problem(status: u16, detail: &str, c: &RequestContext, id: &str) -> Response<Body> {
    let mut response = crate::jmap::reply::response(
        crate::problem::Problem::new(status, detail).body(),
        c.identity.proto,
        id.to_owned(),
    );
    *response.status_mut() = hyper::StatusCode::from_u16(status).expect("fixed status");
    response
        .headers_mut()
        .insert("content-type", "application/problem+json".parse().unwrap());
    response
}

pub(crate) async fn serve(
    kind: Kind,
    service: Option<&RecoveryAdmin>,
    r: &mut hyper::Request<Body>,
    auth: &setjoin_authz::Authorized,
    c: &RequestContext,
    operation: [u8; 16],
    id: &str,
) -> Response<Body> {
    let Some(service) = service.filter(|s| s.ready) else {
        return problem(404, "client-assisted recovery is disabled", c, id);
    };
    let enabled = service
        .feature
        .enabled
        .load(std::sync::atomic::Ordering::Acquire);
    if !enabled {
        return problem(404, "client-assisted recovery is disabled", c, id);
    }
    if matches!(kind, Kind::Approve | Kind::Close) {
        return incident_mutation(kind, service, r, auth, c, operation, id).await;
    }
    if kind == Kind::Accept {
        return accept(service, r, auth, c, operation, id).await;
    }
    if kind == Kind::Open {
        return open(service, r, auth, c, operation, id).await;
    }
    let incident = if kind == Kind::Artifacts {
        let decoded = crate::mailboxes::segment(r.uri().path(), 6);
        match identifier(&decoded) {
            Some(id) => Some(id),
            None => return problem(400, "invalid recovery identifier", c, id),
        }
    } else {
        None
    };
    let limit = match crate::admin_identity_input::query(r.uri(), "limit").as_deref() {
        None | Some("") => {
            if kind != Kind::List {
                100i32
            } else {
                50i32
            }
        }
        Some(value) => match value.parse::<i32>() {
            Ok(n) if (1..=100).contains(&n) => n,
            _ => {
                return problem(
                    400,
                    match kind {
                        Kind::Signals => "invalid continuity signal limit",
                        Kind::Artifacts => "invalid recovery artifact limit",
                        Kind::List => "invalid recovery list limit",
                        Kind::Approve | Kind::Close | Kind::Open | Kind::Accept => {
                            unreachable!("writes served above")
                        }
                    },
                    c,
                    id,
                )
            }
        },
    };
    if let Some(incident) = incident {
        let user = auth.context().user_id();
        return match setjoin_platform::upgrades::read(
            &service.worker,
            "SELECT mail_recovery_artifact_list($1,$2::text::uuid,$3)::text",
            &[
                (&user, Type::INT8),
                (&incident, Type::TEXT),
                (&limit, Type::INT4),
            ],
        )
        .await
        {
            Ok(body) => crate::jmap::reply::response(
                body.unwrap_or_default(),
                c.identity.proto,
                id.to_owned(),
            ),
            Err(error) => refused(&error, r, c, id),
        };
    }
    if kind == Kind::Signals {
        let user = auth.context().user_id();
        return match setjoin_platform::upgrades::read(
            &service.worker,
            "SELECT continuity_admin_status($1,$2)::text",
            &[(&user, Type::INT8), (&limit, Type::INT4)],
        )
        .await
        {
            Ok(body) => crate::jmap::reply::response(
                body.unwrap_or_default(),
                c.identity.proto,
                id.to_owned(),
            ),
            Err(error) => refused(&error, r, c, id),
        };
    }
    let before =
        match crate::admin_identity_input::query(r.uri(), "before").filter(|v| !v.is_empty()) {
            None => None,
            Some(value) => match crate::guests_input::timestamp(&value) {
                Ok(value) => Some(value),
                Err(_) => return problem(400, "invalid recovery list cursor", c, id),
            },
        };
    let status = crate::admin_identity_input::query(r.uri(), "status").filter(|v| !v.is_empty());
    if status
        .as_deref()
        .is_some_and(|s| !matches!(s, "open" | "closed" | "expired"))
    {
        return problem(400, "invalid recovery incident status", c, id);
    }
    let user = auth.context().user_id();
    match setjoin_platform::upgrades::read(
        &service.worker,
        "SELECT mail_recovery_incident_list($1,$2,$3::text::timestamptz,$4::text)::text",
        &[
            (&user, Type::INT8),
            (&limit, Type::INT4),
            (&before, Type::TEXT),
            (&status, Type::TEXT),
        ],
    )
    .await
    {
        Ok(body) => {
            crate::jmap::reply::response(body.unwrap_or_default(), c.identity.proto, id.to_owned())
        }
        Err(error) => refused(&error, r, c, id),
    }
}

macro_rules! strict_body {
    ($name:ident { $($field:ident: $ty:ty = $key:literal),+ $(,)? }) => {
        #[derive(Default)]
        struct $name { $($field: $ty),+ }
        impl<'de> serde::Deserialize<'de> for $name {
            fn deserialize<D: serde::Deserializer<'de>>(decoder: D) -> Result<Self, D::Error> {
                struct Fields;
                impl<'de> serde::de::Visitor<'de> for Fields {
                    type Value = $name;
                    fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                        f.write_str("a recovery request object")
                    }
                    fn visit_unit<E: serde::de::Error>(self) -> Result<Self::Value, E> {
                        Ok($name::default())
                    }
                    fn visit_map<M: serde::de::MapAccess<'de>>(self, mut map: M) -> Result<Self::Value, M::Error> {
                        let mut body = $name::default();
                        while let Some(key) = map.next_key::<String>()? {
                            match crate::guests_input::fold(&key).as_str() {
                                $($key => { if let Some(value) = map.next_value::<Option<$ty>>()? { body.$field = value; } })+
                                _ => return Err(serde::de::Error::custom("unknown recovery request field")),
                            }
                        }
                        Ok(body)
                    }
                }
                decoder.deserialize_any(Fields)
            }
        }
    };
}
strict_body!(ReasonBody {
    reason: String = "reason"
});

async fn decode<T: serde::de::DeserializeOwned>(
    r: &mut hyper::Request<Body>,
) -> Result<T, &'static str> {
    use http_body_util::BodyExt;
    const CAP: usize = 1 << 20;
    let mut bytes = Vec::new();
    let mut failed = false;
    while bytes.len() <= CAP {
        let Some(frame) = r.body_mut().frame().await else {
            break;
        };
        match frame {
            Ok(frame) => {
                if let Ok(data) = frame.into_data() {
                    bytes.extend_from_slice(&data[..data.len().min(CAP + 1 - bytes.len())]);
                }
            }
            Err(_) => {
                failed = true;
                break;
            }
        }
    }
    let over = bytes.len() > CAP;
    bytes.truncate(CAP);
    let fixed = crate::guests_input::go_json_bytes(&bytes);
    let mut stream = serde_json::Deserializer::from_slice(&fixed).into_iter::<T>();
    let first = stream
        .next()
        .ok_or("invalid recovery request")?
        .map_err(|_| "invalid recovery request")?;
    if over || failed || stream.next().is_some() {
        return Err("recovery request must contain exactly one JSON object");
    }
    Ok(first)
}

const BAD_REASON: &str =
    "body reason must exactly match X-Audit-Reason and contain 8-1024 safe characters";
fn reason_ok(r: &hyper::Request<Body>, reason: &str) -> bool {
    let reason = reason.trim();
    (8..=1024).contains(&reason.len())
        && !reason.contains(['\r', '\n', '\0'])
        && r.headers()
            .get("x-audit-reason")
            .and_then(|v| std::str::from_utf8(v.as_bytes()).ok())
            .is_some_and(|header| header.trim() == reason)
}

async fn incident_mutation(
    kind: Kind,
    service: &RecoveryAdmin,
    r: &mut hyper::Request<Body>,
    auth: &setjoin_authz::Authorized,
    c: &RequestContext,
    operation: [u8; 16],
    id: &str,
) -> hyper::Response<Body> {
    let Some(incident) = identifier(&crate::mailboxes::segment(r.uri().path(), 6)) else {
        return problem(400, "invalid recovery identifier", c, id);
    };
    let body = match decode::<ReasonBody>(r).await {
        Ok(body) => body,
        Err(detail) => return problem(400, detail, c, id),
    };
    if !reason_ok(r, &body.reason) {
        return problem(400, BAD_REASON, c, id);
    }
    let actor = auth.context();
    let user = actor.user_id();
    let reason = body.reason.trim();
    let (command, sql) = match kind {
        Kind::Approve => ("mail_recovery_incident_approve", "SELECT mail_recovery_incident_approve($4::bigint,$5::text::uuid,$6::text)::text WHERE $1::bigint>0 AND $2::bigint>0 AND $3::text<>''"),
        Kind::Close => ("mail_recovery_incident_close", "SELECT mail_recovery_incident_close($4::bigint,$5::text::uuid,$6::text)::text WHERE $1::bigint>0 AND $2::bigint>0 AND $3::text<>''"),
        _ => unreachable!("incident mutation kind"),
    };
    match setjoin_platform::upgrades::write(
        &service.worker,
        actor,
        command,
        sql,
        &[
            (&user, Type::INT8),
            (&incident, Type::TEXT),
            (&reason, Type::TEXT),
        ],
        operation,
    )
    .await
    {
        setjoin_pg::CommandOutcome::Committed(body) => {
            crate::jmap::reply::response(body.unwrap_or_default(), c.identity.proto, id.to_owned())
        }
        setjoin_pg::CommandOutcome::RolledBack(
            setjoin_pg::Rejection::Statement(error) | setjoin_pg::Rejection::Body(error),
        ) => refused(&error, r, c, id),
        setjoin_pg::CommandOutcome::RolledBack(_) => {
            problem(500, "recovery control operation failed", c, id)
        }
        setjoin_pg::CommandOutcome::Unknown { operation } => {
            crate::mailboxes::unknown_outcome(operation, c, id)
        }
    }
}

fn identifier(value: &str) -> Option<String> {
    setjoin_contracts::ids::go_uuid(value).filter(|id| id != "00000000-0000-0000-0000-000000000000")
}

fn refused(
    error: &setjoin_pg::StatementFailure,
    r: &hyper::Request<Body>,
    c: &RequestContext,
    id: &str,
) -> Response<Body> {
    let refusal = match error.sqlstate.as_deref() {
        Some("BZ002" | "BZ003") => Some(setjoin_platform::upgrades::Refusal {
            status: 403,
            detail: if error.sqlstate.as_deref() == Some("BZ002") {
                "access denied"
            } else {
                "not authorized to send from this address"
            },
            code: error.sqlstate.clone().expect("matched SQLSTATE"),
            remediation:
                "Complete the required authorization, approval, or recovery step before retrying."
                    .into(),
        }),
        Some("BZ251") => setjoin_platform::upgrades::classify(error),
        _ => None,
    };
    let Some(refusal) = refusal else {
        return problem(500, "recovery control operation failed", c, id);
    };
    let path = crate::guests_input::go_utf8(&crate::inventory::unescape(
        r.uri()
            .path()
            .strip_prefix("/api")
            .unwrap_or(r.uri().path()),
    ));
    let kind = format!(
        "https://setjoin.com/problems/reducer/{}",
        refusal.code.to_ascii_lowercase()
    );
    crate::mailboxes::render(
        crate::problem::Problem::new(refusal.status, refusal.detail)
            .kind(&kind)
            .instance(&path)
            .code(&refusal.code)
            .retryable(false)
            .remediation(&refusal.remediation),
        Some(&crate::mailboxes::language(r)),
        c,
        id,
    )
}

#[derive(Default)]
struct OpenBody {
    incident: String,
    mailboxes: Vec<String>,
    evidence: std::collections::BTreeMap<String, String>,
    minimum: String,
    maximum: String,
    expires: Option<chrono::DateTime<chrono::Utc>>,
    reason: String,
    approval: bool,
    key: String,
}
impl<'de> serde::Deserialize<'de> for OpenBody {
    fn deserialize<D: serde::Deserializer<'de>>(decoder: D) -> Result<Self, D::Error> {
        struct Fields;
        impl<'de> serde::de::Visitor<'de> for Fields {
            type Value = OpenBody;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("a recovery incident request")
            }
            fn visit_unit<E: serde::de::Error>(self) -> Result<Self::Value, E> {
                Ok(OpenBody::default())
            }
            fn visit_map<M: serde::de::MapAccess<'de>>(
                self,
                mut fields: M,
            ) -> Result<Self::Value, M::Error> {
                let mut body = OpenBody::default();
                macro_rules! string {
                    ($field:ident) => {
                        if let Some(value) = fields.next_value::<Option<String>>()? {
                            body.$field = value;
                        }
                    };
                }
                while let Some(key) = fields.next_key::<String>()? {
                    match crate::guests_input::fold(&key).as_str() {
                        "incidentid" => { string!(incident); }
                        "minimumtimeline" => { string!(minimum); }
                        "maximumtimeline" => { string!(maximum); }
                        "reason" => { string!(reason); }
                        "idempotencykey" => { string!(key); }
                        "approvalrequired" => if let Some(value) = fields.next_value::<Option<bool>>()? { body.approval = value; },
                        "mailboxids" => {
                            body.mailboxes = fields.next_value::<Option<Vec<Option<String>>>>()?.unwrap_or_default().into_iter().map(Option::unwrap_or_default).collect();
                        }
                        "evidence" => match fields.next_value::<Option<std::collections::BTreeMap<String,Option<String>>>>()? {
                            None => body.evidence.clear(),
                            Some(values) => for (key,value) in values { body.evidence.insert(key,value.unwrap_or_default()); },
                        },
                        "expiresat" => if let Some(value) = fields.next_value::<Option<String>>()? {
                            body.expires = Some(crate::guests_input::parse_time(&value).map_err(|_|serde::de::Error::custom("invalid recovery time"))?);
                        },
                        _ => return Err(serde::de::Error::custom("unknown recovery request field")),
                    }
                }
                Ok(body)
            }
        }
        decoder.deserialize_any(Fields)
    }
}
fn positive(value: &str) -> Option<i64> {
    let id: i64 = value.parse().ok()?;
    (id > 0 && id.to_string() == value).then_some(id)
}

// Go exactIdempotency writes its problem, then AdminOpen appends the scope
// problem. Preserve those two wire documents; each uses the shared encoder.
fn idempotency_problems(detail: &str, c: &RequestContext, id: &str) -> hyper::Response<Body> {
    let body = crate::problem::Problem::new(400, detail).body()
        + &crate::problem::Problem::new(400, "invalid recovery incident scope").body();
    let mut response = crate::jmap::reply::response(body, c.identity.proto, id.to_owned());
    *response.status_mut() = hyper::StatusCode::BAD_REQUEST;
    response
        .headers_mut()
        .insert("content-type", "application/problem+json".parse().unwrap());
    response
}
async fn open(
    service: &RecoveryAdmin,
    r: &mut hyper::Request<Body>,
    auth: &setjoin_authz::Authorized,
    c: &RequestContext,
    operation: [u8; 16],
    id: &str,
) -> hyper::Response<Body> {
    use sha2::{Digest, Sha256};
    let body = match decode::<OpenBody>(r).await {
        Ok(body) => body,
        Err(detail) => return problem(400, detail, c, id),
    };
    if !reason_ok(r, &body.reason) {
        return problem(400, BAD_REASON, c, id);
    }
    let incident = identifier(&body.incident);
    let header = r
        .headers()
        .get("idempotency-key")
        .and_then(|v| std::str::from_utf8(v.as_bytes()).ok());
    if body.key.is_empty() || header.map(str::trim) != Some(body.key.as_str()) {
        return idempotency_problems(
            "body idempotencyKey must exactly match Idempotency-Key",
            c,
            id,
        );
    }
    let Some(key) = identifier(&body.key) else {
        return idempotency_problems("invalid recovery idempotency key", c, id);
    };
    let (Some(incident), Some(minimum), Some(maximum)) =
        (incident, positive(&body.minimum), positive(&body.maximum))
    else {
        return problem(400, "invalid recovery incident scope", c, id);
    };
    if maximum < minimum || !(1..=100).contains(&body.mailboxes.len()) {
        return problem(400, "invalid recovery incident scope", c, id);
    }
    let mut mailboxes = Vec::new();
    for mailbox in &body.mailboxes {
        let Some(mailbox) = positive(mailbox) else {
            return problem(400, "invalid recovery mailbox id", c, id);
        };
        mailboxes.push(mailbox);
    }
    let now = chrono::Utc::now();
    let Some(expires) = body.expires else {
        return problem(400, "invalid recovery incident evidence or expiry", c, id);
    };
    let mut seen = std::collections::BTreeSet::new();
    let evidence_ok = body.evidence.len() == mailboxes.len()
        && mailboxes.iter().all(|mailbox| {
            seen.insert(*mailbox)
                && body.evidence.get(&mailbox.to_string()).is_some_and(|hash| {
                    hash.len() == 64
                        && hash
                            .bytes()
                            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
                })
        });
    if !evidence_ok || expires <= now || expires > now + chrono::Duration::days(7) {
        return problem(400, "invalid recovery incident evidence or expiry", c, id);
    }
    if crate::platform_upgrades::step_up(auth, &incident).is_none() {
        return problem(
            403,
            "fresh AAL2 step-up with two verified factors is required",
            c,
            id,
        );
    }
    let actor = auth.context();
    let user = actor.user_id();
    let at = chrono::DateTime::from_timestamp(auth.issued_at(), 0)
        .expect("fresh AAL2 issued time")
        .to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    let binding = Sha256::digest(
        format!(
            "setjoin-mail-recovery-step-up-v1\n{user}\n{}\n{at}\n{incident}",
            auth.token_id()
        )
        .as_bytes(),
    )
    .to_vec();
    let evidence = serde_json::to_string(&body.evidence).expect("string evidence map");
    let expires = expires.timestamp_micros();
    let reason = body.reason.trim();
    let outcome=setjoin_platform::upgrades::write(&service.worker,actor,"mail_recovery_incident_open",
        "SELECT mail_recovery_incident_open($4::bigint,$5::text::uuid,$6::bigint[],$7::text::jsonb,$8::bigint,$9::bigint,'epoch'::timestamptz+$10::bigint*interval '1 microsecond',$11::text,$12::boolean,$13::bytea,$14::text::uuid)::text WHERE $1::bigint>0 AND $2::bigint>0 AND $3::text<>''",
        &[(&user,Type::INT8),(&incident,Type::TEXT),(&mailboxes,Type::INT8_ARRAY),(&evidence,Type::TEXT),(&minimum,Type::INT8),(&maximum,Type::INT8),(&expires,Type::INT8),(&reason,Type::TEXT),(&body.approval,Type::BOOL),(&binding,Type::BYTEA),(&key,Type::TEXT)],operation,
    ).await;
    match outcome {
        setjoin_pg::CommandOutcome::Committed(body) => {
            let mut response = crate::jmap::reply::response(
                body.unwrap_or_default(),
                c.identity.proto,
                id.to_owned(),
            );
            *response.status_mut() = hyper::StatusCode::CREATED;
            response
        }
        setjoin_pg::CommandOutcome::RolledBack(
            setjoin_pg::Rejection::Statement(error) | setjoin_pg::Rejection::Body(error),
        ) => refused(&error, r, c, id),
        setjoin_pg::CommandOutcome::RolledBack(_) => {
            problem(500, "recovery control operation failed", c, id)
        }
        setjoin_pg::CommandOutcome::Unknown { operation } => {
            crate::mailboxes::unknown_outcome(operation, c, id)
        }
    }
}

strict_body!(AcceptBody {
    resolution: String = "resolution",
    reason: String = "reason"
});
async fn accept(
    service: &RecoveryAdmin,
    r: &mut hyper::Request<Body>,
    auth: &setjoin_authz::Authorized,
    c: &RequestContext,
    operation: [u8; 16],
    id: &str,
) -> Response<Body> {
    let Some(artifact) = identifier(&crate::mailboxes::segment(r.uri().path(), 6)) else {
        return problem(400, "invalid recovery identifier", c, id);
    };
    let body = match decode::<AcceptBody>(r).await {
        Ok(body) => body,
        Err(detail) => return problem(400, detail, c, id),
    };
    if !reason_ok(r, &body.reason) {
        return problem(400, BAD_REASON, c, id);
    }
    if !matches!(body.resolution.as_str(), "accept" | "accept_fork") {
        return problem(400, "invalid recovery resolution", c, id);
    }
    let actor = auth.context();
    let user = actor.user_id();
    let reason = body.reason.trim();
    match setjoin_platform::upgrades::write(&service.worker,actor,"mail_recovery_artifact_ingest",
        "SELECT mail_recovery_artifact_ingest($4::bigint,$5::text::uuid,$6::text,$7::text)::text WHERE $1::bigint>0 AND $2::bigint>0 AND $3::text<>''",
        &[(&user,Type::INT8),(&artifact,Type::TEXT),(&body.resolution,Type::TEXT),(&reason,Type::TEXT)],operation,
    ).await {
        setjoin_pg::CommandOutcome::Committed(body)=>crate::jmap::reply::response(body.unwrap_or_default(),c.identity.proto,id.to_owned()),
        setjoin_pg::CommandOutcome::RolledBack(setjoin_pg::Rejection::Statement(error)|setjoin_pg::Rejection::Body(error))=>refused(&error,r,c,id),
        setjoin_pg::CommandOutcome::RolledBack(_)=>problem(500,"recovery control operation failed",c,id),
        setjoin_pg::CommandOutcome::Unknown{operation}=>crate::mailboxes::unknown_outcome(operation,c,id),
    }
}

struct CacheStop(std::sync::Mutex<Option<tokio::sync::oneshot::Sender<()>>>);
impl CacheStop {
    fn stop(&self) {
        if let Some(stop) = self.0.lock().expect("recovery cache stop").take() {
            let _ = stop.send(());
        }
    }
}
impl Drop for CacheStop {
    fn drop(&mut self) {
        self.stop();
    }
}
#[derive(Clone)]
struct FeatureCache {
    enabled: std::sync::Arc<std::sync::atomic::AtomicBool>,
    stop: std::sync::Arc<CacheStop>,
}
impl FeatureCache {
    async fn reload(value: &std::sync::atomic::AtomicBool, worker: &ScopedExecutor) {
        let enabled=worker.read("SELECT COALESCE((SELECT enabled FROM feature_toggles WHERE key='feature.client_recovery_ingest'),false)",&[]).await.ok().and_then(|rows|rows.first().and_then(|row|row.try_get::<_,bool>(0).ok())).unwrap_or(false);
        value.store(enabled, std::sync::atomic::Ordering::Release);
    }
    async fn new(worker: ScopedExecutor, direct: Option<String>) -> Self {
        use setjoin_pg::workers::DirectListener;
        let value = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let (send, mut stop) = tokio::sync::oneshot::channel();
        let guard = std::sync::Arc::new(CacheStop(std::sync::Mutex::new(Some(send))));
        let mut listener = match direct.as_deref() {
            Some(dsn) => tokio::time::timeout(
                std::time::Duration::from_secs(5),
                DirectListener::connect(dsn, "config_changed"),
            )
            .await
            .ok()
            .and_then(Result::ok),
            None => None,
        };
        // Subscribe before loading, closing the same startup window as Go.
        Self::reload(&value, &worker).await;
        if let Some(direct) = direct {
            let value = value.clone();
            tokio::spawn(async move {
                loop {
                    if listener.is_none() {
                        tokio::select! {_=&mut stop=>return,_=tokio::time::sleep(std::time::Duration::from_secs(1))=>{}}
                        listener = tokio::select! {_=&mut stop=>return,r=tokio::time::timeout(std::time::Duration::from_secs(5),DirectListener::connect(&direct,"config_changed"))=>r.ok().and_then(Result::ok)};
                        if listener.is_some() {
                            Self::reload(&value, &worker).await;
                        }
                    }
                    let Some(active) = listener.as_mut() else {
                        continue;
                    };
                    let message = tokio::select! {_=&mut stop=>return,r=active.recv()=>r};
                    if message.is_none() {
                        listener = None;
                        continue;
                    }
                    // Notifications are hints only. Read authoritative rows, never
                    // trust payload values (including malformed/forged envelopes).
                    tokio::select! {_=&mut stop=>return,_=tokio::time::sleep(std::time::Duration::from_millis(50))=>{}}
                    Self::reload(&value, &worker).await;
                }
            });
        }
        Self {
            enabled: value,
            stop: guard,
        }
    }
}
impl RecoveryAdmin {
    pub(crate) async fn new(worker: ScopedExecutor, ready: bool, direct: Option<String>) -> Self {
        let feature = FeatureCache::new(worker.clone(), direct).await;
        Self {
            worker,
            ready,
            feature,
        }
    }
    pub(crate) fn shutdown(&self) {
        self.feature.stop.stop();
    }
}
