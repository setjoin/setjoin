//! Shared F13 fixtures: signed test tokens, resource ledger and exact cleanup.
#![allow(dead_code)]
use super::common;
use super::BoxError;
use hyper::Response;
use serde_json::{json, Value};
use setjoin_conformance::fixture;

pub fn token(user: i64, jti: &str) -> String {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B, Engine};
    use p256::ecdsa::{signature::Signer, SigningKey};
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let h = B.encode(json!({"alg":"ES256","kid":"test-es256-1","typ":"JWT"}).to_string());
    let b = B.encode(
        json!({"uid":user,"email":"meet1@test","typ":"access","jti":jti,"fam":jti,
            "iss":"mailserver","aud":["mailserver-gateway"],"iat":now-10,"exp":now+600})
        .to_string(),
    );
    let sig: p256::ecdsa::Signature = SigningKey::from_slice(&[0x11; 32])
        .unwrap()
        .sign(format!("{h}.{b}").as_bytes());
    format!("{h}.{b}.{}", B.encode(sig.to_bytes()))
}

pub fn ledger(line: &str) -> Result<(), BoxError> {
    use std::io::Write;
    if let Ok(path) = std::env::var("GOFREE_RESOURCE_LEDGER") {
        writeln!(
            std::fs::OpenOptions::new().append(true).open(path)?,
            "{line}"
        )?;
    }
    Ok(())
}

/// Remove the accounts' meetings, the channels created for them and their
/// audits, then the accounts. Meeting rows go first (their FKs cascade).
pub async fn cleanup(
    c: &tokio_postgres::Client,
    accounts: &[&fixture::Account],
) -> Result<(), BoxError> {
    let users: Vec<i64> = accounts.iter().map(|a| a.user).collect();
    let channels: Vec<i64> = c
        .query(
            "SELECT id FROM chat_channels WHERE created_by = ANY($1)",
            &[&users],
        )
        .await?
        .iter()
        .map(|r| r.get(0))
        .collect();
    // Recordings reference their meeting without a cascade.
    c.execute(
        "DELETE FROM meeting_recordings WHERE meeting_id IN (SELECT id FROM meetings WHERE owner_user_id = ANY($1))",
        &[&users],
    )
    .await?;
    c.execute(
        "DELETE FROM meetings WHERE owner_user_id = ANY($1)",
        &[&users],
    )
    .await?;
    c.batch_execute(&format!(
        "BEGIN; SET LOCAL session_replication_role=replica; \
         DELETE FROM chat_audit_log WHERE channel_id = ANY(ARRAY[{0}]::bigint[]); \
         DELETE FROM admin_audit_log WHERE user_id = ANY(ARRAY[{1}]::bigint[]); COMMIT;",
        channels
            .iter()
            .map(i64::to_string)
            .collect::<Vec<_>>()
            .join(","),
        users
            .iter()
            .map(i64::to_string)
            .collect::<Vec<_>>()
            .join(",")
    ))
    .await?;
    for channel in channels {
        c.execute("DELETE FROM chat_channels WHERE id=$1", &[&channel])
            .await?;
    }
    // Spaces created for the accounts (a finished recording lands in the owner's drive)
    // reference their owner without a cascade.
    c.execute(
        "DELETE FROM drive_nodes WHERE space_id IN (SELECT id FROM drive_spaces WHERE owner_user_id = ANY($1))",
        &[&users],
    )
    .await?;
    c.batch_execute(&format!(
        "BEGIN; SET LOCAL session_replication_role=replica; \
         DELETE FROM drive_audit_log WHERE space_id IN (SELECT id FROM drive_spaces WHERE owner_user_id = ANY(ARRAY[{}]::bigint[])); COMMIT;",
        users.iter().map(i64::to_string).collect::<Vec<_>>().join(",")
    ))
    .await?;
    c.execute(
        "DELETE FROM drive_spaces WHERE owner_user_id = ANY($1)",
        &[&users],
    )
    .await?;
    for a in accounts {
        fixture::remove(c, a).await?;
    }
    Ok(())
}

pub async fn observe(response: Response<hyper::body::Incoming>) -> Result<Value, BoxError> {
    let status = response.status().as_u16();
    let headers = response
        .headers()
        .iter()
        .filter(|(k, _)| {
            !matches!(
                k.as_str(),
                "date" | "content-length" | "connection" | "transfer-encoding"
            )
        })
        .map(|(k, v)| (k.to_string(), json!(v.to_str().unwrap())))
        .collect::<serde_json::Map<_, _>>();
    let bytes = common::body_bytes(response).await;
    let body = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes)
            .unwrap_or_else(|_| Value::String(String::from_utf8_lossy(&bytes).into_owned()))
    };
    Ok(json!({"response":{"status":status,"headers":headers,"body":body}}))
}

pub async fn events(
    listeners: &mut [(String, setjoin_conformance::harness::Listener)],
    c: &tokio_postgres::Client,
) -> Result<Value, BoxError> {
    let mut out = Vec::new();
    for (channel, listener) in listeners.iter_mut() {
        for event in listener.drain(c).await? {
            out.push(json!({"channel":channel,"payload":serde_json::from_str::<Value>(&event)?}));
        }
    }
    Ok(json!(out))
}

pub async fn rows(c: &tokio_postgres::Client, sql: &str, users: &[i64]) -> Result<Value, BoxError> {
    let raw: String = c.query_one(sql, &[&users.to_vec()]).await?.get(0);
    Ok(serde_json::from_str(&raw)?)
}

/// Every table a Meet golden route can write, scoped to the two principals.
pub async fn snapshot(
    c: &tokio_postgres::Client,
    a: &fixture::Account,
    b: &fixture::Account,
) -> Result<Value, BoxError> {
    let users = [a.user, b.user];
    let mut out = serde_json::Map::new();
    for (name, sql) in [
        ("meetings", "SELECT coalesce(jsonb_agg(to_jsonb(t) ORDER BY id),'[]')::text FROM meetings t WHERE owner_user_id = ANY($1)"),
        ("meeting_participants", "SELECT coalesce(jsonb_agg(to_jsonb(t) ORDER BY meeting_id,identity),'[]')::text FROM meeting_participants t WHERE meeting_id IN (SELECT id FROM meetings WHERE owner_user_id = ANY($1))"),
        ("chat_channels", "SELECT coalesce(jsonb_agg(to_jsonb(t) ORDER BY id),'[]')::text FROM chat_channels t WHERE created_by = ANY($1)"),
        ("chat_channel_members", "SELECT coalesce(jsonb_agg(to_jsonb(t) ORDER BY channel_id,user_id),'[]')::text FROM chat_channel_members t WHERE channel_id IN (SELECT id FROM chat_channels WHERE created_by = ANY($1))"),
        ("chat_audit_log", "SELECT coalesce(jsonb_agg((to_jsonb(t)-'id'-'checksum'-'prev_checksum') ORDER BY id),'[]')::text FROM chat_audit_log t WHERE channel_id IN (SELECT id FROM chat_channels WHERE created_by = ANY($1))"),
        ("guest_notification_intents", "SELECT coalesce(jsonb_agg((to_jsonb(t)-'id') ORDER BY ref,user_id),'[]')::text FROM guest_notification_intents t WHERE user_id = ANY($1)"),
    ] {
        out.insert(name.into(), rows(c, sql, &users).await?);
    }
    let invalid: i64 = c
        .query_one(
            "SELECT count(*) FROM chat_channels c CROSS JOIN LATERAL verify_chat_audit_chain(c.id) v WHERE c.created_by = ANY($1) AND NOT v.valid",
            &[&users.to_vec()],
        )
        .await?
        .get(0);
    assert_eq!(invalid, 0, "chat audit chain");
    Ok(Value::Object(out))
}

pub async fn audit_rows(
    c: &tokio_postgres::Client,
    before: i64,
    a: &fixture::Account,
    b: &fixture::Account,
) -> Result<Value, BoxError> {
    let users = vec![a.user, b.user];
    let invalid: i64 = c
        .query_one(
            "SELECT count(*) FROM admin_audit_log t CROSS JOIN LATERAL verify_audit_chain(t.id,t.id) v WHERE t.id>$1 AND NOT v.valid",
            &[&before],
        )
        .await?
        .get(0);
    assert_eq!(invalid, 0, "core audit chain");
    let raw: String = c
        .query_one(
            "SELECT coalesce(jsonb_agg(to_jsonb(t)-'id'-'checksum'-'occurred_at' ORDER BY id),'[]')::text FROM admin_audit_log t WHERE id>$1 AND user_id = ANY($2)",
            &[&before, &users],
        )
        .await?
        .get(0);
    Ok(serde_json::from_str(&raw)?)
}

/// Generated currencies kept apart: user, meeting and channel IDs may collide
/// numerically, so each is replaced only under keys that carry its contract.
pub struct Ids {
    users: Vec<(i64, String)>,
    meetings: Vec<(i64, String)>,
    channels: Vec<(i64, String)>,
    requests: Vec<(i64, String)>,
    breakouts: Vec<(i64, String)>,
    recordings: Vec<(i64, String)>,
    presentations: Vec<(i64, String)>,
    participants: Vec<(i64, String)>,
    nodes: Vec<(i64, String)>,
    versions: Vec<(i64, String)>,
    text: Vec<(String, String)>,
}
impl Ids {
    pub async fn load(
        c: &tokio_postgres::Client,
        a: &fixture::Account,
        b: &fixture::Account,
    ) -> Result<Self, BoxError> {
        let mut ids = Ids {
            users: vec![(a.user, "<owner>".into()), (b.user, "<foreign>".into())],
            meetings: vec![],
            channels: vec![],
            requests: vec![],
            breakouts: vec![],
            recordings: vec![],
            presentations: vec![],
            participants: vec![],
            nodes: vec![],
            versions: vec![],
            text: vec![],
        };
        ids.refresh(c, a, b).await?;
        Ok(ids)
    }
    pub async fn with_new(
        mut self,
        c: &tokio_postgres::Client,
        a: &fixture::Account,
        b: &fixture::Account,
    ) -> Result<Self, BoxError> {
        self.refresh(c, a, b).await?;
        Ok(self)
    }
    async fn refresh(
        &mut self,
        c: &tokio_postgres::Client,
        a: &fixture::Account,
        b: &fixture::Account,
    ) -> Result<(), BoxError> {
        self.meetings.clear();
        self.channels.clear();
        self.requests.clear();
        self.breakouts.clear();
        self.recordings.clear();
        self.presentations.clear();
        self.participants.clear();
        self.nodes.clear();
        self.versions.clear();
        self.text.clear();
        for (label, user) in [("owner", a.user), ("foreign", b.user)] {
            for (n, row) in c
                .query(
                    "SELECT id,slug,room_name::text,chat_channel_id FROM meetings WHERE owner_user_id=$1 ORDER BY id",
                    &[&user],
                )
                .await?
                .iter()
                .enumerate()
            {
                let name = format!("{label}-{}", n + 1);
                self.meetings.push((row.get(0), format!("<meeting-{name}>")));
                self.text.push((row.get(1), format!("<slug-{name}>")));
                self.text.push((row.get(2), format!("<room-{name}>")));
                if let Some(channel) = row.get::<_, Option<i64>>(3) {
                    self.channels.push((channel, format!("<channel-{name}>")));
                }
            }
        }
        let users = vec![a.user, b.user];
        for (n, row) in c
            .query(
                "SELECT id FROM meeting_join_requests WHERE meeting_id IN (SELECT id FROM meetings WHERE owner_user_id = ANY($1)) ORDER BY id",
                &[&users],
            )
            .await?
            .iter()
            .enumerate()
        {
            self.requests.push((row.get(0), format!("<request-{}>", n + 1)));
        }
        for (n, row) in c
            .query(
                "SELECT id, room_name::text FROM meeting_breakouts WHERE meeting_id IN (SELECT id FROM meetings WHERE owner_user_id = ANY($1)) ORDER BY meeting_id, idx, id",
                &[&users],
            )
            .await?
            .iter()
            .enumerate()
        {
            self.breakouts.push((row.get(0), format!("<breakout-{}>", n + 1)));
            self.text.push((row.get(1), format!("<room-breakout-{}>", n + 1)));
        }
        for (n, row) in c
            .query(
                "SELECT id FROM meeting_recordings WHERE meeting_id IN (SELECT id FROM meetings WHERE owner_user_id = ANY($1)) ORDER BY id",
                &[&users],
            )
            .await?
            .iter()
            .enumerate()
        {
            let id: i64 = row.get(0);
            self.recordings.push((id, format!("<recording-{}>", n + 1)));
            // The staging key names its recording by number.
            self.text.push((format!("meet-egress/{id}-"), format!("meet-egress/<recording-{}>-", n + 1)));
        }
        for (n, row) in c
            .query(
                "SELECT id FROM meeting_presentations WHERE meeting_id IN (SELECT id FROM meetings WHERE owner_user_id = ANY($1)) ORDER BY id",
                &[&users],
            )
            .await?
            .iter()
            .enumerate()
        {
            let id: i64 = row.get(0);
            self.presentations.push((id, format!("<presentation-{}>", n + 1)));
            // The stable-reference path names its presentation by number.
            self.text.push((format!("annotations/p{id}-"), format!("annotations/<presentation-{}>-", n + 1)));
        }
        for (n, row) in c
            .query(
                "SELECT DISTINCT file_node_id FROM drive_file_versions WHERE author_user_id = ANY($1) ORDER BY 1",
                &[&users],
            )
            .await?
            .iter()
            .enumerate()
        {
            self.nodes.push((row.get(0), format!("<node-{}>", n + 1)));
        }
        for (n, row) in c
            .query(
                "SELECT id FROM drive_file_versions WHERE author_user_id = ANY($1) ORDER BY id",
                &[&users],
            )
            .await?
            .iter()
            .enumerate()
        {
            self.versions
                .push((row.get(0), format!("<version-{}>", n + 1)));
        }
        // Participant surrogate ids are named by meeting and identity.
        for row in c
            .query(
                "SELECT id, meeting_id, identity FROM meeting_participants WHERE meeting_id IN (SELECT id FROM meetings WHERE owner_user_id = ANY($1))",
                &[&users],
            )
            .await?
            .iter()
        {
            let (id, meeting, who): (i64, i64, String) = (row.get(0), row.get(1), row.get(2));
            let who = match who.strip_prefix("u:").and_then(|u| u.parse::<i64>().ok()) {
                Some(u) => Self::lookup(&self.users, u)
                    .and_then(|l| l.as_str().map(str::to_owned))
                    .unwrap_or(who),
                None if guest_identity(&who) => "g:<guest>".into(),
                None => who,
            };
            if let Some(Value::String(meeting)) = Self::lookup(&self.meetings, meeting) {
                self.participants.push((id, format!("<participant-{meeting}-{who}>")));
            }
        }
        Ok(())
    }
    fn lookup(table: &[(i64, String)], n: i64) -> Option<Value> {
        table.iter().find(|(id, _)| *id == n).map(|(_, l)| json!(l))
    }
    pub fn normalize(&self, value: &mut Value, key: &str, table: &str) {
        match value {
            Value::Object(o) => {
                let table_here = if o.contains_key("room_name") && o.contains_key("owner_user_id") {
                    "meetings"
                } else if o.contains_key("kind") && o.contains_key("created_by") {
                    "chat_channels"
                } else if o.contains_key("display_name") && o.contains_key("secret") {
                    "meeting_join_requests"
                } else if o.contains_key("idx") && o.contains_key("room_name") {
                    "meeting_breakouts"
                } else if o.contains_key("egress_id") && o.contains_key("started_by") {
                    "meeting_recordings"
                } else if o.contains_key("presenter_participant_id") {
                    "meeting_presentations"
                } else if o.contains_key("presentation_id")
                    && o.contains_key("kind")
                    && o.contains_key("created_at")
                    && !o.contains_key("snapshot_path")
                {
                    "meeting_presentation_events"
                } else if o.contains_key("snapshot_path") {
                    "meeting_presentation_annotations"
                } else {
                    table
                };
                // A participant's surrogate id is named by meeting and identity.
                if let (Some(Value::Number(m)), Some(Value::String(who)), true) =
                    (o.get("meeting_id"), o.get("identity"), o.contains_key("id"))
                {
                    let meeting = m.as_i64().and_then(|m| Self::lookup(&self.meetings, m));
                    let who = match who.strip_prefix("u:").and_then(|u| u.parse::<i64>().ok()) {
                        Some(u) => Self::lookup(&self.users, u)
                            .and_then(|l| l.as_str().map(str::to_owned))
                            .unwrap_or_else(|| who.clone()),
                        None if guest_identity(who) => "g:<guest>".into(),
                        None => who.clone(),
                    };
                    if let Some(Value::String(meeting)) = meeting {
                        o.insert("id".into(), format!("<participant-{meeting}-{who}>").into());
                    }
                }
                // Audit targets name a channel or meeting by their own contract.
                let target = o
                    .get("target_type")
                    .and_then(Value::as_str)
                    .map(str::to_owned);
                for (k, v) in o.iter_mut() {
                    if k == "target_id" && matches!(v, Value::Number(_)) {
                        let n = v.as_i64().unwrap();
                        let named = match target.as_deref() {
                            Some("chat_channel") => Self::lookup(&self.channels, n),
                            Some("meeting") => Self::lookup(&self.meetings, n),
                            _ => None,
                        };
                        if let Some(named) = named {
                            *v = named;
                        }
                    } else if (k.ends_with("_at") || k.ends_with("At") || k == "captionsSince")
                        && matches!(v, Value::String(_))
                    {
                        assert!(
                            chrono::DateTime::parse_from_rfc3339(v.as_str().unwrap()).is_ok(),
                            "invalid generated timestamp {k}: {v}"
                        );
                        *v = "<timestamp>".into();
                    } else {
                        self.normalize(v, k, table_here);
                    }
                }
            }
            Value::Array(items) => {
                for v in items {
                    self.normalize(v, key, table)
                }
            }
            Value::Number(n) => {
                let n = n.as_i64();
                let replacement = n.and_then(|n| match key {
                    "owner_user_id" | "user_id" | "created_by" | "userId" | "ownerUserId" => {
                        Self::lookup(&self.users, n)
                    }
                    "meeting_id" | "meetingId" => Self::lookup(&self.meetings, n),
                    "requestId" | "request_id" | "join_request_id" | "decided_by_request" => {
                        Self::lookup(&self.requests, n)
                    }
                    "breakoutId" | "breakout_id" | "myBreakoutId" => {
                        Self::lookup(&self.breakouts, n)
                    }
                    "recordingId" | "recording_id" => Self::lookup(&self.recordings, n),
                    "id" if table == "meeting_join_requests" => Self::lookup(&self.requests, n),
                    "id" if table == "meeting_breakouts" => Self::lookup(&self.breakouts, n),
                    "id" if table == "meeting_recordings" => Self::lookup(&self.recordings, n),
                    "decided_by" | "started_by" => Self::lookup(&self.users, n),
                    "chat_channel_id" | "chatChannelId" | "channel_id" => {
                        Self::lookup(&self.channels, n)
                    }
                    "presentation_id" | "presentationId" => Self::lookup(&self.presentations, n),
                    "id" if table == "meeting_presentations" => {
                        Self::lookup(&self.presentations, n)
                    }
                    "id" if table == "meeting_presentation_events"
                        || table == "meeting_presentation_annotations" =>
                    {
                        Some(json!("<row-id>"))
                    }
                    "presenter_participant_id"
                    | "actor_participant_id"
                    | "presenterParticipantId"
                    | "targetParticipantId"
                    | "myParticipantId" => Self::lookup(&self.participants, n),
                    "drive_node_id" | "driveNodeId" => Self::lookup(&self.nodes, n),
                    "drive_version_id" | "driveVersionId" => Self::lookup(&self.versions, n),
                    "initiated_by" | "last_actor_user_id" | "actor_user_id" => {
                        Self::lookup(&self.users, n)
                    }
                    "id" if table == "meetings" => Self::lookup(&self.meetings, n),
                    "id" if table == "chat_channels" => Self::lookup(&self.channels, n),
                    _ => None,
                });
                if let Some(r) = replacement {
                    *value = r;
                }
            }
            Value::String(s) if key == "secret" => *s = "<secret>".into(),
            // The envelope frame names its presentation as a decimal string.
            Value::String(s) if key == "presentationId" => {
                if let Some(Value::String(label)) = s
                    .parse::<i64>()
                    .ok()
                    .and_then(|n| Self::lookup(&self.presentations, n))
                {
                    *s = label;
                }
            }
            Value::String(s) => {
                let mut text = s.clone();
                for (raw, label) in &self.text {
                    text = text.replace(raw.as_str(), label);
                }
                for (user, label) in &self.users {
                    if text == format!("u:{user}") {
                        text = format!("u:{label}");
                    }
                    if text == format!("meet:{user}") {
                        text = format!("meet:{label}");
                    }
                    if text == format!("chat:{user}") {
                        text = format!("chat:{label}");
                    }
                }
                // Guest identities come from a sequence; the conference identity
                // names its meeting.
                if guest_identity(&text) {
                    text = "g:<guest>".into();
                }
                if let Some(Value::String(meeting)) = text
                    .strip_prefix("cc:")
                    .and_then(|n| n.parse::<i64>().ok())
                    .and_then(|n| Self::lookup(&self.meetings, n))
                {
                    text = format!("cc:{meeting}");
                }
                *s = text;
            }
            _ => {}
        }
    }
}

fn guest_identity(text: &str) -> bool {
    text.strip_prefix("g:")
        .is_some_and(|rest| !rest.is_empty() && rest.bytes().all(|b| b.is_ascii_digit()))
}

pub fn normalize_instance(value: &mut Value, actual: &str, canonical: &str) {
    match value {
        Value::Object(o) => {
            for (k, v) in o.iter_mut() {
                if k == "instance" && v.as_str() == Some(actual) {
                    *v = canonical.into();
                } else {
                    normalize_instance(v, actual, canonical);
                }
            }
        }
        Value::Array(items) => items
            .iter_mut()
            .for_each(|v| normalize_instance(v, actual, canonical)),
        _ => {}
    }
}
