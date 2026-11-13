//! Owner-side observer, independent from the request executor. No model SQL.
use super::BoxError;
use crate::fixture::Seed;
use serde_json::{json, Value};
use std::collections::HashMap;
pub struct Observation {
    pub rows: Value,
    ids: HashMap<(String, String), String>,
    actor: i64,
    space: i64,
    domain: i64,
    mailbox: i64,
    node: i64,
    email: String,
}
pub async fn snapshot(c: &tokio_postgres::Client, s: &Seed) -> Result<Observation, BoxError> {
    let mut rows = json!({});
    let tables = [
        ("spaces", "drive_spaces", "id=$1"),
        ("nodes", "drive_nodes", "space_id=$1"),
        ("files", "drive_files", "space_id=$1"),
        ("versions", "drive_file_versions", "space_id=$1"),
        ("branches", "drive_file_branches", "space_id=$1"),
        ("changes", "drive_changes", "space_id=$1"),
        ("drive_audit", "drive_audit_log", "space_id=$1"),
        ("grants", "drive_export_grants", "space_id=$1"),
        (
            "alarms",
            "drive_audit_alarms",
            "space_id=$1 OR created_by=(SELECT owner_user_id FROM drive_spaces WHERE id=$1)",
        ),
        ("sessions", "office_editor_sessions", "space_id=$1"),
        ("launches", "office_editor_launches", "space_id=$1"),
        ("locks", "office_wopi_locks", "space_id=$1"),
        ("receipts", "office_save_receipts", "space_id=$1"),
        (
            "labels",
            "drive_version_labels",
            "version_id IN(SELECT id FROM drive_file_versions WHERE space_id=$1)",
        ),
    ];
    for (name, table, filter) in tables {
        let order = match name {
            "files" => "node_id",
            "changes" => "seq",
            "labels" => "version_id,label",
            "locks" => "session_id",
            _ => "id",
        };
        let sql =
            format!("SELECT to_jsonb(t)::text FROM {table} t WHERE {filter} ORDER BY {order}");
        rows[name] = json!(c
            .query(&sql, &[&s.space])
            .await?
            .iter()
            .map(|r| serde_json::from_str::<Value>(&r.get::<_, String>(0)))
            .collect::<Result<Vec<_>, _>>()?);
    }
    for(name,sql,args)in [
 ("version_chunks","SELECT to_jsonb(t)::text FROM drive_version_chunks t JOIN drive_file_versions v ON v.id=t.version_id WHERE v.space_id=$1 ORDER BY version_id,stream,ordinal",s.space),
 ("members","SELECT to_jsonb(t)::text FROM drive_space_members t WHERE space_id=$1 ORDER BY user_id",s.space),
 ("claims","SELECT to_jsonb(t)::text FROM drive_upload_claims t WHERE user_id=$1 ORDER BY scope_key,sha256",s.account.user),
 ("authorizations","SELECT to_jsonb(t)::text FROM drive_upload_authorizations t WHERE user_id=$1 ORDER BY scope_key,sha256,target_node_id",s.account.user),
 ("mailboxes","SELECT to_jsonb(t)::text FROM mailboxes t WHERE id=$1",s.account.mailbox),
 ("core_audit","SELECT to_jsonb(t)::text FROM admin_audit_log t WHERE user_id=$1 ORDER BY id",s.account.user),
 ]{rows[name]=json!(c.query(sql,&[&args]).await?.iter().map(|r|serde_json::from_str::<Value>(&r.get::<_,String>(0))).collect::<Result<Vec<_>,_>>()?);}
    let locks = c
        .query(
            "SELECT to_jsonb(t)::text FROM drive_file_locks t WHERE space_id=$1 ORDER BY node_id",
            &[&s.space],
        )
        .await?;
    if !locks.is_empty() {
        rows["file_locks"] = json!(locks
            .iter()
            .map(|r| serde_json::from_str::<Value>(&r.get::<_, String>(0)))
            .collect::<Result<Vec<_>, _>>()?);
    }
    let chunks=c.query("SELECT to_jsonb(ch)::text,ch.ref_count=(SELECT count(*) FROM drive_version_chunks vc WHERE vc.scope_key=ch.scope_key AND vc.chunk_sha256=ch.sha256) FROM drive_chunks ch WHERE EXISTS(SELECT 1 FROM drive_version_chunks vc JOIN drive_file_versions v ON v.id=vc.version_id WHERE v.space_id=$1 AND vc.scope_key=ch.scope_key AND vc.chunk_sha256=ch.sha256) ORDER BY scope_key,sha256",&[&s.space]).await?;
    if chunks.iter().any(|r| !r.get::<_, bool>(1)) {
        return Err("chunk refcount invariant".into());
    }
    rows["chunks"] = json!(chunks
        .iter()
        .map(|r| serde_json::from_str::<Value>(&r.get::<_, String>(0)))
        .collect::<Result<Vec<_>, _>>()?);
    let invalid: i64 = c
        .query_one(
            "SELECT count(*) FROM verify_drive_audit_chain($1) WHERE NOT valid",
            &[&s.space],
        )
        .await?
        .get(0);
    if invalid != 0 {
        return Err("broken Drive audit chain".into());
    }
    let core_invalid:i64=c.query_one("SELECT count(*) FROM admin_audit_log t CROSS JOIN LATERAL verify_audit_chain(t.id,t.id) v WHERE t.user_id=$1 AND NOT v.valid",&[&s.account.user]).await?.get(0);
    if core_invalid != 0 {
        return Err("broken core audit chain".into());
    }
    let email: String = c
        .query_one("SELECT email FROM users WHERE id=$1", &[&s.account.user])
        .await?
        .get(0);
    let mut o = Observation {
        rows,
        ids: HashMap::new(),
        actor: s.account.user,
        space: s.space,
        domain: s.account.domain,
        mailbox: s.account.mailbox,
        node: s.node,
        email,
    };
    for (i, member) in o.rows["members"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|r| r["user_id"] != o.actor)
        .enumerate()
    {
        o.ids.insert(
            ("actor".into(), member["user_id"].to_string()),
            format!("<other-actor:{i}>"),
        );
    }
    let mut other_actors = std::collections::BTreeSet::new();
    for table in ["members", "drive_audit"] {
        for row in o.rows[table].as_array().unwrap() {
            if let Some(actor) = row["user_id"].as_i64() {
                if actor != o.actor {
                    other_actors.insert(actor);
                }
            }
        }
    }
    for (i, actor) in other_actors.into_iter().enumerate() {
        o.ids.insert(
            ("actor".into(), actor.to_string()),
            format!("<other-actor:{i}>"),
        );
    }
    for (table, kind) in [
        ("spaces", "space"),
        ("nodes", "node"),
        ("versions", "version"),
        ("branches", "branch"),
        ("grants", "grant"),
        ("alarms", "alarm"),
        ("sessions", "session"),
        ("launches", "launch"),
        ("receipts", "receipt"),
        ("core_audit", "core-audit"),
    ] {
        let mut ordered = o.rows[table].as_array().unwrap().clone();
        if matches!(kind, "session" | "launch" | "receipt") {
            ordered.sort_by_key(|r| r["created_at"].as_str().unwrap_or("").to_owned());
        }
        let mut ids: Vec<Value> = ordered
            .iter()
            .filter_map(|r| r.get("id").cloned())
            .collect();
        if !matches!(kind, "session" | "launch" | "receipt") {
            ids.sort_by(|a, b| match (a.as_i64(), b.as_i64()) {
                (Some(a), Some(b)) => a.cmp(&b),
                _ => a.to_string().cmp(&b.to_string()),
            });
        }
        for (i, id) in ids.iter().enumerate() {
            o.ids
                .insert((kind.into(), id.to_string()), format!("<{kind}:{i}>"));
        }
    }
    Ok(o)
}
impl Observation {
    pub fn normalize(&self, v: &mut Value, key: &str, table: &str) -> Result<(), BoxError> {
        if v.is_null() {
            return Ok(());
        }
        let kind = match key {
            "id" => match table {
                "mailboxes" => "mailbox",
                "spaces" => "space",
                "nodes" => "node",
                "versions" => "version",
                "branches" => "branch",
                "grants" => "grant",
                "alarms" => "alarm",
                "sessions" => "session",
                "launches" => "launch",
                "receipts" => "receipt",
                "core_audit" => "core-audit",
                _ => "",
            },
            "space_id" | "spaceId" => "space",
            "file_node_id" | "fileNodeId" | "node_id" | "nodeId" | "parent_id" | "parentId"
            | "newNodeId" => "node",
            "opened_from_version_id"
            | "version_id"
            | "versionId"
            | "parent_version_id"
            | "parentVersionId"
            | "head_version_id"
            | "headVersionId"
            | "base_version_id"
            | "baseVersionId"
            | "fromVersionId"
            | "forked_from_version_id"
            | "forkedFromVersionId"
            | "conflict_of"
            | "conflictOf"
            | "merged_from_version_id"
            | "result_version_id"
            | "expected_base_id" => "version",
            "branch_id" | "branchId" | "result_branch_id" => "branch",
            "session_id" | "sessionId" => "session",
            "launch_id" | "launchId" => "launch",
            "grant_id" | "grantId" => "grant",
            "holderId" | "minted_by" | "revoked_by" | "consumed_by" | "authorUserId"
            | "author_user_id" | "user_id" | "actor_user_id" | "actorUserId" | "owner_user_id"
            | "created_by" | "createdBy" | "resolved_by" | "resolvedBy" | "granted_by"
            | "author" | "actorId" | "userId" | "grantee" | "purged_by" => "actor",
            "domain_id" => "domain",
            "mailbox_id" => "mailbox",
            _ => "",
        };
        if kind == "actor" && *v == self.actor {
            *v = json!("<actor>");
            return Ok(());
        }
        if kind == "domain" && *v == self.domain {
            *v = json!("<domain>");
            return Ok(());
        }
        if kind == "mailbox" && *v == self.mailbox {
            *v = json!("<mailbox>");
            return Ok(());
        }
        if let Some(id) = self.ids.get(&(kind.into(), v.to_string())) {
            *v = json!(id);
            return Ok(());
        }
        match v {
            Value::Object(m) => {
                if let Some(source) = m.get("source").and_then(Value::as_str).map(str::to_owned) {
                    let k = match source.as_str() {
                        "version" => "versionId",
                        "branch" => "branchId",
                        "office" => "receiptId",
                        _ => "",
                    };
                    if !k.is_empty() {
                        if let Some(v) = m.get_mut("sourceId") {
                            self.normalize(v, k, table)?;
                        }
                    }
                }
                let target = m
                    .get("target_type")
                    .or_else(|| m.get("targetType"))
                    .and_then(Value::as_str)
                    .map(|s| match s {
                        "space" => "spaceId",
                        "version" => "versionId",
                        "branch" => "branchId",
                        _ => "nodeId",
                    })
                    .map(str::to_owned);
                if let Some(kind) = target {
                    for k in ["target_id", "targetId"] {
                        if let Some(v) = m.get_mut(k) {
                            self.normalize(v, &kind, table)?;
                        }
                    }
                }
                for (k, v) in m {
                    self.normalize(v, k, if table.is_empty() { k } else { table })?;
                }
            }
            Value::Array(a) => {
                for v in a {
                    self.normalize(v, key, table)?
                }
            }
            Value::String(t) if key == "cohort_key" && t == &format!("file-{}", self.node) => {
                *t = "file-<node:0>".into()
            }
            Value::String(t) if matches!(key, "wopiSrc" | "editorUrl") => {
                *t = t
                    .replace(&format!("/files/{}", self.node), "/files/<node:0>")
                    .replace(&format!("%2Ffiles%2F{}", self.node), "%2Ffiles%2F<node:0>");
            }
            Value::String(t) if t == &self.email => *t = "<actor-email>".into(),
            Value::String(t)
                if key == "at"
                    || key.ends_with("_at")
                    || key.ends_with("At")
                    || key == "retain_until"
                    || key == "worm_applied_until" =>
            {
                if key == "sending_quota_reset_at" {
                    chrono::NaiveDate::parse_from_str(t, "%Y-%m-%d")?;
                    return Ok(());
                }
                chrono::DateTime::parse_from_rfc3339(t)
                    .map_err(|e| format!("invalid {key} timestamp {t}: {e}"))?;
                *t = "<timestamp>".into();
            }
            Value::String(t) if key == "_checksum" || key == "checksum" => {
                if t.len() != 64 || !t.bytes().all(|b| b.is_ascii_hexdigit()) {
                    return Err("invalid audit checksum".into());
                }
                *t = "<verified-checksum>".into();
            }
            Value::String(t) if key == "token_hash" => {
                if t.len() != 64 || !t.bytes().all(|b| b.is_ascii_hexdigit()) {
                    return Err("invalid credential hash".into());
                }
                *t = "<credential-hash>".into();
            }
            Value::String(t) if key == "storage_ref" => {
                *t = t.replace(&format!("/s{}/", self.space), "/s<space>/")
            }
            Value::String(t) if key == "scope_key" && t == &format!("s{}", self.space) => {
                *t = "s<space>".into()
            }
            _ => {}
        }
        Ok(())
    }
    pub fn csv(&self, raw: &str) -> Result<String, BoxError> {
        let bytes = raw.as_bytes();
        let mut start = 0;
        let mut cells = Vec::new();
        let mut rows = Vec::new();
        let mut quoted = false;
        let mut i = 0;
        while i < bytes.len() {
            match bytes[i] {
                b'"' => {
                    if quoted && bytes.get(i + 1) == Some(&b'"') {
                        i += 1
                    } else {
                        quoted = !quoted
                    }
                }
                b',' | b'\n' if !quoted => {
                    let cell = &raw[start..i];
                    let decoded = if cell.starts_with('"') && cell.ends_with('"') {
                        cell[1..cell.len() - 1].replace("\"\"", "\"")
                    } else {
                        cell.into()
                    };
                    cells.push((start, i, decoded));
                    start = i + 1;
                    if bytes[i] == b'\n' {
                        if cells.len() != 8 {
                            return Err("audit CSV column count".into());
                        }
                        rows.push(std::mem::take(&mut cells));
                    }
                }
                _ => {}
            }
            i += 1;
        }
        if quoted || start != raw.len() {
            return Err("audit CSV incomplete record".into());
        }
        let mut replacements = Vec::new();
        for row in rows.into_iter().skip(1) {
            chrono::DateTime::parse_from_rfc3339(&row[1].2)?;
            replacements.push((row[1].0, row[1].1, "<timestamp>".to_owned()));
            if row[2].2 == self.email {
                replacements.push((row[2].0, row[2].1, "<actor-email>".into()));
            }
            if !row[6].2.is_empty() {
                let mut id = json!(row[6].2.parse::<i64>()?);
                self.normalize(
                    &mut id,
                    match row[5].2.as_str() {
                        "version" => "versionId",
                        "branch" => "branchId",
                        "space" => "spaceId",
                        _ => "nodeId",
                    },
                    "",
                )?;
                if let Some(text) = id.as_str() {
                    replacements.push((row[6].0, row[6].1, text.to_owned()));
                }
            }
        }
        let mut out = raw.to_owned();
        replacements.sort_by_key(|(a, _, _)| *a);
        for (a, b, text) in replacements.into_iter().rev() {
            let text = if raw[a..b].starts_with('"') {
                format!("\"{}\"", text.replace('"', "\"\""))
            } else {
                text
            };
            out.replace_range(a..b, &text);
        }
        Ok(out)
    }
    pub fn normalized_rows(&self) -> Result<Value, BoxError> {
        let mut v = self.rows.clone();
        self.normalize(&mut v, "", "")?;
        Ok(v)
    }
    pub fn normalize_response(
        &self,
        v: &mut Value,
        path: &str,
        canonical: &str,
    ) -> Result<(), BoxError> {
        use base64::Engine;
        use sha2::Digest;
        if let Some(raw) = v.as_str() {
            if raw.starts_with("ID,Timestamp,User,IP,Action,Target Type,Target ID,Notes\n") {
                *v = json!(self.csv(raw)?);
            }
        }
        for (field, table) in [("accessToken", "launches"), ("token", "grants")] {
            if let Some(token) = v.get(field).and_then(Value::as_str) {
                let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(token)?;
                if bytes.len() != 32 {
                    return Err("invalid issued credential entropy".into());
                }
                let hash = format!("{:x}", sha2::Sha256::digest(token.as_bytes()));
                if !self.rows[table]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|r| r["token_hash"] == hash)
                {
                    return Err("issued credential does not match stored hash".into());
                }
                v[field] = json!("<issued-credential>");
            }
        }
        if let Some(cursor) = v.get("nextCursor").and_then(Value::as_str) {
            let (payload, signature) = cursor.split_once('.').ok_or("cursor missing signature")?;
            let mut payload: Value = serde_json::from_slice(
                &base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(payload)?,
            )?;
            if base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(signature)?
                .len()
                != 32
            {
                return Err("cursor signature length".into());
            }
            let kind = match payload["sourceRank"].as_i64() {
                Some(10) => "versionId",
                Some(20 | 21) => "branchId",
                Some(30 | 40) => "",
                Some(50) => "receiptId",
                _ => return Err("unknown cursor source rank".into()),
            };
            if !kind.is_empty() {
                self.normalize(&mut payload["sourceId"], kind, "")?;
            }
            v["nextCursor"] = json!({"payload":payload,"signature":"<process-hmac>"});
        }
        if let Some(instance) = v.get_mut("instance") {
            let decoded = decoded_path(path);
            if *instance == path {
                *instance = json!(canonical)
            } else if *instance == decoded && decoded != path {
                normalize_encoded_instance(v);
            }
        }
        self.normalize(
            v,
            "",
            match canonical {
                "/drive/search" | "/drive/spaces/{id}/trash" => "nodes",
                "/drive/files/{id}/versions" => "versions",
                "/drive/files/{id}/branches" => "branches",
                "/drive/audit-alarms" => "alarms",
                _ => "",
            },
        )
    }
}

/// Table snapshots are sets; HTTP arrays and ordered notifications remain ordered.
pub fn canonical_states(observation: &mut Value) {
    normalize_problem_bodies(observation);
    normalize_generated_names(observation);
    for key in ["before", "effects"] {
        if let Some(tables) = observation.get_mut(key).and_then(Value::as_object_mut) {
            for rows in tables.values_mut() {
                if let Some(rows) = rows.as_array_mut() {
                    rows.sort_by_key(Value::to_string);
                }
            }
        }
    }
}

pub fn normalize_generated_names(v: &mut Value) {
    match v {
        Value::Object(m) => {
            if m.get("auto_created") == Some(&json!(true))
                || m.get("autoCreated") == Some(&json!(true))
                || m.get("auto") == Some(&json!(true))
            {
                if let Some(Value::String(name)) = m.get_mut("name") {
                    let parts: Vec<_> = name.split_whitespace().collect();
                    if let Some(date) = parts
                        .iter()
                        .find(|part| chrono::NaiveDate::parse_from_str(part, "%Y-%m-%d").is_ok())
                    {
                        *name = name.replace(*date, "<date>");
                    }
                }
            }
            for v in m.values_mut() {
                normalize_generated_names(v)
            }
        }
        Value::Array(a) => {
            for v in a {
                normalize_generated_names(v)
            }
        }
        _ => {}
    }
}

pub fn normalize_encoded_instance(body: &mut Value) {
    if let Some(instance) = body
        .get("instance")
        .and_then(Value::as_str)
        .map(str::to_owned)
    {
        let mut parts: Vec<String> = instance.split('/').map(str::to_owned).collect();
        if parts.len() > 4 && parts[3].parse::<i64>().is_ok() {
            parts[3] = "{id}".into();
            body["instance"] = json!(parts.join("/"));
        }
    }
}

fn decoded_path(raw: &str) -> String {
    let bytes = raw.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let (Some(a), Some(b)) = (
                (bytes[i + 1] as char).to_digit(16),
                (bytes[i + 2] as char).to_digit(16),
            ) {
                out.push((a * 16 + b) as u8);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn normalize_problem_bodies(v: &mut Value) {
    match v {
        Value::Object(m) => {
            if m.get("headers")
                .is_some_and(|h| h["content-type"] == "application/problem+json")
            {
                if let Some(raw) = m.get("body").and_then(Value::as_str) {
                    if let Ok(body) = serde_json::from_str::<Value>(raw) {
                        m.insert("body".into(), body);
                    }
                }
            }
            for v in m.values_mut() {
                normalize_problem_bodies(v)
            }
        }
        Value::Array(a) => {
            for v in a {
                normalize_problem_bodies(v)
            }
        }
        _ => {}
    }
}
