//! Admin identity (F01) slice `idv2-sources`, second half: the group mapping and
//! inventory reads, the identity job reads and the source detail. Reads only; the
//! writes live in `idv2_writes`. Wire shapes follow `encoding/json` (struct order or
//! sorted maps, HTML-escaped by the caller).
use super::idv2::Refusal;
use super::{go_escape, nano, s};
use serde_json::Value;
use setjoin_pg::{ScopedExecutor, StatementFailure, Type};

fn failed(detail: &str) -> Refusal {
    Refusal {
        status: 500,
        detail: detail.to_owned(),
        reducer: None,
    }
}

/// Go's `sensitiveList`: `SensitivePermissions` sorted.
pub const SENSITIVE: [&str; 34] = [
    "access.policy_write",
    "approvals.manage",
    "apps.manage",
    "audit.export",
    "backup.write",
    "chat.compliance_manage",
    "chat.ediscovery",
    "compliance.write",
    "directory.groups.manage",
    "domains.write",
    "drive.manage",
    "exchange.assessment.attest",
    "exchange.assessment.audit",
    "exchange.assessment.decide",
    "exchange.assessment.delete",
    "exchange.assessment.publish",
    "exchange.assessment.run",
    "federation.manage",
    "guests.manage",
    "identity.write",
    "mail.export",
    "mail.offline_policy",
    "mail.security",
    "mam.write",
    "office.manage",
    "roles.manage",
    "security.write",
    "sharing.manage",
    "system.config",
    "system.recovery",
    "system.upgrade",
    "users.delete",
    "users.impersonate",
    "users.suspend",
];

/// One decoded `groupMapping` element. `bad` records a type mismatch (Go's
/// `json.Unmarshal` fills what it can and reports an error at the end).
#[derive(Default)]
struct Mapping {
    group: String,
    distribution: Option<i64>,
    role: Option<String>,
    department: Option<i64>,
}

/// The member for `name` as `encoding/json` finds it: an exact key first, then a
/// case-folded one.
fn member<'a>(object: &'a serde_json::Map<String, Value>, name: &str) -> Option<&'a Value> {
    object.get(name).or_else(|| {
        object
            .iter()
            .find(|(k, _)| super::fold(k) == name)
            .map(|(_, v)| v)
    })
}

fn decode_mappings(raw: &str) -> (Vec<Mapping>, bool) {
    let Ok(Value::Array(items)) = serde_json::from_str::<Value>(raw) else {
        // `null` leaves the slice nil; any other type is a decode error.
        return (Vec::new(), !raw.trim().eq("null"));
    };
    let mut bad = false;
    let mut out = Vec::with_capacity(items.len());
    for item in &items {
        let mut m = Mapping::default();
        match item {
            Value::Null => {}
            Value::Object(object) => {
                match member(object, "idp_group") {
                    None | Some(Value::Null) => {}
                    Some(Value::String(v)) => m.group = v.clone(),
                    Some(_) => bad = true,
                }
                for (name, slot) in [
                    ("distribution_group_id", &mut m.distribution),
                    ("department_id", &mut m.department),
                ] {
                    match member(object, name) {
                        None | Some(Value::Null) => {}
                        Some(v) => match v.as_i64() {
                            Some(n) if v.is_i64() || v.is_u64() => *slot = Some(n),
                            _ => bad = true,
                        },
                    }
                }
                match member(object, "admin_role") {
                    None | Some(Value::Null) => {}
                    Some(Value::String(v)) => m.role = Some(v.clone()),
                    Some(_) => bad = true,
                }
            }
            _ => bad = true,
        }
        out.push(m);
    }
    (out, bad)
}

fn render_mappings(list: &[Mapping]) -> String {
    let items: Vec<String> = list
        .iter()
        .map(|m| {
            let mut text = format!("{{\"idp_group\":{}", s(&m.group));
            if let Some(n) = m.distribution {
                text.push_str(&format!(",\"distribution_group_id\":{n}"));
            }
            if let Some(role) = &m.role {
                text.push_str(&format!(",\"admin_role\":{}", s(role)));
            }
            if let Some(n) = m.department {
                text.push_str(&format!(",\"department_id\":{n}"));
            }
            text.push('}');
            text
        })
        .collect();
    format!("[{}]", items.join(","))
}

/// `GET /admin/identity/group-mappings` (request pool; Go ignores query errors).
pub async fn group_mappings(exec: &ScopedExecutor) -> String {
    let mut saml: std::collections::BTreeMap<String, String> = Default::default();
    let mut oidc: std::collections::BTreeMap<String, String> = Default::default();
    if let Ok(rows) = exec
        .read(
            "SELECT idp_entity_id, COALESCE(group_mappings, '[]'::JSONB)::text FROM saml_sp_registrations WHERE enabled = TRUE",
            &[],
        )
        .await
    {
        for row in rows {
            if let (Ok(idp), Ok(raw)) = (row.try_get::<_, String>(0), row.try_get::<_, String>(1)) {
                saml.insert(idp, render_mappings(&decode_mappings(&raw).0));
            }
        }
    }
    if let Ok(rows) = exec
        .read(
            "SELECT key, value::text FROM system_config WHERE key LIKE 'oidc_provider_%_config'",
            &[],
        )
        .await
    {
        for row in rows {
            let (Ok(_key), Ok(raw)) = (row.try_get::<_, String>(0), row.try_get::<_, String>(1))
            else {
                continue;
            };
            let Ok(Value::Object(config)) = serde_json::from_str::<Value>(&raw) else {
                continue;
            };
            let name = match member(&config, "name") {
                None | Some(Value::Null) => String::new(),
                Some(Value::String(v)) => v.clone(),
                Some(_) => continue,
            };
            let list = match member(&config, "group_mappings") {
                None | Some(Value::Null) => Vec::new(),
                Some(v) => {
                    let (list, bad) = decode_mappings(&v.to_string());
                    if bad {
                        continue;
                    }
                    list
                }
            };
            oidc.insert(name, render_mappings(&list));
        }
    }
    let object = |m: &std::collections::BTreeMap<String, String>| {
        let items: Vec<String> = m.iter().map(|(k, v)| format!("{}:{v}", s(k))).collect();
        format!("{{{}}}", items.join(","))
    };
    go_escape(&format!(
        "{{\"oidc\":{},\"saml\":{}}}\n",
        object(&oidc),
        object(&saml)
    ))
}

fn inventory_failed() -> Refusal {
    failed("inventory unavailable")
}

/// `GET /admin/identity/inventory` on the worker pool; the body Go's `WriteJSON` sends.
pub async fn inventory(worker: &ScopedExecutor) -> Result<String, Refusal> {
    let people = worker
        .read(
            &format!(
                "SELECT count(*)::bigint, count(*) FILTER (WHERE u.enabled)::bigint, \
                 count(*) FILTER (WHERE NOT u.enabled)::bigint, \
                 count(*) FILTER (WHERE g.user_id IS NOT NULL)::bigint, \
                 count(*) FILTER (WHERE g.user_id IS NULL)::bigint, \
                 count(*) FILTER (WHERE g.user_id IS NULL AND NOT EXISTS (SELECT 1 FROM public.mailboxes mb WHERE mb.user_id = u.id AND mb.is_primary))::bigint, \
                 count(*) FILTER (WHERE u.oidc_subject IS NOT NULL AND u.oidc_issuer IS NOT NULL)::bigint, \
                 count(*) FILTER (WHERE (u.oidc_subject IS NULL) <> (u.oidc_issuer IS NULL))::bigint, \
                 count(*) FILTER (WHERE u.saml_name_id IS NOT NULL AND u.saml_idp_entity_id IS NOT NULL)::bigint, \
                 count(*) FILTER (WHERE (u.saml_name_id IS NULL) <> (u.saml_idp_entity_id IS NULL))::bigint, \
                 {} \
                 FROM public.users u LEFT JOIN public.guest_accounts g ON g.user_id = u.id",
                nano("clock_timestamp()")
            ),
            &[],
        )
        .await
        .map_err(|_| inventory_failed())?;
    let people = people.first().ok_or_else(inventory_failed)?;
    let n =
        |row: &setjoin_pg::Row, i: usize| row.try_get::<_, i64>(i).map_err(|_| inventory_failed());
    let generated: String = people.try_get(10).map_err(|_| inventory_failed())?;
    let mailboxes = worker
        .read(
            "SELECT count(*) FILTER (WHERE user_id IS NULL AND resource_type IS NULL)::bigint, \
             count(*) FILTER (WHERE user_id IS NULL AND resource_type IS NOT NULL)::bigint FROM public.mailboxes",
            &[],
        )
        .await
        .map_err(|_| inventory_failed())?;
    let mailboxes = mailboxes.first().ok_or_else(inventory_failed)?;
    let lifecycle = worker
        .read(
            "SELECT COALESCE(jsonb_object_agg(source, source_count), '{}'::jsonb)::text FROM (\
             SELECT COALESCE(NULLIF(btrim(sync_source), ''), 'unknown') AS source, count(*)::bigint AS source_count \
             FROM public.users GROUP BY 1) counts",
            &[],
        )
        .await
        .map_err(|_| inventory_failed())?;
    let lifecycle: String = lifecycle
        .first()
        .and_then(|r| r.try_get(0).ok())
        .ok_or_else(inventory_failed)?;
    let Ok(Value::Object(lifecycle)) = serde_json::from_str::<Value>(&lifecycle) else {
        return Err(inventory_failed());
    };
    let legacy = worker
        .read(
            "SELECT (SELECT count(*)::bigint FROM public.identity_legacy_federation_pair_inventory), \
             (SELECT count(*)::bigint FROM public.sso_distribution_group_legacy_inventory), \
             (SELECT count(*)::bigint FROM public.sso_admin_role_legacy_inventory)",
            &[],
        )
        .await
        .map_err(|_| inventory_failed())?;
    let legacy = legacy.first().ok_or_else(inventory_failed)?;
    let sensitive: Vec<String> = SENSITIVE.iter().map(|p| (*p).to_owned()).collect();
    let protected = worker
        .read(
            "SELECT * FROM (WITH break_glass AS (SELECT DISTINCT elem.raw_user_id::bigint AS user_id FROM public.system_config sc, \
             LATERAL jsonb_array_elements_text(sc.value) AS elem(raw_user_id) WHERE sc.key = 'ca_break_glass_user_ids'), \
             sensitive_holders AS (SELECT DISTINCT ara.user_id FROM public.admin_role_assignments ara \
             JOIN public.admin_role_groups rg ON rg.id = ara.role_group_id WHERE rg.permissions && $1::text[] \
             AND (ara.expires_at IS NULL OR ara.expires_at > now()) AND public.admin_assignment_active(ara.eligible, ara.activated_until)), \
             protected AS (SELECT user_id FROM break_glass UNION SELECT user_id FROM sensitive_holders) \
             SELECT (SELECT count(*)::bigint FROM protected), (SELECT count(*)::bigint FROM break_glass), \
             (SELECT count(*)::bigint FROM sensitive_holders)) q",
            &[(&sensitive, Type::TEXT_ARRAY)],
        )
        .await
        .map_err(|_| inventory_failed())?;
    let protected = protected.first().ok_or_else(inventory_failed)?;
    let secrets = worker
        .read(
            "SELECT * FROM (WITH secret_rows AS (SELECT CASE WHEN key LIKE 'ad_sync_%' THEN 'ad' WHEN key LIKE 'ldap_sync_%' THEN 'ldap' END AS connector, \
             CASE WHEN value IS NULL OR value = 'null'::jsonb OR value = '\"\"'::jsonb THEN 'unset' \
             WHEN jsonb_typeof(value) = 'object' AND value->>'format' = 'setjoin-config-secret' AND value->>'version' = '1' AND value ? 'ciphertext' THEN 'encrypted' \
             ELSE 'attention_required' END AS state FROM public.system_config \
             WHERE right(key, 4) = '_enc' AND (key LIKE 'ad_sync_%' OR key LIKE 'ldap_sync_%')), \
             connector_states AS (SELECT connector, CASE WHEN bool_or(state = 'attention_required') THEN 'attention_required' \
             WHEN bool_or(state = 'encrypted') THEN 'encrypted' ELSE 'unset' END AS state FROM secret_rows GROUP BY connector) \
             SELECT COALESCE(max(state) FILTER (WHERE connector = 'ad'), 'unset'), COALESCE(max(state) FILTER (WHERE connector = 'ldap'), 'unset') FROM connector_states) q",
            &[],
        )
        .await
        .map_err(|_| inventory_failed())?;
    let secrets = secrets.first().ok_or_else(inventory_failed)?;
    let ad: String = secrets.try_get(0).map_err(|_| inventory_failed())?;
    let ldap: String = secrets.try_get(1).map_err(|_| inventory_failed())?;
    let unclassified = n(people, 5)?;
    let (oidc_partial, saml_partial, legacy_pairs) = (n(people, 7)?, n(people, 9)?, n(legacy, 0)?);
    let (groups, roles) = (n(legacy, 1)?, n(legacy, 2)?);
    let mut blockers: Vec<&str> = Vec::new();
    if unclassified > 0 {
        blockers.push("unclassified_user_without_primary_mailbox");
    }
    if oidc_partial > 0 || saml_partial > 0 || legacy_pairs > 0 {
        blockers.push("legacy_incomplete_federation_pair");
    }
    if groups > 0 || roles > 0 {
        blockers.push("legacy_sso_entitlement_provenance");
    }
    if ad == "attention_required" || ldap == "attention_required" {
        blockers.push("connector_secret_attention_required");
    }
    let sources: Vec<String> = lifecycle
        .iter()
        .map(|(k, v)| format!("{}:{}", s(k), v))
        .collect();
    let body = format!(
        "{{\"schemaVersion\":1,\"generatedAt\":{},\"people\":{{\"total\":{},\"enabled\":{},\"disabled\":{},\"guests\":{},\"members\":{},\"unclassifiedWithoutMailbox\":{}}},\
         \"mailboxes\":{{\"shared\":{},\"resources\":{}}},\"lifecycleSources\":{{{}}},\
         \"federationPairs\":{{\"oidcComplete\":{},\"oidcPartial\":{},\"samlComplete\":{},\"samlPartial\":{},\"legacyInventoried\":{}}},\
         \"protectedAccounts\":{{\"total\":{},\"breakGlass\":{},\"sensitiveRoleHolders\":{}}},\
         \"entitlementAmbiguity\":{{\"distributionGroupMemberships\":{},\"adminRoleAssignments\":{}}},\
         \"connectorSecrets\":{{\"ad\":{},\"ldap\":{}}},\"blockers\":[{}]}}\n",
        s(&generated),
        n(people, 0)?,
        n(people, 1)?,
        n(people, 2)?,
        n(people, 3)?,
        n(people, 4)?,
        unclassified,
        n(mailboxes, 0)?,
        n(mailboxes, 1)?,
        sources.join(","),
        n(people, 6)?,
        oidc_partial,
        n(people, 8)?,
        saml_partial,
        legacy_pairs,
        n(protected, 0)?,
        n(protected, 1)?,
        n(protected, 2)?,
        groups,
        roles,
        s(&ad),
        s(&ldap),
        blockers.iter().map(|b| s(b)).collect::<Vec<_>>().join(",")
    );
    Ok(go_escape(&body))
}

/// `GET /admin/identity/v2/inventory/export`: the reducer's jsonb text.
pub async fn inventory_export(worker: &ScopedExecutor) -> Result<String, Refusal> {
    let rows = worker
        .read("SELECT identity_inventory_export()::text", &[])
        .await
        .map_err(|e| classify(&e).unwrap_or_else(|| failed("identity inventory export failed")))?;
    Ok(rows
        .first()
        .and_then(|r| r.try_get::<_, Option<String>>(0).ok().flatten())
        .unwrap_or_default())
}

/// `identity_job_read`: the jsonb text, empty when no row is visible to the actor.
pub async fn job(worker: &ScopedExecutor, actor: i64, id: &str) -> Result<String, Refusal> {
    let rows = worker
        .read(
            "SELECT identity_job_read($1,$2::text::uuid)::text",
            &[(&actor, Type::INT8), (&id, Type::TEXT)],
        )
        .await
        .map_err(|_| failed("identity job read failed"))?;
    Ok(rows
        .first()
        .and_then(|r| r.try_get::<_, Option<String>>(0).ok().flatten())
        .unwrap_or_default())
}

/// `identity_job_results` after the permission re-check.
pub async fn job_results(
    worker: &ScopedExecutor,
    actor: i64,
    id: &str,
    after: i64,
    limit: i32,
) -> Result<String, Refusal> {
    let rows = worker
        .read(
            "SELECT identity_job_results($1,$2::text::uuid,$3,$4)::text",
            &[
                (&actor, Type::INT8),
                (&id, Type::TEXT),
                (&after, Type::INT8),
                (&limit, Type::INT4),
            ],
        )
        .await
        .map_err(|e| classify(&e).unwrap_or_else(|| failed("identity job results failed")))?;
    Ok(rows
        .first()
        .and_then(|r| r.try_get::<_, Option<String>>(0).ok().flatten())
        .unwrap_or_default())
}

/// A known reducer refusal projected like `reducererr.WriteClassified`.
pub fn classify(e: &StatementFailure) -> Option<Refusal> {
    let code = e.sqlstate.as_deref()?;
    let (status, detail) = match code {
        "BZ228" | "BZ241" => (400, "invalidArguments"),
        "BZ229" | "BZ230" | "BZ232" | "BZ233" | "BZ234" | "BZ235" | "BZ237" | "BZ238" | "BZ240" => {
            (409, "conflict")
        }
        "BZ231" => (422, "unprocessable"),
        "BZ236" | "BZ239" => (403, "forbidden"),
        _ => return None,
    };
    let class_remediation = match status {
        409 => "Refresh current state, resolve the conflict, and retry.",
        403 => "Complete the required authorization, approval, or recovery step before retrying.",
        400 => "Correct the request fields and retry.",
        _ => "Correct the requested operation using the documented runbook and retry.",
    };
    // A HINT's `remediation` replaces the class text; a malformed HINT is no reducer error.
    let remediation = match e.hint.as_deref().filter(|h| !h.is_empty()) {
        None => class_remediation.to_owned(),
        Some(hint) => {
            let Ok(Value::Object(object)) = serde_json::from_str::<Value>(hint) else {
                return None;
            };
            match member(&object, "remediation") {
                Some(Value::String(text)) if !text.is_empty() => text.clone(),
                None | Some(Value::Null) | Some(Value::String(_)) => class_remediation.to_owned(),
                Some(_) => return None,
            }
        }
    };
    Some(Refusal {
        status,
        detail: detail.to_owned(),
        reducer: Some((code.to_owned(), remediation)),
    })
}

/// Go's `identitySourceSecretCatalog`.
pub fn secret_catalog(kind: &str) -> &'static [&'static str] {
    match kind {
        "ad" | "ldap" => &["bindPassword"],
        "scim" => &["bearerToken"],
        "saml" => &["metadataClientSecret"],
        "oidc" => &["clientSecret"],
        _ => &[],
    }
}

/// The decrypted stored source (`identityStoredSourceDocument`).
pub struct Stored {
    /// Compacted JSON of `document` (what `json.Marshal` writes), `null` when absent.
    pub document: String,
    /// The stored bytes of `document` verbatim; empty when absent (Go's nil `RawMessage`).
    pub raw: String,
    pub secrets: std::collections::BTreeMap<String, String>,
}

/// `decodeStoredIdentitySource`: an empty envelope is an empty document, anything else
/// is opened and strictly decoded. Any failure is Go's one "cannot be decrypted" 500.
pub fn decode_stored(
    codec: &setjoin_config_secret::ConfigSecretCodec,
    key: &str,
    envelope: &[u8],
) -> Option<Stored> {
    if envelope.is_empty() {
        return Some(Stored {
            document: "null".into(),
            raw: String::new(),
            secrets: Default::default(),
        });
    }
    let plain = codec
        .decrypt(&format!("identity_source.{key}"), envelope)
        .ok()?;
    let text = std::str::from_utf8(&plain).ok()?;
    let members: std::collections::BTreeMap<String, Box<serde_json::value::RawValue>> =
        serde_json::from_str(text).ok()?;
    let mut stored = Stored {
        document: "null".into(),
        raw: String::new(),
        secrets: Default::default(),
    };
    for (name, raw) in &members {
        match super::fold(name).as_str() {
            "document" => {
                stored.document = super::idv2::compact(raw.get());
                stored.raw = raw.get().to_owned();
            }
            "secrets" => {
                let parsed: Option<std::collections::BTreeMap<String, String>> =
                    serde_json::from_str(raw.get()).ok()?;
                stored.secrets = parsed.unwrap_or_default();
            }
            _ => return None,
        }
    }
    Some(stored)
}

/// One `identity_sources` row for the detail and the write paths.
pub struct SourceRow {
    pub id: i64,
    pub display_name: String,
    pub kind: String,
    pub state: String,
    pub generation: i64,
    pub mapping_version: i64,
    pub envelope: Vec<u8>,
    pub capabilities: String,
    pub last_success: Option<String>,
    pub last_failure: Option<String>,
    pub last_error: Option<String>,
}

/// `loadIdentitySource`; `None` is `pgx.ErrNoRows`.
pub async fn load_source(
    worker: &ScopedExecutor,
    key: &str,
) -> Result<Option<SourceRow>, StatementFailure> {
    let sql = format!(
        "SELECT id,display_name,kind,state,generation,mapping_version,config_envelope,capabilities::text,{},{},last_error_code \
         FROM identity_sources WHERE source_key=$1",
        nano("last_success_at"),
        nano("last_failure_at")
    );
    let rows = worker.read(&sql, &[(&key, Type::TEXT)]).await?;
    let Some(r) = rows.first() else {
        return Ok(None);
    };
    let bad = |_| StatementFailure {
        sqlstate: None,
        hint: None,
        message: "invalid identity source row".into(),
    };
    Ok(Some(SourceRow {
        id: r.try_get(0).map_err(bad)?,
        display_name: r.try_get(1).map_err(bad)?,
        kind: r.try_get(2).map_err(bad)?,
        state: r.try_get(3).map_err(bad)?,
        generation: r.try_get(4).map_err(bad)?,
        mapping_version: r.try_get(5).map_err(bad)?,
        envelope: r
            .try_get::<_, Option<Vec<u8>>>(6)
            .map_err(bad)?
            .unwrap_or_default(),
        capabilities: r.try_get(7).map_err(bad)?,
        last_success: r.try_get(8).map_err(bad)?,
        last_failure: r.try_get(9).map_err(bad)?,
        last_error: r.try_get(10).map_err(bad)?,
    }))
}

/// `GET /admin/identity/v2/sources/{sourceKey}` body (sorted map keys, compact).
pub fn source_detail_body(key: &str, row: &SourceRow, stored: &Stored) -> String {
    let posture: Vec<String> = {
        let mut names: Vec<&str> = secret_catalog(&row.kind).to_vec();
        names.sort_unstable();
        names
            .iter()
            .map(|n| {
                format!(
                    "{}:{}",
                    s(n),
                    stored.secrets.get(*n).is_some_and(|v| !v.is_empty())
                )
            })
            .collect()
    };
    let opt = |v: &Option<String>| v.as_deref().map(s).unwrap_or_else(|| "null".into());
    go_escape(&format!(
        "{{\"capabilities\":{},\"displayName\":{},\"document\":{},\"generation\":{},\"kind\":{},\"lastErrorCode\":{},\"lastFailureAt\":{},\"lastSuccessAt\":{},\"mappingVersion\":{},\"secretConfigured\":{{{}}},\"sourceKey\":{},\"state\":{}}}",
        super::idv2::compact(&row.capabilities),
        s(&row.display_name),
        stored.document,
        s(&row.generation.to_string()),
        s(&row.kind),
        opt(&row.last_error),
        opt(&row.last_failure),
        opt(&row.last_success),
        s(&row.mapping_version.to_string()),
        posture.join(","),
        s(key),
        s(&row.state)
    ))
}
