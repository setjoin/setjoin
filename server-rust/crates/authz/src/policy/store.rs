//! Request-credential reads of org policy metadata. No pooled SET ROLE.
use super::eval::{Context, Policy, Snapshot};
use serde_json::Value;
use setjoin_contracts::ids::ActorId;
use setjoin_pg::{Param, ScopedExecutor, StatementFailure, Type};
use sha2::{Digest, Sha256};

async fn documents(
    exec: &ScopedExecutor,
    sql: &str,
    params: &[Param<'_>],
) -> Result<Vec<Value>, StatementFailure> {
    exec.read(sql, params)
        .await?
        .iter()
        .map(|r| serde_json::from_str(&r.get::<_, String>(0)).map_err(|_| super::invalid()))
        .collect()
}
pub(super) async fn policies(exec: &ScopedExecutor) -> Result<Vec<Policy>, StatementFailure> {
    Ok(documents(exec,"SELECT to_jsonb(p)::text FROM conditional_access_policies p WHERE state IN ('on','report_only') AND deleted_at IS NULL ORDER BY priority ASC",&[]).await?.into_iter().filter(|p|["conditions","actions"].iter().all(|k|p[*k].is_null()||p[*k].is_object())).map(Policy::from_document).collect())
}
pub(super) async fn locations(exec: &ScopedExecutor) -> Result<Vec<Value>, StatementFailure> {
    documents(
        exec,
        "SELECT to_jsonb(l)::text FROM named_locations l WHERE deleted_at IS NULL",
        &[],
    )
    .await
}
pub(super) async fn strengths(exec: &ScopedExecutor) -> Result<Vec<Value>, StatementFailure> {
    documents(exec, "SELECT to_jsonb(s)::text FROM auth_strengths s", &[]).await
}
pub async fn break_glass(exec: &ScopedExecutor) -> Result<Vec<i64>, StatementFailure> {
    let rows = exec
        .read(
            "SELECT value::text FROM system_config WHERE key='ca_break_glass_user_ids'",
            &[],
        )
        .await?;
    Ok(rows
        .first()
        .and_then(|r| serde_json::from_str::<Vec<i64>>(&r.get::<_, String>(0)).ok())
        .unwrap_or_default())
}
impl Snapshot {
    /// Uncached, read-only simulator snapshot; errors abort the HTTP simulation.
    pub async fn load(exec: &ScopedExecutor) -> Result<Self, StatementFailure> {
        Ok(Self {
            policies: policies(exec).await?,
            locations: Some(locations(exec).await?),
            strengths: strengths(exec).await?,
            break_glass: break_glass(exec).await?,
        })
    }
}
/// Go resolves group and role membership with explicit user predicates. These
/// reads deliberately preserve its request-pool RLS view (no worker credential).
pub async fn resolve_scope(
    exec: &ScopedExecutor,
    user: i64,
) -> Result<(Vec<i64>, Vec<i64>), StatementFailure> {
    let groups = exec
        .read(
            "SELECT group_id FROM user_group_members WHERE user_id=$1",
            &[(&user, Type::INT8)],
        )
        .await?
        .iter()
        .map(|r| r.get(0))
        .collect();
    let roles=exec.read("SELECT role_group_id FROM admin_role_assignments WHERE user_id=$1 AND (expires_at IS NULL OR expires_at>now())",&[(&user,Type::INT8)]).await?.iter().map(|r|r.get(0)).collect();
    Ok((groups, roles))
}
/// Go's advisory device tier, with its two user-scoped FORCE-RLS reads.
pub async fn resolve_trust(exec: &ScopedExecutor, c: &Context) -> String {
    if c.device_fp.is_empty() || c.user_id <= 0 {
        return "unknown".into();
    }
    let hash = format!("{:x}", Sha256::digest(c.device_fp.as_bytes()));
    let actor = ActorId::new(c.user_id).expect("positive user");
    if exec.read_user_scoped(actor,"SELECT compliance_status='compliant' FROM managed_devices WHERE device_hash=$1 AND user_id=$2",&[(&hash,Type::TEXT),(&c.user_id,Type::INT8)]).await.is_ok_and(|r|r.first().is_some_and(|r|r.get::<_,bool>(0))){return "managed".into();}
    if exec.read_user_scoped(actor,"SELECT EXISTS(SELECT 1 FROM device_registry WHERE user_id=$1 AND device_hash=$2 AND last_seen>now()-INTERVAL '90 days' AND auth_count>=3)",&[(&c.user_id,Type::INT8),(&hash,Type::TEXT)]).await.is_ok_and(|r|r[0].get::<_,bool>(0)){return "known".into();}
    "unknown".into()
}
pub async fn resolve_geo(exec: &ScopedExecutor, country: &str) -> Result<String, StatementFailure> {
    if country.is_empty() {
        return Ok("low".into());
    }
    Ok(exec
        .read(
            "SELECT tier FROM geo_country_tiers WHERE country_code=$1",
            &[(&country, Type::TEXT)],
        )
        .await?
        .first()
        .map_or_else(|| "low".into(), |r| r.get(0)))
}
