//! End-user Chat: verified user identity, request credential and canonical reducers.
use setjoin_authz::AuthContext;
use setjoin_pg::{MailboxAuthContext, ScopedExecutor, StatementFailure, Type};

fn scope(actor: &AuthContext) -> MailboxAuthContext {
    actor.database_scope()
}

pub async fn saves(exec: &ScopedExecutor, actor: &AuthContext) -> Result<String, StatementFailure> {
    let rows = exec
        .read_scoped(
            &scope(actor),
            "SELECT chat_saves_list($1)::text",
            &[(&actor.user_id(), Type::INT8)],
        )
        .await?;
    Ok(rows[0].get::<_, String>(0))
}

/// Personal bookmark toggle. The canonical reducer owns authorization and effects.
pub async fn save(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    message: i64,
    operation: [u8; 16],
) -> setjoin_pg::CommandOutcome<serde_json::Value, StatementFailure> {
    use setjoin_contracts::{
        command::CommandEnvelope,
        ids::{Digest, OperationId},
    };
    use sha2::{Digest as _, Sha256};
    let auth = scope(actor);
    let envelope = CommandEnvelope {
        operation: OperationId(operation),
        authority: auth.authority(),
        binding: setjoin_db::lifecycle::accepted_contract(),
        payload_digest: Digest(Sha256::digest(b"chat_save_toggle").into()),
        command: (),
    };
    setjoin_pg::run_receipted_command(exec,setjoin_pg::ReceiptCommand{family:"F12",command:"chat_save_toggle"},&envelope,&auth,std::time::Instant::now()+std::time::Duration::from_secs(30),
        "SELECT to_jsonb(chat_save_toggle($2,$4))::text WHERE $1::bigint IS NOT NULL AND $3::text IS NOT NULL",&[(&message,Type::INT8)],
        |rows|serde_json::from_str(rows[0].get::<_,&str>(0)).map_err(|_|StatementFailure{sqlstate:None,message:"invalid Chat result".into(),hint:None})).await
}

pub async fn thread(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    message: i64,
) -> Result<String, StatementFailure> {
    let rows = exec
        .read_scoped(
            &scope(actor),
            "SELECT chat_thread_list($1,$2)::text",
            &[(&actor.user_id(), Type::INT8), (&message, Type::INT8)],
        )
        .await?;
    Ok(rows[0].get::<_, String>(0))
}

pub async fn my_threads(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    limit: Option<i64>,
) -> Result<String, StatementFailure> {
    let rows = exec
        .read_scoped(
            &scope(actor),
            "SELECT chat_my_threads($1,$2::bigint::integer)::text",
            &[(&actor.user_id(), Type::INT8), (&limit, Type::INT8)],
        )
        .await?;
    Ok(rows[0].get::<_, String>(0))
}

pub struct Search<'a> {
    pub query: &'a str,
    pub channel: Option<i64>,
    pub author: Option<i64>,
    pub before: Option<i64>,
    pub has: Option<String>,
    pub han: bool,
}
pub async fn search(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    search: Search<'_>,
) -> Result<String, StatementFailure> {
    let rows = exec
        .read_scoped(
            &scope(actor),
            "SELECT chat_search($1,$2,$3,$4,$5,$6,$7)::text",
            &[
                (&actor.user_id(), Type::INT8),
                (&search.query, Type::TEXT),
                (&search.channel, Type::INT8),
                (&search.author, Type::INT8),
                (&search.before, Type::INT8),
                (&search.has, Type::TEXT),
                (&search.han, Type::BOOL),
            ],
        )
        .await?;
    Ok(rows[0].get::<_, String>(0))
}

async fn member_command(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    name: &'static str,
    sql: &str,
    params: &[setjoin_pg::Param<'_>],
    operation: [u8; 16],
) -> setjoin_pg::CommandOutcome<serde_json::Value, StatementFailure> {
    use setjoin_contracts::{
        command::CommandEnvelope,
        ids::{Digest, OperationId},
    };
    use sha2::{Digest as _, Sha256};
    let auth = scope(actor);
    let envelope = CommandEnvelope {
        operation: OperationId(operation),
        authority: auth.authority(),
        binding: setjoin_db::lifecycle::accepted_contract(),
        payload_digest: Digest(Sha256::digest(name.as_bytes()).into()),
        command: (),
    };
    setjoin_pg::run_receipted_command(
        exec,
        setjoin_pg::ReceiptCommand {
            family: "F12",
            command: name,
        },
        &envelope,
        &auth,
        std::time::Instant::now() + std::time::Duration::from_secs(30),
        sql,
        params,
        |rows| {
            serde_json::from_str(rows[0].get::<_, &str>(0)).map_err(|_| StatementFailure {
                sqlstate: None,
                message: "invalid Chat result".into(),
                hint: None,
            })
        },
    )
    .await
}
pub async fn edit(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    message: i64,
    body: &str,
    operation: [u8; 16],
) -> setjoin_pg::CommandOutcome<serde_json::Value, StatementFailure> {
    member_command(exec,actor,"chat_message_edit","SELECT to_jsonb(chat_message_edit($2,$4,$5))::text WHERE $1::bigint IS NOT NULL AND $3::text IS NOT NULL",&[(&message,Type::INT8),(&body,Type::TEXT)],operation).await
}

pub async fn delete(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    message: i64,
    operation: [u8; 16],
) -> setjoin_pg::CommandOutcome<serde_json::Value, StatementFailure> {
    member_command(exec,actor,"chat_message_delete","SELECT to_jsonb(chat_message_delete($2,$4))::text WHERE $1::bigint IS NOT NULL AND $3::text IS NOT NULL",&[(&message,Type::INT8)],operation).await
}

pub async fn reaction(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    message: i64,
    emoji: &str,
    operation: [u8; 16],
) -> setjoin_pg::CommandOutcome<serde_json::Value, StatementFailure> {
    member_command(exec,actor,"chat_reaction_toggle","SELECT to_jsonb(chat_reaction_toggle($2,$4,$5))::text WHERE $1::bigint IS NOT NULL AND $3::text IS NOT NULL",&[(&message,Type::INT8),(&emoji,Type::TEXT)],operation).await
}

pub async fn pin(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    message: i64,
    operation: [u8; 16],
) -> setjoin_pg::CommandOutcome<serde_json::Value, StatementFailure> {
    member_command(exec,actor,"chat_pin_toggle","SELECT to_jsonb(chat_pin_toggle($2,$4))::text WHERE $1::bigint IS NOT NULL AND $3::text IS NOT NULL",&[(&message,Type::INT8)],operation).await
}

/// `translate.egress` intent record, written before message text leaves for
/// the AI provider (frozen Go `translateMessage`, active only while
/// `feature.chat_compliance` is ON). `after` is the JSON text Go marshals.
pub async fn translate_egress(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    channel: i64,
    message: i64,
    after: &str,
    operation: [u8; 16],
) -> setjoin_pg::CommandOutcome<serde_json::Value, StatementFailure> {
    member_command(exec,actor,"chat_access_audit_translate","SELECT 'null'::text FROM (SELECT chat_access_audit($2,$4,'translate.egress','message',$5,NULL,$6::text::jsonb,NULL,NULL)) effect WHERE $1::bigint IS NOT NULL AND $3::text IS NOT NULL",&[(&channel,Type::INT8),(&message,Type::INT8),(&after,Type::TEXT)],operation).await
}

pub async fn scheduled(
    exec: &ScopedExecutor,
    actor: &AuthContext,
) -> Result<String, StatementFailure> {
    let rows = exec
        .read_scoped(
            &scope(actor),
            "SELECT chat_scheduled_list($1)::text",
            &[(&actor.user_id(), Type::INT8)],
        )
        .await?;
    Ok(rows[0].get::<_, String>(0))
}

pub async fn cancel(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    action: &str,
    operation: [u8; 16],
) -> setjoin_pg::CommandOutcome<serde_json::Value, StatementFailure> {
    member_command(exec,actor,"chat_scheduled_cancel","SELECT 'null'::text FROM (SELECT chat_scheduled_cancel($2,$4::text::uuid)) effect WHERE $1::bigint IS NOT NULL AND $3::text IS NOT NULL",&[(&action,Type::TEXT)],operation).await
}

pub async fn vote(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    poll: i64,
    option: i64,
    operation: [u8; 16],
) -> setjoin_pg::CommandOutcome<serde_json::Value, StatementFailure> {
    member_command(exec,actor,"chat_poll_vote","SELECT 'null'::text FROM (SELECT chat_poll_vote($2,$4,$5)) effect WHERE $1::bigint IS NOT NULL AND $3::text IS NOT NULL",&[(&poll,Type::INT8),(&option,Type::INT8)],operation).await
}

pub async fn close(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    poll: i64,
    operation: [u8; 16],
) -> setjoin_pg::CommandOutcome<serde_json::Value, StatementFailure> {
    member_command(exec,actor,"chat_poll_close","SELECT 'null'::text FROM (SELECT chat_poll_close($2,$4)) effect WHERE $1::bigint IS NOT NULL AND $3::text IS NOT NULL",&[(&poll,Type::INT8)],operation).await
}

pub async fn results(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    poll: i64,
) -> Result<String, StatementFailure> {
    let rows = exec
        .read_scoped(
            &scope(actor),
            "SELECT chat_poll_results($1,$2)::text",
            &[(&actor.user_id(), Type::INT8), (&poll, Type::INT8)],
        )
        .await?;
    Ok(rows[0].get::<_, String>(0))
}

/// Frozen Go authorizes any successful global preview-cache image. The
/// authenticated Chat-capability gate precedes this explicit shared-cache read.
pub async fn image_type(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    hash: &str,
) -> Result<Option<String>, StatementFailure> {
    let rows = exec
        .read_scoped(
            &scope(actor),
            "SELECT content_type FROM blobs WHERE sha256=$1 AND chat_link_preview_image_owner($1)",
            &[(&hash, Type::TEXT)],
        )
        .await?;
    Ok(rows.first().and_then(|r| r.try_get(0).ok()))
}

/// Go's independent routine denial audit. Failure never changes the denial;
/// the canonical reducer owns audit-policy suppression and the chain row.
pub async fn app_blocked(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    ip: &str,
    operation: [u8; 16],
) {
    let _=member_command(exec,actor,"app_blocked","SELECT 'null'::text FROM (SELECT audit_write($2,'app_blocked','app',NULL,NULL,NULL,$4::text::inet,'chat','routine')) effect WHERE $1::bigint IS NOT NULL AND $3::text IS NOT NULL",&[(&ip,Type::TEXT)],operation).await;
}

/// Global URL cache, as in Go. The actor is the committed send's verified actor;
/// URL possession is the cache capability, independent of channel membership.
pub async fn unfurl_lookup(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    hash: &str,
) -> Result<Option<serde_json::Value>, StatementFailure> {
    let rows = exec
        .read_scoped(
            &scope(actor),
            "SELECT chat_link_preview_lookup($1)::text",
            &[(&hash, Type::TEXT)],
        )
        .await?;
    rows[0]
        .get::<_, Option<String>>(0)
        .map(|raw| {
            serde_json::from_str(&raw).map_err(|_| StatementFailure {
                sqlstate: None,
                message: "invalid unfurl cache JSON".into(),
                hint: None,
            })
        })
        .transpose()
}
/// Only a message ID returned by this actor's committed send reaches this seam.
/// The canonical reducer owns gone/GxP checks, provenance and notifications.
pub async fn unfurl_apply(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    message: i64,
    hash: &str,
    operation: [u8; 16],
) -> setjoin_pg::CommandOutcome<serde_json::Value, StatementFailure> {
    member_command(exec,actor,"chat_message_unfurl_apply",
        "SELECT 'null'::text FROM (SELECT chat_message_unfurl_apply($4,$5)) effect WHERE $1::bigint IS NOT NULL AND $2::bigint IS NOT NULL AND $3::text IS NOT NULL",
        &[(&message,Type::INT8),(&hash,Type::TEXT)],operation).await
}

pub async fn unfurl_claim(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    hash: &str,
    url: &str,
    operation: [u8; 16],
) -> setjoin_pg::CommandOutcome<serde_json::Value, StatementFailure> {
    member_command(exec,actor,"chat_link_preview_claim",
        "SELECT to_jsonb(chat_link_preview_claim($4,$5))::text WHERE $1::bigint IS NOT NULL AND $2::bigint IS NOT NULL AND $3::text IS NOT NULL",
        &[(&hash,Type::TEXT),(&url,Type::TEXT)],operation).await
}
pub struct FetchedPreview {
    pub title: Option<String>,
    pub description: Option<String>,
    pub image: Option<String>,
    pub ok: bool,
}
pub async fn unfurl_write(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    hash: &str,
    preview: &FetchedPreview,
    operation: [u8; 16],
) -> setjoin_pg::CommandOutcome<serde_json::Value, StatementFailure> {
    let status = if preview.ok { "ok" } else { "error" };
    member_command(exec,actor,"chat_link_preview_cache_write",
        "SELECT 'null'::text FROM (SELECT chat_link_preview_cache_write($4,$5,$6,$7,$8)) effect WHERE $1::bigint IS NOT NULL AND $2::bigint IS NOT NULL AND $3::text IS NOT NULL",
        &[(&hash,Type::TEXT),(&preview.title,Type::TEXT),(&preview.description,Type::TEXT),(&preview.image,Type::TEXT),(&status,Type::TEXT)],operation).await
}

/// Frozen Go's one INSERT after the image PUT. This is shared content-addressed
/// blob metadata; the trusted hash/size/type come from the fetched bytes, never
/// a user-owned identity. Cache reducers exclusively maintain references.
#[allow(clippy::too_many_arguments)]
pub async fn unfurl_blob(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    hash: &str,
    reference: &str,
    size: i64,
    content_type: &str,
    operation: [u8; 16],
) -> setjoin_pg::CommandOutcome<serde_json::Value, StatementFailure> {
    member_command(exec,actor,"chat_unfurl_blob_insert",
        "WITH inserted AS (INSERT INTO blobs(sha256,minio_ref,size_bytes,content_type,ref_count) SELECT $4,$5,$6,$7,0 WHERE $1::bigint IS NOT NULL AND $2::bigint IS NOT NULL AND $3::text IS NOT NULL ON CONFLICT(sha256) DO NOTHING) SELECT 'null'::text",
        &[(&hash,Type::TEXT),(&reference,Type::TEXT),(&size,Type::INT8),(&content_type,Type::TEXT)],operation).await
}
