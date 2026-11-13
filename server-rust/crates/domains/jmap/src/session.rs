//! Data behind the authenticated JMAP discovery session. Public branding reads
//! only the same named system_config keys Go exposes to ordinary members.
use setjoin_pg::{MailboxAuthContext, ScopedExecutor, StatementFailure, Type};
use std::collections::BTreeMap;

pub struct Delegated {
    pub id: i64,
    pub email: String,
    pub grants: Vec<String>,
    pub aliases: Vec<String>,
}
pub async fn delegated(
    exec: &ScopedExecutor,
    auth: &MailboxAuthContext,
) -> Result<Vec<Delegated>, StatementFailure> {
    let user = auth.actor().get();
    let mailbox = auth.mailbox().get();
    let rows=exec.read_iterated("SELECT * FROM (WITH delegated AS (SELECT md.mailbox_id,array_agg(DISTINCT md.permission::text ORDER BY md.permission::text) AS grants FROM mailbox_delegates md WHERE md.user_id=$1 AND md.permission IN ('read','send_as','send_on_behalf','full_access') AND md.mailbox_id<>$2 GROUP BY md.mailbox_id) SELECT d.mailbox_id,mb.email::text,d.grants,CASE WHEN d.grants && ARRAY['send_as','full_access']::text[] THEN ARRAY(SELECT a.email::text FROM aliases a WHERE a.mailbox_id=d.mailbox_id AND lower(a.email)<>lower(mb.email) ORDER BY lower(a.email),a.id) ELSE ARRAY[]::text[] END FROM delegated d JOIN mailboxes mb ON mb.id=d.mailbox_id WHERE mb.enabled=TRUE ORDER BY lower(mb.email),d.mailbox_id) AS owned_delegates", &[(&user,Type::INT8),(&mailbox,Type::INT8)]).await?;
    Ok(rows
        .into_iter()
        .filter_map(|r| {
            Some(Delegated {
                id: r.try_get(0).ok()?,
                email: r.try_get(1).ok()?,
                grants: r.try_get(2).ok()?,
                aliases: r.try_get(3).ok()?,
            })
        })
        .collect())
}

pub async fn effective_caps(
    exec: &ScopedExecutor,
    auth: &MailboxAuthContext,
) -> Result<String, StatementFailure> {
    let mailbox = auth.mailbox().get();
    let rows = exec
        .read_scoped(
            auth,
            "SELECT effective_capabilities($1)::text",
            &[(&mailbox, Type::INT8)],
        )
        .await?;
    rows.first()
        .and_then(|r| r.try_get(0).ok())
        .ok_or_else(|| StatementFailure {
            hint: None,
            sqlstate: None,
            message: "missing capabilities".into(),
        })
}
#[derive(Default)]
pub struct Settings {
    pub deleted_days: i32,
    pub spam_days: i32,
    pub brand_name: String,
    pub brand_logo: String,
    pub help_email: String,
    pub strict: bool,
    pub flags: BTreeMap<String, bool>,
}
pub async fn settings(exec: &ScopedExecutor, auth: &MailboxAuthContext) -> Settings {
    let mailbox = auth.mailbox().get();
    let mut s = Settings {
        deleted_days: 30,
        spam_days: 30,
        ..Default::default()
    };
    if let Ok(rows)=exec.read_scoped(auth,
        "SELECT COALESCE(mb.deleted_purge_days,COALESCE(NULLIF((SELECT value #>> '{}' FROM system_config WHERE key='deleted_items_purge_days'),'0')::int,30),30), \
         COALESCE(mb.spam_purge_days,COALESCE(NULLIF((SELECT value #>> '{}' FROM system_config WHERE key='spam_purge_days'),'0')::int,30),30) \
         FROM mailboxes mb WHERE mb.id=$1",&[(&mailbox,Type::INT8)]).await {
        if let Some(row)=rows.first(){s.deleted_days=row.get(0);s.spam_days=row.get(1);}
    }
    if let Ok(rows)=exec.read("SELECT COALESCE((SELECT value #>> '{}' FROM system_config WHERE key='brand_name'),'SetJoin'),COALESCE((SELECT value #>> '{}' FROM system_config WHERE key='brand_logo_url'),'')",&[]).await {
        if let Some(row)=rows.first(){s.brand_name=row.get(0);s.brand_logo=row.get(1);}
    }
    if let Ok(rows) = exec
        .read(
            "SELECT COALESCE((SELECT value #>> '{}' FROM system_config WHERE key='help_email'),'')",
            &[],
        )
        .await
    {
        if let Some(row) = rows.first() {
            s.help_email = row.get(0);
        }
    }
    if let Ok(rows)=exec.read("SELECT COALESCE((SELECT lower(value #>> '{}') FROM system_config WHERE key='apps_caps_strict'),'') IN ('1','true')",&[]).await {
        if let Some(row)=rows.first(){s.strict=row.get(0);}
    }
    let keys = vec![
        "feature.shared_task_lists",
        "feature.biometric_unlock",
        "feature.windows_sso_unlock",
        "dengbao.sod_mode",
    ];
    if let Ok(rows) = exec
        .read(
            "SELECT key,enabled FROM feature_toggles WHERE key=ANY($1::text[])",
            &[(&keys, Type::TEXT_ARRAY)],
        )
        .await
    {
        for row in rows {
            s.flags.insert(row.get(0), row.get(1));
        }
    }
    s
}

pub async fn sod_class(
    exec: &ScopedExecutor,
    auth: &MailboxAuthContext,
) -> Result<String, StatementFailure> {
    let user = auth.actor().get();
    let rows=exec.read_iterated("SELECT DISTINCT rg.sod_class::text FROM admin_role_assignments ra JOIN admin_role_groups rg ON rg.id=ra.role_group_id WHERE ra.user_id=$1 AND (ra.expires_at IS NULL OR ra.expires_at>now()) AND rg.sod_class IS NOT NULL", &[(&user,Type::INT8)]).await?;
    let classes: std::collections::BTreeSet<String> = rows
        .iter()
        .filter_map(|r| r.try_get::<_, String>(0).ok())
        .filter(|s| !s.is_empty())
        .collect();
    Ok(if classes.len() == 1 {
        classes.into_iter().next().unwrap()
    } else {
        String::new()
    })
}

/// Mirrors Go's mailbox-only CallScoped scope through the SQL adapter.
pub async fn register_device(
    exec: &ScopedExecutor,
    auth: &MailboxAuthContext,
    envelope: &setjoin_contracts::command::CommandEnvelope<()>,
    fingerprint: &str,
    platform: &str,
) -> setjoin_pg::CommandOutcome<i64, StatementFailure> {
    setjoin_pg::run_receipted_command(
        exec,
        setjoin_pg::ReceiptCommand {
            family: "jmap",
            command: "session.device",
        },
        envelope,
        auth,
        std::time::Instant::now() + std::time::Duration::from_secs(10),
        "SELECT jmap_session_device_register($1,$4,$5) WHERE $2::bigint>0 AND $3::text<>''",
        &[(&fingerprint, Type::TEXT), (&platform, Type::TEXT)],
        |rows| {
            rows.first()
                .and_then(|r| r.try_get(0).ok())
                .ok_or_else(|| StatementFailure {
                    hint: None,
                    sqlstate: None,
                    message: "missing native device".into(),
                })
        },
    )
    .await
}
pub async fn device_caps(
    exec: &ScopedExecutor,
    auth: &MailboxAuthContext,
    device: i64,
) -> Result<String, StatementFailure> {
    let mailbox = auth.mailbox().get();
    let rows = exec
        .read_scoped(
            auth,
            "SELECT effective_capabilities($1,$2)::text",
            &[(&mailbox, Type::INT8), (&device, Type::INT8)],
        )
        .await?;
    rows.first()
        .and_then(|r| r.try_get(0).ok())
        .ok_or_else(|| StatementFailure {
            hint: None,
            sqlstate: None,
            message: "missing device capabilities".into(),
        })
}

/// Same live union order as Go's permissions.ResolveAuthority; self-knowledge only.
pub async fn permissions(
    exec: &ScopedExecutor,
    auth: &MailboxAuthContext,
) -> Result<Vec<String>, StatementFailure> {
    let user = auth.actor().get();
    let rows=exec.read("SELECT rg.permissions FROM admin_role_assignments ra JOIN admin_role_groups rg ON rg.id=ra.role_group_id WHERE ra.user_id=$1 AND (ra.expires_at IS NULL OR ra.expires_at>now()) AND admin_assignment_active(ra.eligible,ra.activated_until)",&[(&user,Type::INT8)]).await?;
    let mut result = Vec::new();
    for row in rows {
        for p in row.get::<_, Vec<String>>(0) {
            if !result.contains(&p) {
                result.push(p);
            }
        }
    }
    Ok(result)
}
