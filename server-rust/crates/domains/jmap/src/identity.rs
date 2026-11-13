//! Identity self-knowledge and atomic alias edits, mirroring frozen Go.
use crate::{Failure, SetOutcome};
use setjoin_contracts::command::CommandEnvelope;
use setjoin_pg::{
    CommandOutcome, MailboxAuthContext, ReceiptCommand, Rejection, ScopedExecutor,
    StatementFailure, Type, run_receipted_command,
};
#[derive(Default)]
pub struct Primary {
    pub email: String,
    pub name: String,
    pub given: Option<String>,
    pub family: Option<String>,
    pub avatar: Option<String>,
}
pub struct Entry {
    pub id: i64,
    pub name: String,
    pub email: String,
    pub signature: Option<String>,
    pub reply: Option<String>,
}
pub async fn primary(exec: &ScopedExecutor, auth: &MailboxAuthContext) -> Primary {
    let user = auth.actor().get();
    let rows=exec.read("SELECT email::text,display_name::text,first_name::text,last_name::text,avatar_sha256::text FROM users WHERE id=$1",&[(&user,Type::INT8)]).await.unwrap_or_default();
    rows.first()
        .and_then(|r| {
            Some(Primary {
                email: r.try_get(0).ok()?,
                name: r.try_get(1).ok()?,
                given: r.try_get(2).ok()?,
                family: r.try_get(3).ok()?,
                avatar: r.try_get(4).ok()?,
            })
        })
        .unwrap_or_default()
}
pub async fn aliases(exec: &ScopedExecutor, auth: &MailboxAuthContext) -> Vec<Entry> {
    let user = auth.actor().get();
    let rows=exec.read_iterated("SELECT a.id,COALESCE(a.display_name,a.email)::text,a.email::text,a.signature::text,a.reply_to::text FROM aliases a JOIN mailboxes m ON m.id=a.mailbox_id WHERE m.user_id=$1",&[(&user,Type::INT8)]).await.unwrap_or_default();
    rows.iter()
        .filter_map(|r| {
            Some(Entry {
                id: r.try_get(0).ok()?,
                name: r.try_get(1).ok()?,
                email: r.try_get(2).ok()?,
                signature: r.try_get(3).ok()?,
                reply: r.try_get(4).ok()?,
            })
        })
        .collect()
}
pub async fn delegated(exec: &ScopedExecutor, auth: &MailboxAuthContext) -> Vec<Entry> {
    let user = auth.actor().get();
    let rows=exec.read_iterated("SELECT mb.id,COALESCE(mb.display_name,mb.email)::text,mb.email::text FROM mailboxes mb JOIN mailbox_delegates md ON md.mailbox_id=mb.id WHERE md.user_id=$1 AND md.permission IN ('send_as','full_access') AND mb.user_id<>$1",&[(&user,Type::INT8)]).await.unwrap_or_default();
    rows.iter()
        .filter_map(|r| {
            Some(Entry {
                id: r.try_get(0).ok()?,
                name: r.try_get(1).ok()?,
                email: r.try_get(2).ok()?,
                signature: None,
                reply: None,
            })
        })
        .collect()
}
pub async fn state(exec: &ScopedExecutor, auth: &MailboxAuthContext) -> Option<String> {
    let user = auth.actor().get();
    let rows = exec
        .read(
            "SELECT floor(extract(epoch FROM updated_at))::bigint FROM users WHERE id=$1",
            &[(&user, Type::INT8)],
        )
        .await
        .ok()?;
    Some(rows.first()?.try_get::<_, i64>(0).ok()?.to_string())
}
pub async fn set(
    exec: &ScopedExecutor,
    auth: &MailboxAuthContext,
    envelope: &CommandEnvelope<()>,
    create: &Option<String>,
    update: &Option<String>,
    destroy: &Option<Vec<i64>>,
) -> SetOutcome {
    let out=run_receipted_command(exec,ReceiptCommand{family:"jmap",command:"identity.set"},envelope,auth,std::time::Instant::now()+std::time::Duration::from_secs(10),"SELECT jmap_identity_set_batch($1,$4::text::jsonb,$5::text::jsonb,$6)::text WHERE $2::bigint>0 AND $3::text<>''",&[(create,Type::TEXT),(update,Type::TEXT),(destroy,Type::INT8_ARRAY)],|rows|rows.first().and_then(|r|r.try_get(0).ok()).ok_or_else(||StatementFailure{hint:None,sqlstate:None,message:"missing identity set result".into()})).await;
    match out {
        CommandOutcome::Committed(raw) => SetOutcome::Done(raw),
        CommandOutcome::Unknown { operation } => SetOutcome::Unknown { operation },
        CommandOutcome::RolledBack(Rejection::Statement(f)) => {
            SetOutcome::Failed(match crate::classify_failure(&f) {
                Failure::Forward => Failure::ServerFail,
                f => f,
            })
        }
        _ => SetOutcome::Failed(Failure::ServerFail),
    }
}
