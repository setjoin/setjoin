//! Read-only push tokens scoped to the verified mailbox and actor.
use setjoin_pg::{MailboxAuthContext, ScopedExecutor, Type};
pub async fn tokens(exec: &ScopedExecutor, auth: &MailboxAuthContext) -> [String; 6] {
    let mailbox = auth.mailbox().get();
    let user = auth.actor().get();
    let mut tokens = std::array::from_fn(|_| "unavailable".to_owned());
    if let Ok(rows)=exec.read_scoped(auth,"SELECT jmap_email_state::int8,jmap_mailbox_state::int8,jmap_thread_state::int8 FROM mailboxes WHERE id=$1 AND user_id=$2",&[(&mailbox,Type::INT8),(&user,Type::INT8)]).await {
        if let Some(row)=rows.first() { for (index,token) in tokens.iter_mut().enumerate().take(3) { *token=encode(row.get(index)); } }
    }
    for (index, sql) in [
        "SELECT coalesce(max(jmap_state),0)::int8 FROM calendars WHERE mailbox_id=$1",
        "SELECT coalesce(max(jmap_state),0)::int8 FROM addressbooks WHERE mailbox_id=$1",
        "SELECT coalesce(max(jmap_state),0)::int8 FROM tasks WHERE mailbox_id=$1",
    ]
    .into_iter()
    .enumerate()
    {
        if let Ok(rows) = exec.read_scoped(auth, sql, &[(&mailbox, Type::INT8)]).await {
            if let Some(row) = rows.first() {
                tokens[index + 3] = encode(row.get(0));
            }
        }
    }
    tokens
}
fn encode(n: i64) -> String {
    if n < 0 {
        "unavailable".into()
    } else {
        n.to_string()
    }
}
