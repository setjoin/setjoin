//! Blob metadata is actor-owned across all owned mailboxes, exactly as frozen
//! Go. The worker credential supplies cross-mailbox visibility; every query
//! still predicates on the authenticated actor (R1).
use setjoin_pg::{MailboxAuthContext, ScopedExecutor, StatementFailure, Type};
use std::collections::BTreeMap;

pub struct Blob {
    pub size: i64,
    pub content_type: String,
}
pub async fn owned(
    exec: &ScopedExecutor,
    auth: &MailboxAuthContext,
    ids: &[String],
) -> Result<BTreeMap<String, Blob>, StatementFailure> {
    let ids = ids.to_vec();
    let user = auth.actor().get();
    let rows = exec
        .read_iterated(
            "SELECT DISTINCT b.sha256,b.size_bytes,b.content_type FROM blobs b \
         JOIN message_attachments ma ON ma.blob_sha256=b.sha256 \
         JOIN messages m ON m.id=ma.message_id \
         JOIN mailboxes mb ON mb.id=m.mailbox_id \
         WHERE b.sha256=ANY($1) AND mb.user_id=$2",
            &[(&ids, Type::TEXT_ARRAY), (&user, Type::INT8)],
        )
        .await?;
    let mut found = BTreeMap::new();
    for row in rows {
        let (Ok(id), Ok(size), Ok(content_type)) = (
            row.try_get::<_, String>(0),
            row.try_get::<_, i64>(1),
            row.try_get::<_, Option<String>>(2),
        ) else {
            continue;
        };
        found.insert(
            id,
            Blob {
                size,
                content_type: content_type
                    .filter(|s| !s.is_empty())
                    .unwrap_or_else(|| "application/octet-stream".into()),
            },
        );
    }
    Ok(found)
}
