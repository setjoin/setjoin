//! Blob metadata is actor-owned across all owned mailboxes, exactly as frozen
//! Go. Cross-mailbox reads execute `sql::BLOB_OWNED` (`SqlScope::WorkerBypass`)
//! on the gateway worker pool while predicating on the authenticated actor (R1).
use setjoin_pg::Row;
use std::collections::BTreeMap;

pub struct Blob {
    pub size: i64,
    pub content_type: String,
}

/// Decode rows produced by [`crate::sql::BLOB_OWNED`].
pub fn decode_owned(rows: &[Row]) -> BTreeMap<String, Blob> {
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
    found
}
